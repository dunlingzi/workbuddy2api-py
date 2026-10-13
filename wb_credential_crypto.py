#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""wb_credential_crypto — WorkBuddy 5.6.x 本地凭据字段解密（at-rest crypto, suite 1）。

## 背景

WorkBuddy 5.6.2 起，桌面端把 `.info` 里的敏感字段做了本地加密：

    {"$wbEncrypted": 1, "envelope": base64(JSON{suite,keyId,nonce,authTag,ciphertext})}

受影响字段：`auth.accessToken` / `auth.refreshToken` / `account.nickname` / `account.phoneNumber`
（`account.uid`、`auth.expiresAt` 等仍为明文，所以导入入库不受影响，但拿不到明文 token）。

## 算法（逆向 5.6.2 `packages/at-rest-crypto` 得出）

- AES-256-GCM，nonce 12B，authTag 16B（cryptography 风格：decrypt 时 ciphertext+tag 拼接）
- 静态钥（build key）：`atRestSecretKey`（base64 字符串，内嵌于 Electron fork 原生层
  `electron.workbuddyStorage`，全网安装一致 —— keyblob 的 protectorKeyId 固定为 9127dea1b44020a7）
- 实际 AES 密钥 = sha256(atRestSecretKey 字符串 utf8)；keyId = sha256(key).hexdigest()[:16]
- AAD（field framing，无 sequence/final）：
    "WB-AAD\\0" + 0x01 + LP("WBEV1") + LP("sym-v1") + u32be(suite) + LP(keyId) + 0x02 + 0x00 + 0x00
  其中 LP(s) = u32be(len(s)) + s

## 静态钥的获取

静态钥只能从桌面端运行时提取（Electron fuse 开了 asar integrity，不能改包）。
用项目内 `scripts/wb_extract_atrest_key.py`（Node inspector + CDP，零文件改动）提取一次，
配置到 `WORKBUDDY_AT_REST_SECRET_KEY`（.env）。换桌面端大版本若失效需重新提取。
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import struct

logger = logging.getLogger("wb_credential_crypto")

_SECRET_ENV = "WORKBUDDY_AT_REST_SECRET_KEY"
_KEY_CACHE: bytes | None = None
_KEY_TRIED = False

AAD_DOMAIN = b"WB-AAD\x00"
FRAMING_CODE = {"file": 1, "field": 2}
FORMAT_ID = {"file": "WBEF1", "field": "WBEV1"}


def _lp(s: str) -> bytes:
    b = s.encode("utf-8")
    return struct.pack(">I", len(b)) + b


def _build_aad(key_id: str, suite: int, framing: str = "field", scheme: str = "sym-v1") -> bytes:
    """buildAuthenticatedContextAad 的 sym-v1 whole-value 分支（无 sequence/final）。"""
    return b"".join([
        AAD_DOMAIN,
        bytes([1]),
        _lp(FORMAT_ID[framing]),
        _lp(scheme),
        struct.pack(">I", suite),
        _lp(key_id),
        bytes([FRAMING_CODE[framing]]),
        b"\x00",
        bytes([0]),
    ])


def _secret_from_env_file() -> str:
    """converter 独立运行时不加载 .env（由 main.py 托管时才注入环境），这里直接读项目根 .env 兜底。"""
    try:
        root = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(root, ".env"), encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith(f"{_SECRET_ENV}="):
                    return line.split("=", 1)[1].strip()
    except Exception:
        pass
    return ""


def get_secret_key() -> bytes | None:
    """静态钥 AES 字节 = sha256(atRestSecretKey 字符串)。未配置返回 None（调用方降级）。"""
    global _KEY_CACHE, _KEY_TRIED
    if _KEY_CACHE is not None or _KEY_TRIED:
        return _KEY_CACHE
    _KEY_TRIED = True
    raw = os.environ.get(_SECRET_ENV, "").strip() or _secret_from_env_file()
    if not raw:
        return None
    try:
        _KEY_CACHE = hashlib.sha256(raw.encode("utf-8")).digest()
    except Exception:
        _KEY_CACHE = None
    return _KEY_CACHE


def reset_key_cache() -> None:
    """环境变量变化后（测试/热更新）清缓存。"""
    global _KEY_CACHE, _KEY_TRIED
    _KEY_CACHE = None
    _KEY_TRIED = False


def is_encrypted_wrapper(value) -> bool:
    """standard 形态：{ "$wbEncrypted": 1, "envelope": str }（asym-v1 带 scheme 的暂不支持）。"""
    return (
        isinstance(value, dict)
        and value.get("$wbEncrypted") == 1
        and isinstance(value.get("envelope"), str)
        and "scheme" not in value
    )


def decrypt_envelope(envelope_b64: str, key: bytes, framing: str = "field") -> bytes:
    """解单个字段 envelope。认证失败抛 InvalidTag。"""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    envelope = json.loads(base64.b64decode(envelope_b64))
    suite = int(envelope.get("suite", 1))
    nonce = base64.b64decode(envelope["nonce"])
    tag = base64.b64decode(envelope["authTag"])
    ct = base64.b64decode(envelope.get("ciphertext") or "")
    aad = _build_aad(envelope["keyId"], suite, framing)
    try:
        return AESGCM(key).decrypt(nonce, ct + tag, aad)
    except InvalidTag as e:
        raise ValueError(f"at-rest field decrypt failed (keyId={envelope.get('keyId')})") from e


def _try_decrypt_value(value, key: bytes):
    """wrapper → 明文字符串；其它值原样返回；解密失败返回原值（不炸导入链路）。"""
    if not is_encrypted_wrapper(value):
        return value
    try:
        return decrypt_envelope(value["envelope"], key, "field").decode("utf-8")
    except Exception as e:
        logger.warning("at-rest 字段解密失败（保留密文原样）：%s", e)
        return value


# .info 里已观测到的加密字段（逐一尝试即可，别的字段是明文）
_ENCRYPTED_PATHS = (
    ("auth", "accessToken"),
    ("auth", "refreshToken"),
    ("account", "nickname"),
    ("account", "phoneNumber"),
)


def ensure_plain_auth(auth_json: str) -> str:
    """把 5.6.x 密文 .info 转成明文形态；已是明文/无静态钥/解析失败时原样返回。

    放在导入入库与 CredentialManager 读取的必经路上：密文字段解开后，下游
    （token 刷新、鉴权头、昵称显示）全部按 5.5.6 的明文行为工作。
    """
    key = get_secret_key()
    if key is None or not auth_json or "$wbEncrypted" not in auth_json:
        return auth_json
    try:
        data = json.loads(auth_json)
    except Exception:
        return auth_json
    changed = False
    for section, field in _ENCRYPTED_PATHS:
        node = data.get(section)
        if not isinstance(node, dict):
            continue
        plain = _try_decrypt_value(node.get(field), key)
        if plain is not node.get(field):
            node[field] = plain
            changed = True
    if not changed:
        return auth_json
    try:
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception:
        return auth_json
