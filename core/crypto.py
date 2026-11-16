from __future__ import annotations

import base64
import os
import re
from typing import Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

VERIFIER_PLAINTEXT = "MD_VAULT_VERIFIER_OK_V1"
VERIFIER_AAD = b"mdvault:header:verifier"
DEFAULT_ITERATIONS = 600_000
ENC_PATTERN = re.compile(r"^ENC\[(v1|v2):([A-Za-z0-9_\-=]+):([A-Za-z0-9_\-=]+)\]$")
ANY_ENC_PATTERN = re.compile(r"^ENC\[v(\d+):([A-Za-z0-9_\-=]+):([A-Za-z0-9_\-=]+)\]$")


class CryptoError(Exception):
    """Base exception for vault cryptographic operations."""


class InvalidMasterPasswordError(CryptoError):
    """Raised when master password verification fails."""


class CryptoIntegrityError(CryptoError):
    """Raised when ciphertext is corrupted or tampered with."""


def build_field_aad(entry_id: str, field_name: str) -> bytes:
    """Build deterministic AES-GCM Associated Authenticated Data binding entry ID & field."""
    clean_id = (entry_id or "").strip()
    clean_field = (field_name or "").strip()
    if not clean_id or not clean_field:
        raise ValueError("AAD 绑定需要有效的 entry_id 与 field_name")
    return f"mdvault:entry:{clean_id}:{clean_field}".encode("utf-8")


def is_encrypted_token(value: str) -> bool:
    """Return True if value matches the ENC[v1|v2:<nonce>:<ciphertext>] format."""
    if not value:
        return False
    return bool(ENC_PATTERN.match(value.strip()))


def is_v2_encrypted_token(value: str) -> bool:
    """Return True if value is specifically an AAD-bound ENC[v2:...] token."""
    if not value:
        return False
    m = ENC_PATTERN.match(value.strip())
    return bool(m and m.group(1) == "v2")


def derive_aes_key(
    master_password: str,
    salt: bytes,
    iterations: int = DEFAULT_ITERATIONS,
) -> bytes:
    """Derive a 256-bit AES key from master password using PBKDF2-HMAC-SHA256."""
    if not master_password:
        raise ValueError("主密码不能为空")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(master_password.encode("utf-8"))


class CryptoEngine:
    """In-memory AES-256-GCM field encryption/decryption engine."""

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("AES-256 key must be exactly 32 bytes")
        self._key: Optional[bytes] = key

    @property
    def is_unlocked(self) -> bool:
        return self._key is not None

    def lock(self) -> None:
        """Clear derived key reference from memory."""
        self._key = None

    def _require_aesgcm(self) -> AESGCM:
        if self._key is None:
            raise CryptoError("密码库当前处于锁定状态")
        return AESGCM(self._key)

    @classmethod
    def create_new(
        cls,
        master_password: str,
        iterations: int = DEFAULT_ITERATIONS,
    ) -> Tuple["CryptoEngine", str, str]:
        """Create a fresh salt, derive key, and generate AAD-bound verifier token."""
        salt = os.urandom(16)
        salt_b64 = base64.urlsafe_b64encode(salt).decode("ascii")
        key = derive_aes_key(master_password, salt, iterations)
        engine = cls(key)
        verifier = engine.encrypt_value(VERIFIER_PLAINTEXT, aad=VERIFIER_AAD)
        return engine, salt_b64, verifier

    @classmethod
    def unlock_existing(
        cls,
        master_password: str,
        salt_b64: str,
        verifier_token: str,
        iterations: int = DEFAULT_ITERATIONS,
    ) -> "CryptoEngine":
        """Verify master password against stored salt and verifier token (v1 & v2 compatible)."""
        try:
            salt = base64.urlsafe_b64decode(salt_b64.encode("ascii"))
        except Exception as exc:
            raise CryptoIntegrityError("密码库头部盐值 (salt) 格式损坏") from exc

        try:
            key = derive_aes_key(master_password, salt, iterations)
        except ValueError as exc:
            raise InvalidMasterPasswordError(str(exc)) from exc

        engine = cls(key)
        try:
            verified = engine.decrypt_token(verifier_token, aad=VERIFIER_AAD)
        except (InvalidTag, CryptoIntegrityError) as exc:
            engine.lock()
            raise InvalidMasterPasswordError("主密码不正确，请重新输入") from exc

        if verified != VERIFIER_PLAINTEXT:
            engine.lock()
            raise InvalidMasterPasswordError("主密码校验未通过")

        return engine

    def encrypt_value(self, plaintext: str, aad: Optional[bytes] = None) -> str:
        """
        Encrypt non-empty plaintext using AES-256-GCM.
        Produces ENC[v2:<nonce>:<ct>] when context AAD is supplied, or ENC[v1:...] when aad is None.
        """
        if plaintext == "":
            return ""
        aesgcm = self._require_aesgcm()
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)
        nonce_b64 = base64.urlsafe_b64encode(nonce).decode("ascii")
        ct_b64 = base64.urlsafe_b64encode(ct).decode("ascii")
        ver = "v2" if aad is not None else "v1"
        return f"ENC[{ver}:{nonce_b64}:{ct_b64}]"

    def seal_if_plaintext(
        self,
        value: str,
        aad: Optional[bytes] = None,
        upgrade_v1: bool = False,
    ) -> Tuple[str, bool]:
        """
        Ensure a sensitive string is encrypted (and optionally migrated from v1 to AAD-bound v2).
        Automatically detects and heals nested ENC[...] tokens caused by legacy client re-sealing.
        Returns (encrypted_token, was_newly_sealed).
        """
        if not value:
            return "", False
        stripped = value.strip()
        match = ENC_PATTERN.match(stripped)
        if match:
            ver = match.group(1)
            inner = self.decrypt_token(stripped, aad=aad)
            if is_encrypted_token(inner):
                real_pt = self.decrypt_if_needed(inner, aad=aad)
                return self.encrypt_value(real_pt, aad=aad), True
            if ver == "v1" and upgrade_v1 and aad is not None:
                return self.encrypt_value(inner, aad=aad), True
            return stripped, False
        if ANY_ENC_PATTERN.match(stripped):
            raise CryptoIntegrityError("检测到更高版本的加密字段格式，请使用新版 MD-Vault 打开")
        return self.encrypt_value(value, aad=aad), True

    def decrypt_token(self, token: str, aad: Optional[bytes] = None) -> str:
        """Strictly decrypt an ENC[v1:...] or AAD-bound ENC[v2:...] token."""
        if token == "":
            return ""
        stripped = token.strip()
        match = ENC_PATTERN.match(stripped)
        if not match:
            if ANY_ENC_PATTERN.match(stripped):
                raise CryptoIntegrityError("检测到更高版本的加密字段格式，请升级 MD-Vault 客户端")
            raise CryptoIntegrityError("无效的加密字段格式")

        ver, nonce_b64, ct_b64 = match.group(1), match.group(2), match.group(3)
        try:
            nonce = base64.urlsafe_b64decode(nonce_b64.encode("ascii"))
            ct = base64.urlsafe_b64decode(ct_b64.encode("ascii"))
        except Exception as exc:
            raise CryptoIntegrityError("加密字段 Base64 解码失败") from exc

        aesgcm = self._require_aesgcm()
        effective_aad = aad if ver == "v2" else None
        try:
            pt = aesgcm.decrypt(nonce, ct, effective_aad)
        except InvalidTag as exc:
            raise CryptoIntegrityError(
                "密文完整性或上下文绑定校验失败（密钥不匹配、密文被篡改或跨条目替换）"
            ) from exc
        return pt.decode("utf-8")

    def decrypt_if_needed(
        self, value: str, aad: Optional[bytes] = None, max_depth: int = 8
    ) -> str:
        """Decrypt ENC[v1|v2:...] token (unwrapping any nested layers), or return as-is if plaintext."""
        if not value:
            return ""
        current = value
        depth = 0
        while is_encrypted_token(current) and depth < max_depth:
            current = self.decrypt_token(current, aad=aad)
            depth += 1
        return current
