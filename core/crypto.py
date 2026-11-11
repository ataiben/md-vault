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
DEFAULT_ITERATIONS = 600_000
ENC_PATTERN = re.compile(r"^ENC\[v1:([A-Za-z0-9_\-=]+):([A-Za-z0-9_\-=]+)\]$")


class CryptoError(Exception):
    """Base exception for vault cryptographic operations."""


class InvalidMasterPasswordError(CryptoError):
    """Raised when master password verification fails."""


class CryptoIntegrityError(CryptoError):
    """Raised when ciphertext is corrupted or tampered with."""


def is_encrypted_token(value: str) -> bool:
    """Return True if value matches the ENC[v1:<nonce>:<ciphertext>] format."""
    if not value:
        return False
    return bool(ENC_PATTERN.match(value.strip()))


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
        """Create a fresh salt, derive key, and generate verifier token."""
        salt = os.urandom(16)
        salt_b64 = base64.urlsafe_b64encode(salt).decode("ascii")
        key = derive_aes_key(master_password, salt, iterations)
        engine = cls(key)
        verifier = engine.encrypt_value(VERIFIER_PLAINTEXT)
        return engine, salt_b64, verifier

    @classmethod
    def unlock_existing(
        cls,
        master_password: str,
        salt_b64: str,
        verifier_token: str,
        iterations: int = DEFAULT_ITERATIONS,
    ) -> "CryptoEngine":
        """Verify master password against stored salt and verifier token."""
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
            verified = engine.decrypt_token(verifier_token)
        except (InvalidTag, CryptoIntegrityError) as exc:
            engine.lock()
            raise InvalidMasterPasswordError("主密码不正确，请重新输入") from exc

        if verified != VERIFIER_PLAINTEXT:
            engine.lock()
            raise InvalidMasterPasswordError("主密码校验未通过")

        return engine

    def encrypt_value(self, plaintext: str) -> str:
        """Encrypt non-empty plaintext into ENC[v1:<nonce>:<ciphertext>]."""
        if plaintext == "":
            return ""
        aesgcm = self._require_aesgcm()
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        nonce_b64 = base64.urlsafe_b64encode(nonce).decode("ascii")
        ct_b64 = base64.urlsafe_b64encode(ct).decode("ascii")
        return f"ENC[v1:{nonce_b64}:{ct_b64}]"

    def seal_if_plaintext(self, value: str) -> Tuple[str, bool]:
        """
        Ensure a sensitive string is encrypted.
        Returns (encrypted_token, was_newly_sealed).
        """
        if not value:
            return "", False
        stripped = value.strip()
        if is_encrypted_token(stripped):
            return stripped, False
        return self.encrypt_value(value), True

    def decrypt_token(self, token: str) -> str:
        """Strictly decrypt an ENC[v1:...] token."""
        if token == "":
            return ""
        match = ENC_PATTERN.match(token.strip())
        if not match:
            raise CryptoIntegrityError("无效的加密字段格式")

        nonce_b64, ct_b64 = match.group(1), match.group(2)
        try:
            nonce = base64.urlsafe_b64decode(nonce_b64.encode("ascii"))
            ct = base64.urlsafe_b64decode(ct_b64.encode("ascii"))
        except Exception as exc:
            raise CryptoIntegrityError("加密字段 Base64 解码失败") from exc

        aesgcm = self._require_aesgcm()
        try:
            pt = aesgcm.decrypt(nonce, ct, None)
        except InvalidTag as exc:
            raise CryptoIntegrityError("密文完整性校验失败（密钥不匹配或密文被篡改）") from exc
        return pt.decode("utf-8")

    def decrypt_if_needed(self, value: str) -> str:
        """Decrypt ENC[v1:...] token, or return as-is if plaintext/empty."""
        if not value:
            return ""
        if is_encrypted_token(value):
            return self.decrypt_token(value)
        return value
