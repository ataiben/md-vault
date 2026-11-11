import pytest

from core.crypto import (
    CryptoEngine,
    CryptoError,
    CryptoIntegrityError,
    InvalidMasterPasswordError,
    is_encrypted_token,
)


def test_create_and_unlock_master_password():
    # Use lower iterations in unit tests for speed while verifying full PBKDF2 + AES-GCM flow
    engine, salt_b64, verifier = CryptoEngine.create_new("MyStrongMaster#2026", iterations=10_000)
    assert is_encrypted_token(verifier)

    unlocked = CryptoEngine.unlock_existing(
        "MyStrongMaster#2026", salt_b64, verifier, iterations=10_000
    )
    assert unlocked.is_unlocked

    with pytest.raises(InvalidMasterPasswordError):
        CryptoEngine.unlock_existing("WrongPassword", salt_b64, verifier, iterations=10_000)


def test_random_nonce_and_tamper_detection():
    engine, _, _ = CryptoEngine.create_new("MasterKey123", iterations=10_000)
    secret = "Apple#Turkey_Region_99!"

    tok1 = engine.encrypt_value(secret)
    tok2 = engine.encrypt_value(secret)
    # Identical plaintexts must produce distinct ciphertexts due to fresh 12-byte random nonce
    assert tok1 != tok2
    assert engine.decrypt_token(tok1) == secret
    assert engine.decrypt_token(tok2) == secret

    # Tamper with ciphertext character -> must fail AES-GCM authentication tag check
    corrupted = tok1[:-3] + ("A" if tok1[-3] != "A" else "B") + tok1[-2:]
    with pytest.raises(CryptoIntegrityError):
        engine.decrypt_token(corrupted)


def test_seal_if_plaintext_and_lock_memory():
    engine, _, _ = CryptoEngine.create_new("MasterKey123", iterations=10_000)

    sealed, changed = engine.seal_if_plaintext("handwritten_plain_pass")
    assert changed is True
    assert is_encrypted_token(sealed)

    sealed_again, changed_again = engine.seal_if_plaintext(sealed)
    assert changed_again is False
    assert sealed_again == sealed

    engine.lock()
    assert not engine.is_unlocked
    with pytest.raises(CryptoError):
        engine.encrypt_value("after_lock")
