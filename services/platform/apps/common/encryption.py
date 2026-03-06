"""
Encryption utilities for PRAHO Platform.

AES-256-GCM authenticated encryption for sensitive data (2FA secrets,
API keys, passwords, settings). Replaces legacy Fernet and Django Signer systems.

Wire format: "aes:" + base64url(NONCE[12B] + CIPHERTEXT + TAG[16B])
Key format: URL-safe base64-encoded 32 random bytes (DJANGO_ENCRYPTION_KEY)
Standard: NIST SP 800-38D (GCM), AES-256 (quantum-safe per NIST PQC)
"""

import base64
import logging
import os
import secrets
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.core.exceptions import ImproperlyConfigured

logger = logging.getLogger(__name__)

# --- Constants ---
ENCRYPTED_PREFIX = "aes:"
AES_KEY_SIZE = 32  # 256 bits
NONCE_SIZE = 12  # 96 bits (GCM standard)

# --- Exceptions ---


class EncryptionError(Exception):
    """Raised when encryption fails."""


class DecryptionError(Exception):
    """Raised when decryption fails due to invalid key, corrupted data, or tampering."""


# --- Internal state (lazy-init) ---
_cached_key: bytes | None = None
_cached_aesgcm: AESGCM | None = None


def _get_aesgcm() -> AESGCM:
    """Get or initialize the cached AESGCM instance."""
    global _cached_key, _cached_aesgcm  # noqa: PLW0603
    key = get_encryption_key()
    if _cached_aesgcm is None or _cached_key != key:
        _cached_aesgcm = AESGCM(key)
        _cached_key = key
    return _cached_aesgcm


# --- Core API ---


def get_encryption_key() -> bytes:
    """Load and validate DJANGO_ENCRYPTION_KEY.

    Expects URL-safe base64-encoded 32 random bytes.
    Generate with: python -c "import secrets, base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"

    Returns:
        Raw 32-byte AES-256 key.

    Raises:
        ImproperlyConfigured: If key is missing or invalid.
    """
    encryption_key = getattr(settings, "ENCRYPTION_KEY", None)

    if not encryption_key:
        encryption_key = os.environ.get("DJANGO_ENCRYPTION_KEY")

    if not encryption_key:
        raise ImproperlyConfigured(
            "DJANGO_ENCRYPTION_KEY environment variable must be set. "
            'Generate with: python -c "import secrets, base64; '
            'print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"'
        )

    try:
        if isinstance(encryption_key, bytes):
            encryption_key = encryption_key.decode("ascii")
        key_bytes = base64.urlsafe_b64decode(encryption_key)
    except Exception as e:
        raise ImproperlyConfigured(f"DJANGO_ENCRYPTION_KEY is not valid base64: {e}") from e

    if len(key_bytes) != AES_KEY_SIZE:
        raise ImproperlyConfigured(f"DJANGO_ENCRYPTION_KEY must decode to {AES_KEY_SIZE} bytes, got {len(key_bytes)}")

    return key_bytes


def encrypt_sensitive_data(data: str) -> str:
    """Encrypt sensitive data using AES-256-GCM.

    Args:
        data: Plain text string to encrypt.

    Returns:
        Encrypted string in format "aes:" + base64url(nonce + ciphertext + tag).
        Empty string if input is empty.

    Raises:
        EncryptionError: If encryption fails.
    """
    if not data:
        return ""

    try:
        aesgcm = _get_aesgcm()
        nonce = os.urandom(NONCE_SIZE)
        ciphertext_and_tag = aesgcm.encrypt(nonce, data.encode("utf-8"), None)
        raw = nonce + ciphertext_and_tag
        return ENCRYPTED_PREFIX + base64.urlsafe_b64encode(raw).decode("ascii")
    except Exception as e:
        raise EncryptionError(f"Encryption failed: {type(e).__name__}") from e


def decrypt_sensitive_data(encrypted_data: str) -> str:
    """Decrypt AES-256-GCM encrypted data.

    Args:
        encrypted_data: Encrypted string with "aes:" prefix.

    Returns:
        Decrypted plain text string. Empty string if input is empty.

    Raises:
        DecryptionError: If decryption fails (wrong key, corrupted, tampered).
    """
    if not encrypted_data:
        return ""

    if not encrypted_data.startswith(ENCRYPTED_PREFIX):
        raise DecryptionError(f"Invalid encrypted data: missing '{ENCRYPTED_PREFIX}' prefix")

    try:
        aesgcm = _get_aesgcm()
        encoded = encrypted_data[len(ENCRYPTED_PREFIX) :]
        raw = base64.urlsafe_b64decode(encoded)
        if len(raw) < NONCE_SIZE + 16:  # nonce + minimum tag
            raise ValueError("Ciphertext too short")
        nonce = raw[:NONCE_SIZE]
        ciphertext_and_tag = raw[NONCE_SIZE:]
        plaintext = aesgcm.decrypt(nonce, ciphertext_and_tag, None)
        return plaintext.decode("utf-8")
    except DecryptionError:
        raise
    except Exception as e:
        logger.error(f"Failed to decrypt sensitive data: {type(e).__name__}")
        raise DecryptionError(f"Decryption failed: {type(e).__name__}") from e


# --- Settings-compat API (absorbed from SettingsEncryption) ---


def is_encrypted(value: Any) -> bool:
    """Check if a value is encrypted (has the 'aes:' prefix)."""
    if not isinstance(value, str):
        return False
    return value.startswith(ENCRYPTED_PREFIX)


def encrypt_value(value: Any) -> str | None:
    """Encrypt any value (converted to string) for settings/config storage.

    Args:
        value: Value to encrypt. Converted to str before encryption.

    Returns:
        Encrypted string, or None if input is None.

    Raises:
        EncryptionError: If encryption fails.
    """
    if value is None:
        return None
    return encrypt_sensitive_data(str(value))


def decrypt_value(encrypted_value: str) -> str:
    """Decrypt an encrypted value.

    If the value is not encrypted (no 'aes:' prefix), returns it as-is.
    Rejects legacy Fernet ciphertext to prevent silent data corruption.

    Raises:
        DecryptionError: If decryption of an encrypted value fails.
    """
    if not encrypted_value:
        return encrypted_value
    if encrypted_value.startswith("gAAAAA"):
        raise DecryptionError("Legacy Fernet-encrypted data detected — run data migration to clear stale ciphertext")
    if not is_encrypted(encrypted_value):
        return encrypted_value
    return decrypt_sensitive_data(encrypted_value)


def decrypt_if_needed(value: Any) -> Any:
    """Decrypt value if encrypted, return as-is otherwise."""
    if isinstance(value, str) and is_encrypted(value):
        return decrypt_sensitive_data(value)
    return value


def encrypt_if_sensitive(value: Any, is_sensitive: bool) -> Any:
    """Conditionally encrypt value if marked as sensitive."""
    if is_sensitive and value is not None:
        return encrypt_value(value)
    return value


# --- Backup codes (hashing, not encryption — unchanged) ---


def generate_backup_codes(count: int = 8) -> list[str]:
    """Generate secure backup codes for 2FA recovery.

    Args:
        count: Number of backup codes to generate (default 8).

    Returns:
        List of secure backup codes (8 digits each).
    """
    return ["".join(secrets.choice("0123456789") for _ in range(8)) for _ in range(count)]


def hash_backup_code(code: str) -> str:
    """Hash backup code for secure storage using Django's password hashing."""
    return make_password(code)


def verify_backup_code(code: str, hashed_code: str) -> bool:
    """Verify backup code against stored hash."""
    return check_password(code, hashed_code)
