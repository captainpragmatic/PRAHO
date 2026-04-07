"""
Encryption utilities for PRAHO Platform.

AES-256-GCM authenticated encryption for sensitive data (2FA secrets,
API keys, passwords, settings). Replaces legacy Fernet and Django Signer systems.

Wire format v1 (legacy, no AAD):  "aes:v1:" + base64url(nonce[12B] + ciphertext + tag[16B])
Wire format v2 (AAD-bound):       "aes:v2:" + base64url(aad_len[2B] + aad + nonce[12B] + ciphertext + tag[16B])
Legacy format (pre-versioning):   "aes:" + base64url(nonce[12B] + ciphertext + tag[16B])

Key format: URL-safe base64-encoded 32 random bytes (DJANGO_ENCRYPTION_KEY)
Standard: NIST SP 800-38D (GCM), AES-256 (quantum-safe per NIST PQC)
"""

import base64
import logging
import os
import secrets
import struct
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.core.exceptions import ImproperlyConfigured

logger = logging.getLogger(__name__)

# --- Constants ---
ENCRYPTED_PREFIX = "aes:"
VERSIONED_V1_PREFIX = "aes:v1:"
VERSIONED_V2_PREFIX = "aes:v2:"
AES_KEY_SIZE = 32  # 256 bits
NONCE_SIZE = 12  # 96 bits (GCM standard)
AAD_LEN_SIZE = 2  # uint16 for AAD length

# --- Exceptions ---


class EncryptionError(Exception):
    """Raised when encryption fails."""


class DecryptionError(Exception):
    """Raised when decryption fails due to invalid key, corrupted data, or tampering."""


# --- Internal state (lazy-init) ---
_aesgcm_cache: dict[bytes, AESGCM] = {}


def _get_aesgcm(key: bytes) -> AESGCM:
    """Get or create a cached AESGCM instance for the given key."""
    if key not in _aesgcm_cache:
        _aesgcm_cache[key] = AESGCM(key)
    return _aesgcm_cache[key]


def _clear_aesgcm_cache() -> None:
    """Clear the AESGCM cache (for testing only)."""
    _aesgcm_cache.clear()


# --- Key management ---


def _decode_key(key_b64: str | bytes) -> bytes:
    """Decode and validate a single base64 encryption key."""
    try:
        if isinstance(key_b64, bytes):
            key_b64 = key_b64.decode("ascii")
        key_bytes = base64.urlsafe_b64decode(key_b64)
    except Exception as e:
        raise ImproperlyConfigured(f"Encryption key is not valid base64: {e}") from e

    if len(key_bytes) != AES_KEY_SIZE:
        raise ImproperlyConfigured(f"Encryption key must decode to {AES_KEY_SIZE} bytes, got {len(key_bytes)}")

    return key_bytes


def get_encryption_keys() -> list[bytes]:
    """Load the ordered keyring [current, ...previous].

    Checks ``settings.ENCRYPTION_KEYS`` (list) first, falls back to
    ``settings.ENCRYPTION_KEY`` / ``DJANGO_ENCRYPTION_KEY`` env var.
    First key is used for new encryptions; all keys are tried for decryption.
    """
    # Try ENCRYPTION_KEYS list first
    keys_setting = getattr(settings, "ENCRYPTION_KEYS", None)
    if keys_setting and isinstance(keys_setting, list):
        keys_b64 = [k for k in keys_setting if k]
        if keys_b64:
            return [_decode_key(k) for k in keys_b64]

    # Fall back to single ENCRYPTION_KEY / env var
    single_key = getattr(settings, "ENCRYPTION_KEY", None) or os.environ.get("DJANGO_ENCRYPTION_KEY")
    if not single_key:
        raise ImproperlyConfigured(
            "DJANGO_ENCRYPTION_KEY environment variable must be set. "
            'Generate with: python -c "import secrets, base64; '
            'print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"'
        )
    return [_decode_key(single_key)]


def get_encryption_key() -> bytes:
    """Return the current (first) encryption key. Backward-compatible API."""
    return get_encryption_keys()[0]


# --- Core API ---


def encrypt_sensitive_data(data: str, *, aad: bytes | None = None) -> str:
    """Encrypt sensitive data using AES-256-GCM.

    Args:
        data: Plain text string to encrypt.
        aad: Optional Associated Authenticated Data for context binding.
             When provided, produces v2 format; otherwise v1.

    Returns:
        Encrypted string. Empty string if input is empty.

    Raises:
        EncryptionError: If encryption fails.
    """
    if not data:
        return ""

    try:
        key = get_encryption_keys()[0]
        aesgcm = _get_aesgcm(key)
        nonce = os.urandom(NONCE_SIZE)
        ciphertext_and_tag = aesgcm.encrypt(nonce, data.encode("utf-8"), aad)

        if aad is not None:
            # v2: embed AAD in payload so decryption is self-contained
            aad_len = struct.pack("!H", len(aad))  # 2-byte big-endian length
            raw = aad_len + aad + nonce + ciphertext_and_tag
            return VERSIONED_V2_PREFIX + base64.urlsafe_b64encode(raw).decode("ascii")

        # v1: no AAD
        raw = nonce + ciphertext_and_tag
        return VERSIONED_V1_PREFIX + base64.urlsafe_b64encode(raw).decode("ascii")
    except Exception as e:
        raise EncryptionError(f"Encryption failed: {type(e).__name__}") from e


def decrypt_sensitive_data(encrypted_data: str, *, aad: bytes | None = None) -> str:
    """Decrypt AES-256-GCM encrypted data.

    Supports all wire formats: v2 (AAD-bound), v1 (no AAD), legacy (pre-versioning).
    Tries all keys in the keyring for key rotation support.

    Args:
        encrypted_data: Encrypted string with "aes:" prefix.
        aad: Optional AAD for v1/legacy format override. Ignored for v2
             (AAD is embedded in the payload).

    Returns:
        Decrypted plain text string. Empty string if input is empty.

    Raises:
        DecryptionError: If decryption fails with all keys.
    """
    if not encrypted_data:
        return ""

    if not encrypted_data.startswith(ENCRYPTED_PREFIX):
        raise DecryptionError(f"Invalid encrypted data: missing '{ENCRYPTED_PREFIX}' prefix")

    try:
        parsed = _parse_ciphertext(encrypted_data, aad)
    except DecryptionError:
        raise
    except Exception as e:
        raise DecryptionError(f"Failed to parse ciphertext: {type(e).__name__}") from e

    return _decrypt_with_keyring(parsed["nonce"], parsed["ciphertext_and_tag"], parsed["aad"])


def _parse_ciphertext(encrypted_data: str, aad_override: bytes | None) -> dict[str, Any]:
    """Parse wire format and extract nonce, ciphertext+tag, and AAD."""
    if encrypted_data.startswith(VERSIONED_V2_PREFIX):
        encoded = encrypted_data[len(VERSIONED_V2_PREFIX) :]
        raw = base64.urlsafe_b64decode(encoded)
        if len(raw) < AAD_LEN_SIZE:
            raise DecryptionError("v2 ciphertext too short for AAD length")
        aad_len = struct.unpack("!H", raw[:AAD_LEN_SIZE])[0]
        if len(raw) < AAD_LEN_SIZE + aad_len + NONCE_SIZE + 16:
            raise DecryptionError("v2 ciphertext too short")
        aad = raw[AAD_LEN_SIZE : AAD_LEN_SIZE + aad_len]
        rest = raw[AAD_LEN_SIZE + aad_len :]
        nonce = rest[:NONCE_SIZE]
        ciphertext_and_tag = rest[NONCE_SIZE:]
        return {"nonce": nonce, "ciphertext_and_tag": ciphertext_and_tag, "aad": aad}

    if encrypted_data.startswith(VERSIONED_V1_PREFIX):
        encoded = encrypted_data[len(VERSIONED_V1_PREFIX) :]
    else:
        # Legacy format: "aes:<payload>" (pre-versioning)
        encoded = encrypted_data[len(ENCRYPTED_PREFIX) :]

    raw = base64.urlsafe_b64decode(encoded)
    if len(raw) < NONCE_SIZE + 16:
        raise DecryptionError("Ciphertext too short")
    nonce = raw[:NONCE_SIZE]
    ciphertext_and_tag = raw[NONCE_SIZE:]
    return {"nonce": nonce, "ciphertext_and_tag": ciphertext_and_tag, "aad": aad_override}


def _decrypt_with_keyring(nonce: bytes, ciphertext_and_tag: bytes, aad: bytes | None) -> str:
    """Try decryption with each key in the keyring."""
    keys = get_encryption_keys()
    last_error: Exception | None = None

    for key in keys:
        try:
            aesgcm = _get_aesgcm(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext_and_tag, aad)
            return plaintext.decode("utf-8")
        except Exception as e:
            last_error = e
            continue

    logger.error("Failed to decrypt with any key in keyring (%d keys tried)", len(keys))
    raise DecryptionError(f"Decryption failed with all {len(keys)} keys: {type(last_error).__name__}") from last_error


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
