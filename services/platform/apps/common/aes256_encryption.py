"""
AES-256-GCM Encryption Module - PRAHO Platform
Enterprise-grade encryption for data at rest.

This module provides:
- AES-256-GCM authenticated encryption (256-bit key, 128-bit auth tag)
- Secure key derivation using PBKDF2-HMAC-SHA256 (310,000 iterations per OWASP 2023)
- Automatic nonce generation (96-bit, never reused)
- Backward compatibility with existing Fernet encryption
- Key rotation support with versioned encryption

Security References:
- NIST SP 800-38D (GCM Mode)
- OWASP Password Storage Cheat Sheet 2023
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import os
import struct
from typing import Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

logger = logging.getLogger(__name__)

# Encryption constants
AES_KEY_SIZE = 32  # 256 bits
NONCE_SIZE = 12  # 96 bits (recommended for GCM)
AUTH_TAG_SIZE = 16  # 128 bits (included in ciphertext by AESGCM)
SALT_SIZE = 16  # 128 bits for key derivation
PBKDF2_ITERATIONS = 310_000  # OWASP 2023 recommendation for PBKDF2-HMAC-SHA256

# Encryption version prefixes for forward compatibility
VERSION_AES256_GCM = b"\x01"  # Current version: AES-256-GCM
VERSION_FERNET_LEGACY = b"\x00"  # Legacy Fernet-encrypted data


class AES256EncryptionError(Exception):
    """Base exception for AES-256 encryption operations"""


class AES256DecryptionError(AES256EncryptionError):
    """Decryption failed - invalid key, corrupted data, or tampered ciphertext"""


class AES256KeyError(AES256EncryptionError):
    """Invalid or missing encryption key"""


class AES256Cipher:
    """
    AES-256-GCM authenticated encryption cipher.

    Provides:
    - 256-bit AES encryption (military-grade)
    - GCM mode with authentication (prevents tampering)
    - Unique nonce per encryption (cryptographically secure)
    - Optional additional authenticated data (AAD)

    Usage:
        cipher = AES256Cipher()
        encrypted = cipher.encrypt("sensitive data")
        decrypted = cipher.decrypt(encrypted)
    """

    def __init__(self, key: bytes | None = None) -> None:
        """
        Initialize AES-256-GCM cipher.

        Args:
            key: 32-byte encryption key. If None, derives from environment.
        """
        self._key = key or self._get_or_derive_key()
        self._validate_key()
        self._aesgcm = AESGCM(self._key)

        # Keep Fernet for backward compatibility with legacy data
        self._fernet_key = self._get_fernet_key()
        self._fernet = Fernet(self._fernet_key) if self._fernet_key else None

    def _get_or_derive_key(self) -> bytes:
        """
        Get encryption key from environment or derive from master key.

        Priority:
        1. DJANGO_AES256_KEY (raw 32-byte key, base64 encoded)
        2. Derived from CREDENTIAL_VAULT_MASTER_KEY using PBKDF2
        3. Derived from DJANGO_SECRET_KEY using PBKDF2 (fallback)
        """
        # Try direct AES-256 key first
        aes_key = os.environ.get("DJANGO_AES256_KEY") or getattr(
            settings, "AES256_ENCRYPTION_KEY", None
        )
        if aes_key:
            try:
                key_bytes = base64.urlsafe_b64decode(aes_key)
                if len(key_bytes) == AES_KEY_SIZE:
                    return key_bytes
            except (binascii.Error, TypeError, ValueError):
                logger.debug("Invalid DJANGO_AES256_KEY value; falling back to derived key")

        # Derive from master key
        master_key = (
            os.environ.get("CREDENTIAL_VAULT_MASTER_KEY")
            or getattr(settings, "CREDENTIAL_VAULT_MASTER_KEY", None)
            or os.environ.get("DJANGO_SECRET_KEY")
            or getattr(settings, "SECRET_KEY", None)
        )

        if not master_key:
            raise ImproperlyConfigured(
                "AES-256 encryption requires DJANGO_AES256_KEY or "
                "CREDENTIAL_VAULT_MASTER_KEY environment variable. "
                "Generate with: python -c \"import secrets, base64; "
                "print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())\""
            )

        return self._derive_key(master_key.encode() if isinstance(master_key, str) else master_key)

    def _derive_key(self, master_key: bytes, salt: bytes | None = None) -> bytes:
        """
        Derive AES-256 key from master key using PBKDF2.

        Uses a static salt derived from the master key itself for deterministic
        key derivation (required for decryption without storing salt).
        """
        # Use deterministic salt based on master key hash
        if salt is None:
            salt = hashlib.sha256(b"PRAHO_AES256_SALT_V1" + master_key).digest()[:SALT_SIZE]

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend(),
        )
        return kdf.derive(master_key)

    def _get_fernet_key(self) -> bytes | None:
        """Get Fernet key for legacy decryption compatibility."""
        fernet_key = os.environ.get("DJANGO_ENCRYPTION_KEY") or getattr(settings, "ENCRYPTION_KEY", None)
        if fernet_key:
            return fernet_key.encode() if isinstance(fernet_key, str) else fernet_key
        return None

    def _validate_key(self) -> None:
        """Validate encryption key meets requirements."""
        if not self._key or len(self._key) != AES_KEY_SIZE:
            raise AES256KeyError(
                f"AES-256 requires exactly {AES_KEY_SIZE} bytes (256 bits). "
                f"Got {len(self._key) if self._key else 0} bytes."
            )

    def encrypt(
        self,
        plaintext: str | bytes,
        associated_data: bytes | None = None
    ) -> str:
        """
        Encrypt data using AES-256-GCM.

        Format: VERSION (1 byte) + NONCE (12 bytes) + CIPHERTEXT (variable + 16 byte tag)
        All base64-encoded for safe storage.

        Args:
            plaintext: Data to encrypt (string or bytes)
            associated_data: Optional AAD for additional authentication

        Returns:
            Base64-encoded encrypted string safe for database storage
        """
        if not plaintext:
            return ""

        try:
            # Convert to bytes if string
            data = plaintext.encode("utf-8") if isinstance(plaintext, str) else plaintext

            # Generate unique nonce (CRITICAL: never reuse with same key)
            nonce = os.urandom(NONCE_SIZE)

            # Encrypt with authentication
            ciphertext = self._aesgcm.encrypt(nonce, data, associated_data)

            # Pack: version + nonce + ciphertext (includes auth tag)
            encrypted = VERSION_AES256_GCM + nonce + ciphertext

            return base64.urlsafe_b64encode(encrypted).decode("utf-8")

        except Exception as e:
            logger.error(f"AES-256 encryption failed: {type(e).__name__}")
            raise AES256EncryptionError(f"Encryption failed: {e}") from e

    def decrypt(
        self,
        ciphertext: str,
        associated_data: bytes | None = None
    ) -> str:
        """
        Decrypt AES-256-GCM encrypted data.

        Supports backward compatibility with legacy Fernet encryption.

        Args:
            ciphertext: Base64-encoded encrypted string
            associated_data: Optional AAD (must match encryption AAD)

        Returns:
            Decrypted plaintext string
        """
        if not ciphertext:
            return ""

        try:
            # Decode from base64
            encrypted = base64.urlsafe_b64decode(ciphertext.encode("utf-8"))

            # Check version byte
            version = encrypted[:1]

            if version == VERSION_AES256_GCM:
                # AES-256-GCM decryption
                nonce = encrypted[1:1 + NONCE_SIZE]
                ct = encrypted[1 + NONCE_SIZE:]

                plaintext = self._aesgcm.decrypt(nonce, ct, associated_data)
                return plaintext.decode("utf-8")

            elif version == VERSION_FERNET_LEGACY or self._is_fernet_token(encrypted):
                # Legacy Fernet decryption
                return self._decrypt_fernet_legacy(ciphertext)

            else:
                # Try Fernet as fallback for unmarked legacy data
                return self._decrypt_fernet_legacy(ciphertext)

        except AES256DecryptionError:
            raise
        except Exception as e:
            logger.error(f"AES-256 decryption failed: {type(e).__name__}")
            raise AES256DecryptionError(f"Decryption failed: {e}") from e

    def _is_fernet_token(self, data: bytes) -> bool:
        """Check if data looks like a Fernet token."""
        # Fernet tokens start with version byte 0x80
        return len(data) > 0 and data[0] == 0x80

    def _decrypt_fernet_legacy(self, ciphertext: str) -> str:
        """Decrypt legacy Fernet-encrypted data."""
        if not self._fernet:
            raise AES256DecryptionError(
                "Cannot decrypt legacy data: DJANGO_ENCRYPTION_KEY not configured"
            )

        try:
            # Handle double-base64 encoding from old encryption
            try:
                encrypted_bytes = base64.b64decode(ciphertext.encode("utf-8"))
            except Exception:
                encrypted_bytes = ciphertext.encode("utf-8")

            decrypted = self._fernet.decrypt(encrypted_bytes)
            return decrypted.decode("utf-8")

        except InvalidToken:
            raise AES256DecryptionError("Invalid Fernet token - data may be corrupted")
        except Exception as e:
            raise AES256DecryptionError(f"Legacy decryption failed: {e}") from e

    def encrypt_dict(self, data: dict[str, Any]) -> str:
        """Encrypt a dictionary as JSON."""
        return self.encrypt(json.dumps(data, separators=(",", ":")))

    def decrypt_dict(self, ciphertext: str) -> dict[str, Any]:
        """Decrypt to dictionary from JSON."""
        plaintext = self.decrypt(ciphertext)
        return json.loads(plaintext) if plaintext else {}

    def re_encrypt(self, old_ciphertext: str) -> str:
        """
        Re-encrypt data from legacy format to AES-256-GCM.

        Use for migrating existing encrypted data to the new format.
        """
        plaintext = self.decrypt(old_ciphertext)
        return self.encrypt(plaintext)


# Module-level cipher instance (lazy initialization)
_cipher_instance: AES256Cipher | None = None


def get_aes256_cipher() -> AES256Cipher:
    """Get global AES-256 cipher instance with lazy initialization."""
    global _cipher_instance
    if _cipher_instance is None:
        _cipher_instance = AES256Cipher()
    return _cipher_instance


def encrypt_aes256(plaintext: str) -> str:
    """
    Encrypt data using AES-256-GCM.

    Convenience function for simple encryption needs.
    """
    return get_aes256_cipher().encrypt(plaintext)


def decrypt_aes256(ciphertext: str) -> str:
    """
    Decrypt AES-256-GCM encrypted data.

    Convenience function with legacy Fernet support.
    """
    return get_aes256_cipher().decrypt(ciphertext)


def generate_aes256_key() -> str:
    """
    Generate a new AES-256 encryption key.

    Returns base64-encoded 32-byte key suitable for DJANGO_AES256_KEY.
    """
    import secrets
    key = secrets.token_bytes(AES_KEY_SIZE)
    return base64.urlsafe_b64encode(key).decode("utf-8")


def migrate_to_aes256(old_ciphertext: str) -> str:
    """
    Migrate legacy Fernet-encrypted data to AES-256-GCM.

    Use in data migrations to upgrade encryption.
    """
    return get_aes256_cipher().re_encrypt(old_ciphertext)
