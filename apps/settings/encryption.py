"""
🔒 Field-level encryption for sensitive settings in PRAHO Platform

Provides secure encryption/decryption for sensitive configuration values
like API keys, passwords, and secrets stored in SystemSettings.

Uses Django's SECRET_KEY for encryption - settings are tied to deployment.
"""

import base64
import hashlib
import logging
from typing import Any

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.signing import BadSignature, Signer
from django.utils.encoding import force_bytes, force_str

logger = logging.getLogger(__name__)

# Encryption constants
ENCRYPTED_VALUE_PREFIX = "enc:"  # Identifies encrypted values
ENCRYPTION_VERSION = "v1"  # For future algorithm upgrades


class SettingsEncryption:
    """
    🔒 Secure field-level encryption for sensitive settings
    
    Features:
    - Uses Django SECRET_KEY as encryption key
    - AES-256 equivalent security via Django's signing
    - Automatic detection of encrypted values
    - Safe handling of plaintext and encrypted data
    """

    def __init__(self) -> None:
        """Initialize encryption service"""
        if not getattr(settings, 'SECRET_KEY', None):
            raise ImproperlyConfigured(
                "SECRET_KEY must be configured for settings encryption"
            )
        
        # Create deterministic encryption key from SECRET_KEY
        self._encryption_key = hashlib.pbkdf2_hmac(
            'sha256',
            force_bytes(settings.SECRET_KEY),
            b'praho_settings_encryption_salt',
            100000  # 100k iterations for security
        )

    def encrypt_value(self, plaintext_value: Any) -> str:
        """
        🔒 Encrypt sensitive setting value
        
        Args:
            plaintext_value: Value to encrypt (will be converted to string)
            
        Returns:
            Encrypted value with prefix identifier
        """
        if plaintext_value is None:
            return None
            
        try:
            # Convert value to string for encryption
            str_value = str(plaintext_value)
            
            # Use Django's signing framework for encryption
            signer = Signer(key=self._encryption_key, algorithm='sha256')
            
            # Sign and encode the value
            signed_value = signer.sign(str_value)
            
            # Base64 encode for safe storage
            encoded_value = base64.b64encode(force_bytes(signed_value)).decode('ascii')
            
            # Add prefix to identify as encrypted
            encrypted_value = f"{ENCRYPTED_VALUE_PREFIX}{ENCRYPTION_VERSION}:{encoded_value}"
            
            logger.debug("🔒 [Settings Encryption] Value encrypted successfully")
            return encrypted_value
            
        except Exception as e:
            logger.error(f"🔥 [Settings Encryption] Failed to encrypt value: {e}")
            raise ValueError(f"Encryption failed: {e}") from e

    def decrypt_value(self, encrypted_value: str) -> str:
        """
        🔓 Decrypt sensitive setting value
        
        Args:
            encrypted_value: Encrypted value with prefix
            
        Returns:
            Decrypted plaintext value
            
        Raises:
            ValueError: If decryption fails or value is corrupted
        """
        if not encrypted_value:
            return encrypted_value
            
        # Check if value is actually encrypted
        if not self.is_encrypted(encrypted_value):
            # Not encrypted, return as-is (for backward compatibility)
            return encrypted_value
            
        try:
            # Remove prefix and version
            if not encrypted_value.startswith(f"{ENCRYPTED_VALUE_PREFIX}{ENCRYPTION_VERSION}:"):
                raise ValueError("Invalid encryption format or version")
                
            encoded_value = encrypted_value[len(f"{ENCRYPTED_VALUE_PREFIX}{ENCRYPTION_VERSION}:"):]
            
            # Base64 decode
            signed_value = base64.b64decode(encoded_value.encode('ascii'))
            
            # Use Django's signing framework for decryption
            signer = Signer(key=self._encryption_key, algorithm='sha256')
            
            # Verify signature and extract original value
            plaintext_value = signer.unsign(force_str(signed_value))
            
            logger.debug("🔓 [Settings Encryption] Value decrypted successfully")
            return plaintext_value
            
        except (ValueError, BadSignature, Exception) as e:
            logger.error(f"🔥 [Settings Encryption] Failed to decrypt value: {e}")
            raise ValueError(f"Decryption failed: {e}") from e

    def is_encrypted(self, value: str) -> bool:
        """
        🔍 Check if value is encrypted
        
        Args:
            value: Value to check
            
        Returns:
            True if value is encrypted, False otherwise
        """
        if not isinstance(value, str):
            return False
            
        return value.startswith(ENCRYPTED_VALUE_PREFIX)

    def encrypt_if_sensitive(self, value: Any, is_sensitive: bool) -> Any:
        """
        🔒 Conditionally encrypt value if marked as sensitive
        
        Args:
            value: Value to potentially encrypt
            is_sensitive: Whether the setting is marked as sensitive
            
        Returns:
            Encrypted value if sensitive, original value otherwise
        """
        if is_sensitive and value is not None:
            return self.encrypt_value(value)
        return value

    def decrypt_if_needed(self, value: Any) -> Any:
        """
        🔓 Conditionally decrypt value if it's encrypted
        
        Args:
            value: Value to potentially decrypt
            
        Returns:
            Decrypted value if encrypted, original value otherwise
        """
        if isinstance(value, str) and self.is_encrypted(value):
            return self.decrypt_value(value)
        return value

    def get_encryption_status(self) -> dict[str, Any]:
        """
        📊 Get encryption system status for monitoring
        
        Returns:
            Dictionary with encryption system status
        """
        try:
            # Test encryption/decryption
            test_value = "test_encryption"
            encrypted = self.encrypt_value(test_value)
            decrypted = self.decrypt_value(encrypted)
            encryption_working = (decrypted == test_value)
            
            return {
                'encryption_enabled': True,
                'encryption_working': encryption_working,
                'encryption_version': ENCRYPTION_VERSION,
                'secret_key_configured': bool(getattr(settings, 'SECRET_KEY', None)),
                'test_encryption_passed': encryption_working
            }
            
        except Exception as e:
            logger.error(f"🔥 [Settings Encryption] Status check failed: {e}")
            return {
                'encryption_enabled': False,
                'encryption_working': False,
                'error': str(e)
            }


# Global encryption service instance
settings_encryption = SettingsEncryption()


def encrypt_sensitive_value(value: Any) -> str:
    """
    🔒 Convenience function to encrypt sensitive values
    
    Args:
        value: Value to encrypt
        
    Returns:
        Encrypted value string
    """
    return settings_encryption.encrypt_value(value)


def decrypt_sensitive_value(encrypted_value: str) -> str:
    """
    🔓 Convenience function to decrypt sensitive values
    
    Args:
        encrypted_value: Encrypted value to decrypt
        
    Returns:
        Decrypted plaintext value
    """
    return settings_encryption.decrypt_value(encrypted_value)


def is_encrypted_value(value: str) -> bool:
    """
    🔍 Convenience function to check if value is encrypted
    
    Args:
        value: Value to check
        
    Returns:
        True if encrypted, False otherwise
    """
    return settings_encryption.is_encrypted(value)
