"""
Encryption utilities for PRAHO Platform
Secure encryption/decryption for sensitive data like 2FA secrets.
"""

import base64
import os

from cryptography.fernet import Fernet
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


def get_encryption_key() -> bytes:
    """
    Get or generate encryption key for sensitive data.
    Uses DJANGO_ENCRYPTION_KEY environment variable or generates one.
    """
    encryption_key = getattr(settings, 'ENCRYPTION_KEY', None)

    if not encryption_key:
        # Try to get from environment
        encryption_key = os.environ.get('DJANGO_ENCRYPTION_KEY')

    if not encryption_key:
        raise ImproperlyConfigured(
            "DJANGO_ENCRYPTION_KEY environment variable must be set. "
            "Generate one with: from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
        )

    # Handle both string and bytes
    if isinstance(encryption_key, str):
        encryption_key = encryption_key.encode()

    return encryption_key


def encrypt_sensitive_data(data: str) -> str:
    """
    Encrypt sensitive data (like 2FA secrets) for database storage.
    
    Args:
        data: Plain text string to encrypt
        
    Returns:
        Base64-encoded encrypted string safe for database storage
    """
    if not data:
        return ''

    key = get_encryption_key()
    fernet = Fernet(key)
    encrypted_bytes = fernet.encrypt(data.encode('utf-8'))
    return base64.b64encode(encrypted_bytes).decode('utf-8')


def decrypt_sensitive_data(encrypted_data: str) -> str:
    """
    Decrypt sensitive data from database storage.
    
    Args:
        encrypted_data: Base64-encoded encrypted string from database
        
    Returns:
        Decrypted plain text string
    """
    if not encrypted_data:
        return ''

    try:
        key = get_encryption_key()
        fernet = Fernet(key)
        encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
        decrypted_bytes = fernet.decrypt(encrypted_bytes)
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        # Log error but don't expose decryption details
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Failed to decrypt sensitive data: {type(e).__name__}")
        return ''


def generate_backup_codes(count: int = 8) -> list[str]:
    """
    Generate secure backup codes for 2FA recovery.
    
    Args:
        count: Number of backup codes to generate (default 8)
        
    Returns:
        List of secure backup codes (8 digits each)
    """
    import secrets

    backup_codes = []
    for _ in range(count):
        # Generate 8-digit backup code
        code = ''.join(secrets.choice('0123456789') for _ in range(8))
        backup_codes.append(code)

    return backup_codes


def hash_backup_code(code: str) -> str:
    """
    Hash backup code for secure storage.
    Uses Django's password hashing for consistency.
    """
    from django.contrib.auth.hashers import make_password
    return make_password(code)


def verify_backup_code(code: str, hashed_code: str) -> bool:
    """
    Verify backup code against stored hash.
    """
    from django.contrib.auth.hashers import check_password
    return check_password(code, hashed_code)
