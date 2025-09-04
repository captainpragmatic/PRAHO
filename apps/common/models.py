"""
Common app models - PRAHO Platform
Import models from credential_vault module for Django to discover them.
"""

# Import all models from credential_vault module so Django can find them
from .credential_vault import CredentialAccessLog, EncryptedCredential

__all__ = ["CredentialAccessLog", "EncryptedCredential"]