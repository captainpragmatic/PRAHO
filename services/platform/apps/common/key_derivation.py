"""
HKDF-based key derivation for domain-separated cryptographic keys.
Implements NIST SP 800-57 section 5.2 key separation using RFC 5869 HKDF.
"""

from __future__ import annotations

import functools
import os

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

# Domain-to-env-var registry for optional per-domain overrides
_DOMAIN_ENV_VARS: dict[str, str] = {
    "mfa-backup": "MFA_BACKUP_CODE_PEPPER",
    "unsubscribe": "UNSUBSCRIBE_TOKEN_SECRET",
    "siem-hash-chain": "SIEM_HASH_CHAIN_SECRET",
    "sensitive-data-hash": "SENSITIVE_DATA_HASH_KEY",
}

VALID_DOMAINS: frozenset[str] = frozenset(_DOMAIN_ENV_VARS.keys())
MIN_ENV_KEY_LENGTH = 32


@functools.lru_cache(maxsize=8)
def derive_key(domain: str) -> bytes:
    """Derive a 32-byte domain-specific key using HKDF-SHA256.

    If a domain-specific env var is set and >= 32 chars, it is derived through HKDF.
    Otherwise, HKDF derives the key from Django's SECRET_KEY.
    """
    if domain not in VALID_DOMAINS:
        raise ValueError(f"Unknown key derivation domain '{domain}'. Valid: {sorted(VALID_DOMAINS)}")

    info = f"praho-{domain}".encode()

    env_var = _DOMAIN_ENV_VARS.get(domain)
    if env_var:
        env_value = os.environ.get(env_var, "")
        if env_value:
            if len(env_value) < MIN_ENV_KEY_LENGTH:
                raise ImproperlyConfigured(f"{env_var} must be at least {MIN_ENV_KEY_LENGTH} characters long")
            hkdf = HKDF(algorithm=SHA256(), length=32, salt=None, info=info)
            return hkdf.derive(env_value.encode("utf-8"))

    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=info,
    )
    if not settings.SECRET_KEY:  # noqa: SECRET_KEY — this IS the key derivation module
        raise ImproperlyConfigured("SECRET_KEY must be configured for key derivation")
    return hkdf.derive(settings.SECRET_KEY.encode())  # noqa: SECRET_KEY — HKDF input material


def get_key_hex(domain: str) -> str:
    """Return the derived key as a hex string."""
    return derive_key(domain).hex()
