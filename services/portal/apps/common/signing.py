"""Settings-only validation for Portal's outbound signing credential."""

import re

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

# The platform's PORTAL_ID_RE (apps/common/portal_hmac.py), copied: the portal cannot import the platform.
# tests/integration asserts the two stay equal.
PORTAL_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,128}")
MIN_DEPLOYED_SECRET_LENGTH = 32


def validate_secret(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ImproperlyConfigured(f"{name} must be a non-empty signing secret")
    if getattr(settings, "PORTAL_HMAC_REQUIRE_ISOLATION", False) and name == "PORTAL_HMAC_SECRET":
        # A deployed portal's own key: as long as the platform secret, and never that secret itself.
        if len(value) < MIN_DEPLOYED_SECRET_LENGTH:
            raise ImproperlyConfigured(f"{name} must be at least {MIN_DEPLOYED_SECRET_LENGTH} characters")
        if value == getattr(settings, "PLATFORM_API_SECRET", None):
            raise ImproperlyConfigured(f"{name} must not reuse PLATFORM_API_SECRET")
    return value


def validate_portal_id() -> str:
    """The deployed portal's id, exactly as the platform's registry spells ids (no comment, no space)."""
    portal_id = getattr(settings, "PORTAL_ID", None)
    if not isinstance(portal_id, str) or not PORTAL_ID_RE.fullmatch(portal_id):
        raise ImproperlyConfigured(f"PORTAL_ID must match {PORTAL_ID_RE.pattern}, got {portal_id!r}")
    return portal_id


def resolve_signing_secret() -> str:
    per_portal = getattr(settings, "PORTAL_HMAC_SECRET", None)
    if per_portal is not None:
        return validate_secret(per_portal, "PORTAL_HMAC_SECRET")
    if getattr(settings, "PORTAL_HMAC_REQUIRE_ISOLATION", False):
        raise ImproperlyConfigured("PORTAL_HMAC_SECRET is required for deployed Portal services")
    return validate_secret(getattr(settings, "PLATFORM_API_SECRET", None), "PLATFORM_API_SECRET")
