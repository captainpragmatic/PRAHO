"""Settings-only validation for Portal's outbound signing credential."""

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


def validate_secret(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ImproperlyConfigured(f"{name} must be a non-empty signing secret")
    return value


def resolve_signing_secret() -> str:
    per_portal = getattr(settings, "PORTAL_HMAC_SECRET", None)
    if per_portal is not None:
        return validate_secret(per_portal, "PORTAL_HMAC_SECRET")
    if getattr(settings, "PORTAL_HMAC_REQUIRE_ISOLATION", False):
        raise ImproperlyConfigured("PORTAL_HMAC_SECRET is required for deployed Portal services")
    return validate_secret(getattr(settings, "PLATFORM_API_SECRET", None), "PLATFORM_API_SECRET")
