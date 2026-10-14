"""Cached platform defaults and session-scoped customer display preferences."""

from __future__ import annotations

import hashlib
import logging
from typing import TypedDict

from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.http import HttpRequest

from apps.api_client.services import PlatformAPIError, api_client
from apps.common.localisation import (
    LANGUAGES,
    DisplayLocalisation,
    LocalisationDefaults,
    resolve_display,
    validated_preferences,
)

logger = logging.getLogger(__name__)


class PublicDefaults(TypedDict):
    success: bool
    localisation: dict[str, str]
    company: dict[str, str]


_COMPANY_FIELDS = frozenset({"legal_name", "email_support", "email_privacy", "email_finance", "phone"})
# Shown on the legal pages. Optional, so the portal also reads a Platform that does not send them yet.
_COMPANY_OPTIONAL_FIELDS = frozenset({"email_dpo", "email_contact", "address", "registration_number", "brand_name"})
_LOCALISATION_FIELDS = frozenset(LocalisationDefaults().customer_payload())


def _string_mapping(value: object, fields: frozenset[str]) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("Invalid public defaults fields")
    result: dict[str, str] = {}
    for field in fields:
        item: object = value[field]
        if not isinstance(item, str):
            raise ValueError("Invalid public defaults value type")
        result[field] = item
    return result


def _validated_payload(response: object) -> PublicDefaults:
    if not isinstance(response, dict) or response.get("success") is not True:
        raise ValueError("Invalid public defaults response")
    localisation = _string_mapping(response.get("localisation"), _LOCALISATION_FIELDS)
    defaults = LocalisationDefaults.from_mapping(localisation)
    if localisation != defaults.customer_payload():
        raise ValueError("Invalid localisation values")

    company_value = response.get("company")
    if not isinstance(company_value, dict) or not set(company_value) <= _COMPANY_FIELDS | _COMPANY_OPTIONAL_FIELDS:
        raise ValueError("Invalid public defaults fields")
    company = _string_mapping(
        {field: company_value.get(field, "") for field in _COMPANY_FIELDS | _COMPANY_OPTIONAL_FIELDS},
        _COMPANY_FIELDS | _COMPANY_OPTIONAL_FIELDS,
    )
    if not set(company_value) >= _COMPANY_FIELDS:
        raise ValueError("Invalid public defaults fields")
    if not company["legal_name"].strip():
        raise ValueError("Invalid company legal name")
    if not company["brand_name"].strip():
        company["brand_name"] = settings.COMPANY_IDENTITY_DEFAULTS["brand_name"]
    for field in ("email_support", "email_privacy", "email_finance", "email_dpo", "email_contact"):
        address = company[field]
        if address or field in {"email_support", "email_privacy"}:
            validate_email(address)
    if any("\r" in value or "\n" in value for value in company.values()):
        raise ValueError("Invalid company identity control characters")
    return {"success": True, "localisation": localisation, "company": company}


def platform_cache_key(name: str) -> str:
    """A cache key scoped to the Platform this portal talks to, so answers from another are never read."""
    identity = f"{api_client.base_url}|{api_client.portal_id}"
    return f"{name}:" + hashlib.sha256(identity.encode()).hexdigest()[:24]


def get_public_defaults() -> PublicDefaults:
    """Read and cache the entire validated public payload for both consumers."""
    key = platform_cache_key("localisation")
    try:
        cached = _validated_payload(cache.get(key))
    except (ValidationError, ValueError, TypeError):
        pass
    else:
        return cached

    try:
        payload = _validated_payload(api_client.get_localisation_defaults())
    except (PlatformAPIError, ValidationError, ValueError, TypeError):
        logger.warning("⚠️ [Localisation] Platform defaults unavailable; using last-good or catalog defaults")
        try:
            payload = _validated_payload(cache.get(key + ":last_good"))
        except (ValidationError, ValueError, TypeError):
            payload = _validated_payload(
                {
                    "success": True,
                    "localisation": LocalisationDefaults().customer_payload(),
                    "company": settings.COMPANY_IDENTITY_DEFAULTS,
                }
            )
        # Outages and rejected responses never extend the last-good lifetime.
        cache.set(key, payload, timeout=60)
        return payload

    cache.set(key + ":last_good", payload, timeout=3600)
    cache.set(key, payload, timeout=60)
    return payload


def get_localisation_defaults() -> LocalisationDefaults:
    return LocalisationDefaults.from_mapping(get_public_defaults()["localisation"])


def get_company_identity() -> dict[str, str]:
    """Return a copy so a context consumer cannot mutate the cached identity."""
    return dict(get_public_defaults()["company"])


def get_request_localisation(request: HttpRequest | None = None) -> DisplayLocalisation:
    if request is not None and hasattr(request, "localisation"):
        return request.localisation  # type: ignore[no-any-return]  # Cached DisplayLocalisation created below
    preferences = request.session.get("localisation_preferences") if request and hasattr(request, "session") else None
    if preferences is None and request is not None and hasattr(request, "session"):
        preferences = {"preferred_language": request.session.get("_language")}
    policy = resolve_display(get_localisation_defaults(), preferences)
    if request is not None:
        request.localisation = policy  # type: ignore[attr-defined]  # Request-scoped display policy attached by this middleware
    return policy


def store_localisation_preferences(request: HttpRequest, values: object) -> None:
    """Keep raw inheritance choices, so cached sessions still follow new defaults."""
    preferences = validated_preferences(values)
    legacy_language = request.session.get("_language")
    if (
        not request.session.get("localisation_preferences_saved")
        and isinstance(legacy_language, str)
        and legacy_language in LANGUAGES
    ):
        preferences["preferred_language"] = legacy_language
    request.session["localisation_preferences"] = preferences
    if hasattr(request, "localisation"):
        del request.localisation
