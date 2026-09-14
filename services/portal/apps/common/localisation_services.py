"""Cached platform defaults and session-scoped customer display preferences."""

from __future__ import annotations

import hashlib
import logging

from django.core.cache import cache
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


def get_localisation_defaults() -> LocalisationDefaults:
    identity = f"{api_client.base_url}|{api_client.portal_id}"
    key = "localisation:" + hashlib.sha256(identity.encode()).hexdigest()[:24]
    cached = cache.get(key)
    if isinstance(cached, dict):
        return LocalisationDefaults.from_mapping(cached)
    try:
        response = api_client.get_localisation_defaults()
        if not isinstance(response, dict):
            raise ValueError("Invalid localisation response")
        values = response.get("localisation")
        if response.get("success") is not True or not isinstance(values, dict):
            raise ValueError("Invalid localisation response")
        defaults = LocalisationDefaults.from_mapping(values)
        # Reject incomplete/corrupt payloads so they cannot replace last-known-good data.
        if any(values.get(name) != value for name, value in defaults.customer_payload().items()):
            raise ValueError("Invalid localisation values")
    except (PlatformAPIError, ValueError, TypeError):
        logger.warning("[Localisation] Platform defaults unavailable; using cached or built-in defaults")
        values = cache.get(key + ":last_good") or LocalisationDefaults().customer_payload()
        cache.set(key, values, timeout=30)
        return LocalisationDefaults.from_mapping(values)
    values = defaults.customer_payload()
    cache.set(key + ":last_good", values, timeout=3600)
    cache.set(key, values, timeout=60)
    return defaults


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
