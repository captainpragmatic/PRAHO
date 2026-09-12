"""Runtime localisation policy for staff pages and the portal settings contract."""

from __future__ import annotations

import logging
from typing import Any

from django.core.exceptions import ObjectDoesNotExist
from django.db import DatabaseError
from django.http import HttpRequest

from apps.common.localisation import (
    LANGUAGES,
    DisplayLocalisation,
    LocalisationDefaults,
    resolve_display,
    validated_preferences,
)

logger = logging.getLogger(__name__)


def get_localisation_defaults() -> LocalisationDefaults:
    from apps.settings.services import SettingsService  # noqa: PLC0415  # ADR-0007: runtime cross-app dependency

    try:
        return LocalisationDefaults.from_mapping(
            {
                "default_language": SettingsService.get_setting("system.default_language"),
                "default_country": SettingsService.get_setting("system.default_country"),
                "timezone": SettingsService.get_setting("system.timezone"),
                "staff_date_format": SettingsService.get_setting("system.staff_date_format"),
                "customer_date_format": SettingsService.get_setting("system.customer_date_format"),
            }
        )
    except DatabaseError:
        logger.warning("[Localisation] Settings unavailable; using catalog defaults")
        return LocalisationDefaults()


def user_localisation_preferences(user: Any) -> dict[str, str]:
    try:
        profile = user.profile
    except (ObjectDoesNotExist, AttributeError):
        return validated_preferences(None)
    return validated_preferences(
        {
            "preferred_language": profile.preferred_language,
            "timezone": profile.timezone,
            "date_format": profile.date_format,
        }
    )


def get_request_localisation(request: HttpRequest | None = None) -> DisplayLocalisation:
    if request is not None and hasattr(request, "localisation"):
        return request.localisation  # type: ignore[no-any-return]  # Cached DisplayLocalisation created below
    preferences = user_localisation_preferences(request.user) if request and hasattr(request, "user") else None
    if (
        request is not None
        and hasattr(request, "session")
        and not request.session.get("localisation_preferences_saved")
    ):
        legacy_language = request.session.get("_language") or request.session.get("django_language")
        if isinstance(legacy_language, str) and legacy_language in LANGUAGES:
            preferences = {**(preferences or {}), "preferred_language": legacy_language}
    policy = resolve_display(get_localisation_defaults(), preferences, staff=True)
    if request is not None:
        request.localisation = policy  # type: ignore[attr-defined]  # Request-scoped display policy attached by this middleware
    return policy
