"""Localisation values and display formatting, mirrored across isolated services."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from functools import lru_cache
from typing import Any
from zoneinfo import ZoneInfo, available_timezones

from babel import Locale
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.dateparse import parse_date, parse_datetime
from django.utils.translation import get_language
from django.utils.translation import gettext_lazy as _

COUNTRY_CODE_LENGTH = 2

DATE_FORMAT_CHOICES = (
    ("%d.%m.%Y", _("DD.MM.YYYY — 23.11.2026")),
    ("%Y-%m-%d", _("YYYY-MM-DD — 2026-11-23")),
    ("%d/%m/%Y", _("DD/MM/YYYY — 23/11/2026")),
    ("%m/%d/%Y", _("MM/DD/YYYY — 11/23/2026")),
)
DATE_FORMATS = frozenset(value for value, _label in DATE_FORMAT_CHOICES)
LANGUAGE_CHOICES = (("en", _("English")), ("ro", _("Romanian")))
LANGUAGES = frozenset(value for value, _label in LANGUAGE_CHOICES)
TIMEZONES = frozenset(available_timezones() - {"localtime"})  # Host-dependent alias is not portable between services.
INHERIT_LABEL = _("Use system default")


@lru_cache(maxsize=2)
def country_choices(language: str = "en") -> tuple[tuple[str, str], ...]:
    """Use existing CLDR territory data; exclude aggregate and unknown regions."""
    names = Locale.parse(language if language in LANGUAGES else "en").territories
    return tuple(
        sorted(
            (
                (str(code), str(name))
                for code, name in names.items()
                if len(code) == COUNTRY_CODE_LENGTH
                and code.isalpha()
                and code not in {"EU", "EZ", "UN", "ZZ", "QO", "XA", "XB"}
            ),
            key=lambda item: item[1],
        )
    )


COUNTRIES = frozenset(code for code, _name in country_choices())


@lru_cache(maxsize=1)
def _localized_country_codes() -> dict[str, str]:
    """Preserve the fiscal country normalizer's English/Romanian compatibility."""
    country_codes: dict[str, str] = {}
    for language in ("en", "ro"):
        for code, name in country_choices(language):
            country_codes[code.casefold()] = code
            country_codes[name.strip().casefold()] = code
    return country_codes


def normalize_country_code(value: object) -> str:
    return _localized_country_codes().get(str(value or "").strip().casefold(), "")


def country_name(code: str, language: str | None = None) -> str:
    return dict(country_choices(language or get_language() or "en")).get(code, code)


def validate_timezone(value: str) -> None:
    """Validate an optional user timezone without changing the active timezone."""
    if value and value not in TIMEZONES:
        raise ValidationError(_("Select a valid timezone."))


def validated_preferences(values: object) -> dict[str, str]:
    """Normalize optional/legacy API preferences; invalid values inherit."""
    source = values if isinstance(values, dict) else {}
    return {
        key: value if isinstance(value := source.get(key), str) and value in choices else ""
        for key, choices in (
            ("preferred_language", LANGUAGES),
            ("timezone", TIMEZONES),
            ("date_format", DATE_FORMATS),
        )
    }


@dataclass(frozen=True)
class LocalisationDefaults:
    """Catalog defaults, also the portal's fallback during platform outages."""

    default_language: str = "en"
    default_country: str = "RO"
    timezone: str = "Europe/Bucharest"
    staff_date_format: str = "%d.%m.%Y"
    customer_date_format: str = "%d.%m.%Y"

    @classmethod
    def from_mapping(cls, values: dict[str, Any]) -> LocalisationDefaults:
        fallback = cls()
        fields = {
            "default_language": LANGUAGES,
            "default_country": COUNTRIES,
            "timezone": TIMEZONES,
            "staff_date_format": DATE_FORMATS,
            "customer_date_format": DATE_FORMATS,
        }
        return cls(
            **{
                name: value
                if isinstance(value := values.get(name), str) and value in choices
                else getattr(fallback, name)
                for name, choices in fields.items()
            }
        )

    def customer_payload(self) -> dict[str, str]:
        return {
            "default_language": self.default_language,
            "default_country": self.default_country,
            "timezone": self.timezone,
            "customer_date_format": self.customer_date_format,
        }


@dataclass(frozen=True)
class DisplayLocalisation:
    language: str
    country: str
    timezone: str
    date_format: str


def resolve_display(
    defaults: LocalisationDefaults, preferences: object = None, *, staff: bool = False
) -> DisplayLocalisation:
    values = validated_preferences(preferences)
    return DisplayLocalisation(
        language=values["preferred_language"] or defaults.default_language,
        country=defaults.default_country,
        timezone=values["timezone"] or defaults.timezone,
        date_format=values["date_format"] or (defaults.staff_date_format if staff else defaults.customer_date_format),
    )


def format_localised_date(value: object, policy: DisplayLocalisation, kind: str = "date") -> str:
    """Render display values without changing ORM, accounting, or process timezone."""
    if isinstance(value, str):
        try:
            value = parse_date(value) or parse_datetime(value)
        except ValueError:
            return ""
    if not isinstance(value, date):
        return ""
    if isinstance(value, datetime) and timezone.is_aware(value):
        value = timezone.localtime(value, ZoneInfo(policy.timezone))
    patterns = {
        "date": policy.date_format,
        "datetime": policy.date_format + " %H:%M",
        "datetime_seconds": policy.date_format + " %H:%M:%S",
        "time": "%H:%M",
        "time_seconds": "%H:%M:%S",
        "month_year": "%Y-%m" if policy.date_format == "%Y-%m-%d" else "%m/%Y",
    }
    if kind not in patterns:
        raise ValueError(f"Unknown date display kind: {kind}")
    if not isinstance(value, datetime) and kind not in {"date", "month_year"}:
        return value.strftime(policy.date_format)
    return value.strftime(patterns[kind])
