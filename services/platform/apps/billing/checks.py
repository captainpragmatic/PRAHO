"""Fail-closed validation of the deployment's default billing currency (#103).

Runs as a standard Django system check (never at import time). RON requires no
database access; a non-RON default must have a resolvable provenanced FX rate, else
the deployment is misconfigured (it would open the automated billing paths to a
currency that cannot be issued). Bootstrap/migrate with RON before enabling a foreign
default.
"""

from __future__ import annotations

from django.conf import settings
from django.core.checks import Error, register
from django.db import DatabaseError
from django.utils import timezone


@register("billing_currency")
def check_billing_default_currency(**_kwargs: object) -> list[Error]:
    """Validate BILLING_DEFAULT_CURRENCY during system checks, never during app import."""
    from apps.billing.currency_service import (  # noqa: PLC0415  # ADR-0007: deferred billing dependency
        CurrencyNotIssuableError,
        CurrencyValidationError,
        assert_currency_issuable,
        normalize_currency_code,
    )

    raw = getattr(settings, "BILLING_DEFAULT_CURRENCY", "RON")
    if not isinstance(raw, str):
        return [
            Error(
                "BILLING_DEFAULT_CURRENCY must be a currency-code string.",
                hint="Use RON, or a supported currency with a resolvable provenanced rate to RON.",
                id="billing.E001",
            )
        ]

    try:
        code = normalize_currency_code(raw)
    except CurrencyValidationError as exc:
        return [Error(f"BILLING_DEFAULT_CURRENCY: {exc}", id="billing.E001")]

    if raw != code:
        return [
            Error(
                "BILLING_DEFAULT_CURRENCY must use an uppercase code without surrounding whitespace.",
                hint=f"Use {code}.",
                id="billing.E001",
            )
        ]

    try:
        assert_currency_issuable(code, timezone.localdate())
    except CurrencyNotIssuableError as exc:
        return [
            Error(
                f"BILLING_DEFAULT_CURRENCY: {exc}",
                hint="Provision a provenanced rate effective today or earlier, or configure RON.",
                id="billing.E001",
            )
        ]
    except DatabaseError:
        return [
            Error(
                "BILLING_DEFAULT_CURRENCY could not be validated against the FX-rate database.",
                hint="Restore database access; for initial setup, migrate with RON before enabling a foreign default.",
                id="billing.E002",
            )
        ]

    return []
