"""Identity of the deploying operator — platform-only fiscal configuration.

Deliberately NOT in localisation.py: that module is pure display policy and is
required to stay byte-identical across the isolated services, while operator
jurisdiction is business configuration the portal has no business knowing.
"""

from __future__ import annotations

from django.conf import settings

from apps.common.localisation import normalize_country_code

# Reference jurisdiction only — the project originated in Romania (ADR-0047).
# Not an assertion that RO fits any given deployment.
REFERENCE_OPERATOR_COUNTRY = "RO"


def operator_country() -> str:
    """ISO-3166-1 alpha-2 country the deploying operator is established in.

    This is the *supplier's* jurisdiction, never a customer's. Resolution order:
    the explicit code, then the legacy display name (COMPANY_COUNTRY holds
    "România", not a code, so it is normalized rather than trusted), then the
    reference default. An upgraded deployment that set only the legacy name is
    therefore honored rather than silently treated as Romanian.
    """
    for candidate in (
        getattr(settings, "COMPANY_COUNTRY_CODE", ""),
        getattr(settings, "COMPANY_COUNTRY", ""),
    ):
        if normalized := normalize_country_code(candidate):
            return normalized
    return REFERENCE_OPERATOR_COUNTRY


def operator_is_romanian() -> bool:
    """Whether the operator is established in Romania: e-Factura, D390, SmartBill and ROTLD apply."""
    return operator_serves("RO")


def operator_in_eu() -> bool:
    """Whether the operator is established in an EU member state (ISO codes: Greece is GR, not EL)."""
    from apps.billing.config import is_eu_country  # noqa: PLC0415  # ADR-0007: deferred cross-app import

    return is_eu_country(operator_country())


def operator_serves(jurisdiction: str) -> bool:
    """Whether a feature bound to one jurisdiction ("" for none) applies to this operator."""
    return not jurisdiction or jurisdiction == operator_country()
