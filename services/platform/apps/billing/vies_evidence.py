"""Evidence required for a reverse-charge decision."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apps.customers.models import CustomerTaxProfile


def normalize_vat_number(raw: object) -> str:
    """Uppercase and remove spaces, dots and hyphens, or return empty for a falsy value."""
    # Keep these separators aligned with the revalidation sweep's SQL.
    return re.sub(r"[ .-]", "", str(raw).upper()) if raw else ""


def vat_number_matches_country(vat_number: object, country_code: str) -> bool:
    """Bind the issuing country to the billing country; GR and EL are equivalent."""
    from apps.common.eu_vat_validator import parse_vat_number  # noqa: PLC0415

    if not vat_number or not country_code.strip():
        return False
    country = country_code.strip().upper()
    country = "EL" if country == "GR" else country
    issuing_country, digits = parse_vat_number(str(vat_number), default_country=country)
    issuing_country = "EL" if issuing_country == "GR" else issuing_country
    return bool(digits) and issuing_country == country


def vies_verified_for(tax_profile: CustomerTaxProfile | None, vat_number: object) -> bool:
    """Single, I/O-free evidence decision: VIES validity for the exact invoiced number."""
    return (
        tax_profile is not None
        and tax_profile.vies_verification_status == tax_profile.VIESVerificationStatus.VALID
        and normalize_vat_number(tax_profile.vat_number) == normalize_vat_number(vat_number) != ""
    )
