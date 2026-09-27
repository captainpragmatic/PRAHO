"""Evidence required for a reverse-charge decision."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apps.customers.models import CustomerTaxProfile


def normalize_vat_number(raw: object) -> str:
    """Return uppercase ASCII letters and digits, or empty for a falsy value."""
    return re.sub(r"[^A-Z0-9]", "", str(raw).upper()) if raw else ""


def vies_verified_for(tax_profile: CustomerTaxProfile | None, vat_number: object) -> bool:
    """Single, I/O-free evidence decision: VIES validity for the exact invoiced number."""
    return (
        tax_profile is not None
        and tax_profile.vies_verification_status == tax_profile.VIESVerificationStatus.VALID
        and normalize_vat_number(tax_profile.vat_number) == normalize_vat_number(vat_number) != ""
    )
