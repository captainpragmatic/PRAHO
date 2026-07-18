"""Immutable fiscal-identity snapshots for billing documents."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from babel import Locale
from django.core.exceptions import ObjectDoesNotExist

from apps.common.cnp_validator import CNPValidator

_ISO_ALPHA_2_LENGTH = 2


@lru_cache(maxsize=1)
def _localized_country_codes() -> dict[str, str]:
    """Index English and Romanian CLDR country names by their ISO alpha-2 code."""
    country_codes: dict[str, str] = {}
    for locale_name in ("en", "ro"):
        for code, country_name in Locale.parse(locale_name).territories.items():
            normalized_code = str(code).upper()
            if len(normalized_code) == _ISO_ALPHA_2_LENGTH and normalized_code.isalpha():
                country_codes[normalized_code.casefold()] = normalized_code
                country_codes[str(country_name).strip().casefold()] = normalized_code
    return country_codes


def normalize_country_code(value: object) -> str:
    """Return an ISO alpha-2 code, or empty when a free-text country is unknown."""
    normalized = str(value or "").strip()
    return _localized_country_codes().get(normalized.casefold(), "")


def billing_country_code(value: object, *, default: str = "RO") -> str:
    """Resolve a billing snapshot country without disguising invalid input as Romania."""
    source = str(value or "").strip()
    if not source:
        return default
    country_code = normalize_country_code(source)
    if not country_code:
        raise ValueError(f"Unknown billing country: {source}")
    return country_code


def normalize_business_tax_id(value: object) -> str:
    """Treat surrounding whitespace as presentation, not as a fiscal identifier."""
    return str(value or "").strip()


def validated_cnp_or_empty(value: object) -> str:
    """Return a canonical valid CNP, or empty when no usable identifier exists."""
    candidate = "".join(str(value or "").split())
    if not candidate:
        return ""
    return candidate if CNPValidator.validate(candidate).is_valid else ""


@dataclass(frozen=True)
class CustomerFiscalIdentity:
    """Business and personal identifiers supplied by a customer."""

    business_tax_id: str = ""
    cnp: str = ""


def get_customer_fiscal_identity(customer: Any) -> CustomerFiscalIdentity:
    """Read the current customer profile for snapshotting onto a new document.

    Billing documents must copy these values at creation time. XML generation must
    never consult the mutable customer profile for an already-issued invoice.
    """
    try:
        tax_profile = customer.tax_profile
    except (ObjectDoesNotExist, AttributeError, TypeError):
        return CustomerFiscalIdentity()

    business_tax_id = normalize_business_tax_id(getattr(tax_profile, "vat_number", "")) or normalize_business_tax_id(
        getattr(tax_profile, "cui", "")
    )
    cnp = validated_cnp_or_empty(getattr(tax_profile, "cnp", ""))
    return CustomerFiscalIdentity(
        business_tax_id=business_tax_id,
        cnp=cnp if not business_tax_id else "",
    )
