"""
EU VAT Number Validator for PRAHO Platform.

Provides EU VAT number format validation using python-stdnum for all 27 EU
member states, with Romanian CUI delegation to CUIValidator for check-digit
verification via the ANAF algorithm.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from stdnum.eu import vat as stdnum_vat
from stdnum.exceptions import ValidationError as StdnumValidationError

from apps.common.cui_validator import CUIValidator

logger = logging.getLogger(__name__)

# EU-27 member state VAT prefix codes.
# NOTE: Greece uses "EL" (from "Ellada") as its VAT prefix in the EU system,
# not the ISO-3166 code "GR". Both the VIES REST API and python-stdnum expect
# "EL" for Greek VAT numbers (e.g., "EL094259216").
EU_COUNTRIES: frozenset[str] = frozenset(
    {
        "AT",
        "BE",
        "BG",
        "CY",
        "CZ",
        "DE",
        "DK",
        "EE",
        "EL",  # Greece — EU VAT prefix is EL (not ISO code GR)
        "ES",
        "FI",
        "FR",
        "HR",
        "HU",
        "IE",
        "IT",
        "LT",
        "LU",
        "LV",
        "MT",
        "NL",
        "PL",
        "PT",
        "RO",
        "SE",
        "SI",
        "SK",
    }
)

# Country prefix pattern: 2 uppercase letters followed by alphanumeric body
# Some EU VAT numbers contain letters (e.g., IE1234567T, FR12345678901)
_VAT_PREFIX_RE = re.compile(r"^([A-Z]{2})([A-Z0-9]+)$")


@dataclass
class VATFormatResult:
    """Result of VAT format validation."""

    is_valid: bool
    country_code: str
    vat_digits: str
    full_vat_number: str
    error_message: str = ""


def parse_vat_number(raw: str, *, default_country: str = "RO") -> tuple[str, str]:
    """Extract country code and VAT body from a raw VAT number string.

    Args:
        raw: Raw VAT number (e.g., "RO12345678", "DE123456789", "12345678").
        default_country: Country code to use when no prefix is found.
            Callers should pass the customer's known country when available
            to avoid misclassifying non-RO VATs as Romanian.

    Returns:
        Tuple of (country_code, vat_body).
    """
    cleaned = re.sub(r"[\s\-.]", "", raw.strip()).upper()

    match = _VAT_PREFIX_RE.match(cleaned)
    if match:
        return match.group(1), match.group(2)

    # No country prefix — use caller-provided default
    return default_country.upper(), cleaned


def is_eu_country(country_code: str) -> bool:
    """Check if the given country code is an EU-27 member state."""
    return country_code.upper() in EU_COUNTRIES


def validate_vat_format(country_code: str, vat_digits: str) -> VATFormatResult:
    """Validate VAT number format for the given EU country.

    For RO: delegates to CUIValidator.validate_strict() (ANAF check digit).
    For other EU countries: uses stdnum.eu.vat.validate().

    Args:
        country_code: 2-letter uppercase country code.
        vat_digits: VAT number body (without country prefix).

    Returns:
        VATFormatResult with validation outcome.
    """
    country_code = country_code.upper()
    full_vat = f"{country_code}{vat_digits}"

    if not is_eu_country(country_code):
        return VATFormatResult(
            is_valid=False,
            country_code=country_code,
            vat_digits=vat_digits,
            full_vat_number=full_vat,
            error_message=f"Country code '{country_code}' is not an EU-27 member state",
        )

    if country_code == "RO":
        return _validate_ro(vat_digits, full_vat)

    return _validate_eu(country_code, vat_digits, full_vat)


def _validate_ro(vat_digits: str, full_vat: str) -> VATFormatResult:
    """Validate Romanian CUI via CUIValidator.validate_strict()."""
    result = CUIValidator.validate_strict(vat_digits)
    if result.is_valid:
        logger.debug("RO VAT number format valid: %s", full_vat)
        return VATFormatResult(
            is_valid=True,
            country_code="RO",
            vat_digits=result.digits,
            full_vat_number=f"RO{result.digits}",
        )
    return VATFormatResult(
        is_valid=False,
        country_code="RO",
        vat_digits=vat_digits,
        full_vat_number=full_vat,
        error_message=result.error_message,
    )


def _validate_eu(country_code: str, vat_digits: str, full_vat: str) -> VATFormatResult:
    """Validate non-RO EU VAT number via stdnum."""
    try:
        stdnum_vat.validate(full_vat)
        logger.debug("EU VAT number format valid: %s", full_vat)
        return VATFormatResult(
            is_valid=True,
            country_code=country_code,
            vat_digits=vat_digits,
            full_vat_number=full_vat,
        )
    except StdnumValidationError as e:
        logger.debug("VAT number format invalid: %s - %s", full_vat, e)
        return VATFormatResult(
            is_valid=False,
            country_code=country_code,
            vat_digits=vat_digits,
            full_vat_number=full_vat,
            error_message=str(e),
        )
