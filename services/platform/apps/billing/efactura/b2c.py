"""
B2C (Business-to-Consumer) support for e-Factura.

From January 2025, B2C invoices are mandatory for Romanian e-Factura.
B2C invoices use CNP (Cod Numeric Personal) instead of CUI for buyers.

This module provides:
- CNP validation
- B2C invoice detection
- B2C-specific XML generation requirements
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import date
from typing import TYPE_CHECKING, Any, ClassVar

from .settings import efactura_settings

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

CNP_CHECKSUM_SPECIAL = 10
CNP_LENGTH = 13


@dataclass
class CNPValidationResult:
    """Result of CNP validation."""

    is_valid: bool
    error_message: str = ""
    gender: str | None = None
    birth_date: date | None = None
    county_code: str | None = None


class CNPValidator:
    """
    Romanian CNP (Cod Numeric Personal) validator.

    CNP structure (13 digits):
    - Position 1: Gender and century (S)
    - Positions 2-7: Birth date (YYMMDD)
    - Positions 8-9: County code (JJ)
    - Positions 10-12: Sequential number (NNN)
    - Position 13: Check digit (C)

    Formula: S AA LL ZZ JJ NNN C
    """

    # Gender/century codes
    GENDER_CODES: ClassVar[dict[str, tuple[str, int | None]]] = {
        "1": ("M", 1900),  # Male, 1900-1999
        "2": ("F", 1900),  # Female, 1900-1999
        "3": ("M", 1800),  # Male, 1800-1899
        "4": ("F", 1800),  # Female, 1800-1899
        "5": ("M", 2000),  # Male, 2000-2099
        "6": ("F", 2000),  # Female, 2000-2099
        "7": ("M", None),  # Male, foreign resident
        "8": ("F", None),  # Female, foreign resident
        "9": ("?", None),  # Foreigner
    }

    # County codes (JJ)
    COUNTY_CODES: ClassVar[dict[str, str]] = {
        "01": "Alba",
        "02": "Arad",
        "03": "Argeș",
        "04": "Bacău",
        "05": "Bihor",
        "06": "Bistrița-Năsăud",
        "07": "Botoșani",
        "08": "Brașov",
        "09": "Brăila",
        "10": "Buzău",
        "11": "Caraș-Severin",
        "12": "Cluj",
        "13": "Constanța",
        "14": "Covasna",
        "15": "Dâmbovița",
        "16": "Dolj",
        "17": "Galați",
        "18": "Gorj",
        "19": "Harghita",
        "20": "Hunedoara",
        "21": "Ialomița",
        "22": "Iași",
        "23": "Ilfov",
        "24": "Maramureș",
        "25": "Mehedinți",
        "26": "Mureș",
        "27": "Neamț",
        "28": "Olt",
        "29": "Prahova",
        "30": "Satu Mare",
        "31": "Sălaj",
        "32": "Sibiu",
        "33": "Suceava",
        "34": "Teleorman",
        "35": "Timiș",
        "36": "Tulcea",
        "37": "Vaslui",
        "38": "Vâlcea",
        "39": "Vrancea",
        "40": "București",
        "41": "București Sector 1",
        "42": "București Sector 2",
        "43": "București Sector 3",
        "44": "București Sector 4",
        "45": "București Sector 5",
        "46": "București Sector 6",
        "51": "Călărași",
        "52": "Giurgiu",
    }

    # Check digit weights
    CHECK_WEIGHTS: ClassVar[list[int]] = [2, 7, 9, 1, 4, 6, 3, 5, 8, 2, 7, 9]

    @classmethod
    def validate(cls, cnp: str) -> CNPValidationResult:
        """
        Validate a Romanian CNP.

        Args:
            cnp: CNP string to validate

        Returns:
            CNPValidationResult with validation status and extracted info
        """
        # Remove any whitespace
        cnp = cnp.strip().replace(" ", "")

        # Check format (13 digits)
        if not re.match(r"^\d{13}$", cnp):
            return CNPValidationResult(
                is_valid=False,
                error_message="CNP must be exactly 13 digits",
            )

        # Extract components
        gender_code = cnp[0]
        year = cnp[1:3]
        month = cnp[3:5]
        day = cnp[5:7]
        county = cnp[7:9]
        check_digit = int(cnp[12])

        # Validate gender code
        if gender_code not in cls.GENDER_CODES:
            return CNPValidationResult(
                is_valid=False,
                error_message=f"Invalid gender/century code: {gender_code}",
            )

        gender, century = cls.GENDER_CODES[gender_code]

        # Calculate check digit
        calculated_check = cls._calculate_check_digit(cnp[:12])
        if calculated_check != check_digit:
            return CNPValidationResult(
                is_valid=False,
                error_message="Invalid check digit",
            )

        # Validate and parse birth date
        birth_date = None
        if century:
            try:
                full_year = century + int(year)
                birth_date = date(full_year, int(month), int(day))
            except ValueError:
                return CNPValidationResult(
                    is_valid=False,
                    error_message=f"Invalid birth date: {year}/{month}/{day}",
                )

        # Validate county code
        if county not in cls.COUNTY_CODES and county not in ("00", "99"):
            # 00 and 99 are valid for special cases
            return CNPValidationResult(
                is_valid=False,
                error_message=f"Invalid county code: {county}",
            )

        return CNPValidationResult(
            is_valid=True,
            gender=gender,
            birth_date=birth_date,
            county_code=county,
        )

    @classmethod
    def _calculate_check_digit(cls, cnp_12: str) -> int:
        """Calculate check digit for first 12 digits of CNP."""
        total = sum(int(d) * w for d, w in zip(cnp_12, cls.CHECK_WEIGHTS, strict=False))
        remainder = total % 11
        return 1 if remainder == CNP_CHECKSUM_SPECIAL else remainder

    @classmethod
    def format(cls, cnp: str) -> str:
        """Format CNP for display (e.g., 1 850101 12 345 6)."""
        cnp = cnp.strip().replace(" ", "")
        if len(cnp) != CNP_LENGTH:
            return cnp
        return f"{cnp[0]} {cnp[1:7]} {cnp[7:9]} {cnp[9:12]} {cnp[12]}"


@dataclass
class B2CInvoiceInfo:
    """Information about a B2C invoice."""

    is_b2c: bool
    customer_cnp: str | None = None
    customer_name: str = ""
    requires_efactura: bool = False
    validation_result: CNPValidationResult | None = None


class B2CDetector:
    """
    Detect and validate B2C invoices.

    B2C invoices are identified by:
    - No tax ID (CUI) on the buyer
    - Romanian buyer country
    - Amount above minimum threshold
    """

    def __init__(self, settings: Any = None):
        """Initialize with optional settings override."""
        self._settings = settings or efactura_settings

    def detect(
        self,
        invoice: object,
        customer_identifier: str | None = None,
    ) -> B2CInvoiceInfo:
        """
        Detect if an invoice is B2C and validate customer identifier.

        Args:
            invoice: Invoice object with bill_to_* attributes
            customer_identifier: Optional CNP or other identifier

        Returns:
            B2CInvoiceInfo with detection results
        """
        # Get invoice attributes
        bill_to_country = getattr(invoice, "bill_to_country", None)
        bill_to_tax_id = getattr(invoice, "bill_to_tax_id", None)
        bill_to_name = getattr(invoice, "bill_to_name", "")
        total_cents = getattr(invoice, "total_cents", 0)

        # Not B2C if has tax ID (CUI)
        if bill_to_tax_id:
            return B2CInvoiceInfo(is_b2c=False)

        # Not B2C if not Romanian
        if bill_to_country != "RO":
            return B2CInvoiceInfo(is_b2c=False)

        # Check if B2C e-Factura is enabled
        if not self._settings.b2c_enabled:
            return B2CInvoiceInfo(
                is_b2c=True,
                customer_name=bill_to_name,
                requires_efactura=False,
            )

        # Check minimum amount
        minimum = self._settings.b2c_minimum_amount_cents
        if minimum > 0 and total_cents < minimum:
            return B2CInvoiceInfo(
                is_b2c=True,
                customer_name=bill_to_name,
                requires_efactura=False,
            )

        # Validate CNP if provided
        validation_result = None
        if customer_identifier:
            validation_result = CNPValidator.validate(customer_identifier)

        return B2CInvoiceInfo(
            is_b2c=True,
            customer_cnp=customer_identifier if validation_result and validation_result.is_valid else None,
            customer_name=bill_to_name,
            requires_efactura=True,
            validation_result=validation_result,
        )

    def is_b2c_required(self, invoice: object) -> bool:
        """Check if B2C e-Factura is required for this invoice."""
        info = self.detect(invoice)
        return info.is_b2c and info.requires_efactura


class B2CXMLBuilder:
    """
    Helper for B2C-specific XML generation.

    B2C invoices have different requirements:
    - Use CNP instead of CUI for buyer identification
    - Different scheme ID (RO:CNP instead of RO:CUI)
    - Buyer VAT scheme may be omitted
    """

    B2C_SCHEME_ID = "RO:CNP"
    ANAF_TEST_CNP = "0000000000000"  # For testing in sandbox

    @classmethod
    def get_buyer_identification(
        cls,
        cnp: str | None,
        name: str,
        is_test_environment: bool = False,
    ) -> dict[str, Any]:
        """
        Get buyer identification for B2C invoice XML.

        Args:
            cnp: Customer CNP (optional)
            name: Customer name
            is_test_environment: Whether in test/sandbox mode

        Returns:
            Dictionary with buyer identification info for XML builder
        """
        # In test environment, ANAF accepts all zeros CNP
        if is_test_environment and not cnp:
            cnp = cls.ANAF_TEST_CNP

        return {
            "identifier": cnp or "",
            "scheme_id": cls.B2C_SCHEME_ID if cnp else "",
            "name": name,
            "is_b2c": True,
            "has_vat_registration": False,
        }

    @classmethod
    def validate_for_submission(
        cls,
        cnp: str | None,
        is_test_environment: bool = False,
    ) -> tuple[bool, str]:
        """
        Validate B2C invoice is ready for submission.

        Args:
            cnp: Customer CNP
            is_test_environment: Whether in test/sandbox mode

        Returns:
            Tuple of (is_valid, error_message)
        """
        if is_test_environment:
            # Test environment accepts any CNP including all zeros
            return True, ""

        if not cnp:
            return False, "CNP is required for B2C e-Factura submission"

        result = CNPValidator.validate(cnp)
        if not result.is_valid:
            return False, f"Invalid CNP: {result.error_message}"

        return True, ""


# Module-level instances
cnp_validator = CNPValidator()
b2c_detector = B2CDetector()
