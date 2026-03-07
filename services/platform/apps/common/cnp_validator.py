"""
Romanian CNP (Cod Numeric Personal) validator.

Extracted from apps.billing.efactura.b2c for reuse across the platform.
Pure Python — no Django dependencies in the core validator.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from typing import ClassVar

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


def validate_cnp(value: str) -> None:
    """Django model-field validator for Romanian CNP."""
    from django.core.exceptions import ValidationError  # noqa: PLC0415  # Deferred: keeps core validator Django-free
    from django.utils.translation import (  # noqa: PLC0415  # Deferred: keeps core validator Django-free
        gettext_lazy as _,
    )

    result = CNPValidator.validate(value)
    if not result.is_valid:
        raise ValidationError(_(result.error_message), code="invalid_cnp")
