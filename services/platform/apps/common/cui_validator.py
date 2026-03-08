"""
Romanian CUI (Cod Unic de Identificare) validator.

Extracted to apps.common for reuse across customers, billing, and audit apps.
Pure Python — no Django dependencies in the core validator.

CUI format: 2-10 digits, optionally prefixed with "RO" (for VAT-registered entities).
The model field stores the RO-prefixed form (e.g., "RO12345678").
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Romanian CUI control key weights (used for check digit calculation)
CUI_WEIGHTS = (7, 5, 3, 2, 1, 7, 5, 3, 2)
CUI_CONTROL_DIVISOR = 11
CUI_CONTROL_THRESHOLD = 10
CUI_MIN_DIGITS = 2
CUI_MAX_DIGITS = 10


@dataclass
class CUIValidationResult:
    """Result of CUI validation."""

    is_valid: bool
    error_message: str = ""
    digits: str = ""  # Raw digit string (no RO prefix)
    has_ro_prefix: bool = False


class CUIValidator:
    """
    Romanian CUI (Cod Unic de Identificare) validator.

    CUI structure:
    - 2-10 digits identifying a Romanian legal entity
    - Optionally prefixed with "RO" for VAT-registered entities
    - The last digit is a check digit (for CUIs with 8+ digits)

    Accepts both "RO12345678" and "12345678" formats.
    """

    _CUI_PATTERN = re.compile(r"^(RO)?(\d{2,10})$", re.IGNORECASE)

    @classmethod
    def validate(cls, cui: str) -> CUIValidationResult:
        """Validate a Romanian CUI value.

        Args:
            cui: CUI string, with or without RO prefix.

        Returns:
            CUIValidationResult with validation details.
        """
        if not cui or not cui.strip():
            return CUIValidationResult(is_valid=False, error_message="CUI is empty")

        cui = cui.strip()
        match = cls._CUI_PATTERN.match(cui)
        if not match:
            return CUIValidationResult(
                is_valid=False,
                error_message="CUI must be 2-10 digits, optionally prefixed with RO",
            )

        has_ro = match.group(1) is not None
        digits = match.group(2)

        if len(digits) < CUI_MIN_DIGITS or len(digits) > CUI_MAX_DIGITS:
            return CUIValidationResult(
                is_valid=False,
                error_message=f"CUI must have {CUI_MIN_DIGITS}-{CUI_MAX_DIGITS} digits",
            )

        return CUIValidationResult(
            is_valid=True,
            digits=digits,
            has_ro_prefix=has_ro,
        )

    @classmethod
    def normalize(cls, cui: str) -> str:
        """Normalize CUI to RO-prefixed uppercase form (e.g., 'ro12345678' -> 'RO12345678')."""
        result = cls.validate(cui)
        if not result.is_valid:
            return cui
        return f"RO{result.digits}"


def validate_cui(value: str) -> None:
    """Django model-field validator for Romanian CUI.

    Accepts both 'RO12345678' and '12345678' formats.
    Use on model fields: validators=[validate_cui]
    """
    from django.core.exceptions import ValidationError  # noqa: PLC0415  # Deferred: keeps core validator Django-free
    from django.utils.translation import (  # noqa: PLC0415  # Deferred: keeps core validator Django-free
        gettext_lazy as _,
    )

    result = CUIValidator.validate(value)
    if not result.is_valid:
        raise ValidationError(_(result.error_message), code="invalid_cui")
