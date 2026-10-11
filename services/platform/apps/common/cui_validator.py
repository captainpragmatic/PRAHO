"""
Romanian CUI (Cod Unic de Identificare) validator.

Extracted to apps.common for reuse across customers, billing, and audit apps.
Pure Python — no Django dependencies in the core validator.

CUI format: 2-10 digits. Input may carry an "RO" prefix, but a CUI is stored as its digits
("12345678"): the prefix asserts VAT registration, which a CUI alone does not. The VAT number
(CustomerTaxProfile.vat_number) carries the prefix.
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

    _CUI_PATTERN = re.compile(r"^(RO)?([0-9]{2,10})$", re.IGNORECASE)

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

        # Strip optional RO/ro prefix before digit checks so we can give specific messages.
        prefix_match = re.match(r"^(RO)?(.*)$", cui, re.IGNORECASE)
        has_ro = prefix_match is not None and prefix_match.group(1) is not None
        body = prefix_match.group(2) if prefix_match else cui

        # Check for non-digit characters in the body first (most specific message).
        if body and not body.isascii():
            return CUIValidationResult(
                is_valid=False,
                error_message="CUI must contain only digits",
            )
        if body and not re.fullmatch(r"[0-9]+", body):
            return CUIValidationResult(
                is_valid=False,
                error_message="CUI must contain only digits",
            )

        # Now validate overall structure with the compiled pattern.
        match = cls._CUI_PATTERN.match(cui)
        if not match:
            # The body contains only digits but fails length: either too short or too long.
            return CUIValidationResult(
                is_valid=False,
                error_message="CUI must have 2-10 digits",
            )

        has_ro = match.group(1) is not None
        digits = match.group(2)

        return CUIValidationResult(
            is_valid=True,
            digits=digits,
            has_ro_prefix=has_ro,
        )

    @classmethod
    def normalize(cls, cui: str) -> str:
        """The stored form of a CUI: its digits ('ro12345678' -> '12345678'). Invalid input is returned as is."""
        result = cls.validate(cui)
        if not result.is_valid:
            return cui
        return result.digits

    @staticmethod
    def _compute_check_digit(digits_without_check: str) -> int:
        """ANAF check digit: the body left-padded to 9 digits, weighted by the key 753217532,
        summed, times 10, modulo 11; a remainder of 10 gives 0.
        """
        padded = digits_without_check.zfill(len(CUI_WEIGHTS))
        total = sum(int(d) * w for d, w in zip(padded, CUI_WEIGHTS, strict=True))
        remainder = (total * 10) % CUI_CONTROL_DIVISOR
        return 0 if remainder == CUI_CONTROL_THRESHOLD else remainder

    @classmethod
    def validate_strict(cls, cui: str) -> CUIValidationResult:
        """Validate CUI with ANAF check digit verification, at every length.

        The default validate() method stays lenient (no check digit check).
        This method is opt-in for callers that need ANAF-level correctness.
        """
        result = cls.validate(cui)
        if not result.is_valid:
            return result
        if result.digits:
            body, check = result.digits[:-1], int(result.digits[-1])
            expected = cls._compute_check_digit(body)
            if check != expected:
                return CUIValidationResult(
                    is_valid=False,
                    error_message="CUI check digit mismatch",
                    digits=result.digits,
                    has_ro_prefix=result.has_ro_prefix,
                )
        return result


_ROMANIAN_CUI_SHAPE = re.compile(r"^(RO)?[0-9]{2,10}$", re.IGNORECASE)


def is_romanian_cui(value: str | None) -> bool:
    """Whether a stored tax ID is a Romanian CUI (digits, optionally RO-prefixed), valid or not.

    The same field holds foreign tax IDs (e.g. DE999999999), so "has a value" is not "Romanian".
    """
    return bool(value) and bool(_ROMANIAN_CUI_SHAPE.match(str(value).strip()))


def normalize_cui_digits(value: str) -> str:
    """The digits of a valid CUI, check digit verified, with or without an RO prefix.

    Raises ValueError with the validator's reason for anything else.
    """
    result = CUIValidator.validate_strict(value.strip())
    if not result.is_valid:
        raise ValueError(result.error_message)
    return result.digits


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
