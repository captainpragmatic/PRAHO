"""
Tests for apps.common.cnp_validator — canonical CNP validation.

Covers CNPValidator.validate(), the validate_cnp Django field validator,
and SecureInputValidator.validate_cnp_romanian().
"""

from django.core.exceptions import ValidationError
from django.test import TestCase

from apps.common.cnp_validator import CNPValidator, validate_cnp
from apps.common.validators import SecureInputValidator

# Pre-computed valid CNPs (checksum-correct)
VALID_CNP_MALE_1985 = "1850101123451"  # M, 1985-01-01, Cluj (12)
VALID_CNP_FOREIGN = "9850101123456"  # Foreigner (code 9)


class TestCNPValidatorValidate(TestCase):
    """CNPValidator.validate() — the pure-Python core."""

    def test_valid_cnp_passes(self) -> None:
        result = CNPValidator.validate(VALID_CNP_MALE_1985)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.gender, "M")
        assert result.birth_date is not None
        self.assertEqual(result.birth_date.year, 1985)
        self.assertEqual(result.county_code, "12")

    def test_century_marker_0_rejected(self) -> None:
        """Digit 0 is NOT a valid gender/century code."""
        # Build a 13-digit string starting with 0
        cnp = "0850101123456"
        result = CNPValidator.validate(cnp)
        self.assertFalse(result.is_valid)
        self.assertIn("gender/century", result.error_message.lower())

    def test_all_valid_century_markers_accepted(self) -> None:
        """Codes 1-9 are valid (including 9 for foreigners)."""
        for code in "123456789":
            cnp_12 = f"{code}850101123450"[:12]
            check = CNPValidator._calculate_check_digit(cnp_12)
            cnp = cnp_12 + str(check)
            result = CNPValidator.validate(cnp)
            # Some may fail on county/date for synthetic data, but NOT on gender code
            if not result.is_valid:
                self.assertNotIn("gender/century", result.error_message.lower())

    def test_foreigner_code_9_valid(self) -> None:
        result = CNPValidator.validate(VALID_CNP_FOREIGN)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.gender, "?")

    def test_invalid_checksum_rejected(self) -> None:
        # Flip last digit
        bad_cnp = VALID_CNP_MALE_1985[:-1] + ("0" if VALID_CNP_MALE_1985[-1] != "0" else "1")
        result = CNPValidator.validate(bad_cnp)
        self.assertFalse(result.is_valid)
        self.assertIn("check digit", result.error_message.lower())

    def test_invalid_birth_date_rejected(self) -> None:
        # Feb 30 doesn't exist — build CNP with month=02, day=30
        cnp_12 = "185023012345"
        check = CNPValidator._calculate_check_digit(cnp_12)
        cnp = cnp_12 + str(check)
        result = CNPValidator.validate(cnp)
        self.assertFalse(result.is_valid)
        self.assertIn("birth date", result.error_message.lower())

    def test_invalid_county_code_rejected(self) -> None:
        # County 98 is invalid (not in COUNTY_CODES, not 00/99)
        cnp_12 = "185010198345"
        check = CNPValidator._calculate_check_digit(cnp_12)
        cnp = cnp_12 + str(check)
        result = CNPValidator.validate(cnp)
        self.assertFalse(result.is_valid)
        self.assertIn("county", result.error_message.lower())

    def test_too_short_rejected(self) -> None:
        result = CNPValidator.validate("12345")
        self.assertFalse(result.is_valid)

    def test_too_long_rejected(self) -> None:
        result = CNPValidator.validate("12345678901234")
        self.assertFalse(result.is_valid)

    def test_non_numeric_rejected(self) -> None:
        result = CNPValidator.validate("185010112345a")
        self.assertFalse(result.is_valid)

    def test_whitespace_stripping(self) -> None:
        result = CNPValidator.validate(f"  {VALID_CNP_MALE_1985}  ")
        self.assertTrue(result.is_valid)


class TestValidateCnpDjangoValidator(TestCase):
    """validate_cnp() — the Django model-field wrapper."""

    def test_valid_cnp_no_exception(self) -> None:
        validate_cnp(VALID_CNP_MALE_1985)  # Should not raise

    def test_invalid_cnp_raises_validation_error(self) -> None:
        with self.assertRaises(ValidationError) as cm:
            validate_cnp("0000000000000")
        self.assertEqual(cm.exception.code, "invalid_cnp")

    def test_empty_string_raises(self) -> None:
        """Empty string is not 13 digits."""
        with self.assertRaises(ValidationError):
            validate_cnp("")


class TestSecureInputValidatorCNP(TestCase):
    """SecureInputValidator.validate_cnp_romanian() — security-aware wrapper."""

    def test_valid_cnp_returns_stripped(self) -> None:
        result = SecureInputValidator.validate_cnp_romanian(f"  {VALID_CNP_MALE_1985}  ")
        self.assertEqual(result, VALID_CNP_MALE_1985)

    def test_invalid_cnp_raises(self) -> None:
        with self.assertRaises(ValidationError):
            SecureInputValidator.validate_cnp_romanian("0000000000000")

    def test_empty_returns_empty(self) -> None:
        self.assertEqual(SecureInputValidator.validate_cnp_romanian(""), "")

    def test_malicious_input_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            SecureInputValidator.validate_cnp_romanian("<script>alert(1)</script>")

    def test_oversized_input_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            SecureInputValidator.validate_cnp_romanian("1" * 21)
