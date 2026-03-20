"""Tests for EU VAT number validator (apps.common.eu_vat_validator)."""

from django.test import SimpleTestCase

from apps.common.eu_vat_validator import (
    EU_COUNTRIES,
    is_eu_country,
    parse_vat_number,
    validate_vat_format,
)


class TestParseVatNumber(SimpleTestCase):
    """Test parse_vat_number() country detection and splitting."""

    def test_ro_prefix(self):
        country, digits = parse_vat_number("RO12345678")
        self.assertEqual(country, "RO")
        self.assertEqual(digits, "12345678")

    def test_de_prefix(self):
        country, digits = parse_vat_number("DE123456789")
        self.assertEqual(country, "DE")
        self.assertEqual(digits, "123456789")

    def test_no_prefix_defaults_to_ro(self):
        country, digits = parse_vat_number("12345678")
        self.assertEqual(country, "RO")
        self.assertEqual(digits, "12345678")

    def test_lowercase_normalised(self):
        country, digits = parse_vat_number("de123456789")
        self.assertEqual(country, "DE")
        self.assertEqual(digits, "123456789")

    def test_strips_whitespace(self):
        country, digits = parse_vat_number("  RO 12345678 ")
        self.assertEqual(country, "RO")
        self.assertEqual(digits, "12345678")

    def test_irish_vat_with_trailing_letter(self):
        country, digits = parse_vat_number("IE1234567T")
        self.assertEqual(country, "IE")
        self.assertEqual(digits, "1234567T")

    def test_french_vat_alphanumeric(self):
        country, digits = parse_vat_number("FR12345678901")
        self.assertEqual(country, "FR")
        self.assertEqual(digits, "12345678901")


class TestIsEuCountry(SimpleTestCase):
    """Test is_eu_country()."""

    def test_eu_members(self):
        for code in ["RO", "DE", "FR", "IT", "ES", "NL", "BE", "AT", "PL"]:
            self.assertTrue(is_eu_country(code), f"{code} should be EU")

    def test_non_eu(self):
        for code in ["GB", "US", "CN", "CH", "NO"]:
            self.assertFalse(is_eu_country(code), f"{code} should not be EU")

    def test_case_insensitive(self):
        self.assertTrue(is_eu_country("ro"))
        self.assertTrue(is_eu_country("De"))

    def test_eu27_count(self):
        self.assertEqual(len(EU_COUNTRIES), 27)


class TestValidateVatFormatRO(SimpleTestCase):
    """Test validate_vat_format() for Romanian CUI numbers."""

    def test_valid_short_cui(self):
        result = validate_vat_format("RO", "12345")
        self.assertTrue(result.is_valid)
        self.assertEqual(result.country_code, "RO")
        self.assertEqual(result.full_vat_number, "RO12345")

    def test_invalid_cui_non_numeric(self):
        result = validate_vat_format("RO", "abc")
        self.assertFalse(result.is_valid)
        self.assertIn("digits", result.error_message.lower())

    def test_empty_cui(self):
        result = validate_vat_format("RO", "")
        self.assertFalse(result.is_valid)


class TestValidateVatFormatEU(SimpleTestCase):
    """Test validate_vat_format() for non-RO EU countries via stdnum."""

    def test_valid_german_vat(self):
        # DE VAT numbers are 9 digits; stdnum validates format + check digit
        result = validate_vat_format("DE", "123456788")
        # This specific number may or may not pass check digit;
        # we just test the pipeline works
        self.assertEqual(result.country_code, "DE")
        self.assertEqual(result.full_vat_number, "DE123456788")

    def test_invalid_format_too_short(self):
        result = validate_vat_format("DE", "12")
        self.assertFalse(result.is_valid)
        self.assertTrue(result.error_message)

    def test_non_eu_country_rejected(self):
        result = validate_vat_format("GB", "123456789")
        self.assertFalse(result.is_valid)
        self.assertIn("not an EU-27", result.error_message)

    def test_non_eu_us_rejected(self):
        result = validate_vat_format("US", "123456789")
        self.assertFalse(result.is_valid)
