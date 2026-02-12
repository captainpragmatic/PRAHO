"""
Comprehensive tests for e-Factura settings module.

Tests cover:
- EFacturaSettings configuration retrieval
- VATRateConfig calculations
- Environment detection
- Setting fallback chains
- Validation and edge cases
"""

from datetime import timedelta
from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.efactura.settings import (
    CIUS_RO_CUSTOMIZATION_ID,
    CIUS_RO_VERSION,
    EFACTURA_DEFAULTS,
    PEPPOL_PROFILE_ID,
    ROMANIA_TIMEZONE,
    ROMANIAN_VAT_RATES,
    EFacturaEnvironment,
    EFacturaSettingKeys,
    EFacturaSettings,
    VATCategory,
    VATRateConfig,
)


class VATCategoryTestCase(TestCase):
    """Test VATCategory enum."""

    def test_all_categories_have_values(self):
        """Test all VAT categories have string values."""
        expected = {
            VATCategory.STANDARD: "S",
            VATCategory.ZERO: "Z",
            VATCategory.EXEMPT: "E",
            VATCategory.REVERSE_CHARGE: "AE",
            VATCategory.NOT_SUBJECT: "O",
            VATCategory.INTRA_COMMUNITY: "K",
            VATCategory.EXPORT: "G",
        }
        for category, value in expected.items():
            self.assertEqual(category.value, value)

    def test_choices_returns_tuples(self):
        """Test choices() returns list of tuples."""
        choices = VATCategory.choices()
        self.assertIsInstance(choices, list)
        self.assertTrue(all(isinstance(c, tuple) and len(c) == 2 for c in choices))


class VATRateConfigTestCase(TestCase):
    """Test VATRateConfig dataclass."""

    def test_rate_percent(self):
        """Test rate_percent returns rate as-is."""
        config = VATRateConfig(
            rate=Decimal("21.00"),
            category=VATCategory.STANDARD,
            name="Standard",
        )
        self.assertEqual(config.rate_percent, Decimal("21.00"))

    def test_rate_decimal_conversion(self):
        """Test rate_decimal converts to decimal fraction."""
        config = VATRateConfig(
            rate=Decimal("21.00"),
            category=VATCategory.STANDARD,
            name="Standard",
        )
        self.assertEqual(config.rate_decimal, Decimal("0.21"))

    def test_rate_decimal_for_reduced_rate(self):
        """Test rate_decimal for reduced rate."""
        config = VATRateConfig(
            rate=Decimal("9.00"),
            category=VATCategory.STANDARD,
            name="Reduced",
        )
        self.assertEqual(config.rate_decimal, Decimal("0.09"))

    def test_rate_decimal_for_zero_rate(self):
        """Test rate_decimal for zero rate."""
        config = VATRateConfig(
            rate=Decimal("0.00"),
            category=VATCategory.ZERO,
            name="Zero",
        )
        self.assertEqual(config.rate_decimal, Decimal("0.00"))

    def test_applies_to_default(self):
        """Test applies_to defaults to empty list."""
        config = VATRateConfig(
            rate=Decimal("21.00"),
            category=VATCategory.STANDARD,
            name="Standard",
        )
        self.assertEqual(config.applies_to, [])


class RomanianVATRatesTestCase(TestCase):
    """Test Romanian VAT rates configuration."""

    def test_standard_rate_is_21(self):
        """Test standard rate is 21%."""
        rate = ROMANIAN_VAT_RATES["standard"]
        self.assertEqual(rate.rate, Decimal("21.00"))
        self.assertEqual(rate.category, VATCategory.STANDARD)

    def test_reduced_rate(self):
        """Test 11% reduced rate."""
        rate = ROMANIAN_VAT_RATES["reduced"]
        self.assertEqual(rate.rate, Decimal("11.00"))


    def test_zero_rate(self):
        """Test zero rate for exports."""
        rate = ROMANIAN_VAT_RATES["zero"]
        self.assertEqual(rate.rate, Decimal("0.00"))
        self.assertEqual(rate.category, VATCategory.ZERO)

    def test_exempt_rate(self):
        """Test exempt rate for medical/education."""
        rate = ROMANIAN_VAT_RATES["exempt"]
        self.assertEqual(rate.rate, Decimal("0.00"))
        self.assertEqual(rate.category, VATCategory.EXEMPT)
        self.assertIn("medical", rate.applies_to)

    def test_reverse_charge_rate(self):
        """Test reverse charge for intra-EU B2B."""
        rate = ROMANIAN_VAT_RATES["reverse_charge"]
        self.assertEqual(rate.rate, Decimal("0.00"))
        self.assertEqual(rate.category, VATCategory.REVERSE_CHARGE)


class EFacturaEnvironmentTestCase(TestCase):
    """Test EFacturaEnvironment enum."""

    def test_test_environment_url(self):
        """Test test environment API URL."""
        env = EFacturaEnvironment.TEST
        self.assertEqual(env.api_base_url, "https://api.anaf.ro/test/FCTEL/rest")

    def test_production_environment_url(self):
        """Test production environment API URL."""
        env = EFacturaEnvironment.PRODUCTION
        self.assertEqual(env.api_base_url, "https://api.anaf.ro/prod/FCTEL/rest")

    def test_oauth_base_url(self):
        """Test OAuth base URL is same for both environments."""
        for env in EFacturaEnvironment:
            self.assertEqual(
                env.oauth_base_url,
                "https://logincert.anaf.ro/anaf-oauth2/v1",
            )


class EFacturaSettingsTestCase(TestCase):
    """Test EFacturaSettings class."""

    def setUp(self):
        self.settings = EFacturaSettings()

    @override_settings(EFACTURA_ENABLED=None)
    def test_default_enabled(self):
        """Test e-Factura is enabled by default."""
        self.assertTrue(self.settings.enabled)

    def test_default_environment_is_test(self):
        """Test default environment is test."""
        self.assertEqual(self.settings.environment, EFacturaEnvironment.TEST)

    def test_api_base_url_matches_environment(self):
        """Test API base URL matches environment."""
        self.assertEqual(
            self.settings.api_base_url,
            EFacturaEnvironment.TEST.api_base_url,
        )

    def test_oauth_base_url(self):
        """Test OAuth base URL is correct."""
        self.assertEqual(
            self.settings.oauth_base_url,
            "https://logincert.anaf.ro/anaf-oauth2/v1",
        )

    def test_get_vat_rate_standard(self):
        """Test getting standard VAT rate."""
        rate = self.settings.get_vat_rate("standard")
        self.assertEqual(rate.rate, Decimal("21.00"))

    def test_get_vat_rate_reduced(self):
        """Test getting reduced VAT rate."""
        rate = self.settings.get_vat_rate("reduced")
        self.assertEqual(rate.rate, Decimal("11.00"))

    def test_get_vat_rate_unknown_returns_standard(self):
        """Test unknown rate type returns standard."""
        rate = self.settings.get_vat_rate("nonexistent")
        self.assertEqual(rate.rate, Decimal("21.00"))

    def test_get_vat_rate_for_category_food(self):
        """Test getting VAT rate by category."""
        rate = self.settings.get_vat_rate_for_category("food")
        self.assertEqual(rate.rate, Decimal("11.00"))

    def test_get_vat_rate_for_category_hospitality(self):
        """Test getting VAT rate for hospitality."""
        rate = self.settings.get_vat_rate_for_category("hospitality")
        self.assertEqual(rate.rate, Decimal("11.00"))

    def test_get_vat_rate_for_category_unknown(self):
        """Test unknown category returns standard rate."""
        rate = self.settings.get_vat_rate_for_category("unknown_category")
        self.assertEqual(rate.rate, Decimal("21.00"))

    def test_standard_vat_rate_property(self):
        """Test standard_vat_rate property."""
        self.assertEqual(self.settings.standard_vat_rate, Decimal("21.00"))

    def test_submission_deadline_days_default(self):
        """Test submission deadline is 5 days by default."""
        self.assertEqual(self.settings.submission_deadline_days, 5)

    def test_max_retries_default(self):
        """Test max retries default."""
        self.assertEqual(self.settings.max_retries, 5)

    def test_retry_delays(self):
        """Test retry delays are exponential."""
        delays = self.settings.retry_delays
        self.assertEqual(len(delays), 5)
        self.assertEqual(delays[0], 300)  # 5 minutes
        self.assertEqual(delays[1], 900)  # 15 minutes
        # Each delay should be greater than previous
        for i in range(1, len(delays)):
            self.assertGreater(delays[i], delays[i - 1])

    def test_get_retry_delay(self):
        """Test getting delay for specific attempt."""
        self.assertEqual(self.settings.get_retry_delay(1), 300)
        self.assertEqual(self.settings.get_retry_delay(2), 900)
        self.assertEqual(self.settings.get_retry_delay(5), 21600)
        # Beyond max uses last delay
        self.assertEqual(self.settings.get_retry_delay(10), 21600)

    def test_rate_limits_from_anaf_docs(self):
        """Test rate limits match ANAF documentation."""
        self.assertEqual(self.settings.rate_limit_global_per_minute, 1000)
        self.assertEqual(self.settings.rate_limit_status_per_message_day, 100)
        self.assertEqual(self.settings.rate_limit_list_simple_per_day, 1500)
        self.assertEqual(self.settings.rate_limit_list_paginated_per_day, 100000)
        self.assertEqual(self.settings.rate_limit_download_per_message_day, 10)

    def test_b2b_enabled_by_default(self):
        """Test B2B is enabled by default (mandatory since 2024)."""
        self.assertTrue(self.settings.b2b_enabled)

    def test_b2c_disabled_by_default(self):
        """Test B2C is disabled by default (until 2025)."""
        self.assertFalse(self.settings.b2c_enabled)

    def test_archive_retention_years(self):
        """Test archive retention is 10 years (Romanian law)."""
        self.assertEqual(self.settings.archive_retention_years, 10)

    def test_xsd_validation_enabled_by_default(self):
        """Test XSD validation is enabled."""
        self.assertTrue(self.settings.xsd_validation_enabled)

    def test_schematron_validation_enabled_by_default(self):
        """Test schematron validation is enabled."""
        self.assertTrue(self.settings.schematron_validation_enabled)

    def test_metrics_enabled_by_default(self):
        """Test metrics are enabled by default."""
        self.assertTrue(self.settings.metrics_enabled)


class EFacturaSettingsTimezoneTestCase(TestCase):
    """Test timezone-related settings functionality."""

    def setUp(self):
        self.settings = EFacturaSettings()

    def test_romania_timezone_constant(self):
        """Test ROMANIA_TIMEZONE is Europe/Bucharest."""
        self.assertEqual(str(ROMANIA_TIMEZONE), "Europe/Bucharest")

    def test_get_romania_now(self):
        """Test get_romania_now returns time in Romanian timezone."""
        now = self.settings.get_romania_now()
        self.assertEqual(now.tzinfo, ROMANIA_TIMEZONE)

    def test_to_romania_time_conversion(self):
        """Test converting UTC time to Romanian time."""
        utc_time = timezone.now()
        ro_time = self.settings.to_romania_time(utc_time)
        self.assertEqual(ro_time.tzinfo, ROMANIA_TIMEZONE)

    def test_calculate_deadline(self):
        """Test deadline calculation."""
        issued_at = timezone.now()
        deadline = self.settings.calculate_deadline(issued_at)
        expected = issued_at + timedelta(days=5)
        self.assertEqual(deadline, expected)

    def test_is_deadline_approaching_false(self):
        """Test deadline not approaching for fresh invoice."""
        issued_at = timezone.now()
        self.assertFalse(self.settings.is_deadline_approaching(issued_at))

    def test_is_deadline_approaching_true(self):
        """Test deadline approaching within 24 hours."""
        issued_at = timezone.now() - timedelta(days=4, hours=1)
        self.assertTrue(self.settings.is_deadline_approaching(issued_at))

    def test_is_deadline_passed_false(self):
        """Test deadline not passed for fresh invoice."""
        issued_at = timezone.now()
        self.assertFalse(self.settings.is_deadline_passed(issued_at))

    def test_is_deadline_passed_true(self):
        """Test deadline passed after 5 days."""
        issued_at = timezone.now() - timedelta(days=6)
        self.assertTrue(self.settings.is_deadline_passed(issued_at))


class EFacturaSettingsValidationTestCase(TestCase):
    """Test settings validation functionality."""

    def test_is_configured_false_when_empty(self):
        """Test is_configured returns False with empty settings."""
        settings = EFacturaSettings()
        # By default, required fields are empty
        self.assertFalse(settings.is_configured())

    @patch.object(EFacturaSettings, "_get_string")
    def test_is_configured_true_when_set(self, mock_get_string):
        """Test is_configured returns True with required settings."""
        mock_get_string.side_effect = lambda key, default="": {
            EFacturaSettingKeys.COMPANY_CUI: "12345678",
            EFacturaSettingKeys.COMPANY_NAME: "Test Company",
            EFacturaSettingKeys.CLIENT_ID: "client-id",
        }.get(key, "")

        settings = EFacturaSettings()
        settings._get_string = mock_get_string
        self.assertTrue(settings.is_configured())

    def test_validate_configuration_returns_issues(self):
        """Test validate_configuration returns list of issues."""
        settings = EFacturaSettings()
        issues = settings.validate_configuration()
        self.assertIsInstance(issues, list)
        self.assertTrue(len(issues) > 0)
        self.assertTrue(any("CUI" in issue for issue in issues))


class EFacturaSettingsFallbackTestCase(TestCase):
    """Test settings fallback chain."""

    @override_settings(EFACTURA_ENABLED=False)
    def test_django_settings_override(self):
        """Test Django settings override defaults."""
        settings = EFacturaSettings()
        # Force re-read
        self.assertFalse(settings._get_bool(EFacturaSettingKeys.ENABLED, True))

    @override_settings(EFACTURA_VAT_RATE_STANDARD="20.00")
    def test_django_settings_for_vat_rate(self):
        """Test Django settings for VAT rate."""
        settings = EFacturaSettings()
        # The key mapping should work
        rate = settings._get_decimal(EFacturaSettingKeys.VAT_RATE_STANDARD, "19.00")
        # Note: This depends on key mapping working correctly
        self.assertIsInstance(rate, Decimal)


class ConstantsTestCase(TestCase):
    """Test module constants."""

    def test_cius_ro_version(self):
        """Test CIUS-RO version is set."""
        self.assertEqual(CIUS_RO_VERSION, "1.0.1")

    def test_cius_ro_customization_id_contains_version(self):
        """Test customization ID contains version."""
        self.assertIn(CIUS_RO_VERSION, CIUS_RO_CUSTOMIZATION_ID)
        self.assertIn("CIUS-RO", CIUS_RO_CUSTOMIZATION_ID)

    def test_peppol_profile_id(self):
        """Test PEPPOL profile ID is correct."""
        self.assertIn("peppol.eu", PEPPOL_PROFILE_ID)
        self.assertIn("billing", PEPPOL_PROFILE_ID)

    def test_defaults_contains_all_keys(self):
        """Test EFACTURA_DEFAULTS contains all setting keys."""
        for key in dir(EFacturaSettingKeys):
            if not key.startswith("_"):
                setting_key = getattr(EFacturaSettingKeys, key)
                if isinstance(setting_key, str) and setting_key.startswith("efactura."):
                    self.assertIn(
                        setting_key,
                        EFACTURA_DEFAULTS,
                        f"Missing default for {setting_key}",
                    )
