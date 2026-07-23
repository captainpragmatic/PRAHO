# ===============================================================================
# BILLING TERMS — SETTINGSSERVICE INTEGRATION TESTS
# ===============================================================================
"""
Tests that billing term values are correctly resolved from SettingsService,
with proper fallback to defaults when no DB records exist.

Covers:
1. Invoice payment terms: default and DB-backed
2. Proforma validity: default and DB-backed
3. Payment grace period: default
4. get_payment_due_date() uses SettingsService
"""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from apps.billing.config import (
    get_invoice_generation_lead_days,
    get_invoice_payment_terms_days,
    get_payment_due_date,
)
from apps.billing.recurring_billing import fixed_renewal_schedule
from apps.settings.services import SettingsService


class InvoicePaymentTermsTests(TestCase):
    """Test invoice payment terms resolution from SettingsService."""

    def test_default_returns_14(self) -> None:
        """No DB record → get_invoice_payment_terms_days() returns 14."""
        result = get_invoice_payment_terms_days()
        self.assertEqual(result, 14)

    def test_reads_from_db_when_set(self) -> None:
        """DB record with value 21 → function returns 21."""
        SettingsService.update_setting(
            key="billing.invoice_payment_terms_days",
            value=21,
            reason="test override",
        )

        result = get_invoice_payment_terms_days()
        self.assertEqual(result, 21)


class InvoiceGenerationLeadTimeTests(TestCase):
    """Renewal invoices retain the current 14-day default with guarded overrides."""

    def setUp(self) -> None:
        SettingsService.clear_all_cache()

    def tearDown(self) -> None:
        SettingsService.clear_all_cache()

    def test_default_preserves_the_existing_14_day_schedule(self) -> None:
        self.assertEqual(get_invoice_generation_lead_days(), 14)

    def test_reads_operator_override_from_settings(self) -> None:
        result = SettingsService.update_setting(
            key="billing.invoice_generation_lead_days",
            value=21,
            reason="test override",
        )
        self.assertTrue(result.is_ok(), result)

        self.assertEqual(get_invoice_generation_lead_days(), 21)

    def test_rejects_lead_shorter_than_the_automatic_collection_notice(self) -> None:
        result = SettingsService.update_setting(
            key="billing.invoice_generation_lead_days",
            value=6,
            reason="invalid test override",
        )

        self.assertTrue(result.is_err(), result)

    def test_rejects_lead_time_longer_than_the_supported_monthly_window(self) -> None:
        result = SettingsService.update_setting(
            key="billing.invoice_generation_lead_days",
            value=31,
            reason="invalid test override",
        )

        self.assertTrue(result.is_err(), result)

    @patch("apps.billing.config.SettingsService.get_integer_setting", return_value=1)
    def test_runtime_reader_fails_safe_when_storage_is_below_the_supported_range(self, _mock_get: object) -> None:
        self.assertEqual(get_invoice_generation_lead_days(), 7)

    @patch("apps.billing.config.SettingsService.get_integer_setting", return_value=365)
    def test_runtime_reader_fails_safe_when_storage_is_above_the_supported_range(self, _mock_get: object) -> None:
        self.assertEqual(get_invoice_generation_lead_days(), 30)

    def test_fixed_schedule_changes_only_invoice_generation_time(self) -> None:
        result = SettingsService.update_setting(
            key="billing.invoice_generation_lead_days",
            value=21,
            reason="test override",
        )
        self.assertTrue(result.is_ok(), result)
        period_end = timezone.now()

        proforma_at, charge_at = fixed_renewal_schedule(period_end)

        self.assertEqual(proforma_at, period_end - timedelta(days=21))
        self.assertEqual(charge_at, period_end - timedelta(days=7))


class ProformaValidityTests(TestCase):
    """Test proforma validity resolution from SettingsService."""

    def test_default_returns_30(self) -> None:
        """No DB record → proforma validity returns 30."""
        result = SettingsService.get_integer_setting("billing.proforma_validity_days", 30)
        self.assertEqual(result, 30)

    def test_reads_from_db_when_set(self) -> None:
        """DB record with value 45 → returns 45."""
        SettingsService.update_setting(
            key="billing.proforma_validity_days",
            value=45,
            reason="test override",
        )

        result = SettingsService.get_integer_setting("billing.proforma_validity_days", 30)
        self.assertEqual(result, 45)


class PaymentGracePeriodTests(TestCase):
    """Test payment grace period resolution from SettingsService."""

    def test_default_returns_5(self) -> None:
        """No DB record → payment grace period returns 5."""
        result = SettingsService.get_integer_setting("billing.payment_grace_period_days", 5)
        self.assertEqual(result, 5)


class GetPaymentDueDateTests(TestCase):
    """Test get_payment_due_date() uses SettingsService for terms."""

    def test_uses_settings_for_due_date(self) -> None:
        """get_payment_due_date() with custom terms produces correct date."""
        SettingsService.update_setting(
            key="billing.invoice_payment_terms_days",
            value=21,
            reason="test override",
        )

        issue_date = timezone.now()
        due_date = get_payment_due_date(issue_date)

        expected = issue_date + timedelta(days=21)
        # Compare to within 1 second (timezone edge cases)
        self.assertAlmostEqual(
            due_date.timestamp(),
            expected.timestamp(),
            delta=1.0,
        )

    def test_default_terms_produce_14_day_offset(self) -> None:
        """Without DB record, get_payment_due_date() uses 14-day default."""
        issue_date = timezone.now()
        due_date = get_payment_due_date(issue_date)

        expected = issue_date + timedelta(days=14)
        self.assertAlmostEqual(
            due_date.timestamp(),
            expected.timestamp(),
            delta=1.0,
        )
