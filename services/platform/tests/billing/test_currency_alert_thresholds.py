"""Alert decisions use recorded money, independently of today's selling currency."""

from decimal import Decimal
from unittest.mock import Mock, patch

from django.test import TestCase

from apps.billing.config import get_large_refund_threshold_cents
from apps.billing.signals import _handle_invoice_refund_completion, _notify_finance_team_large_refund
from apps.provisioning.signals import _handle_new_service_creation
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService


class CurrencyAlertThresholdTests(TestCase):
    def setUp(self):
        SettingsService.clear_all_cache()
        self.addCleanup(SettingsService.clear_all_cache)

    def setting(self, key, value):
        SystemSetting.objects.update_or_create(key=key, defaults={
            "value": value, "default_value": {}, "data_type": "json", "category": "billing",
        })
        SettingsService._clear_setting_cache(key)

    def test_refund_limits_are_explicit_for_each_recorded_currency(self):
        self.setting("billing.large_refund_thresholds_cents", {"RON": 90000, "EUR": 15000, "USD": 25000})
        for code, expected in (("RON", 90000), ("EUR", 15000), ("USD", 25000)):
            with self.subTest(code=code):
                self.assertEqual(get_large_refund_threshold_cents(code), expected)

    def test_unconfigured_or_invalid_foreign_limit_requests_finance_attention(self):
        for values in ({}, {"EUR": True}, {"EUR": "50000"}, {"EUR": -1}, []):
            with self.subTest(values=values):
                self.setting("billing.large_refund_thresholds_cents", values)
                self.assertEqual(get_large_refund_threshold_cents("EUR"), 0)

    def test_legacy_refund_limit_is_preserved_for_ron_only(self):
        self.setting("billing.large_refund_notification_threshold_cents", 125000)
        self.assertEqual(get_large_refund_threshold_cents("RON"), 125000)
        self.assertEqual(get_large_refund_threshold_cents("USD"), 0)

    def test_refund_trigger_passes_original_invoice_currency(self):
        self.setting("billing.large_refund_thresholds_cents", {"RON": 50000, "EUR": 1000})
        invoice = Mock(total_cents=2000)
        invoice.currency.code = "EUR"
        with (
            patch("apps.billing.signals._queue_provider_storno"),
            patch("apps.billing.signals._send_invoice_refund_confirmation"),
            patch("apps.billing.signals._update_customer_invoice_history"),
            patch("apps.billing.signals._handle_efactura_refund_reporting"),
            patch("apps.billing.signals._update_billing_refund_metrics"),
            patch("apps.billing.signals.log_security_event"),
            patch("apps.billing.custom_signals.invoice_refunded.send"),
            patch("apps.billing.signals._notify_finance_team_large_refund") as notify,
            self.captureOnCommitCallbacks(execute=True),
        ):
            _handle_invoice_refund_completion(invoice)
        notify.assert_called_once_with(invoice)

    def test_refund_email_reports_threshold_in_original_invoice_currency(self):
        self.setting("company.email_finance", "finance@example.test")
        self.setting("billing.large_refund_thresholds_cents", {"RON": 50000, "EUR": 1000})
        invoice = Mock(number="INV-CURRENCY", total=Decimal("20"))
        invoice.currency.code = "EUR"
        invoice.customer.get_display_name.return_value = "Currency Test"
        with patch("apps.notifications.services.EmailService.send_template_email") as send:
            _notify_finance_team_large_refund(invoice)
        context = send.call_args.kwargs["context"]
        self.assertEqual(context["currency"], "EUR")
        self.assertEqual(context["threshold"], Decimal("10"))

    def test_service_audit_threshold_uses_its_currency(self):
        self.setting("provisioning.high_value_thresholds_cents", {"RON": 50000, "EUR": 1000, "USD": 90000})
        for code, expected in (("EUR", True), ("USD", False), ("RON", False)):
            with self.subTest(code=code):
                service = Mock(price=Decimal("20"))
                service.currency.code = code
                with patch("apps.provisioning.signals.AuditService.log_event") as audit:
                    _handle_new_service_creation(service)
                context = audit.call_args.kwargs["context"]
                self.assertEqual(context.metadata["high_value_service"], expected)
                self.assertEqual(context.metadata["currency"], code)

    def test_service_without_foreign_limit_is_flagged_for_attention(self):
        service = Mock(price=Decimal("20"))
        service.currency.code = "EUR"
        with patch("apps.provisioning.signals.AuditService.log_event") as audit:
            _handle_new_service_creation(service)
        self.assertTrue(audit.call_args.kwargs["context"].metadata["high_value_service"])
