"""H10: DISABLE_AUDIT_SIGNALS must only be honored during TESTING=True.

Three locations in apps/billing/signals.py check DISABLE_AUDIT_SIGNALS:
  1. _log_billing_model_event (line ~108) — early-return pattern
  2. handle_invoice_created_or_updated (line ~361) — if-not-flag guard
  3. handle_payment_created_or_updated (line ~523) — if-not-flag guard

In production (TESTING=False) the flag MUST be ignored and audit MUST run;
the code MUST emit a critical log instead of silently skipping.
"""

import logging
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase, override_settings

from apps.billing.signals import (
    _log_billing_model_event,
    handle_invoice_created_or_updated,
    handle_payment_created_or_updated,
)


class LogBillingModelEventGuardTests(SimpleTestCase):
    """H10 — location 1: _log_billing_model_event early-return guard."""

    def _make_instance(self) -> MagicMock:
        mock = MagicMock()
        mock.pk = 1
        mock.__class__.__name__ = "Invoice"
        return mock

    @override_settings(DISABLE_AUDIT_SIGNALS=True, TESTING=False)
    def test_audit_runs_when_flag_set_but_testing_is_false(self) -> None:
        """DISABLE_AUDIT_SIGNALS=True without TESTING=True must NOT skip audit."""
        with patch("apps.billing.signals.AuditService") as mock_audit_svc:
            _log_billing_model_event(
                event_type="test_event",
                instance=self._make_instance(),
                description="test description",
            )
            # Audit must have been called — not skipped
            mock_audit_svc.log_event.assert_called_once()

    @override_settings(DISABLE_AUDIT_SIGNALS=True, TESTING=False)
    def test_critical_log_emitted_when_flag_set_outside_testing(self) -> None:
        """A critical log must be emitted when DISABLE_AUDIT_SIGNALS fires outside TESTING."""
        with (
            patch("apps.billing.signals.AuditService"),
            self.assertLogs("apps.billing.signals", level=logging.CRITICAL) as log_cm,
        ):
            _log_billing_model_event(
                event_type="test_event",
                instance=self._make_instance(),
                description="test description",
            )

        self.assertTrue(
            any("DISABLE_AUDIT_SIGNALS" in msg for msg in log_cm.output),
            "Expected a CRITICAL log mentioning DISABLE_AUDIT_SIGNALS",
        )

    @override_settings(DISABLE_AUDIT_SIGNALS=True, TESTING=True)
    def test_audit_skipped_when_flag_set_and_testing_is_true(self) -> None:
        """DISABLE_AUDIT_SIGNALS=True with TESTING=True should skip audit (legitimate test bypass)."""
        with patch("apps.billing.signals.AuditService") as mock_audit_svc:
            _log_billing_model_event(
                event_type="test_event",
                instance=self._make_instance(),
                description="test description",
            )
            mock_audit_svc.log_event.assert_not_called()

    @override_settings(DISABLE_AUDIT_SIGNALS=False, TESTING=False)
    def test_audit_runs_normally_when_flag_absent(self) -> None:
        """Audit runs normally when DISABLE_AUDIT_SIGNALS is not set."""
        with patch("apps.billing.signals.AuditService") as mock_audit_svc:
            _log_billing_model_event(
                event_type="test_event",
                instance=self._make_instance(),
                description="test description",
            )
            mock_audit_svc.log_event.assert_called_once()


class InvoiceSignalAuditGuardTests(SimpleTestCase):
    """H10 — location 2: handle_invoice_created_or_updated if-not-flag guard."""

    def _make_invoice_instance(self) -> MagicMock:
        mock_instance = MagicMock()
        mock_instance.configure_mock(
            pk=1,
            number="INV-001",
            status="issued",
            total_cents=10000,
            efactura_sent=True,
        )
        mock_instance._original_invoice_values = {}
        return mock_instance

    @override_settings(DISABLE_AUDIT_SIGNALS=True, TESTING=False)
    def test_billing_audit_service_called_when_flag_set_but_not_testing(self) -> None:
        """BillingAuditService.log_invoice_event must run even when flag is set and TESTING=False."""
        with (
            patch("apps.billing.signals.BillingAuditService") as mock_bas,
            patch("apps.billing.signals._handle_new_invoice_creation"),
            patch("apps.billing.signals._update_billing_analytics"),
            patch("apps.billing.signals._trigger_efactura_submission"),
        ):
            handle_invoice_created_or_updated(
                sender=MagicMock(),
                instance=self._make_invoice_instance(),
                created=True,
            )
            mock_bas.log_invoice_event.assert_called_once()

    @override_settings(DISABLE_AUDIT_SIGNALS=True, TESTING=True)
    def test_billing_audit_service_skipped_when_flag_set_and_testing(self) -> None:
        """BillingAuditService.log_invoice_event must NOT run when TESTING=True and flag set."""
        with (
            patch("apps.billing.signals.BillingAuditService") as mock_bas,
            patch("apps.billing.signals._handle_new_invoice_creation"),
            patch("apps.billing.signals._update_billing_analytics"),
            patch("apps.billing.signals._trigger_efactura_submission"),
        ):
            handle_invoice_created_or_updated(
                sender=MagicMock(),
                instance=self._make_invoice_instance(),
                created=True,
            )
            mock_bas.log_invoice_event.assert_not_called()


class PaymentSignalAuditGuardTests(SimpleTestCase):
    """H10 — location 3: handle_payment_created_or_updated if-not-flag guard."""

    def _make_payment_instance(self) -> MagicMock:
        mock_instance = MagicMock()
        mock_instance.configure_mock(
            pk=1,
            status="succeeded",
            amount_cents=10000,
            amount=100,
            payment_method="card",
        )
        mock_instance.currency.code = "RON"
        mock_instance._original_payment_values = {}
        return mock_instance

    @override_settings(DISABLE_AUDIT_SIGNALS=True, TESTING=False)
    def test_billing_audit_service_called_when_flag_set_but_not_testing(self) -> None:
        """BillingAuditService.log_payment_event must run even when flag set and TESTING=False."""
        with (
            patch("apps.billing.signals.BillingAuditService") as mock_bas,
            patch("apps.billing.signals._handle_payment_status_change"),
            patch("apps.billing.signals._activate_payment_services"),
            patch("apps.billing.signals._update_customer_payment_credit"),
        ):
            handle_payment_created_or_updated(
                sender=MagicMock(),
                instance=self._make_payment_instance(),
                created=True,
            )
            mock_bas.log_payment_event.assert_called_once()

    @override_settings(DISABLE_AUDIT_SIGNALS=True, TESTING=True)
    def test_billing_audit_service_skipped_when_flag_set_and_testing(self) -> None:
        """BillingAuditService.log_payment_event must NOT run when TESTING=True and flag set."""
        with (
            patch("apps.billing.signals.BillingAuditService") as mock_bas,
            patch("apps.billing.signals._handle_payment_status_change"),
            patch("apps.billing.signals._activate_payment_services"),
            patch("apps.billing.signals._update_customer_payment_credit"),
        ):
            handle_payment_created_or_updated(
                sender=MagicMock(),
                instance=self._make_payment_instance(),
                created=True,
            )
            mock_bas.log_payment_event.assert_not_called()
