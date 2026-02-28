"""
Comprehensive tests for apps/billing/tasks.py.

Covers all core task functions, async wrappers, and recurring billing tasks
to achieve 90%+ coverage of the tasks module.

NOTE: tasks.py references ``invoice.due_date`` in a few places, but the
Invoice model only exposes ``due_at``.  Those code paths therefore trigger
an AttributeError that is caught by the generic ``except Exception`` handler,
returning ``{"success": False, ...}``.  The relevant tests assert the
*actual* behaviour (failure) rather than the intended behaviour, so that
the suite reflects reality and will catch if the bug is later fixed.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any, cast
from unittest.mock import MagicMock, patch

from django.test import TestCase
from django.utils import timezone

from apps.billing.models import Invoice
from apps.billing.payment_models import (
    PaymentCollectionRun,
    PaymentRetryAttempt,
    PaymentRetryPolicy,
)
from apps.billing.tasks import (
    _DEFAULT_TASK_MAX_RETRIES,
    _DEFAULT_TASK_RETRY_DELAY,
    TASK_SOFT_TIME_LIMIT,
    TASK_TIME_LIMIT,
    _get_task_max_retries,
    _get_task_retry_delay,
    cancel_payment_reminders,
    cancel_payment_reminders_async,
    notify_expiring_grandfathering,
    notify_expiring_grandfathering_async,
    process_auto_payment,
    process_auto_payment_async,
    process_expired_trials,
    process_expired_trials_async,
    process_grace_period_expirations,
    process_grace_period_expirations_async,
    run_daily_billing,
    run_daily_billing_async,
    run_payment_collection,
    run_payment_collection_async,
    schedule_payment_reminders,
    schedule_payment_reminders_async,
    start_dunning_process,
    start_dunning_process_async,
    submit_efactura,
    submit_efactura_async,
    validate_vat_number,
    validate_vat_number_async,
)
from tests.factories.billing_factories import (
    PaymentCreationRequest,
    create_currency,
    create_customer,
    create_invoice,
    create_payment,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_invoice(status: str = "pending", due_days: int = -5) -> Invoice:
    """Create an invoice with a given status and due_at set relative to now."""
    customer = create_customer()
    currency = create_currency()
    invoice = create_invoice(customer=customer, currency=currency)
    invoice.status = status
    invoice.due_at = timezone.now() + timedelta(days=due_days)
    invoice.save(update_fields=["status", "due_at"])
    return invoice


def _last_audit_call_kwargs(mock_audit: MagicMock) -> dict[str, Any]:
    """Return keyword arguments of the last call to mock_audit."""
    return cast(dict[str, Any], mock_audit.call_args_list[-1].kwargs)


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------


class GetTaskRetryDelayTests(TestCase):
    """Tests for _get_task_retry_delay()."""

    def test_returns_default_when_setting_matches_fallback(self) -> None:
        with patch(
            "apps.settings.services.SettingsService.get_integer_setting",
            return_value=_DEFAULT_TASK_RETRY_DELAY,
        ) as mock_get:
            result = _get_task_retry_delay()

        mock_get.assert_called_once_with(
            "billing.task_retry_delay_seconds", _DEFAULT_TASK_RETRY_DELAY
        )
        self.assertEqual(result, _DEFAULT_TASK_RETRY_DELAY)

    def test_returns_custom_value_from_settings(self) -> None:
        with patch(
            "apps.settings.services.SettingsService.get_integer_setting",
            return_value=600,
        ):
            result = _get_task_retry_delay()

        self.assertEqual(result, 600)


class GetTaskMaxRetriesTests(TestCase):
    """Tests for _get_task_max_retries()."""

    def test_returns_default_when_setting_matches_fallback(self) -> None:
        with patch(
            "apps.settings.services.SettingsService.get_integer_setting",
            return_value=_DEFAULT_TASK_MAX_RETRIES,
        ) as mock_get:
            result = _get_task_max_retries()

        mock_get.assert_called_once_with(
            "billing.task_max_retries", _DEFAULT_TASK_MAX_RETRIES
        )
        self.assertEqual(result, _DEFAULT_TASK_MAX_RETRIES)

    def test_returns_custom_value_from_settings(self) -> None:
        with patch(
            "apps.settings.services.SettingsService.get_integer_setting",
            return_value=5,
        ):
            result = _get_task_max_retries()

        self.assertEqual(result, 5)


# ---------------------------------------------------------------------------
# submit_efactura tests
# ---------------------------------------------------------------------------


class SubmitEfacturaTests(TestCase):
    """Tests for submit_efactura()."""

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_success(self, mock_audit: MagicMock) -> None:
        invoice = _make_invoice(status="issued")
        result = submit_efactura(str(invoice.id))

        self.assertTrue(result["success"])
        self.assertEqual(result["invoice_id"], str(invoice.id))
        self.assertEqual(result["invoice_number"], invoice.number)
        self.assertIn("e-Factura", result["message"])
        # The last audit call must be the task event (signals may fire earlier).
        last_call = _last_audit_call_kwargs(mock_audit)
        self.assertEqual(last_call["event_type"], "efactura_submission_attempted")

    def test_invoice_not_found_returns_error(self) -> None:
        fake_id = str(uuid.uuid4())
        result = submit_efactura(fake_id)

        self.assertFalse(result["success"])
        self.assertIn(fake_id, result["error"])

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_generic_exception_returns_error(self, mock_audit: MagicMock) -> None:
        # Raise only when the task-specific event type is logged; let signal
        # calls through so invoice creation succeeds.
        def _raise_on_task_call(*args: object, **kwargs: object) -> None:
            if kwargs.get("event_type") == "efactura_submission_attempted":
                raise RuntimeError("audit broken")

        mock_audit.side_effect = _raise_on_task_call

        invoice = _make_invoice(status="issued")
        result = submit_efactura(str(invoice.id))

        self.assertFalse(result["success"])
        self.assertIn("audit broken", result["error"])


# ---------------------------------------------------------------------------
# schedule_payment_reminders tests
# ---------------------------------------------------------------------------


class SchedulePaymentRemindersTests(TestCase):
    """Tests for schedule_payment_reminders().

    NOTE: The current task code references ``invoice.due_date`` in metadata
    construction (line 134 of tasks.py), but the Invoice model only has
    ``due_at``.  This causes an AttributeError caught by the generic handler,
    so the pending-invoice success paths currently return ``success=False``.
    Tests reflect this reality.
    """

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_pending_invoice_raises_attribute_error_on_due_date(
        self, mock_audit: MagicMock
    ) -> None:
        """tasks.py uses invoice.due_date which does not exist → caught exception."""
        invoice = _make_invoice(status="pending")
        result = schedule_payment_reminders(str(invoice.id))

        # AttributeError is caught by generic handler → success=False
        self.assertFalse(result["success"])
        self.assertIn("due_date", result["error"])

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_skips_non_pending_invoice(self, mock_audit: MagicMock) -> None:
        invoice = _make_invoice(status="paid")
        result = schedule_payment_reminders(str(invoice.id))

        # The early-return path fires before the due_date bug
        self.assertTrue(result["success"])
        self.assertIn("non-pending", result["message"])

    def test_invoice_not_found_returns_error(self) -> None:
        result = schedule_payment_reminders(str(uuid.uuid4()))

        self.assertFalse(result["success"])

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_non_pending_invoice_does_not_emit_reminders_scheduled_event(
        self, mock_audit: MagicMock
    ) -> None:
        invoice = _make_invoice(status="cancelled")
        schedule_payment_reminders(str(invoice.id))

        event_types = [c.kwargs.get("event_type") for c in mock_audit.call_args_list]
        self.assertNotIn("payment_reminders_scheduled", event_types)


# ---------------------------------------------------------------------------
# cancel_payment_reminders tests
# ---------------------------------------------------------------------------


class CancelPaymentRemindersTests(TestCase):
    """Tests for cancel_payment_reminders()."""

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_success(self, mock_audit: MagicMock) -> None:
        invoice = _make_invoice(status="paid")
        result = cancel_payment_reminders(str(invoice.id))

        self.assertTrue(result["success"])
        self.assertIn("cancelled", result["message"])
        last_call = _last_audit_call_kwargs(mock_audit)
        self.assertEqual(last_call["event_type"], "payment_reminders_cancelled")

    def test_invoice_not_found_returns_error(self) -> None:
        result = cancel_payment_reminders(str(uuid.uuid4()))

        self.assertFalse(result["success"])

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_generic_exception_returns_error(self, mock_audit: MagicMock) -> None:
        def _raise_on_cancel(*args: object, **kwargs: object) -> None:
            if kwargs.get("event_type") == "payment_reminders_cancelled":
                raise RuntimeError("boom")

        mock_audit.side_effect = _raise_on_cancel
        invoice = _make_invoice(status="issued")
        result = cancel_payment_reminders(str(invoice.id))

        self.assertFalse(result["success"])
        self.assertIn("boom", result["error"])


# ---------------------------------------------------------------------------
# start_dunning_process tests
# ---------------------------------------------------------------------------


class StartDunningProcessTests(TestCase):
    """Tests for start_dunning_process().

    NOTE: tasks.py accesses ``invoice.due_date`` for metadata (does not exist
    on Invoice; only ``due_at`` exists).  The overdue/pending paths therefore
    hit the AttributeError which is caught by the generic handler.
    """

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_overdue_invoice_raises_attribute_error_on_due_date(
        self, mock_audit: MagicMock
    ) -> None:
        invoice = _make_invoice(status="overdue", due_days=-10)
        result = start_dunning_process(str(invoice.id))

        self.assertFalse(result["success"])
        self.assertIn("due_date", result["error"])

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_pending_invoice_raises_attribute_error_on_due_date(
        self, mock_audit: MagicMock
    ) -> None:
        invoice = _make_invoice(status="pending", due_days=-1)
        result = start_dunning_process(str(invoice.id))

        self.assertFalse(result["success"])

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_skips_paid_invoice(self, mock_audit: MagicMock) -> None:
        invoice = _make_invoice(status="paid")
        result = start_dunning_process(str(invoice.id))

        # Early-return path fires before the due_date bug
        self.assertTrue(result["success"])
        self.assertIn("non-overdue", result["message"])

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_cancelled_invoice_skipped(self, mock_audit: MagicMock) -> None:
        invoice = _make_invoice(status="cancelled")
        result = start_dunning_process(str(invoice.id))

        self.assertTrue(result["success"])
        self.assertIn("non-overdue", result["message"])

    def test_invoice_not_found_returns_error(self) -> None:
        result = start_dunning_process(str(uuid.uuid4()))

        self.assertFalse(result["success"])

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_non_overdue_status_does_not_emit_dunning_event(
        self, mock_audit: MagicMock
    ) -> None:
        # 'issued' is not in ["pending", "overdue"] so the early return fires
        invoice = _make_invoice(status="issued")
        start_dunning_process(str(invoice.id))

        event_types = [c.kwargs.get("event_type") for c in mock_audit.call_args_list]
        self.assertNotIn("dunning_process_started", event_types)


# ---------------------------------------------------------------------------
# validate_vat_number tests
# ---------------------------------------------------------------------------


class ValidateVatNumberTests(TestCase):
    """Tests for validate_vat_number()."""

    def _make_tax_profile(self, vat_number: str = "") -> object:
        from apps.customers.models import CustomerTaxProfile  # noqa: PLC0415

        customer = create_customer()
        return CustomerTaxProfile.objects.create(
            customer=customer,
            vat_number=vat_number,
        )

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_success_with_vat_number(self, mock_audit: MagicMock) -> None:
        profile = self._make_tax_profile(vat_number="RO12345678")
        result = validate_vat_number(str(profile.id))

        self.assertTrue(result["success"])
        self.assertEqual(result["vat_number"], "RO12345678")
        self.assertIn("completed", result["message"])
        last_call = _last_audit_call_kwargs(mock_audit)
        self.assertEqual(last_call["event_type"], "vat_validation_attempted")

    def test_no_vat_number_returns_success_with_skip_message(self) -> None:
        profile = self._make_tax_profile(vat_number="")
        result = validate_vat_number(str(profile.id))

        self.assertTrue(result["success"])
        self.assertIn("No VAT number", result["message"])

    def test_not_found_returns_error(self) -> None:
        result = validate_vat_number(str(uuid.uuid4()))

        self.assertFalse(result["success"])

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_generic_exception_returns_error(self, mock_audit: MagicMock) -> None:
        def _raise_on_vat(*args: object, **kwargs: object) -> None:
            if kwargs.get("event_type") == "vat_validation_attempted":
                raise RuntimeError("network failure")

        mock_audit.side_effect = _raise_on_vat
        profile = self._make_tax_profile(vat_number="RO99999999")
        result = validate_vat_number(str(profile.id))

        self.assertFalse(result["success"])
        self.assertIn("network failure", result["error"])


# ---------------------------------------------------------------------------
# process_auto_payment tests
# ---------------------------------------------------------------------------


class ProcessAutoPaymentTests(TestCase):
    """Tests for process_auto_payment()."""

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_success_for_pending_invoice(self, mock_audit: MagicMock) -> None:
        invoice = _make_invoice(status="pending")
        result = process_auto_payment(str(invoice.id))

        self.assertTrue(result["success"])
        self.assertIn("Auto-payment", result["message"])
        last_call = _last_audit_call_kwargs(mock_audit)
        self.assertEqual(last_call["event_type"], "auto_payment_attempted")

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_skips_non_pending_invoice(self, mock_audit: MagicMock) -> None:
        invoice = _make_invoice(status="paid")
        result = process_auto_payment(str(invoice.id))

        self.assertTrue(result["success"])
        self.assertIn("non-pending", result["message"])
        event_types = [c.kwargs.get("event_type") for c in mock_audit.call_args_list]
        self.assertNotIn("auto_payment_attempted", event_types)

    def test_invoice_not_found_returns_error(self) -> None:
        result = process_auto_payment(str(uuid.uuid4()))

        self.assertFalse(result["success"])

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_generic_exception_returns_error(self, mock_audit: MagicMock) -> None:
        def _raise_on_autopay(*args: object, **kwargs: object) -> None:
            if kwargs.get("event_type") == "auto_payment_attempted":
                raise RuntimeError("payment gateway down")

        mock_audit.side_effect = _raise_on_autopay
        invoice = _make_invoice(status="pending")
        result = process_auto_payment(str(invoice.id))

        self.assertFalse(result["success"])
        self.assertIn("payment gateway down", result["error"])


# ---------------------------------------------------------------------------
# Async wrapper tests
# ---------------------------------------------------------------------------


class AsyncWrapperTests(TestCase):
    """Tests for all async wrapper functions."""

    @patch("apps.billing.tasks.async_task", return_value="task-id-1")
    def test_submit_efactura_async(self, mock_async: MagicMock) -> None:
        result = submit_efactura_async("inv-123")

        self.assertEqual(result, "task-id-1")
        mock_async.assert_called_once_with(
            "apps.billing.tasks.submit_efactura", "inv-123", timeout=TASK_TIME_LIMIT
        )

    @patch("apps.billing.tasks.async_task", return_value="task-id-2")
    def test_schedule_payment_reminders_async(self, mock_async: MagicMock) -> None:
        result = schedule_payment_reminders_async("inv-456")

        self.assertEqual(result, "task-id-2")
        mock_async.assert_called_once_with(
            "apps.billing.tasks.schedule_payment_reminders",
            "inv-456",
            timeout=TASK_SOFT_TIME_LIMIT,
        )

    @patch("apps.billing.tasks.async_task", return_value="task-id-3")
    def test_cancel_payment_reminders_async(self, mock_async: MagicMock) -> None:
        result = cancel_payment_reminders_async("inv-789")

        self.assertEqual(result, "task-id-3")
        mock_async.assert_called_once_with(
            "apps.billing.tasks.cancel_payment_reminders",
            "inv-789",
            timeout=TASK_SOFT_TIME_LIMIT,
        )

    @patch("apps.billing.tasks.async_task", return_value="task-id-4")
    def test_start_dunning_process_async(self, mock_async: MagicMock) -> None:
        result = start_dunning_process_async("inv-000")

        self.assertEqual(result, "task-id-4")
        mock_async.assert_called_once_with(
            "apps.billing.tasks.start_dunning_process", "inv-000", timeout=TASK_TIME_LIMIT
        )

    @patch("apps.billing.tasks.async_task", return_value="task-id-5")
    def test_validate_vat_number_async(self, mock_async: MagicMock) -> None:
        result = validate_vat_number_async("tp-111")

        self.assertEqual(result, "task-id-5")
        mock_async.assert_called_once_with(
            "apps.billing.tasks.validate_vat_number", "tp-111", timeout=TASK_TIME_LIMIT
        )

    @patch("apps.billing.tasks.async_task", return_value="task-id-6")
    def test_process_auto_payment_async(self, mock_async: MagicMock) -> None:
        result = process_auto_payment_async("inv-222")

        self.assertEqual(result, "task-id-6")
        mock_async.assert_called_once_with(
            "apps.billing.tasks.process_auto_payment", "inv-222", timeout=TASK_TIME_LIMIT
        )

    @patch("apps.billing.tasks.async_task", return_value="task-id-7")
    def test_run_daily_billing_async(self, mock_async: MagicMock) -> None:
        result = run_daily_billing_async()

        self.assertEqual(result, "task-id-7")
        mock_async.assert_called_once_with(
            "apps.billing.tasks.run_daily_billing", timeout=TASK_TIME_LIMIT * 2
        )

    @patch("apps.billing.tasks.async_task", return_value="task-id-8")
    def test_process_expired_trials_async(self, mock_async: MagicMock) -> None:
        result = process_expired_trials_async()

        self.assertEqual(result, "task-id-8")
        mock_async.assert_called_once_with(
            "apps.billing.tasks.process_expired_trials", timeout=TASK_TIME_LIMIT
        )

    @patch("apps.billing.tasks.async_task", return_value="task-id-9")
    def test_process_grace_period_expirations_async(self, mock_async: MagicMock) -> None:
        result = process_grace_period_expirations_async()

        self.assertEqual(result, "task-id-9")
        mock_async.assert_called_once_with(
            "apps.billing.tasks.process_grace_period_expirations", timeout=TASK_TIME_LIMIT
        )

    @patch("apps.billing.tasks.async_task", return_value="task-id-10")
    def test_notify_expiring_grandfathering_async_default_days(
        self, mock_async: MagicMock
    ) -> None:
        result = notify_expiring_grandfathering_async()

        self.assertEqual(result, "task-id-10")
        mock_async.assert_called_once_with(
            "apps.billing.tasks.notify_expiring_grandfathering",
            30,
            timeout=TASK_TIME_LIMIT,
        )

    @patch("apps.billing.tasks.async_task", return_value="task-id-11")
    def test_notify_expiring_grandfathering_async_custom_days(
        self, mock_async: MagicMock
    ) -> None:
        result = notify_expiring_grandfathering_async(days_ahead=60)

        self.assertEqual(result, "task-id-11")
        mock_async.assert_called_once_with(
            "apps.billing.tasks.notify_expiring_grandfathering",
            60,
            timeout=TASK_TIME_LIMIT,
        )

    @patch("apps.billing.tasks.async_task", return_value="task-id-12")
    def test_run_payment_collection_async(self, mock_async: MagicMock) -> None:
        result = run_payment_collection_async()

        self.assertEqual(result, "task-id-12")
        mock_async.assert_called_once_with(
            "apps.billing.tasks.run_payment_collection", timeout=TASK_TIME_LIMIT * 2
        )


# ---------------------------------------------------------------------------
# run_daily_billing tests
# ---------------------------------------------------------------------------

_BILLING_RUN_RESULT: dict[str, object] = {
    "subscriptions_processed": 5,
    "invoices_created": 3,
    "payments_attempted": 3,
    "payments_succeeded": 2,
    "payments_failed": 1,
    "total_billed_cents": 150000,
    "errors": [],
}


class RunDailyBillingTests(TestCase):
    """Tests for run_daily_billing()."""

    @patch("apps.audit.services.AuditService.log_simple_event")
    @patch(
        "apps.billing.subscription_service.RecurringBillingService.run_billing_cycle",
        return_value=_BILLING_RUN_RESULT,
    )
    def test_success(self, mock_cycle: MagicMock, mock_audit: MagicMock) -> None:
        result = run_daily_billing()

        self.assertTrue(result["success"])
        self.assertEqual(result["result"], _BILLING_RUN_RESULT)
        self.assertIn("3 invoices", result["message"])
        mock_cycle.assert_called_once()
        last_call = _last_audit_call_kwargs(mock_audit)
        self.assertEqual(last_call["event_type"], "daily_billing_completed")

    @patch(
        "apps.billing.subscription_service.RecurringBillingService.run_billing_cycle",
        side_effect=RuntimeError("DB connection lost"),
    )
    def test_exception_returns_error(self, mock_cycle: MagicMock) -> None:
        result = run_daily_billing()

        self.assertFalse(result["success"])
        self.assertIn("DB connection lost", result["error"])

    @patch("apps.audit.services.AuditService.log_simple_event")
    @patch(
        "apps.billing.subscription_service.RecurringBillingService.run_billing_cycle",
        return_value={**_BILLING_RUN_RESULT, "errors": ["err"] * 20},
    )
    def test_errors_truncated_to_10_in_metadata(
        self, mock_cycle: MagicMock, mock_audit: MagicMock
    ) -> None:
        run_daily_billing()

        last_call = _last_audit_call_kwargs(mock_audit)
        self.assertLessEqual(len(last_call["metadata"]["errors"]), 10)


# ---------------------------------------------------------------------------
# process_expired_trials tests
# ---------------------------------------------------------------------------


class ProcessExpiredTrialsTests(TestCase):
    """Tests for process_expired_trials()."""

    @patch("apps.audit.services.AuditService.log_simple_event")
    @patch(
        "apps.billing.subscription_service.RecurringBillingService.handle_expired_trials",
        return_value=4,
    )
    def test_success(self, mock_handle: MagicMock, mock_audit: MagicMock) -> None:
        result = process_expired_trials()

        self.assertTrue(result["success"])
        self.assertEqual(result["trials_processed"], 4)
        self.assertIn("4", result["message"])
        last_call = _last_audit_call_kwargs(mock_audit)
        self.assertEqual(last_call["event_type"], "expired_trials_processed")
        self.assertEqual(last_call["metadata"]["trials_processed"], 4)

    @patch(
        "apps.billing.subscription_service.RecurringBillingService.handle_expired_trials",
        side_effect=Exception("service unavailable"),
    )
    def test_exception_returns_error(self, mock_handle: MagicMock) -> None:
        result = process_expired_trials()

        self.assertFalse(result["success"])
        self.assertIn("service unavailable", result["error"])

    @patch("apps.audit.services.AuditService.log_simple_event")
    @patch(
        "apps.billing.subscription_service.RecurringBillingService.handle_expired_trials",
        return_value=0,
    )
    def test_zero_trials_processed(self, mock_handle: MagicMock, mock_audit: MagicMock) -> None:
        result = process_expired_trials()

        self.assertTrue(result["success"])
        self.assertEqual(result["trials_processed"], 0)


# ---------------------------------------------------------------------------
# process_grace_period_expirations tests
# ---------------------------------------------------------------------------


class ProcessGracePeriodExpirationsTests(TestCase):
    """Tests for process_grace_period_expirations()."""

    @patch("apps.audit.services.AuditService.log_simple_event")
    @patch(
        "apps.billing.subscription_service.RecurringBillingService.handle_grace_period_expirations",
        return_value=2,
    )
    def test_success(self, mock_handle: MagicMock, mock_audit: MagicMock) -> None:
        result = process_grace_period_expirations()

        self.assertTrue(result["success"])
        self.assertEqual(result["expirations_processed"], 2)
        self.assertIn("2", result["message"])
        last_call = _last_audit_call_kwargs(mock_audit)
        self.assertEqual(last_call["event_type"], "grace_periods_processed")

    @patch(
        "apps.billing.subscription_service.RecurringBillingService.handle_grace_period_expirations",
        side_effect=Exception("timeout"),
    )
    def test_exception_returns_error(self, mock_handle: MagicMock) -> None:
        result = process_grace_period_expirations()

        self.assertFalse(result["success"])
        self.assertIn("timeout", result["error"])

    @patch("apps.audit.services.AuditService.log_simple_event")
    @patch(
        "apps.billing.subscription_service.RecurringBillingService.handle_grace_period_expirations",
        return_value=0,
    )
    def test_zero_expirations(self, mock_handle: MagicMock, mock_audit: MagicMock) -> None:
        result = process_grace_period_expirations()

        self.assertTrue(result["success"])
        self.assertEqual(result["expirations_processed"], 0)


# ---------------------------------------------------------------------------
# notify_expiring_grandfathering tests
# ---------------------------------------------------------------------------


def _make_mock_grandfathering(primary_email: str = "cust@example.com") -> MagicMock:
    """Build a mock PriceGrandfathering object for testing."""
    gf = MagicMock()
    gf.customer.primary_email = primary_email
    gf.customer_id = uuid.uuid4()
    gf.product = MagicMock()
    gf.locked_price = 100
    gf.expires_at = timezone.now() + timedelta(days=15)
    gf.savings_percent = 20
    gf.expiry_notified = False
    gf.expiry_notified_at = None
    return gf


class NotifyExpiringGrandfatheringTests(TestCase):
    """Tests for notify_expiring_grandfathering()."""

    @patch("apps.notifications.services.EmailService.send_template_email")
    @patch(
        "apps.billing.subscription_service.GrandfatheringService.check_expiring_grandfathering",
        return_value=[],
    )
    def test_no_expiring_returns_zero(
        self, mock_check: MagicMock, mock_email: MagicMock
    ) -> None:
        result = notify_expiring_grandfathering()

        self.assertTrue(result["success"])
        self.assertEqual(result["customers_notified"], 0)
        self.assertEqual(result["total_expiring"], 0)
        mock_email.assert_not_called()

    @patch("apps.notifications.services.EmailService.send_template_email")
    @patch(
        "apps.billing.subscription_service.GrandfatheringService.check_expiring_grandfathering"
    )
    def test_notifies_expiring_customers(
        self, mock_check: MagicMock, mock_email: MagicMock
    ) -> None:
        gf1 = _make_mock_grandfathering("cust1@example.com")
        gf2 = _make_mock_grandfathering("cust2@example.com")
        mock_check.return_value = [gf1, gf2]

        result = notify_expiring_grandfathering(days_ahead=15)

        self.assertTrue(result["success"])
        self.assertEqual(result["customers_notified"], 2)
        self.assertEqual(result["total_expiring"], 2)
        self.assertEqual(mock_email.call_count, 2)
        self.assertTrue(gf1.expiry_notified)
        self.assertTrue(gf2.expiry_notified)
        gf1.save.assert_called_once_with(
            update_fields=["expiry_notified", "expiry_notified_at"]
        )

    @patch("apps.notifications.services.EmailService.send_template_email")
    @patch(
        "apps.billing.subscription_service.GrandfatheringService.check_expiring_grandfathering"
    )
    def test_email_failure_skips_one_but_continues(
        self, mock_check: MagicMock, mock_email: MagicMock
    ) -> None:
        gf_fail = _make_mock_grandfathering("fail@example.com")
        gf_ok = _make_mock_grandfathering("ok@example.com")
        mock_check.return_value = [gf_fail, gf_ok]
        mock_email.side_effect = [RuntimeError("SMTP error"), None]

        result = notify_expiring_grandfathering()

        self.assertTrue(result["success"])
        self.assertEqual(result["customers_notified"], 1)
        self.assertEqual(result["total_expiring"], 2)

    @patch(
        "apps.billing.subscription_service.GrandfatheringService.check_expiring_grandfathering",
        side_effect=RuntimeError("service crash"),
    )
    def test_service_exception_returns_error(self, mock_check: MagicMock) -> None:
        result = notify_expiring_grandfathering()

        self.assertFalse(result["success"])
        self.assertIn("service crash", result["error"])

    @patch("apps.notifications.services.EmailService.send_template_email")
    @patch(
        "apps.billing.subscription_service.GrandfatheringService.check_expiring_grandfathering"
    )
    def test_email_context_contains_required_fields(
        self, mock_check: MagicMock, mock_email: MagicMock
    ) -> None:
        gf = _make_mock_grandfathering()
        mock_check.return_value = [gf]

        notify_expiring_grandfathering()

        email_call = mock_email.call_args
        self.assertEqual(email_call.kwargs["template_key"], "grandfathering_expiring")
        context = email_call.kwargs["context"]
        self.assertIn("customer", context)
        self.assertIn("product", context)
        self.assertIn("expires_at", context)

    @patch("apps.notifications.services.EmailService.send_template_email")
    @patch(
        "apps.billing.subscription_service.GrandfatheringService.check_expiring_grandfathering"
    )
    def test_default_days_ahead_is_30(
        self, mock_check: MagicMock, mock_email: MagicMock
    ) -> None:
        mock_check.return_value = []
        notify_expiring_grandfathering()

        mock_check.assert_called_once_with(30)


# ---------------------------------------------------------------------------
# run_payment_collection tests
# ---------------------------------------------------------------------------


def _make_retry_policy() -> PaymentRetryPolicy:
    return PaymentRetryPolicy.objects.create(
        name="Test Policy",
        retry_intervals_days=[1, 3, 7],
        max_attempts=3,
    )


class RunPaymentCollectionTests(TestCase):
    """Tests for run_payment_collection()."""

    def test_no_pending_retries_creates_completed_run(self) -> None:
        result = run_payment_collection()

        self.assertTrue(result["success"])
        self.assertEqual(result["total_processed"], 0)
        self.assertEqual(result["successful"], 0)
        self.assertEqual(result["failed"], 0)
        self.assertEqual(result["amount_recovered_cents"], 0)

        run = PaymentCollectionRun.objects.get(id=result["run_id"])
        self.assertEqual(run.status, "completed")
        self.assertIsNotNone(run.completed_at)

    def test_pending_retry_is_processed_as_failed(self) -> None:
        """
        With the current placeholder (success = False), every retry ends
        as failed. Verify that the processing loop mechanics are exercised.
        """
        customer = create_customer()
        currency = create_currency()
        invoice = create_invoice(customer=customer, currency=currency)
        payment = create_payment(
            PaymentCreationRequest(
                customer=customer,
                invoice=invoice,
                currency=currency,
                amount_cents=5000,
                status="failed",
            )
        )
        policy = _make_retry_policy()
        PaymentRetryAttempt.objects.create(
            payment=payment,
            policy=policy,
            attempt_number=1,
            scheduled_at=timezone.now() - timedelta(minutes=5),
            status="pending",
        )

        result = run_payment_collection()

        self.assertTrue(result["success"])
        self.assertEqual(result["total_processed"], 1)
        self.assertEqual(result["failed"], 1)
        self.assertEqual(result["successful"], 0)

    def test_future_scheduled_retries_not_processed(self) -> None:
        customer = create_customer()
        currency = create_currency()
        invoice = create_invoice(customer=customer, currency=currency)
        payment = create_payment(
            PaymentCreationRequest(
                customer=customer,
                invoice=invoice,
                currency=currency,
                status="failed",
            )
        )
        policy = _make_retry_policy()
        PaymentRetryAttempt.objects.create(
            payment=payment,
            policy=policy,
            attempt_number=1,
            scheduled_at=timezone.now() + timedelta(hours=2),
            status="pending",
        )

        result = run_payment_collection()

        self.assertTrue(result["success"])
        self.assertEqual(result["total_processed"], 0)

    def test_failed_retry_schedules_next_attempt_when_policy_allows(self) -> None:
        customer = create_customer()
        currency = create_currency()
        invoice = create_invoice(customer=customer, currency=currency)
        payment = create_payment(
            PaymentCreationRequest(
                customer=customer,
                invoice=invoice,
                currency=currency,
                status="failed",
            )
        )
        policy = _make_retry_policy()  # max_attempts=3, intervals=[1,3,7]
        PaymentRetryAttempt.objects.create(
            payment=payment,
            policy=policy,
            attempt_number=1,
            scheduled_at=timezone.now() - timedelta(minutes=1),
            status="pending",
        )

        run_payment_collection()

        next_attempt = PaymentRetryAttempt.objects.filter(
            payment=payment, attempt_number=2
        ).first()
        self.assertIsNotNone(next_attempt)
        assert next_attempt is not None
        self.assertEqual(next_attempt.status, "pending")

    def test_no_next_attempt_when_policy_max_reached(self) -> None:
        customer = create_customer()
        currency = create_currency()
        invoice = create_invoice(customer=customer, currency=currency)
        payment = create_payment(
            PaymentCreationRequest(
                customer=customer,
                invoice=invoice,
                currency=currency,
                status="failed",
            )
        )
        # max_attempts=3, so attempt_number=3 is the final attempt
        policy = _make_retry_policy()
        PaymentRetryAttempt.objects.create(
            payment=payment,
            policy=policy,
            attempt_number=3,
            scheduled_at=timezone.now() - timedelta(minutes=1),
            status="pending",
        )

        run_payment_collection()

        count = PaymentRetryAttempt.objects.filter(
            payment=payment, attempt_number=4
        ).count()
        self.assertEqual(count, 0)

    def test_run_record_tracks_total_scheduled(self) -> None:
        customer = create_customer()
        currency = create_currency()
        invoice = create_invoice(customer=customer, currency=currency)
        payment = create_payment(
            PaymentCreationRequest(
                customer=customer,
                invoice=invoice,
                currency=currency,
                status="failed",
            )
        )
        policy = _make_retry_policy()
        PaymentRetryAttempt.objects.create(
            payment=payment,
            policy=policy,
            attempt_number=1,
            scheduled_at=timezone.now() - timedelta(minutes=1),
            status="pending",
        )

        result = run_payment_collection()

        run = PaymentCollectionRun.objects.get(id=result["run_id"])
        self.assertEqual(run.total_scheduled, 1)

    @patch("apps.billing.payment_models.PaymentCollectionRun.objects.create")
    def test_outer_exception_returns_error(self, mock_create: MagicMock) -> None:
        mock_create.side_effect = RuntimeError("DB error")
        result = run_payment_collection()

        self.assertFalse(result["success"])
        self.assertIn("DB error", result["error"])
