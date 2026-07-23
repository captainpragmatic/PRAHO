"""
Comprehensive tests for apps/billing/tasks.py.

Covers all core task functions, async wrappers, and recurring billing tasks
to achieve 90%+ coverage of the tasks module.

The suite pins the single PRAHO-owned renewal orchestrator plus reminder,
dunning, retry, and non-renewal lifecycle task boundaries.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any, cast
from unittest.mock import MagicMock, patch

from django.test import TestCase, override_settings
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
    _schedule_next_retry,
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
    reverify_expired_vat_validations,
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
from tests.helpers.fsm_helpers import force_status

from ._billing_service_task_cases import (
    ApiRefundViewTests,
    CreditNoteSignalTests,
    EFacturaServiceTests,
    GenerateEFacturaViewTests,
    InvoiceNumberingServiceTests,
    InvoiceRefundViewTests,
    PaymentCollectionRetryTests,
    PaymentRetryServiceTests,
    ProformaConversionServiceTests,
    ProformaModelConvertTests,
    SendPaymentReminderHelperTests,
    SubmitEfacturaTaskTests,
    UsageAlertEmailTests,
)

# Keep imported case modules visible to unittest discovery without tripping F401.
_IMPORTED_TASK_CASES = (
    ApiRefundViewTests,
    CreditNoteSignalTests,
    EFacturaServiceTests,
    GenerateEFacturaViewTests,
    InvoiceNumberingServiceTests,
    InvoiceRefundViewTests,
    PaymentCollectionRetryTests,
    PaymentRetryServiceTests,
    ProformaConversionServiceTests,
    ProformaModelConvertTests,
    SendPaymentReminderHelperTests,
    SubmitEfacturaTaskTests,
    UsageAlertEmailTests,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_invoice(status: str = "issued", due_days: int = -5) -> Invoice:
    """Create an invoice with a given status and due_at set relative to now."""
    customer = create_customer()
    currency = create_currency()
    invoice = create_invoice(customer=customer, currency=currency)
    force_status(invoice, status, save=False)
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

        mock_get.assert_called_once_with("billing.task_retry_delay_seconds", _DEFAULT_TASK_RETRY_DELAY)
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

        mock_get.assert_called_once_with("billing.task_max_retries", _DEFAULT_TASK_MAX_RETRIES)
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

    @patch("apps.billing.efactura.service.EFacturaService")
    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_success(self, mock_audit: MagicMock, mock_service: MagicMock) -> None:
        invoice = _make_invoice(status="issued")
        document = MagicMock(status="submitted")
        mock_service.return_value.submit_invoice.return_value = MagicMock(
            success=True,
            error_message="",
            document=document,
            document_status="submitted",
            registered_with_anaf=True,
        )
        result = submit_efactura(str(invoice.id))

        self.assertTrue(result["success"])
        self.assertEqual(result["invoice_id"], str(invoice.id))
        self.assertEqual(result["invoice_number"], invoice.number)
        self.assertIn("e-Factura", result["message"])
        # The last audit call must be the task event (signals may fire earlier).
        last_call = _last_audit_call_kwargs(mock_audit)
        self.assertEqual(last_call["event_type"], "efactura_submission_attempted")

        invoice.refresh_from_db()
        self.assertTrue(invoice.meta["efactura_submitted"])

    @patch("apps.billing.efactura.service.EFacturaService")
    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_active_upload_claim_does_not_mark_invoice_as_submitted(
        self,
        mock_audit: MagicMock,
        mock_service: MagicMock,
    ) -> None:
        invoice = _make_invoice(status="issued")
        document = MagicMock(status="uploading")
        mock_service.return_value.submit_invoice.return_value = MagicMock(
            success=True,
            error_message="",
            document=document,
            document_status="uploading",
            registered_with_anaf=False,
        )

        result = submit_efactura(str(invoice.id))

        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "uploading")
        invoice.refresh_from_db()
        self.assertNotIn("efactura_submitted", invoice.meta)

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
    """Tests for schedule_payment_reminders()."""

    @patch("apps.billing.tasks.async_task")
    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_issued_invoice_schedules_three_future_reminders(
        self,
        mock_audit: MagicMock,
        mock_async: MagicMock,
    ) -> None:
        invoice = _make_invoice(status="issued", due_days=14)
        result = schedule_payment_reminders(str(invoice.id))

        self.assertTrue(result["success"], result)
        self.assertEqual(mock_async.call_count, 3)
        last_call = _last_audit_call_kwargs(mock_audit)
        self.assertEqual(last_call["metadata"]["due_at"], invoice.due_at.isoformat())

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_skips_non_pending_invoice(self, mock_audit: MagicMock) -> None:
        invoice = _make_invoice(status="paid")
        result = schedule_payment_reminders(str(invoice.id))

        self.assertTrue(result["success"])
        self.assertIn("non-pending", result["message"])

    def test_invoice_not_found_returns_error(self) -> None:
        result = schedule_payment_reminders(str(uuid.uuid4()))

        self.assertFalse(result["success"])

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_non_pending_invoice_does_not_emit_reminders_scheduled_event(self, mock_audit: MagicMock) -> None:
        invoice = _make_invoice(status="void")
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
    """Tests for start_dunning_process()."""

    @patch("apps.notifications.services.EmailService.send_payment_reminder")
    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_overdue_invoice_starts_email_dunning_with_due_at(
        self,
        mock_audit: MagicMock,
        mock_email: MagicMock,
    ) -> None:
        invoice = _make_invoice(status="overdue", due_days=-10)
        result = start_dunning_process(str(invoice.id))

        self.assertTrue(result["success"], result)
        mock_email.assert_called_once_with(invoice)
        last_call = _last_audit_call_kwargs(mock_audit)
        self.assertEqual(last_call["metadata"]["days_overdue"], 10)

    @patch("apps.notifications.services.EmailService.send_payment_reminder")
    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_issued_overdue_invoice_starts_dunning(
        self,
        mock_audit: MagicMock,
        _mock_email: MagicMock,
    ) -> None:
        invoice = _make_invoice(status="issued", due_days=-1)
        result = start_dunning_process(str(invoice.id))

        self.assertTrue(result["success"], result)

    @patch("apps.notifications.services.EmailService.send_payment_reminder")
    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_active_policy_can_disable_dunning_email(
        self,
        _mock_audit: MagicMock,
        mock_email: MagicMock,
    ) -> None:
        PaymentRetryPolicy.objects.create(
            name="No dunning email",
            retry_intervals_days=[1],
            max_attempts=1,
            send_dunning_emails=False,
            is_default=True,
            is_active=True,
        )
        invoice = _make_invoice(status="overdue", due_days=-1)

        result = start_dunning_process(str(invoice.id))

        self.assertTrue(result["success"], result)
        mock_email.assert_not_called()

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_skips_paid_invoice(self, mock_audit: MagicMock) -> None:
        invoice = _make_invoice(status="paid")
        result = start_dunning_process(str(invoice.id))

        self.assertTrue(result["success"])
        self.assertIn("non-overdue", result["message"])

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_void_invoice_skipped(self, mock_audit: MagicMock) -> None:
        invoice = _make_invoice(status="void")
        result = start_dunning_process(str(invoice.id))

        self.assertTrue(result["success"])
        self.assertIn("non-overdue", result["message"])

    def test_invoice_not_found_returns_error(self) -> None:
        result = start_dunning_process(str(uuid.uuid4()))

        self.assertFalse(result["success"])

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_non_overdue_status_does_not_emit_dunning_event(self, mock_audit: MagicMock) -> None:
        # 'draft' is not in ["issued", "overdue"] so the early return fires
        invoice = _make_invoice(status="draft")
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

    @patch("apps.billing.gateways.vies_gateway.VIESGateway.check_vat")
    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_success_with_vat_number(self, mock_audit: MagicMock, mock_vies: MagicMock) -> None:
        from apps.billing.gateways.vies_gateway import VIESResponse  # noqa: PLC0415

        mock_vies.return_value = VIESResponse(
            is_valid=True,
            country_code="RO",
            vat_number="1234567",
            company_name="Test SRL",
            api_available=True,
        )
        profile = self._make_tax_profile(vat_number="RO1234567")
        result = validate_vat_number(str(profile.id))

        self.assertTrue(result["success"])
        self.assertEqual(result["vat_number"], "RO1234567")
        self.assertIn("completed", result["message"])
        last_call = _last_audit_call_kwargs(mock_audit)
        self.assertEqual(last_call["event_type"], "vat_validation_completed")

    def test_no_vat_number_returns_success_with_skip_message(self) -> None:
        profile = self._make_tax_profile(vat_number="")
        result = validate_vat_number(str(profile.id))

        self.assertTrue(result["success"])
        self.assertIn("No VAT number", result["message"])

    def test_not_found_returns_error(self) -> None:
        result = validate_vat_number(str(uuid.uuid4()))

        self.assertFalse(result["success"])

    @patch("apps.billing.gateways.vies_gateway.VIESGateway.check_vat")
    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_audit_failure_does_not_poison_result(self, mock_audit: MagicMock, mock_vies: MagicMock) -> None:
        """Audit log failure must not affect the validation result (H1 fix).

        The validation was already persisted inside transaction.atomic(); an audit
        log write failure afterwards must not cause the task to report failure.
        """
        from apps.billing.gateways.vies_gateway import VIESResponse  # noqa: PLC0415

        mock_vies.return_value = VIESResponse(
            is_valid=True,
            country_code="RO",
            vat_number="1234567",
            api_available=True,
        )

        def _raise_on_vat(*args: object, **kwargs: object) -> None:
            if kwargs.get("event_type") == "vat_validation_completed":
                raise RuntimeError("network failure")

        mock_audit.side_effect = _raise_on_vat
        profile = self._make_tax_profile(vat_number="RO1234567")
        result = validate_vat_number(str(profile.id))

        # Validation succeeded; audit failure is swallowed and logged but not propagated
        self.assertTrue(result["success"])
        self.assertNotIn("error", result)

    @override_settings(COMPANY_CUI="RO87654321")
    @patch("apps.billing.gateways.vies_gateway.VIESGateway.check_vat")
    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_revalidation_refreshes_timestamp_and_consultation_reference(
        self,
        _mock_audit: MagicMock,
        mock_vies: MagicMock,
    ) -> None:
        from apps.billing.gateways.vies_gateway import VIESResponse  # noqa: PLC0415
        from apps.billing.tax_models import VATValidation  # noqa: PLC0415

        profile = self._make_tax_profile(vat_number="RO1234567")
        validation = VATValidation.objects.create(
            country_code="RO",
            vat_number="1234567",
            full_vat_number="RO1234567",
            is_valid=True,
            is_active=True,
            validation_source="vies",
            expires_at=timezone.now() - timedelta(hours=1),
        )
        old_validation_date = timezone.now() - timedelta(days=30)
        VATValidation.objects.filter(pk=validation.pk).update(validation_date=old_validation_date)
        mock_vies.return_value = VIESResponse(
            is_valid=True,
            country_code="RO",
            vat_number="1234567",
            company_name="Test SRL",
            request_identifier="WAPIAAABy123456789",
            api_available=True,
        )

        result = validate_vat_number(str(profile.id))

        self.assertTrue(result["success"])
        mock_vies.assert_called_once_with(
            "RO",
            "1234567",
            requester_member_state_code="RO",
            requester_number="87654321",
        )
        validation.refresh_from_db()
        self.assertGreater(validation.validation_date, old_validation_date)
        self.assertEqual(validation.consultation_reference, "WAPIAAABy123456789")


class ReverifyExpiredVatValidationsTests(TestCase):
    """Expired VIES evidence must be fully drained rather than silently capped."""

    @patch("apps.billing.tasks.async_task")
    def test_reverification_matches_formatted_profile_vat_number(self, mock_async: MagicMock) -> None:
        from apps.billing.tax_models import VATValidation  # noqa: PLC0415
        from apps.customers.models import CustomerTaxProfile  # noqa: PLC0415

        customer = create_customer(company_name="Formatted VIES Test")
        profile = CustomerTaxProfile.objects.create(
            customer=customer,
            vat_number="de 123-456.789",
            vies_verification_status="valid",
        )
        VATValidation.objects.create(
            country_code="DE",
            vat_number="123456789",
            full_vat_number="DE123456789",
            is_valid=True,
            is_active=True,
            validation_source="vies",
            expires_at=timezone.now() - timedelta(hours=1),
        )

        result = reverify_expired_vat_validations()

        self.assertEqual(result, {"success": True, "queued": 1, "expired_found": 1, "unmatched": 0})
        mock_async.assert_called_once_with("apps.billing.tasks.validate_vat_number", str(profile.id))

    @patch("apps.billing.tasks.async_task")
    def test_failed_format_evidence_never_reenters_the_sweep(self, mock_async: MagicMock) -> None:
        """A structurally invalid number is terminal evidence: re-verifying it cannot
        improve it, and it must not inflate the sweep's unmatched report every day."""
        from apps.billing.tax_models import VATValidation  # noqa: PLC0415
        from apps.customers.models import CustomerTaxProfile  # noqa: PLC0415

        customer = create_customer(company_name="Bad Format SRL")
        profile = CustomerTaxProfile.objects.create(
            customer=customer,
            vat_number="DE12",
            vies_verification_status="pending",
        )

        result = validate_vat_number(str(profile.id))

        self.assertTrue(result["success"])
        self.assertFalse(result["is_valid"])
        validation = VATValidation.objects.get(country_code="DE", vat_number="12")
        self.assertIsNone(validation.expires_at, "failed-format evidence must not expire into the sweep")

        sweep = reverify_expired_vat_validations()

        self.assertEqual(sweep, {"success": True, "queued": 0, "expired_found": 0, "unmatched": 0})
        mock_async.assert_not_called()

    @patch("apps.billing.tasks.async_task")
    def test_reverification_queues_more_than_one_hundred_profiles(self, mock_async: MagicMock) -> None:
        from apps.billing.tax_models import VATValidation  # noqa: PLC0415
        from apps.customers.models import CustomerTaxProfile  # noqa: PLC0415

        expired_at = timezone.now() - timedelta(hours=1)
        for index in range(101):
            vat_number = f"DE{index:09d}"
            customer = create_customer(company_name=f"VIES Test {index}")
            CustomerTaxProfile.objects.create(
                customer=customer,
                vat_number=vat_number,
                vies_verification_status="valid",
            )
            VATValidation.objects.create(
                country_code="DE",
                vat_number=f"{index:09d}",
                full_vat_number=vat_number,
                is_valid=True,
                is_active=True,
                validation_source="vies",
                expires_at=expired_at,
            )

        result = reverify_expired_vat_validations()

        self.assertEqual(result["expired_found"], 101)
        self.assertEqual(result["queued"], 101)
        self.assertEqual(mock_async.call_count, 101)


# ---------------------------------------------------------------------------
# process_auto_payment tests
# ---------------------------------------------------------------------------


class ProcessAutoPaymentTests(TestCase):
    """Tests for process_auto_payment()."""

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_rejects_issued_invoice_without_recurring_authority(self, mock_audit: MagicMock) -> None:
        invoice = _make_invoice(status="issued")
        mock_audit.reset_mock()
        result = process_auto_payment(str(invoice.id))

        self.assertFalse(result["success"])
        self.assertIn("authorized recurring payment method", result["error"])
        mock_audit.assert_not_called()

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

    @patch("apps.billing.tasks.Invoice.objects.get", side_effect=RuntimeError("payment gateway down"))
    def test_generic_exception_returns_error(self, _mock_get: MagicMock) -> None:
        result = process_auto_payment(str(uuid.uuid4()))

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
        mock_async.assert_called_once_with("apps.billing.tasks.submit_efactura", "inv-123", timeout=TASK_TIME_LIMIT)

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
        mock_async.assert_called_once_with("apps.billing.tasks.validate_vat_number", "tp-111", timeout=TASK_TIME_LIMIT)

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
        mock_async.assert_called_once_with("apps.billing.tasks.run_daily_billing", timeout=TASK_TIME_LIMIT * 2)

    @patch("apps.billing.tasks.async_task", return_value="task-id-8")
    def test_process_expired_trials_async(self, mock_async: MagicMock) -> None:
        result = process_expired_trials_async()

        self.assertEqual(result, "task-id-8")
        mock_async.assert_called_once_with("apps.billing.tasks.process_expired_trials", timeout=TASK_TIME_LIMIT)

    @patch("apps.billing.tasks.async_task", return_value="task-id-9")
    def test_process_grace_period_expirations_async(self, mock_async: MagicMock) -> None:
        result = process_grace_period_expirations_async()

        self.assertEqual(result, "task-id-9")
        mock_async.assert_called_once_with(
            "apps.billing.tasks.process_grace_period_expirations", timeout=TASK_TIME_LIMIT
        )

    @patch("apps.billing.tasks.async_task", return_value="task-id-10")
    def test_notify_expiring_grandfathering_async_default_days(self, mock_async: MagicMock) -> None:
        result = notify_expiring_grandfathering_async()

        self.assertEqual(result, "task-id-10")
        mock_async.assert_called_once_with(
            "apps.billing.tasks.notify_expiring_grandfathering",
            30,
            timeout=TASK_TIME_LIMIT,
        )

    @patch("apps.billing.tasks.async_task", return_value="task-id-11")
    def test_notify_expiring_grandfathering_async_custom_days(self, mock_async: MagicMock) -> None:
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
        mock_async.assert_called_once_with("apps.billing.tasks.run_payment_collection", timeout=TASK_TIME_LIMIT * 2)


# ---------------------------------------------------------------------------
# run_daily_billing tests
# ---------------------------------------------------------------------------

_PREPARATION_RESULT: dict[str, object] = {
    "subscriptions_checked": 5,
    "cycles_prepared": 3,
    "proformas_created": 3,
    "errors": [],
}
_COLLECTION_RESULT: dict[str, object] = {
    "proformas_checked": 3,
    "payments_created": 2,
    "payments_failed": 1,
    "errors": [],
}


class RunDailyBillingTests(TestCase):
    """Tests for run_daily_billing()."""

    @patch("apps.audit.services.AuditService.log_simple_event")
    @patch(
        "apps.billing.recurring_billing.RecurringBillingOrchestrator.mark_overdue_renewals",
        return_value=4,
    )
    @patch("apps.billing.recurring_billing.RecurringBillingOrchestrator.collect_due_proformas")
    @patch("apps.billing.recurring_billing.RecurringBillingOrchestrator.prepare_due_proformas")
    @patch(
        "apps.billing.subscription_service.SubscriptionLifecycleService.finalize_period_end_cancellations",
        return_value=2,
    )
    def test_success(
        self,
        mock_finalize: MagicMock,
        mock_prepare: MagicMock,
        mock_collect: MagicMock,
        mock_mark_overdue: MagicMock,
        mock_audit: MagicMock,
    ) -> None:
        mock_prepare.return_value = _PREPARATION_RESULT
        mock_collect.return_value = _COLLECTION_RESULT
        result = run_daily_billing()

        self.assertTrue(result["success"])
        self.assertEqual(result["result"]["preparation"], _PREPARATION_RESULT)
        self.assertEqual(result["result"]["collection"], _COLLECTION_RESULT)
        self.assertEqual(result["result"]["cancellations_finalized"], 2)
        self.assertEqual(result["result"]["renewals_marked_overdue"], 4)
        self.assertIn("3 proformas", result["message"])
        mock_finalize.assert_called_once_with()
        mock_prepare.assert_called_once_with()
        mock_collect.assert_called_once_with()
        mock_mark_overdue.assert_called_once_with()
        last_call = _last_audit_call_kwargs(mock_audit)
        self.assertEqual(last_call["event_type"], "daily_billing_completed")

    @patch(
        "apps.billing.recurring_billing.RecurringBillingOrchestrator.prepare_due_proformas",
        side_effect=RuntimeError("DB connection lost"),
    )
    def test_exception_returns_error(self, mock_prepare: MagicMock) -> None:
        result = run_daily_billing()

        self.assertFalse(result["success"])
        self.assertIn("DB connection lost", result["error"])

    @patch("apps.audit.services.AuditService.log_simple_event")
    @patch(
        "apps.billing.recurring_billing.RecurringBillingOrchestrator.mark_overdue_renewals",
        return_value=0,
    )
    @patch("apps.billing.recurring_billing.RecurringBillingOrchestrator.collect_due_proformas")
    @patch("apps.billing.recurring_billing.RecurringBillingOrchestrator.prepare_due_proformas")
    def test_errors_truncated_to_10_in_metadata(
        self,
        mock_prepare: MagicMock,
        mock_collect: MagicMock,
        _mock_mark_overdue: MagicMock,
        mock_audit: MagicMock,
    ) -> None:
        mock_prepare.return_value = {**_PREPARATION_RESULT, "errors": ["err"] * 20}
        mock_collect.return_value = _COLLECTION_RESULT
        result = run_daily_billing()

        self.assertFalse(result["success"])
        last_call = _last_audit_call_kwargs(mock_audit)
        self.assertLessEqual(len(last_call["metadata"]["errors"]), 10)


# ---------------------------------------------------------------------------
# process_expired_trials tests
# ---------------------------------------------------------------------------


class ProcessExpiredTrialsTests(TestCase):
    """Tests for process_expired_trials()."""

    @patch("apps.audit.services.AuditService.log_simple_event")
    @patch(
        "apps.billing.subscription_service.SubscriptionLifecycleService.handle_expired_trials",
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
        "apps.billing.subscription_service.SubscriptionLifecycleService.handle_expired_trials",
        side_effect=Exception("service unavailable"),
    )
    def test_exception_returns_error(self, mock_handle: MagicMock) -> None:
        result = process_expired_trials()

        self.assertFalse(result["success"])
        self.assertIn("service unavailable", result["error"])

    @patch("apps.audit.services.AuditService.log_simple_event")
    @patch(
        "apps.billing.subscription_service.SubscriptionLifecycleService.handle_expired_trials",
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
        "apps.billing.subscription_service.SubscriptionLifecycleService.handle_grace_period_expirations",
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
        "apps.billing.subscription_service.SubscriptionLifecycleService.handle_grace_period_expirations",
        side_effect=Exception("timeout"),
    )
    def test_exception_returns_error(self, mock_handle: MagicMock) -> None:
        result = process_grace_period_expirations()

        self.assertFalse(result["success"])
        self.assertIn("timeout", result["error"])

    @patch("apps.audit.services.AuditService.log_simple_event")
    @patch(
        "apps.billing.subscription_service.SubscriptionLifecycleService.handle_grace_period_expirations",
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
    def test_no_expiring_returns_zero(self, mock_check: MagicMock, mock_email: MagicMock) -> None:
        result = notify_expiring_grandfathering()

        self.assertTrue(result["success"])
        self.assertEqual(result["customers_notified"], 0)
        self.assertEqual(result["total_expiring"], 0)
        mock_email.assert_not_called()

    @patch("apps.notifications.services.EmailService.send_template_email")
    @patch("apps.billing.subscription_service.GrandfatheringService.check_expiring_grandfathering")
    def test_notifies_expiring_customers(self, mock_check: MagicMock, mock_email: MagicMock) -> None:
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
        gf1.save.assert_called_once_with(update_fields=["expiry_notified", "expiry_notified_at"])

    @patch("apps.notifications.services.EmailService.send_template_email")
    @patch("apps.billing.subscription_service.GrandfatheringService.check_expiring_grandfathering")
    def test_email_failure_skips_one_but_continues(self, mock_check: MagicMock, mock_email: MagicMock) -> None:
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
    @patch("apps.billing.subscription_service.GrandfatheringService.check_expiring_grandfathering")
    def test_email_context_contains_required_fields(self, mock_check: MagicMock, mock_email: MagicMock) -> None:
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
    @patch("apps.billing.subscription_service.GrandfatheringService.check_expiring_grandfathering")
    def test_default_days_ahead_is_30(self, mock_check: MagicMock, mock_email: MagicMock) -> None:
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

    def test_next_retry_stays_anchored_to_the_original_failure(self) -> None:
        """Absolute schedule [1,3,7] means day 3, not three days after attempt one."""
        original_failure = timezone.now() - timedelta(days=1)
        scheduled_at = original_failure + timedelta(days=3)
        policy = MagicMock(max_attempts=3)
        policy.get_next_retry_date.return_value = scheduled_at
        retry = MagicMock(
            policy=policy,
            attempt_number=1,
            payment=MagicMock(created_at=original_failure),
        )
        retry_model = MagicMock()

        _schedule_next_retry(retry, retry_model)

        policy.get_next_retry_date.assert_called_once_with(original_failure, 1)
        retry_model.objects.get_or_create.assert_called_once()
        self.assertEqual(retry_model.objects.get_or_create.call_args.kwargs["defaults"]["scheduled_at"], scheduled_at)

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

    def test_lifecycle_audit_events_emitted(self) -> None:
        """W9: a run emits collection_run_started and collection_run_completed."""
        from apps.audit.models import AuditEvent  # noqa: PLC0415

        result = run_payment_collection()

        run_id = result["run_id"]
        actions = list(
            AuditEvent.objects.filter(object_id=run_id).order_by("timestamp").values_list("action", flat=True)
        )
        self.assertEqual(actions, ["collection_run_started", "collection_run_completed"])

    def test_crashed_run_is_marked_failed_not_stuck_running(self) -> None:
        """W9: pre-fix, a crash left the run in status='running' forever."""
        from unittest.mock import patch  # noqa: PLC0415

        from apps.audit.models import AuditEvent  # noqa: PLC0415

        with patch("apps.billing.tasks._reclaim_stale_payment_retries", side_effect=RuntimeError("db exploded")):
            result = run_payment_collection()

        self.assertFalse(result["success"])
        run = PaymentCollectionRun.objects.get()
        self.assertEqual(run.status, "failed")
        self.assertIsNotNone(run.completed_at)
        self.assertIn("db exploded", run.error_message)
        self.assertTrue(AuditEvent.objects.filter(object_id=str(run.id), action="collection_run_failed").exists())

    def test_audit_failure_does_not_mask_collection_result(self) -> None:
        """An audit outage must not turn a successful collection run into a failure."""
        from unittest.mock import patch  # noqa: PLC0415

        with patch("apps.billing.tasks.AuditService.log_simple_event", side_effect=RuntimeError("audit down")):
            result = run_payment_collection()

        self.assertTrue(result["success"])
        run = PaymentCollectionRun.objects.get(id=result["run_id"])
        self.assertEqual(run.status, "completed")

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

        next_attempt = PaymentRetryAttempt.objects.filter(payment=payment, attempt_number=2).first()
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

        count = PaymentRetryAttempt.objects.filter(payment=payment, attempt_number=4).count()
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

    @patch("apps.billing.tasks._execute_payment_retry")
    @patch("apps.billing.tasks._claim_payment_retry", return_value=False)
    def test_retry_lost_to_another_worker_is_not_charged_twice(
        self,
        _mock_claim: MagicMock,
        mock_execute: MagicMock,
    ) -> None:
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
        PaymentRetryAttempt.objects.create(
            payment=payment,
            policy=_make_retry_policy(),
            attempt_number=1,
            scheduled_at=timezone.now() - timedelta(minutes=1),
            status="pending",
        )

        result = run_payment_collection()

        self.assertTrue(result["success"])
        self.assertEqual(result["total_processed"], 0)
        mock_execute.assert_not_called()

    @patch("apps.billing.payment_service.PaymentService.confirm_payment")
    def test_collection_does_not_count_success_when_fsm_transition_fails(self, mock_confirm_payment: MagicMock) -> None:
        """A failed payment cannot transition to succeeded, so run metrics must not report a recovery."""
        mock_confirm_payment.return_value = {"success": True, "status": "succeeded"}

        customer = create_customer()
        currency = create_currency()
        invoice = create_invoice(customer=customer, currency=currency)
        payment = create_payment(
            PaymentCreationRequest(
                customer=customer,
                invoice=invoice,
                currency=currency,
                amount_cents=5000,
                status="pending",
            )
        )
        force_status(payment, "failed")
        payment.gateway_txn_id = "pi_test_retry_failed"
        payment.save(update_fields=["gateway_txn_id"])

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
        self.assertEqual(run.total_successful, 0)
        self.assertEqual(result["successful"], 0)

        payment.refresh_from_db()
        self.assertEqual(payment.status, "failed")

    @patch("apps.billing.payment_service.PaymentService.confirm_payment")
    def test_collection_does_not_reconfirm_original_pending_payment(self, mock_confirm_payment: MagicMock) -> None:
        """A retry without an authorized subscription method must fail closed."""
        mock_confirm_payment.return_value = {"success": True, "status": "succeeded"}

        customer = create_customer()
        currency = create_currency()
        invoice = create_invoice(customer=customer, currency=currency)
        payment = create_payment(
            PaymentCreationRequest(
                customer=customer,
                invoice=invoice,
                currency=currency,
                amount_cents=5000,
                status="pending",
            )
        )
        payment.gateway_txn_id = "pi_test_retry_pending"
        payment.save(update_fields=["gateway_txn_id"])

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
        self.assertEqual(run.total_successful, 0)
        self.assertEqual(result["successful"], 0)
        self.assertEqual(result["failed"], 1)
        mock_confirm_payment.assert_not_called()

        payment.refresh_from_db()
        self.assertEqual(payment.status, "pending")

    @patch("apps.billing.payment_models.PaymentCollectionRun.objects.create")
    def test_outer_exception_returns_error(self, mock_create: MagicMock) -> None:
        mock_create.side_effect = RuntimeError("DB error")
        result = run_payment_collection()

        self.assertFalse(result["success"])
        self.assertIn("DB error", result["error"])
