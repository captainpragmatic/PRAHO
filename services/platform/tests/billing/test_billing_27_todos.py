"""
Tests for 27 billing TODO fixes.

All lazy imports (inside functions) are patched at their SOURCE module,
not at the consuming module.
"""

from __future__ import annotations

import json
import uuid
from datetime import timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch

from django.test import RequestFactory, TestCase
from django.utils import timezone

from apps.billing.metering_service import UsageAlertService
from apps.billing.models import Invoice, InvoiceSequence, Payment, ProformaInvoice
from apps.billing.payment_service import PaymentService
from apps.billing.proforma_models import ProformaInvoice as ProformaInvoiceModel
from apps.billing.services import (
    EFacturaService,
    InvoiceNumberingService,
    PaymentRetryService,
    ProformaConversionService,
)
from apps.billing.signals import _handle_efactura_refund_reporting
from apps.billing.subscription_service import RecurringBillingService
from apps.billing.tasks import (
    _send_payment_reminder,
    cancel_payment_reminders,
    process_auto_payment,
    run_payment_collection,
    schedule_payment_reminders,
    start_dunning_process,
    submit_efactura,
    validate_vat_number,
)
from apps.billing.views import api_process_refund, generate_e_factura, invoice_refund
from apps.users.models import User

# ===============================================================================
# GROUP A: services.py Placeholder Classes
# ===============================================================================


class PaymentRetryServiceTests(TestCase):
    """A1: PaymentRetryService.retry_payment()"""

    @patch("apps.billing.payment_models.PaymentRetryAttempt")
    @patch("apps.billing.payment_models.PaymentRetryPolicy")
    @patch("apps.billing.models.Payment")
    def test_retry_creates_attempt(self, mock_payment_cls, mock_policy_cls, mock_attempt_cls):
        mock_payment = MagicMock(status="failed")
        mock_payment_cls.objects.select_related.return_value.get.return_value = mock_payment

        mock_policy = MagicMock(max_attempts=3)
        mock_policy.get_next_retry_date.return_value = timezone.now() + timedelta(days=1)
        mock_policy_cls.objects.filter.return_value.first.return_value = mock_policy

        mock_attempt_cls.objects.filter.return_value.count.return_value = 0

        result = PaymentRetryService.retry_payment("payment-123")
        self.assertTrue(result.is_ok())
        mock_attempt_cls.objects.create.assert_called_once()

    @patch("apps.billing.models.Payment")
    def test_retry_payment_not_found(self, mock_payment_cls):
        mock_payment_cls.objects.select_related.return_value.get.side_effect = Payment.DoesNotExist
        result = PaymentRetryService.retry_payment("bad-id")
        self.assertTrue(result.is_err())

    @patch("apps.billing.models.Payment")
    def test_retry_already_succeeded(self, mock_payment_cls):
        mock_payment_cls.objects.select_related.return_value.get.return_value = MagicMock(status="succeeded")
        result = PaymentRetryService.retry_payment("payment-123")
        self.assertTrue(result.is_ok())


class EFacturaServiceTests(TestCase):
    """A2: EFacturaService.submit_invoice()"""

    @patch("apps.billing.efactura_service.EFacturaSubmissionService")
    @patch("apps.billing.models.Invoice")
    def test_submit_delegates(self, mock_invoice_cls, mock_service_cls):
        mock_invoice_cls.objects.get.return_value = MagicMock(number="INV-001")
        mock_service_cls.return_value.submit_invoice.return_value = MagicMock(success=True, message="OK")

        result = EFacturaService.submit_invoice("inv-id")
        self.assertTrue(result.is_ok())

    @patch("apps.billing.models.Invoice")
    def test_submit_not_found(self, mock_invoice_cls):
        mock_invoice_cls.objects.get.side_effect = Invoice.DoesNotExist
        result = EFacturaService.submit_invoice("bad-id")
        self.assertTrue(result.is_err())

    @patch("apps.billing.efactura_service.EFacturaSubmissionService")
    @patch("apps.billing.models.Invoice")
    def test_submit_failure(self, mock_invoice_cls, mock_service_cls):
        mock_invoice_cls.objects.get.return_value = MagicMock(number="INV-001")
        mock_service_cls.return_value.submit_invoice.return_value = MagicMock(success=False, message="ANAF error")

        result = EFacturaService.submit_invoice("inv-id")
        self.assertTrue(result.is_err())


class InvoiceNumberingServiceTests(TestCase):
    """A3: InvoiceNumberingService.get_next_number()"""

    def test_get_next_number(self):
        """InvoiceNumberingService uses real InvoiceSequence — test via DB"""
        # Ensure clean state
        InvoiceSequence.objects.all().delete()
        result = InvoiceNumberingService.get_next_number()
        self.assertTrue(result.startswith("INV-"))

    def test_custom_prefix(self):
        InvoiceSequence.objects.all().delete()
        result = InvoiceNumberingService.get_next_number(prefix="PRO")
        self.assertTrue(result.startswith("PRO-"))


class ProformaConversionServiceTests(TestCase):
    """A4: ProformaConversionService.convert_to_invoice()"""

    def test_conversion_invalid_uuid_returns_err(self):
        """Conversion with nonexistent proforma returns error"""
        # Use numeric ID since ProformaInvoice has integer PK
        result = ProformaConversionService.convert_to_invoice("999999")
        self.assertTrue(result.is_err())

    @patch("apps.billing.models.ProformaInvoice")
    def test_conversion_not_found(self, mock_cls):
        mock_cls.objects.select_related.return_value.get.side_effect = ProformaInvoice.DoesNotExist
        self.assertTrue(ProformaConversionService.convert_to_invoice("x").is_err())

    @patch("apps.billing.models.ProformaInvoice")
    def test_conversion_wrong_status(self, mock_cls):
        mock_cls.objects.select_related.return_value.get.return_value = MagicMock(status="converted", number="P-1")
        self.assertTrue(ProformaConversionService.convert_to_invoice("x").is_err())


# ===============================================================================
# GROUP B: tasks.py Background Tasks
# ===============================================================================


class SubmitEfacturaTaskTests(TestCase):
    """B1: submit_efactura()"""

    @patch("apps.audit.services.AuditService.log_simple_event")
    @patch("apps.billing.efactura_service.EFacturaSubmissionService")
    @patch("apps.billing.tasks.Invoice")
    def test_calls_real_service(self, mock_inv_cls, mock_svc_cls, mock_audit):
        mock_inv = MagicMock(id="i1", number="INV-1", meta={})
        mock_inv.customer = MagicMock(id="c1")
        mock_inv_cls.objects.get.return_value = mock_inv
        mock_svc_cls.return_value.submit_invoice.return_value = MagicMock(success=True, message="OK")

        result = submit_efactura("i1")
        self.assertTrue(result["success"])


class SchedulePaymentRemindersTests(TestCase):
    """B2: schedule_payment_reminders()"""

    @patch("apps.billing.tasks.async_task")
    @patch("apps.audit.services.AuditService.log_simple_event")
    @patch("apps.billing.tasks.Invoice")
    def test_schedules_reminders(self, mock_inv_cls, mock_audit, mock_async):
        mock_inv = MagicMock(
            id="i1", number="INV-1", status="pending",
            due_date=timezone.now().date() + timedelta(days=14),
        )
        mock_inv.customer = MagicMock(id="c1")
        mock_inv_cls.objects.get.return_value = mock_inv

        result = schedule_payment_reminders("i1")
        self.assertTrue(result["success"])
        self.assertTrue(mock_async.call_count >= 1)


class CancelPaymentRemindersTests(TestCase):
    """B3: cancel_payment_reminders()"""

    @patch("django_q.models.Schedule")
    @patch("apps.audit.services.AuditService.log_simple_event")
    @patch("apps.billing.tasks.Invoice")
    def test_cancels_tasks(self, mock_inv_cls, mock_audit, mock_schedule):
        mock_inv = MagicMock(id="i1", number="INV-1")
        mock_inv.customer = MagicMock(id="c1")
        mock_inv_cls.objects.get.return_value = mock_inv
        mock_schedule.objects.filter.return_value.delete.return_value = (2,)

        result = cancel_payment_reminders("i1")
        self.assertTrue(result["success"])


class StartDunningProcessTests(TestCase):
    """B4: start_dunning_process()"""

    @patch("apps.billing.payment_models.PaymentRetryAttempt")
    @patch("apps.billing.payment_models.PaymentRetryPolicy")
    @patch("apps.notifications.services.EmailService")
    @patch("apps.audit.services.AuditService.log_simple_event")
    @patch("apps.billing.tasks.Invoice")
    def test_sends_email_and_schedules(self, mock_inv_cls, mock_audit, mock_email, mock_policy_cls, mock_attempt_cls):
        mock_payment = MagicMock(id="p1")
        mock_inv = MagicMock(id="i1", number="INV-1", status="overdue", due_date=timezone.now().date())
        mock_inv.customer = MagicMock(id="c1")
        mock_inv.payments.filter.return_value.order_by.return_value.exists.return_value = True
        mock_inv.payments.filter.return_value.order_by.return_value.first.return_value = mock_payment
        mock_inv_cls.objects.get.return_value = mock_inv

        mock_policy = MagicMock()
        mock_policy.get_next_retry_date.return_value = timezone.now() + timedelta(days=3)
        mock_policy_cls.objects.filter.return_value.first.return_value = mock_policy

        result = start_dunning_process("i1")
        self.assertTrue(result["success"])
        mock_email.send_payment_reminder.assert_called_once()


class ValidateVatNumberTests(TestCase):
    """B5: validate_vat_number()"""

    @patch("apps.billing.tax_models.VATValidation")
    @patch("apps.common.types.validate_romanian_cui")
    @patch("apps.audit.services.AuditService.log_simple_event")
    @patch("apps.customers.models.CustomerTaxProfile")
    def test_valid_cui(self, mock_tp_cls, mock_audit, mock_validate, mock_vat_cls):
        mock_tp = MagicMock(id="tp-1", vat_number="RO12345678")
        mock_tp.customer = MagicMock(id="c1")
        mock_tp_cls.objects.get.return_value = mock_tp
        mock_validate.return_value = MagicMock(is_ok=MagicMock(return_value=True))

        result = validate_vat_number("tp-1")
        self.assertTrue(result["success"])
        mock_vat_cls.objects.update_or_create.assert_called_once()


class ProcessAutoPaymentTests(TestCase):
    """B6: process_auto_payment()"""

    @patch("apps.billing.payment_service.PaymentService")
    @patch("apps.audit.services.AuditService.log_simple_event")
    @patch("apps.billing.tasks.Invoice")
    def test_with_order(self, mock_inv_cls, mock_audit, mock_pay_svc):
        mock_inv = MagicMock(id="i1", number="INV-1", status="pending", meta={"order_id": "o1"})
        mock_inv.customer = MagicMock(id="c1")
        mock_inv_cls.objects.get.return_value = mock_inv

        mock_pay_svc.create_payment_intent.return_value = {"success": True, "payment_intent_id": "pi_1"}
        mock_pay_svc.confirm_payment.return_value = {"success": True, "status": "succeeded"}

        result = process_auto_payment("i1")
        self.assertTrue(result["success"])

    @patch("apps.audit.services.AuditService.log_simple_event")
    @patch("apps.billing.tasks.Invoice")
    def test_no_order(self, mock_inv_cls, mock_audit):
        mock_inv = MagicMock(id="i1", number="INV-1", status="pending", meta={})
        mock_inv.customer = MagicMock(id="c1")
        mock_inv_cls.objects.get.return_value = mock_inv

        result = process_auto_payment("i1")
        self.assertTrue(result["success"])


class PaymentCollectionRetryTests(TestCase):
    """F2: run_payment_collection()"""

    @patch("apps.billing.payment_service.PaymentService")
    @patch("apps.billing.payment_models.PaymentRetryAttempt")
    @patch("apps.billing.payment_models.PaymentCollectionRun")
    def test_retries_via_stripe(self, mock_run_cls, mock_attempt_cls, mock_pay_svc):
        mock_run = MagicMock(total_processed=0, total_scheduled=0)
        mock_run_cls.objects.create.return_value = mock_run

        mock_retry = MagicMock(id="r1", payment_id="p1", attempt_number=1, status="pending")
        mock_retry.payment = MagicMock(gateway_txn_id="pi_1", payment_method="stripe", amount_cents=5000, status="failed")
        mock_retry.policy = MagicMock(max_attempts=3)
        mock_retry.policy.get_next_retry_date.return_value = timezone.now() + timedelta(days=1)

        mock_qs = MagicMock()
        mock_qs.__iter__ = MagicMock(return_value=iter([mock_retry]))
        mock_qs.count.return_value = 1
        mock_attempt_cls.objects.filter.return_value.select_related.return_value = mock_qs

        mock_pay_svc.confirm_payment.return_value = {"success": True, "status": "succeeded"}

        result = run_payment_collection()
        self.assertTrue(result["success"])


class SendPaymentReminderHelperTests(TestCase):
    """_send_payment_reminder helper"""

    @patch("apps.notifications.services.EmailService")
    @patch("apps.billing.tasks.Invoice")
    def test_sends_email(self, mock_inv_cls, mock_email):
        mock_inv_cls.objects.get.return_value = MagicMock(id="i1", number="INV-1")
        mock_email.send_payment_reminder.return_value = MagicMock(success=True)

        result = _send_payment_reminder("i1")
        self.assertTrue(result["success"])


# ===============================================================================
# GROUP C: payment_service.py
# ===============================================================================


class ProcessRecurringBillingTests(TestCase):
    """C5-C8: process_recurring_billing() delegates"""

    @patch("apps.billing.subscription_service.RecurringBillingService")
    def test_delegates(self, mock_rbs):
        mock_rbs.run_billing_cycle.return_value = {
            "subscriptions_processed": 5, "invoices_created": 3,
            "payments_attempted": 3, "payments_succeeded": 2, "payments_failed": 1,
            "total_billed_cents": 50000, "errors": [],
        }

        result = PaymentService.process_recurring_billing()
        self.assertEqual(result["processed"], 5)
        self.assertEqual(result["succeeded"], 2)


class TriggerDunningOnFailureTests(TestCase):
    """C4: Trigger dunning on payment failure"""

    @patch("apps.billing.tasks.start_dunning_process_async")
    @patch("apps.billing.payment_service.log_security_event")
    @patch("apps.billing.payment_service.Payment")
    def test_triggers_dunning(self, mock_pay_cls, mock_log, mock_dunning):
        mock_invoice = MagicMock(id="i1", number="INV-1")
        mock_payment = MagicMock(id="p1", status="pending", meta={}, invoice=mock_invoice)
        mock_pay_cls.objects.get.return_value = mock_payment

        event_data = {"object": {"id": "pi_1", "last_payment_error": {"message": "Declined"}}}
        success, _msg = PaymentService._handle_stripe_payment_intent("payment_intent.payment_failed", event_data)
        self.assertTrue(success)
        mock_dunning.assert_called_once_with(str(mock_invoice.id))


class TriggerOrderCompletionTests(TestCase):
    """C3: Trigger order completion"""

    @patch("apps.notifications.services.EmailService")
    @patch("apps.billing.payment_service.log_security_event")
    @patch("apps.billing.payment_service.Order")
    @patch("apps.billing.payment_service.Payment")
    def test_order_completed(self, mock_pay_cls, mock_order_cls, mock_log, mock_email):
        mock_order = MagicMock(status="pending", order_number="ORD-1")
        mock_order_cls.objects.get.return_value = mock_order

        mock_payment = MagicMock(
            id="p1", status="pending",
            meta={"order_id": "o1"},
            invoice=MagicMock(id="i1"),
        )
        mock_pay_cls.objects.get.return_value = mock_payment

        event_data = {"object": {"id": "pi_1", "payment_method": "pm_1", "amount_received": 10000}}
        success, _msg = PaymentService._handle_stripe_payment_intent("payment_intent.succeeded", event_data)
        self.assertTrue(success)
        self.assertEqual(mock_order.status, "completed")


# ===============================================================================
# GROUP D: views.py
# ===============================================================================


class GenerateEFacturaViewTests(TestCase):
    """D3: generate_e_factura XML"""

    @patch("apps.billing.invoice_service.generate_e_factura_xml")
    def test_generates_real_xml(self, mock_gen):
        mock_gen.return_value = '<?xml version="1.0"?><Invoice/>'

        factory = RequestFactory()
        request = factory.get("/billing/invoices/1/efactura/")
        # Create user mock that passes isinstance check
        mock_user = MagicMock(spec=User)
        mock_user.can_access_customer.return_value = True
        mock_user.is_authenticated = True
        mock_user.is_staff = True
        request.user = mock_user

        with patch("apps.billing.views.get_object_or_404") as mock_get:
            mock_invoice = MagicMock(number="INV-1", customer=MagicMock())
            mock_get.return_value = mock_invoice
            response = generate_e_factura(request, pk=1)

        self.assertEqual(response["Content-Type"], "application/xml")


class InvoiceRefundViewTests(TestCase):
    """D4: invoice_refund via RefundService"""

    @patch("apps.billing.refund_service.RefundService.refund_invoice")
    def test_calls_refund_service(self, mock_refund):
        mock_result = MagicMock()
        mock_result.is_ok.return_value = True
        mock_result.unwrap.return_value = MagicMock(refund_id="ref-1")
        mock_refund.return_value = mock_result

        factory = RequestFactory()
        request = factory.post("/billing/invoices/x/refund/", {
            "refund_type": "full",
            "refund_reason": "customer_request",
            "refund_notes": "Test",
        })
        mock_user = MagicMock(spec=User)
        mock_user.can_access_customer.return_value = True
        mock_user.id = "u1"
        mock_user.email = "staff@test.com"
        request.user = mock_user

        with patch("apps.billing.views.get_object_or_404") as mock_get:
            mock_inv = MagicMock(id="inv-1", total_cents=10000, customer=MagicMock())
            mock_get.return_value = mock_inv
            response = invoice_refund(request, pk=uuid.UUID("12345678-1234-5678-1234-567812345678"))

        data = json.loads(response.content)
        self.assertTrue(data["success"])


class ApiRefundViewTests(TestCase):
    """D5: API refund processing"""

    @patch("apps.billing.refund_service.RefundService.refund_invoice")
    @patch("apps.billing.views.Payment")
    def test_processes_refund(self, mock_pay_cls, mock_refund):
        mock_payment = MagicMock(id="p1", amount_cents=5000, invoice=MagicMock(id="i1"))
        mock_pay_cls.objects.filter.return_value.select_related.return_value.first.return_value = mock_payment

        mock_result = MagicMock()
        mock_result.is_ok.return_value = True
        mock_result.unwrap.return_value = MagicMock(refund_id="ref-1")
        mock_refund.return_value = mock_result

        factory = RequestFactory()
        request = factory.post(
            "/billing/api/refund/",
            json.dumps({"payment_id": "p1", "reason": "Test"}),
            content_type="application/json",
        )
        request.user = MagicMock()

        response = api_process_refund(request)
        data = json.loads(response.content)
        self.assertTrue(data["success"])


# ===============================================================================
# GROUP E: signals.py Credit Note
# ===============================================================================


class CreditNoteSignalTests(TestCase):
    """E1: Credit note for e-Factura refund"""

    @patch("apps.billing.efactura.models.EFacturaDocument")
    @patch("apps.billing.efactura.models.EFacturaStatus")
    @patch("apps.billing.efactura.xml_builder.UBLCreditNoteBuilder")
    def test_credit_note_generated(self, mock_builder_cls, mock_status, mock_doc_cls):
        mock_status.ACCEPTED.value = "accepted"
        mock_status.DRAFT.value = "draft"

        mock_builder = MagicMock()
        mock_builder.build.return_value = "<CreditNote/>"
        mock_builder_cls.return_value = mock_builder

        mock_invoice = MagicMock(number="INV-1", bill_to_country="RO", updated_at=timezone.now())
        mock_doc = MagicMock(status="accepted", anaf_upload_index="UI123")
        mock_invoice.efactura_document = mock_doc

        _handle_efactura_refund_reporting(mock_invoice)

        mock_builder_cls.assert_called_once()
        mock_doc_cls.objects.create.assert_called_once()


# ===============================================================================
# GROUP F: Subscription & Metering
# ===============================================================================


class SubscriptionProcessPaymentTests(TestCase):
    """F1: RecurringBillingService._process_payment()"""

    @patch("apps.billing.payment_service.PaymentService")
    def test_creates_intent_and_confirms(self, mock_pay_svc):
        mock_sub = MagicMock(id="s1", payment_method_id="pm_1", customer_id="c1")
        mock_inv = MagicMock(id="i1", number="INV-1", total_cents=5000, currency=MagicMock(code="RON"))

        mock_pay_svc.create_payment_intent_direct.return_value = {"success": True, "payment_intent_id": "pi_1"}
        mock_pay_svc.confirm_payment.return_value = {"success": True, "status": "succeeded"}

        result = RecurringBillingService._process_payment(mock_sub, mock_inv)
        self.assertTrue(result.is_ok())

    @patch("apps.billing.payment_service.PaymentService")
    def test_no_payment_method(self, mock_pay_svc):
        result = RecurringBillingService._process_payment(MagicMock(payment_method_id=""), MagicMock())
        self.assertTrue(result.is_err())

    @patch("apps.billing.payment_service.PaymentService")
    def test_intent_fails(self, mock_pay_svc):
        mock_pay_svc.create_payment_intent_direct.return_value = {"success": False, "error": "Declined"}

        mock_sub = MagicMock(id="s1", payment_method_id="pm_1", customer_id="c1")
        mock_inv = MagicMock(id="i1", number="INV-1", total_cents=5000, currency=MagicMock(code="RON"))

        result = RecurringBillingService._process_payment(mock_sub, mock_inv)
        self.assertTrue(result.is_err())
        self.assertIn("Declined", result.error)


class UsageAlertEmailTests(TestCase):
    """F3: UsageAlertService email sending"""

    @patch("apps.notifications.services.EmailService.send_template_email")
    @patch("apps.billing.metering_models.UsageAlert")
    def test_sends_alert_email(self, mock_alert_cls, mock_send):
        mock_alert = MagicMock(
            id="a1", status="pending",
            customer=MagicMock(name="Test", primary_email="test@test.com"),
            usage_value=Decimal("95"),
            usage_percentage=Decimal("95"),
        )
        mock_threshold = MagicMock(
            notify_customer=True, action_on_breach=None,
            meter=MagicMock(display_name="Storage"),
            threshold_value=Decimal("100"), threshold_type="percentage",
        )
        mock_alert.threshold = mock_threshold
        mock_alert_cls.objects.select_related.return_value.get.return_value = mock_alert
        mock_send.return_value = MagicMock(success=True, error=None)

        svc = UsageAlertService()
        result = svc.send_alert_notification("a1")
        self.assertTrue(result.is_ok())
        mock_send.assert_called_once()


# ===============================================================================
# Proforma Model
# ===============================================================================


class ProformaModelConvertTests(TestCase):
    """ProformaInvoice.convert_to_invoice()"""

    @patch("apps.billing.services.ProformaConversionService")
    def test_delegates(self, mock_svc):
        mock_svc.convert_to_invoice.return_value = MagicMock(is_err=MagicMock(return_value=False))
        proforma = ProformaInvoiceModel.__new__(ProformaInvoiceModel)
        proforma.id = "pro-1"
        proforma.convert_to_invoice()
        mock_svc.convert_to_invoice.assert_called_once_with("pro-1")

    @patch("apps.billing.services.ProformaConversionService")
    def test_raises_on_failure(self, mock_svc):
        mock_svc.convert_to_invoice.return_value = MagicMock(
            is_err=MagicMock(return_value=True),
            unwrap_err=MagicMock(return_value="Failed"),
        )
        proforma = ProformaInvoiceModel.__new__(ProformaInvoiceModel)
        proforma.id = "pro-1"
        with self.assertRaises(ValueError):
            proforma.convert_to_invoice()
