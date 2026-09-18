"""Order → proforma → actual payment → locked invoice, including refund settlement."""

from decimal import Decimal

import pytest
from django.core.exceptions import ValidationError

from apps.billing.models import Invoice, Payment
from apps.billing.proforma_service import ProformaPaymentService
from apps.billing.refund_models import Refund
from apps.billing.refund_service import RefundService
from apps.billing.subscription_models import Subscription
from tests.e2e.orm.workflow import WorkflowCase

pytestmark = pytest.mark.e2e


class TestOrderToBillingWorkflow(WorkflowCase):
    def test_complete_order_to_invoice_flow(self):
        order = self.create_order()
        self.assertEqual(order.status, "awaiting_payment")
        self.assertIsNone(order.invoice_id)
        self.assertFalse(Invoice.objects.exists())
        self.assertEqual(order.proforma.total_cents, 15125)
        invoice = self.pay(order)
        self.assertEqual(order.status, "provisioning")
        self.assertEqual(order.invoice_id, invoice.pk)
        self.assertEqual(invoice.status, "paid")
        self.assertIsNotNone(invoice.locked_at)
        self.assertEqual(invoice.total_cents, 15125)
        self.assertEqual(sum(line.line_total_cents for line in invoice.lines.all()), invoice.total_cents)
        self.assertEqual(invoice.lines.get(description__startswith="Setup fee").unit_price_cents, 2500)
        self.assertEqual(invoice.lines.get(description=self.product.name).unit_price_cents, 10000)
        with self.assertRaises(ValidationError):
            invoice.lines.update(unit_price_cents=1)

    def test_complete_invoice_to_payment_flow(self):
        order = self.create_order()
        invoice = self.pay(order)
        payment = Payment.objects.get(proforma=order.proforma, invoice=invoice)
        self.assertEqual((payment.amount_cents, payment.status, payment.payment_method), (15125, "succeeded", "bank"))
        self.assertEqual(payment.reference_number, "E2E-BANK-REFERENCE")
        self.assertEqual(self.pay(order).pk, invoice.pk)
        self.assertEqual(Payment.objects.count(), 1)
        self.assertEqual(Invoice.objects.count(), 1)
        self.assertEqual(Subscription.objects.count(), 1)

    def test_romanian_vat_applied(self):
        invoice = self.pay(self.create_order())
        self.assertEqual((invoice.subtotal_cents, invoice.tax_cents, invoice.total_cents), (12500, 2625, 15125))
        self.assertEqual(set(invoice.lines.values_list("tax_rate", flat=True)), {Decimal("0.21")})


class TestProformaToInvoiceWorkflow(WorkflowCase):
    def test_proforma_creation_and_conversion(self):
        order = self.create_order()
        rejected = ProformaPaymentService.record_payment_and_convert(str(order.proforma_id), 1, "bank")
        self.assertTrue(rejected.is_err())
        self.assertFalse(Invoice.objects.exists())
        self.assertFalse(Payment.objects.exists())
        invoice = self.pay(order)
        order.proforma.refresh_from_db()
        self.assertEqual(order.proforma.status, "converted")
        self.assertEqual(invoice.converted_from_proforma_id, order.proforma_id)
        self.assertEqual(order.proforma.total_cents, invoice.total_cents)


class TestRefundWorkflow(WorkflowCase):
    def refund(self, amount, refund_type):
        order = self.create_order()
        invoice = self.pay(order)
        payment = Payment.objects.get(invoice=invoice)
        with self.captureOnCommitCallbacks(execute=True):
            result = RefundService.refund_invoice(
                invoice.pk,
                {
                    "amount_cents": amount,
                    "refund_type": refund_type,
                    "reason": "customer_request",
                    "reference": f"E2E-{refund_type}",
                    "user_id": str(self.admin.pk),
                },
            )
        self.assertTrue(result.is_ok(), str(result))
        invoice.refresh_from_db()
        payment.refresh_from_db()
        refund = Refund.objects.get(invoice=invoice, payment=payment)
        self.assertEqual(refund.status, "completed")
        self.assertEqual(refund.amount_cents, amount)
        self.assertEqual(refund.customer_id, order.customer_id)
        self.assertEqual(invoice.total_cents, 15125)
        return invoice, payment

    def test_full_refund_workflow(self):
        invoice, payment = self.refund(15125, "full")
        self.assertEqual((invoice.status, payment.status), ("refunded", "refunded"))
        duplicate = RefundService.refund_invoice(invoice.pk, {"refund_type": "full", "reason": "customer_request"})
        self.assertTrue(duplicate.is_err())
        self.assertEqual(Refund.objects.count(), 1)

    def test_partial_refund_workflow(self):
        invoice, payment = self.refund(5000, "partial")
        self.assertEqual((invoice.status, payment.status), ("partially_refunded", "partially_refunded"))
        eligibility = RefundService.get_refund_eligibility("invoice", invoice.pk)
        self.assertTrue(eligibility.is_ok(), str(eligibility))
        self.assertEqual(eligibility.unwrap()["max_refund_amount_cents"], 10125)
