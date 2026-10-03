"""The complete demo command must produce usable data, including on a second run."""

from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.db.models import Sum
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.fiscal_correction_service import record_obligation
from apps.billing.models import FiscalCorrection, Invoice, ProformaInvoice
from apps.billing.refund_models import Refund
from apps.common.management.commands.generate_sample_data import Command
from apps.customers.models import Customer
from apps.orders.models import Order
from tests.billing import _fiscal_correction_helpers as h


@override_settings(DEBUG=True, ENCRYPTION_KEYS=["MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="])
class SampleDataIntegrityTests(TestCase):
    def seed(self):
        call_command("generate_sample_data", customers=1, users=2, stdout=StringIO(), stderr=StringIO())

    def test_complete_seed_twice_reconciles_documents_and_refunds(self):
        for _ in range(2):
            self.seed()
            for model in (Invoice, ProformaInvoice):
                self.assertTrue(model.objects.exists())
                for document in model.objects.all():
                    self.assertEqual(
                        document.total_cents, document.lines.aggregate(total=Sum("line_total_cents"))["total"]
                    )
                    self.assertEqual(document.total_cents, document.subtotal_cents + document.tax_cents)
                    if isinstance(document, Invoice):
                        self.assertEqual(bool(document.locked_at), document.status != "draft")
                        if document.status == "overdue":
                            self.assertLess(document.due_at, timezone.now())
                    elif document.status != "expired":
                        self.assertFalse(document.is_expired)
            for order in Order.objects.all():
                self.assertEqual(order.total_cents, order.items.aggregate(total=Sum("line_total_cents"))["total"] or 0)
            self.assertTrue(Refund.objects.filter(status="completed").exists())
            for refund in Refund.objects.select_related("payment", "invoice"):
                self.assertEqual(refund.payment.invoice_id, refund.invoice_id)
                self.assertEqual(refund.payment.customer_id, refund.customer_id)
                self.assertEqual(refund.invoice.customer_id, refund.customer_id)
                self.assertLessEqual(refund.amount_cents, refund.payment.amount_cents)
                if refund.status == "completed":
                    self.assertEqual(refund.payment.status, "refunded")
                    self.assertEqual(refund.invoice.status, "refunded")
                    # A settled refund owes a fiscal correction exactly as one settled by the
                    # service would, so dev data shows the obligation the books depend on.
                    correction = FiscalCorrection.objects.get(source_refund=refund)
                    self.assertEqual(correction.original_id, refund.invoice_id)
                    self.assertEqual(correction.state, "pending")
                else:
                    self.assertFalse(FiscalCorrection.objects.filter(source_refund=refund).exists())

    def test_cleanup_removes_example_customers_fiscal_corrections_first(self):
        """The `example.` cleanup site: an obligation PROTECTs its refund and its invoice."""
        owner = Customer.objects.create(
            name="Example Buyer",
            customer_type="company",
            company_name="Example Buyer",
            status="active",
            primary_email="buyer@example.com",
        )
        invoice = h.issued_invoice(owner)
        Invoice.objects.filter(pk=invoice.pk).update(meta={"sample_data": True})
        refund = h.pending_refund(invoice=invoice, status="completed")
        self.assertIsNotNone(record_obligation(refund))

        Command(stdout=StringIO(), stderr=StringIO()).create_billing_foundation()

        self.assertFalse(FiscalCorrection.objects.filter(source_refund_id=refund.pk).exists())
        self.assertFalse(Refund.objects.filter(pk=refund.pk).exists())
        self.assertFalse(Invoice.objects.filter(pk=invoice.pk).exists())

    def test_failed_replacement_preserves_previous_dataset(self):
        self.seed()
        customer = Customer.objects.get(primary_email="contact@testcompany.com")
        invoice_ids = list(Invoice.objects.filter(customer=customer).values_list("pk", flat=True))
        with (
            patch.object(Command, "_create_all_customer_data", side_effect=RuntimeError("seed interrupted")),
            self.assertRaisesRegex(RuntimeError, "seed interrupted"),
        ):
            self.seed()
        self.assertCountEqual(Invoice.objects.filter(customer=customer).values_list("pk", flat=True), invoice_ids)

    def test_replacement_refuses_unowned_invoices_and_preserves_payments(self):
        self.seed()
        customer = Customer.objects.get(primary_email="contact@testcompany.com")
        invoice = Invoice.objects.filter(customer=customer, status="draft").get()
        invoice.meta = {}
        invoice.save()
        invoices_before = list(Invoice.objects.values_list("pk", flat=True))
        with self.assertRaisesRegex(CommandError, "not owned"):
            self.seed()
        self.assertCountEqual(Invoice.objects.values_list("pk", flat=True), invoices_before)
