"""Two staff payment submissions must converge on one paid fiscal document."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from decimal import Decimal
from threading import Barrier

from django.db import connections
from django.test import TransactionTestCase, skipUnlessDBFeature
from django.utils import timezone

from apps.billing.models import Currency, Invoice, Payment, ProformaInvoice, ProformaLine
from apps.billing.proforma_service import ProformaPaymentService
from apps.customers.models import Customer


class ManualPaymentConcurrencyTests(TransactionTestCase):
    @skipUnlessDBFeature("has_select_for_update")
    def test_simultaneous_bank_submissions_create_one_payment_and_invoice(self):
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
        customer = Customer.objects.create(name="Concurrent payment", primary_email="race@example.test")
        proforma = ProformaInvoice.objects.create(
            customer=customer,
            currency=currency,
            number="MANUAL-RACE",
            valid_until=timezone.now() + timedelta(days=7),
            status="accepted",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
        )
        ProformaLine.objects.create(
            proforma=proforma, description="Hosting", quantity=1, unit_price_cents=10000, tax_rate=Decimal("0.21")
        )
        ready = Barrier(2)

        def submit():
            try:
                ready.wait(timeout=10)
                result = ProformaPaymentService.record_payment_and_convert(
                    str(proforma.pk), 12100, "bank_transfer", reference="BANK-RACE"
                )
                self.assertTrue(result.is_ok(), str(result))
                return result.unwrap().pk
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(submit) for _ in range(2)]
            invoice_ids = [future.result(timeout=30) for future in futures]
        invoice = Invoice.objects.get(converted_from_proforma=proforma)
        self.assertEqual(invoice_ids, [invoice.pk, invoice.pk])
        self.assertEqual(invoice.status, "paid")
        self.assertEqual(invoice.total_cents, 12100)
        self.assertIsNotNone(invoice.locked_at)
        self.assertEqual(Payment.objects.filter(proforma=proforma, invoice=invoice, status="succeeded").count(), 1)
