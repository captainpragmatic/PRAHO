"""End-to-end capstone: a foreign-currency proforma converts to an issued invoice
whose RON FX snapshot is frozen at conversion (#103).

Ties commit 1 (foreign-currency proforma), commit 3 (freeze-at-conversion + consume at
issue), and the resolver. The e-Factura XML invariants (TaxCurrencyCode=RON, dual
TaxTotal, no cac:TaxExchangeRate) are covered by the e-Factura builder tests (#353).
"""

from datetime import timedelta
from decimal import Decimal

from django.test import TestCase
from django.utils import timezone

from apps.billing.currency_models import Currency, FXRate
from apps.billing.proforma_models import ProformaInvoice
from apps.billing.services import ProformaConversionService
from apps.customers.models import Customer


class ForeignCurrencyConversionE2ETests(TestCase):
    def setUp(self) -> None:
        self.eur, _ = Currency.objects.get_or_create(code="EUR", defaults={"symbol": "€", "decimals": 2})
        self.ron, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.customer = Customer.objects.create(
            customer_type="company", company_name="FX E2E SRL", primary_email="fx-e2e@test.ro", status="active"
        )
        FXRate.objects.create(
            base_code=self.eur, quote_code=self.ron, rate=Decimal("5.01230000"),
            as_of=timezone.localdate() - timedelta(days=1),
            source=FXRate.Source.BNR, source_reference="https://curs.bnr.ro/nbrfxrates.xml",
            fetched_at=timezone.now(),
        )

    def test_eur_proforma_converts_to_issued_invoice_with_frozen_fx(self) -> None:
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.eur,
            number="PRO-EUR-E2E-1",
            subtotal_cents=10_000,
            tax_cents=2_100,
            total_cents=12_100,
            valid_until=timezone.now() + timedelta(days=30),
        )

        result = ProformaConversionService.convert_to_invoice(str(proforma.id))

        self.assertTrue(result.is_ok(), result)
        invoice = result.unwrap()
        self.assertEqual(invoice.currency.code, "EUR")
        self.assertEqual(invoice.status, "issued")
        self.assertIsNotNone(invoice.tax_point_date)
        # FX frozen at the reversible conversion moment (consumed by issue()).
        self.assertEqual(invoice.exchange_to_ron, Decimal("5.01230000"))
        self.assertEqual(invoice.exchange_rate_source, FXRate.Source.BNR)
        self.assertIsNotNone(invoice.locked_at)
