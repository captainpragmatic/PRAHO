"""End-to-end capstone: a foreign-currency proforma converts to an issued invoice
whose RON FX snapshot is frozen at conversion (#103).

Ties commit 1 (foreign-currency proforma), commit 3 (freeze-at-conversion + consume at
issue), and the resolver. The e-Factura XML invariants (TaxCurrencyCode=RON, dual
TaxTotal, no cac:TaxExchangeRate) are covered by the e-Factura builder tests (#353).
"""

from datetime import timedelta
from decimal import Decimal
from importlib import import_module

from django.apps import apps as global_apps
from django.test import TestCase
from django.utils import timezone

from apps.billing.currency_models import Currency, FXRate
from apps.billing.invoice_models import Invoice
from apps.billing.proforma_models import ProformaInvoice
from apps.billing.services import ProformaConversionService
from apps.customers.models import Customer

# The seed migration's module name starts with a digit, so import it by string.
_seed_migration = import_module("apps.billing.migrations.0047_seed_supported_currencies")


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


class ForeignCurrencyConversionFailClosedTests(TestCase):
    """The keystone's *failure* branch: a foreign proforma with NO resolvable rate must
    fail closed at conversion — no half-issued invoice, and the proforma stays convertible
    so an operator can retry once a rate is ingested (#103, stuck-money prevention).

    Deliberately seeds NO FXRate. Discriminating: with the FX safety removed, issue() would
    create an EUR invoice with exchange_to_ron=None and return Ok — both asserts below flip.
    """

    def setUp(self) -> None:
        self.eur, _ = Currency.objects.get_or_create(code="EUR", defaults={"symbol": "€", "decimals": 2})
        self.ron, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.customer = Customer.objects.create(
            customer_type="company", company_name="Stuck FX SRL", primary_email="stuck-fx@test.ro", status="active"
        )

    def test_conversion_fails_closed_when_no_resolvable_rate(self) -> None:
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.eur,
            number="PRO-EUR-STUCK-1",
            subtotal_cents=10_000,
            tax_cents=2_100,
            total_cents=12_100,
            valid_until=timezone.now() + timedelta(days=30),
        )

        result = ProformaConversionService.convert_to_invoice(str(proforma.id))

        # Fail closed: the caller sees an Err (no exception leaks as a 500).
        self.assertTrue(result.is_err(), result)
        # No half-issued invoice survives the rolled-back savepoint.
        self.assertEqual(Invoice.objects.count(), 0)
        # The proforma is untouched and still convertible — retryable once a rate lands.
        proforma.refresh_from_db()
        self.assertEqual(proforma.status, "draft")
        self.assertNotIn("invoice_id", proforma.meta or {})


class SeedCurrenciesMigrationTests(TestCase):
    """The 0046 seed callback is idempotent and preserves existing metadata (#103)."""

    def test_seed_currencies_is_idempotent_and_preserves_metadata(self) -> None:
        # A pre-existing EUR row with custom metadata must NOT be overwritten by the seed.
        Currency.objects.update_or_create(
            code="EUR", defaults={"symbol": "EURO", "decimals": 4, "name": "Custom Euro"}
        )
        before = Currency.objects.count()

        # Running the callback twice is a no-op beyond ensuring the three rows exist.
        _seed_migration.seed_currencies(global_apps, None)
        _seed_migration.seed_currencies(global_apps, None)

        for code in ("RON", "EUR", "USD"):
            self.assertEqual(Currency.objects.filter(code=code).count(), 1)
        # Seed added at most the rows that were missing; no duplicates, no churn on re-run.
        self.assertEqual(Currency.objects.count(), max(before, 3))
        eur = Currency.objects.get(code="EUR")
        self.assertEqual(eur.symbol, "EURO")  # get_or_create left the custom metadata intact
        self.assertEqual(eur.decimals, 4)
