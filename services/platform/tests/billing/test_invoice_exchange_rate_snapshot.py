"""Invoice tax-point and immutable exchange-rate snapshot tests."""

from datetime import date, datetime, timedelta
from decimal import Decimal
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone

from apps.billing.models import Currency, FXRate, Invoice
from apps.customers.models import Customer


class InvoiceExchangeRateSnapshotTestCase(TestCase):
    def setUp(self) -> None:
        self.ron, _ = Currency.objects.get_or_create(
            code="RON", defaults={"name": "Romanian leu", "symbol": "lei", "decimals": 2}
        )
        self.eur, _ = Currency.objects.get_or_create(
            code="EUR", defaults={"name": "Euro", "symbol": "EUR", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            customer_type="company",
            company_name="FX Snapshot SRL",
            status="active",
        )
        self.issued_at = timezone.make_aware(datetime(2026, 7, 20, 10, 0))

    def _invoice(self, currency: Currency, number: str) -> Invoice:
        return Invoice.objects.create(
            customer=self.customer,
            currency=currency,
            number=number,
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
        )

    def _rate(self) -> FXRate:
        return FXRate.objects.create(
            base_code=self.eur,
            quote_code=self.ron,
            rate=Decimal("5.01234567"),
            as_of=date(2026, 7, 17),
            source=FXRate.Source.BNR,
            source_reference="https://www.bnr.ro/nbrfxrates.xml",
            fetched_at=self.issued_at,
        )

    @patch("apps.billing.invoice_models.timezone.now")
    def test_ron_issue_sets_tax_point_without_fx_snapshot(self, now: object) -> None:
        now.return_value = self.issued_at
        invoice = self._invoice(self.ron, "INV-RON-TAX-POINT")

        invoice.issue()
        invoice.save()

        self.assertEqual(invoice.tax_point_date, date(2026, 7, 20))
        self.assertIsNone(invoice.exchange_to_ron)
        self.assertIsNone(invoice.exchange_rate_as_of)
        self.assertEqual(invoice.exchange_rate_source, "")
        self.assertEqual(invoice.exchange_rate_source_reference, "")

    @patch("apps.billing.invoice_models.timezone.now")
    def test_foreign_issue_freezes_latest_provenanced_rate(self, now: object) -> None:
        now.return_value = self.issued_at
        expected = self._rate()
        invoice = self._invoice(self.eur, "INV-EUR-SNAPSHOT")

        invoice.issue()
        invoice.save()

        self.assertEqual(invoice.tax_point_date, date(2026, 7, 20))
        self.assertEqual(invoice.exchange_to_ron, expected.rate)
        self.assertEqual(invoice.exchange_rate_as_of, expected.as_of)
        self.assertEqual(invoice.exchange_rate_source, FXRate.Source.BNR)
        self.assertEqual(invoice.exchange_rate_source_reference, expected.source_reference)

    @patch("apps.billing.invoice_models.timezone.now")
    def test_foreign_issue_without_provenanced_rate_fails_before_transition(self, now: object) -> None:
        now.return_value = self.issued_at
        invoice = self._invoice(self.eur, "INV-EUR-NO-RATE")

        with self.assertRaises(ValidationError):
            invoice.issue()

        self.assertEqual(invoice.status, "draft")
        self.assertIsNone(invoice.locked_at)

    @patch("apps.billing.invoice_models.timezone.now")
    def test_explicit_tax_point_selects_rate_for_that_date(self, now: object) -> None:
        now.return_value = self.issued_at
        expected = self._rate()
        invoice = self._invoice(self.eur, "INV-EUR-EXPLICIT-TAX-POINT")
        invoice.tax_point_date = date(2026, 7, 18)

        invoice.issue()
        invoice.save()

        self.assertEqual(invoice.tax_point_date, date(2026, 7, 18))
        self.assertEqual(invoice.exchange_rate_as_of, expected.as_of)

    @patch("apps.billing.invoice_models.timezone.now")
    def test_locked_invoice_rejects_fx_snapshot_and_currency_changes(self, now: object) -> None:
        now.return_value = self.issued_at
        self._rate()
        invoice = self._invoice(self.eur, "INV-EUR-FROZEN")
        invoice.issue()
        invoice.save()
        invoice.refresh_from_db()

        invoice.exchange_to_ron = Decimal("5.99999999")
        with self.assertRaises(ValidationError):
            invoice.save(update_fields=["exchange_to_ron"])

        invoice.refresh_from_db()
        invoice.currency = self.ron
        with self.assertRaises(ValidationError):
            invoice.save(update_fields=["currency"])

        invoice.refresh_from_db()
        invoice.issued_at = invoice.issued_at + timedelta(days=1)
        with self.assertRaises(ValidationError):
            invoice.save(update_fields=["issued_at"])

        invoice.refresh_from_db()
        invoice.tax_point_date = date(2026, 7, 19)
        with self.assertRaises(ValidationError):
            invoice.save(update_fields=["tax_point_date"])

    @patch("apps.billing.invoice_models.timezone.now")
    def test_status_only_save_persists_complete_issue_snapshot(self, now: object) -> None:
        now.return_value = self.issued_at
        expected = self._rate()
        invoice = self._invoice(self.eur, "INV-EUR-STATUS-ONLY")

        invoice.issue()
        invoice.save(update_fields=["status"])
        invoice.refresh_from_db()

        self.assertEqual(invoice.status, "issued")
        self.assertEqual(invoice.issued_at, self.issued_at)
        self.assertIsNotNone(invoice.locked_at)
        self.assertEqual(invoice.tax_point_date, date(2026, 7, 20))
        self.assertEqual(invoice.exchange_to_ron, expected.rate)
        self.assertEqual(invoice.exchange_rate_as_of, expected.as_of)
