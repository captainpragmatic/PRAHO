"""A reversal must reverse at the original's exchange rate, not today's.

`_freeze_fx` resolves a fresh rate whenever the snapshot it finds is incomplete. The
credit note copied none of the four exchange fields, so a EUR reversal three months
later booked RON at the reversal day's rate while the original was booked at the
issue day's — leaving a permanent residue in the RON ledger that nets to nothing and
appears on no report. Romanian implementing norms retain the original operation's rate
for adjustments of this kind.
"""

from __future__ import annotations

from datetime import date
from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from apps.billing.invoice_models import ISSUER_SMARTBILL, Currency, Invoice
from apps.billing.issuers.service import _get_or_create_credit_note
from tests.factories.billing_factories import CustomerFactory, InvoiceLineFactory


class ReversalKeepsTheOriginalRateTests(TestCase):
    def setUp(self) -> None:
        self.customer = CustomerFactory()
        Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})
        self.eur = Currency.objects.get_or_create(code="EUR", defaults={"symbol": "€", "decimals": 2})[0]

    def _eur_original(self) -> Invoice:
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.eur,
            number="FCT-000650",
            status="draft",
            issued_at=timezone.now(),
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
            issuer_provider=ISSUER_SMARTBILL,
            exchange_to_ron=Decimal("4.9750"),
            exchange_rate_as_of=date(2026, 1, 15),
            exchange_rate_source="BNR",
            exchange_rate_source_reference="bnr:2026-01-15",
        )
        InvoiceLineFactory(
            invoice=invoice,
            description="Hosting",
            quantity=Decimal("1"),
            unit_price_cents=10000,
            tax_rate=Decimal("0.2100"),
            tax_cents=2100,
            line_total_cents=12100,
        )
        return invoice

    def _reverse(self, original: Invoice) -> Invoice:
        return _get_or_create_credit_note(original)

    def test_all_four_exchange_fields_are_carried(self) -> None:
        original = self._eur_original()

        credit_note = self._reverse(original)

        self.assertEqual(credit_note.exchange_to_ron, original.exchange_to_ron)
        self.assertEqual(credit_note.exchange_rate_as_of, original.exchange_rate_as_of)
        self.assertEqual(credit_note.exchange_rate_source, original.exchange_rate_source)
        self.assertEqual(
            credit_note.exchange_rate_source_reference,
            original.exchange_rate_source_reference,
            "the reference is the fourth field and the one _freeze_fx forgets to check",
        )

    def test_issuing_the_reversal_does_not_resolve_a_new_rate(self) -> None:
        """The snapshot must be consumed, never re-resolved.

        If `_freeze_fx` reaches the exchange-rate service at all here, it has decided
        the copied snapshot was incomplete - and it will book the reversal at a
        different rate from the document it reverses.
        """
        original = self._eur_original()
        credit_note = self._reverse(original)
        credit_note.number = "STORNO-000651"

        with patch("apps.billing.exchange_rate_service.ExchangeRateService.resolve") as resolve:
            credit_note.issue()
            credit_note.save()

        resolve.assert_not_called()
        credit_note.refresh_from_db()
        self.assertEqual(credit_note.exchange_to_ron, Decimal("4.9750"))

    def test_a_ron_reversal_carries_no_snapshot(self) -> None:
        """The regression guard: RON documents must stay snapshot-free."""
        ron = Currency.objects.get(code="RON")
        original = Invoice.objects.create(
            customer=self.customer,
            currency=ron,
            number="FCT-000652",
            status="draft",
            issued_at=timezone.now(),
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
            issuer_provider=ISSUER_SMARTBILL,
        )

        credit_note = self._reverse(original)

        self.assertIsNone(credit_note.exchange_to_ron)
