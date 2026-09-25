"""A reversal must reverse at the original's exchange rate, not today's.

`_freeze_fx` resolves a fresh rate whenever the snapshot it finds is incomplete. The
credit note copied none of the four exchange fields, so a EUR reversal three months
later booked RON at the reversal day's rate while the original was booked at the
issue day's — leaving a permanent residue in the RON ledger that nets to nothing and
appears on no report. Romanian implementing norms retain the original operation's rate
for adjustments of this kind.
"""

from __future__ import annotations

import uuid
from datetime import date
from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from apps.billing.invoice_models import ISSUER_SMARTBILL, Currency, Invoice
from apps.billing.issuers.base import Issued, PreparedDocument
from apps.billing.issuers.models import IssuanceState, ProviderIssuance
from apps.billing.issuers.service import _get_or_create_credit_note, issue_storno_for_invoice
from apps.billing.refund_models import Refund
from apps.common.types import Ok
from tests.factories.billing_factories import CustomerFactory, InvoiceLineFactory
from tests.helpers.fsm_helpers import force_status


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


class ResumingAnExistingReversalTests(TestCase):
    """A reversal left pending by an earlier attempt predates the fields added since.

    `_get_or_create_credit_note` copies the snapshot on the CREATE path only, so a row
    from an interrupted or rate-gated attempt keeps whatever the older implementation
    wrote: an empty FX snapshot, and a zero discount against negated GROSS lines.
    `_freeze_fx` then discards the incomplete snapshot and resolves TODAY's rate at
    issuance - exactly the residue the copy exists to prevent.

    Every test above builds the note fresh, so the resume branch was never exercised.
    """

    def setUp(self) -> None:
        self.customer = CustomerFactory()
        Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})
        self.eur = Currency.objects.get_or_create(code="EUR", defaults={"symbol": "€", "decimals": 2})[0]

    def _discounted_eur_original(self) -> Invoice:
        """Lines gross 10000, document discount 1000, so the header subtotal is 9000."""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.eur,
            number="FCT-000660",
            status="draft",
            issued_at=timezone.now(),
            subtotal_cents=9000,
            tax_cents=1890,
            total_cents=10890,
            discount_cents=1000,
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
            tax_cents=1890,
            line_total_cents=11890,
        )
        return invoice

    def _stale_reversal_of(self, original: Invoice) -> Invoice:
        """The row an older implementation would have left behind."""
        credit_note = _get_or_create_credit_note(original)
        Invoice.objects.filter(pk=credit_note.pk).update(
            discount_cents=0,
            exchange_to_ron=None,
            exchange_rate_as_of=None,
            exchange_rate_source="",
            exchange_rate_source_reference="",
        )
        return Invoice.objects.get(pk=credit_note.pk)

    def test_an_issued_reversal_is_never_repaired(self) -> None:
        """The regression guard: a numbered credit note is a legal document.

        Whatever it says is what was filed, so repairing it would rewrite history rather
        than recover an attempt that never finished.
        """
        original = self._discounted_eur_original()
        credit_note = self._stale_reversal_of(original)
        Invoice.objects.filter(pk=credit_note.pk).update(number="STORNO-000661")

        resumed = _get_or_create_credit_note(original)

        self.assertIsNone(resumed.exchange_to_ron, "an issued reversal must be left exactly as filed")
        self.assertEqual(resumed.discount_cents, 0)


class ReversalRepairSafetyTests(TransactionTestCase):
    """`TransactionTestCase` because `issue_storno_for_invoice` refuses an open transaction."""

    def setUp(self) -> None:
        self.customer = CustomerFactory()
        Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})
        self.eur = Currency.objects.get_or_create(code="EUR", defaults={"symbol": "€", "decimals": 2})[0]

    _discounted_eur_original = ResumingAnExistingReversalTests._discounted_eur_original
    _stale_reversal_of = ResumingAnExistingReversalTests._stale_reversal_of

    def _provider_issued(self, original: Invoice) -> None:
        """Make the original look reversible: provider-issued and fully refunded."""
        issued = ProviderIssuance.objects.create(invoice=original, provider=ISSUER_SMARTBILL)
        ProviderIssuance.objects.filter(pk=issued.pk).update(
            state=IssuanceState.ISSUED.value, provider_series="FCT", provider_number="000660"
        )
        force_status(original, "issued")
        force_status(original, "paid")
        Refund.objects.create(
            customer=self.customer,
            invoice=original,
            currency=self.eur,
            amount_cents=original.total_cents,
            original_amount_cents=original.total_cents,
            reference_number=f"RF-{uuid.uuid4().hex[:12]}",
            status="completed",
        )
        force_status(original, "refunded")

    def _reverse(self, original: Invoice) -> object:

        with (
            patch(
                "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.prepare_storno",
                return_value=Ok(PreparedDocument(payload={"number": "000660"}, digest="d")),
            ),
            patch(
                "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.submit_storno",
                return_value=Issued(number="000661", series="STORNO"),
            ),
        ):
            return issue_storno_for_invoice(original.pk)

    def test_resuming_restores_the_original_snapshot(self) -> None:
        """Driven through the real reversal path, which is where the repair now runs."""
        original = self._discounted_eur_original()
        self._provider_issued(original)
        credit_note = self._stale_reversal_of(original)

        self._reverse(original)

        resumed = Invoice.objects.get(pk=credit_note.pk)
        self.assertEqual(resumed.exchange_to_ron, original.exchange_to_ron)
        self.assertEqual(resumed.exchange_rate_as_of, original.exchange_rate_as_of)
        self.assertEqual(resumed.exchange_rate_source, original.exchange_rate_source)
        self.assertEqual(resumed.exchange_rate_source_reference, original.exchange_rate_source_reference)

    def test_resuming_restores_the_negated_discount(self) -> None:
        """Zero against negated gross lines makes the header contradict its own lines."""
        original = self._discounted_eur_original()
        self._provider_issued(original)
        credit_note = self._stale_reversal_of(original)

        self._reverse(original)

        self.assertEqual(Invoice.objects.get(pk=credit_note.pk).discount_cents, -original.discount_cents)

    def test_a_reversal_whose_outcome_is_unknown_is_never_repaired(self) -> None:
        """`number IS NULL` does not mean "no document exists at the provider".

        `outcome_unknown` is the state where those two diverge - it exists because
        SmartBill may hold a real, numbered document we never heard about. The repair ran
        from `_get_or_create_credit_note`, which the storno path calls BEFORE any state
        check on the credit note's issuance, and the refusal that follows is deliberately
        not rolled back - so the rewrite committed against the very document an operator
        is about to reconcile by hand, with no audit trail, via a `queryset.update()` that
        bypasses the locked-invoice guard entirely.
        """

        original = self._discounted_eur_original()
        # The original must look provider-issued, or the reversal is refused long before
        # the repair is reached and the test proves nothing.
        issued = ProviderIssuance.objects.create(invoice=original, provider=ISSUER_SMARTBILL)
        ProviderIssuance.objects.filter(pk=issued.pk).update(
            state=IssuanceState.ISSUED.value, provider_series="FCT", provider_number="000660"
        )
        credit_note = self._stale_reversal_of(original)
        cn_issuance, _ = ProviderIssuance.objects.get_or_create(
            invoice=credit_note, defaults={"provider": ISSUER_SMARTBILL}
        )
        ProviderIssuance.objects.filter(pk=cn_issuance.pk).update(
            state=IssuanceState.OUTCOME_UNKNOWN.value, last_error="No usable reply from SmartBill"
        )
        force_status(original, "issued")
        force_status(original, "paid")
        # One settled refund of the full amount, or `_storno_refusal_reason` bails first.
        Refund.objects.create(
            customer=self.customer,
            invoice=original,
            currency=self.eur,
            amount_cents=original.total_cents,
            original_amount_cents=original.total_cents,
            reference_number=f"RF-{uuid.uuid4().hex[:12]}",
            status="completed",
        )
        force_status(original, "refunded")

        result = issue_storno_for_invoice(original.pk)

        self.assertTrue(result.is_err(), f"an unknown outcome must refuse; got {result}")
        untouched = Invoice.objects.get(pk=credit_note.pk)
        self.assertIsNone(
            untouched.exchange_to_ron,
            "a reversal that may already exist at the provider must not be rewritten",
        )
        self.assertEqual(untouched.discount_cents, 0)
