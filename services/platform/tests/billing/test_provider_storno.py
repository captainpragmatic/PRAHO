"""Refunding a provider-issued invoice.

A locally issued invoice is corrected by an e-Factura credit note. Its
provider-issued counterpart needs the equivalent AT the provider, or the customer
holds a full invoice with nothing reversing it and the accountant's books show
revenue that was returned.

The decisive constraint: `/invoice/reverse` takes only a series and a number. It
carries NO amounts, reverses the whole document or nothing, and may run once per
invoice. A partial refund therefore has no representation and must be refused —
reversing the whole document would credit the customer money they never got back.
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import patch

from django.test import TransactionTestCase
from django.utils import timezone

from apps.billing.invoice_models import (
    DOCUMENT_KIND_CREDIT_NOTE,
    ISSUER_BUILTIN,
    ISSUER_SMARTBILL,
    Currency,
    Invoice,
)
from apps.billing.issuers.base import Ambiguous, Issued, PreparedDocument, Rejected
from apps.billing.issuers.models import IssuanceState, ProviderIssuance
from apps.billing.issuers.service import issue_storno_for_invoice
from apps.common.types import Ok
from tests.factories.billing_factories import CustomerFactory, InvoiceLineFactory
from tests.helpers.fsm_helpers import force_status


def _currency(code: str = "RON") -> Currency:
    obj, _ = Currency.objects.get_or_create(code=code, defaults={"symbol": "L", "decimals": 2})
    return obj


class StornoTestBase(TransactionTestCase):
    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = _currency()
        self.invoice = self._issued_invoice()

    def _issued_invoice(self, issuer: str = ISSUER_SMARTBILL, number: str = "FCT-000500") -> Invoice:
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=number,
            status="draft",
            issued_at=timezone.now(),
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
            bill_to_tax_id="RO12345678",
            bill_to_country="RO",
            issuer_provider=issuer,
            vat_evidence={"version": 1, "scenario": "romania_b2b", "category": "S", "is_business": True},
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
        if issuer == ISSUER_SMARTBILL:
            ProviderIssuance.objects.create(
                invoice=invoice,
                provider=ISSUER_SMARTBILL,
                state=IssuanceState.ISSUED.value,
                provider_series="FCT",
                provider_number=number.rsplit("-", maxsplit=1)[-1],
            )
        return invoice

    def _refund_fully(self, invoice: Invoice) -> None:
        force_status(invoice, "paid")
        force_status(invoice, "refunded")

    def _storno_returning(self, outcome: object, invoice: Invoice | None = None) -> object:
        target = invoice or self.invoice
        with (
            patch(
                "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.prepare_storno",
                return_value=Ok(PreparedDocument(payload={"number": "000500"}, digest="d")),
            ),
            patch(
                "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.submit_storno",
                return_value=outcome,
            ),
        ):
            return issue_storno_for_invoice(target.pk)


class FullRefundTests(StornoTestBase):
    def test_a_full_refund_produces_a_credit_note_with_the_providers_number(self) -> None:
        self._refund_fully(self.invoice)

        result = self._storno_returning(Issued(number="000501", series="STORNO"))

        self.assertTrue(result.is_ok(), msg=getattr(result, "error", ""))
        credit = Invoice.objects.get(document_kind=DOCUMENT_KIND_CREDIT_NOTE)
        self.assertEqual(credit.number, "STORNO-000501")
        self.assertEqual(credit.reverses_invoice_id, self.invoice.pk)

    def test_the_credit_note_mirrors_the_original_with_the_signs_flipped(self) -> None:
        """Reporting that sums invoice rows then nets the correction automatically."""
        self._refund_fully(self.invoice)
        self._storno_returning(Issued(number="000501", series="STORNO"))

        credit = Invoice.objects.get(document_kind=DOCUMENT_KIND_CREDIT_NOTE)
        self.assertEqual(credit.subtotal_cents, -self.invoice.subtotal_cents)
        self.assertEqual(credit.tax_cents, -self.invoice.tax_cents)
        self.assertEqual(credit.total_cents, -self.invoice.total_cents)

    def test_the_credit_note_keeps_the_originals_fiscal_identity(self) -> None:
        """It is a correction to that document, not a new commercial event."""
        self._refund_fully(self.invoice)
        self._storno_returning(Issued(number="000501", series="STORNO"))

        credit = Invoice.objects.get(document_kind=DOCUMENT_KIND_CREDIT_NOTE)
        self.assertEqual(credit.bill_to_tax_id, self.invoice.bill_to_tax_id)
        self.assertEqual(credit.vat_evidence, self.invoice.vat_evidence)


class PartialRefundTests(StornoTestBase):
    def test_a_partial_refund_is_refused_not_approximated(self) -> None:
        """THE constraint of this phase.

        `/invoice/reverse` carries no amounts. Reversing the whole document for a
        partial refund would credit the customer the entire invoice when they were
        refunded part of it.
        """
        force_status(self.invoice, "paid")
        force_status(self.invoice, "partially_refunded")

        result = self._storno_returning(Issued(number="000501", series="STORNO"))

        self.assertTrue(result.is_err())
        self.assertIn("partial refund", result.error.lower())
        self.assertFalse(Invoice.objects.filter(document_kind=DOCUMENT_KIND_CREDIT_NOTE).exists())

    def test_a_partial_refund_raises_a_visible_manual_flag(self) -> None:
        """It needs a human, so it must not merely be skipped in silence."""
        force_status(self.invoice, "paid")

        with patch("apps.billing.signals.log_security_event") as security:
            force_status(self.invoice, "partially_refunded")

        events = [call.kwargs.get("event_type") for call in security.call_args_list]
        self.assertIn("provider_partial_refund_needs_manual_correction", events)


class StornoEligibilityTests(StornoTestBase):
    def test_an_unrefunded_invoice_is_not_reversed(self) -> None:
        result = self._storno_returning(Issued(number="000501", series="STORNO"))
        self.assertTrue(result.is_err())

    def test_a_builtin_invoice_uses_the_efactura_credit_note_path(self) -> None:
        builtin = self._issued_invoice(issuer=ISSUER_BUILTIN, number="INV-LOCAL-0500")
        self._refund_fully(builtin)

        result = issue_storno_for_invoice(builtin.pk)

        self.assertTrue(result.is_err())
        self.assertIn("e-Factura credit-note path", result.error)

    def test_an_invoice_is_never_reversed_twice(self) -> None:
        """SmartBill refuses a second reversal; we should not spend an attempt on it."""
        self._refund_fully(self.invoice)
        self._storno_returning(Issued(number="000501", series="STORNO"))

        result = self._storno_returning(Issued(number="000502", series="STORNO"))

        self.assertTrue(result.is_err())
        self.assertIn("already been reversed", result.error)

    def test_a_credit_note_cannot_itself_be_reversed(self) -> None:
        self._refund_fully(self.invoice)
        self._storno_returning(Issued(number="000501", series="STORNO"))
        credit = Invoice.objects.get(document_kind=DOCUMENT_KIND_CREDIT_NOTE)

        result = issue_storno_for_invoice(credit.pk)

        self.assertTrue(result.is_err())
        self.assertIn("cannot itself be reversed", result.error)


class StornoOutcomeTests(StornoTestBase):
    def test_an_ambiguous_reversal_stops_for_a_human(self) -> None:
        """A lost response may mean the document WAS reversed. Retrying blindly
        would be refused by the provider, leaving us unsure which attempt landed."""
        self._refund_fully(self.invoice)

        result = self._storno_returning(Ambiguous(reason="read timeout after POST"))

        self.assertTrue(result.is_err())
        credit = Invoice.objects.get(document_kind=DOCUMENT_KIND_CREDIT_NOTE)
        issuance = ProviderIssuance.objects.get(invoice=credit)
        self.assertEqual(issuance.state, IssuanceState.OUTCOME_UNKNOWN.value)

    def test_a_refused_reversal_leaves_the_credit_note_unnumbered(self) -> None:
        self._refund_fully(self.invoice)

        result = self._storno_returning(Rejected(errors=("Factura este deja stornata.",)))

        self.assertTrue(result.is_err())
        credit = Invoice.objects.get(document_kind=DOCUMENT_KIND_CREDIT_NOTE)
        self.assertIsNone(credit.number)


class CreditNoteIsNotCollectableTests(StornoTestBase):
    def test_a_credit_note_is_never_dunned(self) -> None:
        """A credit note is an issued document with a NEGATIVE total.

        Unguarded it satisfies every "issued or overdue" check, and the customer is
        chased for money the business owes them.
        """
        from apps.billing.tasks import start_dunning_process  # noqa: PLC0415

        self._refund_fully(self.invoice)
        self._storno_returning(Issued(number="000501", series="STORNO"))
        credit = Invoice.objects.get(document_kind=DOCUMENT_KIND_CREDIT_NOTE)
        force_status(credit, "issued")

        result = start_dunning_process(str(credit.id))

        self.assertNotIn("dunning_started", str(result))
        self.assertIn("Credit notes are never dunned", result.get("message", ""))
