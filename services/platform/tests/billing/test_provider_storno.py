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

from datetime import UTC, datetime
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
from apps.billing.issuers.smartbill.issuer import SmartBillIssuer
from apps.billing.refund_models import Refund
from apps.common.types import Ok
from apps.settings.services import SettingsService
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
        self._settled_refund(invoice, abs(invoice.total_cents), refund_type="full")

    def _settled_refund(self, invoice: Invoice, amount_cents: int, *, refund_type: str = "partial") -> Refund:
        """A refund that actually settled, which is what the storno guard counts."""
        self._refund_seq = getattr(self, "_refund_seq", 0) + 1
        return Refund.objects.create(
            customer=invoice.customer,
            invoice=invoice,
            status="completed",
            refund_type=refund_type,
            amount_cents=amount_cents,
            currency=invoice.currency,
            original_amount_cents=abs(invoice.total_cents),
            reference_number=f"REF-{invoice.pk}-{self._refund_seq}",
        )

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

        submitted = []
        with patch(
            "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.submit_storno",
            side_effect=lambda *a, **k: submitted.append(a),
        ):
            result = issue_storno_for_invoice(self.invoice.pk)

        self.assertTrue(result.is_err())
        self.assertIn("partial refund", result.error.lower())
        self.assertFalse(Invoice.objects.filter(document_kind=DOCUMENT_KIND_CREDIT_NOTE).exists())
        # The refusal has to happen before the call, not be recovered from after it.
        # SmartBill has no idempotency key and its reversal is not itself reversible.
        self.assertEqual(submitted, [], "a refused reversal must never reach the provider")

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
        self.assertIn("already been reversed by credit note", result.error)

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


class StornoResumeTests(StornoTestBase):
    """A crash must not permanently wedge an invoice.

    The first version of this code treated the existence of a credit-note row as
    proof the invoice had been reversed. Creating the row and hearing back from the
    provider are two steps, so a crash between them left a draft that made every
    later attempt answer "already reversed" forever - a refund the customer could
    never be issued, with no way back short of hand-editing the database.
    """

    def test_an_unclaimed_credit_note_row_is_resumed_not_refused(self) -> None:
        """Row existence must never be the "already reversed" test.

        This is the state an interrupted attempt used to leave behind, and the state
        any half-finished reversal converges on: a credit note that exists but was
        never submitted. Answering "already reversed" here is a refund the customer
        can never be issued, recoverable only by hand-editing the database.
        """
        self._refund_fully(self.invoice)

        orphan = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=None,
            status="draft",
            document_kind=DOCUMENT_KIND_CREDIT_NOTE,
            reverses_invoice=self.invoice,
            issuer_provider=ISSUER_SMARTBILL,
            subtotal_cents=-10000,
            tax_cents=-2100,
            total_cents=-12100,
            bill_to_name=self.invoice.bill_to_name,
            bill_to_country="RO",
        )
        ProviderIssuance.objects.create(invoice=orphan, provider=ISSUER_SMARTBILL, state=IssuanceState.PENDING.value)

        result = self._storno_returning(Issued(number="000501", series="STORNO"))

        self.assertTrue(result.is_ok(), msg=getattr(result, "error", ""))
        self.assertEqual(
            Invoice.objects.filter(document_kind=DOCUMENT_KIND_CREDIT_NOTE).count(),
            1,
            "the resumed attempt must reuse the existing credit note, not mint a second",
        )
        orphan.refresh_from_db()
        self.assertEqual(orphan.number, "STORNO-000501")
        # Resuming must also repair what the interrupted attempt never wrote. A
        # numbered credit note with no lines reverses the header while line-based
        # VAT and EC-Sales reporting see no correction at all - arguably worse than
        # no credit note, because it looks settled.
        self.assertEqual(
            [line.line_total_cents for line in orphan.lines.all()],
            [-line.line_total_cents for line in self.invoice.lines.all()],
            "a resumed credit note must carry the original's lines, negated",
        )

    def test_the_credit_note_carries_the_originals_lines_negated(self) -> None:
        """Header totals alone are invisible to line-based VAT reporting.

        `d390`, EC-Sales and the VAT report all attribute amounts by walking
        `InvoiceLine` rows for their rate and tax category. A credit note with no
        lines nets to zero in every one of them however correct its totals are.
        """
        self._refund_fully(self.invoice)
        self._storno_returning(Issued(number="000501", series="STORNO"))

        credit = Invoice.objects.get(document_kind=DOCUMENT_KIND_CREDIT_NOTE)
        original_line = self.invoice.lines.get()
        credit_line = credit.lines.get()

        self.assertEqual(credit_line.line_total_cents, -original_line.line_total_cents)
        self.assertEqual(credit_line.unit_price_cents, -original_line.unit_price_cents)
        self.assertEqual(credit_line.tax_cents, -original_line.tax_cents)
        self.assertEqual(
            credit_line.quantity,
            original_line.quantity,
            "quantity stays positive: negating it would corrupt the discount line's item count",
        )
        self.assertEqual(credit_line.tax_category_code, original_line.tax_category_code)


class SplitCorrectionTests(StornoTestBase):
    """`/invoice/reverse` credits the whole document, so it must be the whole story."""

    def test_two_settled_refunds_refuse_a_whole_document_reversal(self) -> None:
        """Over-crediting is the failure mode, and it is silent without this guard.

        An invoice refunded in two instalments may already have had the first
        corrected by hand in SmartBill's own interface. Reversing the whole document
        on top of that credits the customer twice, and nothing downstream notices.
        """
        force_status(self.invoice, "paid")
        force_status(self.invoice, "refunded")
        self._settled_refund(self.invoice, 4000)
        self._settled_refund(self.invoice, 8100)

        submitted = []
        with patch(
            "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.submit_storno",
            side_effect=lambda *a, **k: submitted.append(a),
        ):
            result = issue_storno_for_invoice(self.invoice.pk)

        self.assertTrue(result.is_err())
        self.assertIn("2 settled refunds", result.error)
        self.assertEqual(submitted, [], "a refused reversal must never reach the provider")
        self.assertFalse(Invoice.objects.filter(document_kind=DOCUMENT_KIND_CREDIT_NOTE).exists())

    def test_a_failed_refund_attempt_does_not_block_the_reversal(self) -> None:
        """Counting attempts rather than settlements would wedge the invoice again."""
        self._refund_fully(self.invoice)
        Refund.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            status="failed",
            refund_type="partial",
            amount_cents=500,
            currency=self.currency,
            original_amount_cents=12100,
            reference_number="REF-FAILED-1",
        )

        result = self._storno_returning(Issued(number="000501", series="STORNO"))

        self.assertTrue(result.is_ok(), msg=getattr(result, "error", ""))

    def test_a_refund_that_does_not_cover_the_total_is_refused(self) -> None:
        force_status(self.invoice, "paid")
        force_status(self.invoice, "refunded")
        self._settled_refund(self.invoice, 4000)

        result = issue_storno_for_invoice(self.invoice.pk)

        self.assertTrue(result.is_err())
        self.assertIn("4000 cents", result.error)


class StornoResumeWithRealMapperTests(StornoTestBase):
    """The resume path must survive the real `prepare_storno`, not a mocked one.

    The first version of this suite mocked `prepare_storno` everywhere, which hid a
    second copy of the row-existence check living inside it. The orphan-wedge fix in
    `service.py` was unreachable in production because the mapper refused first, and
    no test could see it. Only `submit_storno` is mocked here.
    """

    def _submit_only(self, outcome: object, invoice: Invoice) -> object:
        with patch(
            "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.submit_storno",
            return_value=outcome,
        ):
            return issue_storno_for_invoice(invoice.pk)

    def _config(self) -> None:
        for key, value in (
            ("integrations.smartbill_cif", "RO12345678"),
            ("integrations.smartbill_storno_series", "STORNO"),
        ):
            SettingsService.update_setting(key, value, reason="test")

    def test_an_unsubmitted_credit_note_is_resumed_through_the_real_mapper(self) -> None:
        self._config()
        self._refund_fully(self.invoice)

        orphan = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=None,
            status="draft",
            document_kind=DOCUMENT_KIND_CREDIT_NOTE,
            reverses_invoice=self.invoice,
            issuer_provider=ISSUER_SMARTBILL,
            subtotal_cents=-10000,
            tax_cents=-2100,
            total_cents=-12100,
            bill_to_name=self.invoice.bill_to_name,
            bill_to_country="RO",
        )
        ProviderIssuance.objects.create(invoice=orphan, provider=ISSUER_SMARTBILL, state=IssuanceState.PENDING.value)

        result = self._submit_only(Issued(number="000501", series="STORNO"), self.invoice)

        self.assertTrue(result.is_ok(), msg=getattr(result, "error", ""))
        orphan.refresh_from_db()
        self.assertEqual(orphan.number, "STORNO-000501")

    def test_the_storno_is_dated_in_the_romanian_day(self) -> None:
        """A storno dated before its original is refused by SmartBill outright.

        The instant is pinned rather than taken from the clock: for most of the day
        the UTC and Romanian dates agree, so a live-clock assertion passes whether or
        not the conversion happens and proves nothing.
        """
        self._config()
        self._refund_fully(self.invoice)

        # 22:30 UTC on 31 January is 00:30 on 1 February in Bucharest.
        straddling = datetime(2026, 1, 31, 22, 30, tzinfo=UTC)
        with patch("apps.billing.issuers.smartbill.issuer.timezone.now", return_value=straddling):
            prepared = SmartBillIssuer().prepare_storno(self.invoice)

        self.assertTrue(prepared.is_ok(), msg=getattr(prepared, "error", ""))
        self.assertEqual(prepared.unwrap().payload["issueDate"], "2026-02-01")
