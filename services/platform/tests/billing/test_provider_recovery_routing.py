"""Recovery has to know which provider call a row is owed, and when to stop.

`pending` records that a provider call is owed, not WHICH one. A rate-gated reversal
returns to `pending` by design, so excluding credit notes from the issuance sweep
stopped them being POSTed to /invoice. A reversal is resumed through the fiscal
correction it issues, which names exactly one document; resuming it by its original
found only the first credit note an original carried and stranded any other.

Separately, `claim()` accepts a FAILED source, so the state machine was built for
retry, but nothing selected those rows. A refusal is REJECTED only from a recognised
refusal envelope, which is the classifier's guarantee that nothing was created - so
retrying is safe. What it is not is unconditional: a permanent validation error would
otherwise be resubmitted forever against a rate-limited third party.
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from apps.billing import fiscal_correction_worker
from apps.billing.fiscal_correction_models import FiscalCorrection
from apps.billing.fiscal_correction_service import record_obligation
from apps.billing.invoice_models import (
    DOCUMENT_KIND_CREDIT_NOTE,
    ISSUER_SMARTBILL,
    Currency,
    Invoice,
)
from apps.billing.issuers.base import Issued, PreparedDocument
from apps.billing.issuers.models import MAX_SUBMISSIONS, IssuanceState, ProviderIssuance
from apps.billing.issuers.service import issue_invoice_externally
from apps.billing.issuers.smartbill.client import RateGateWait
from apps.billing.issuers.tasks import sweep_pending_issuances
from apps.common.types import Ok
from tests.billing import _fiscal_correction_helpers as h
from tests.factories.billing_factories import CustomerFactory, InvoiceLineFactory


class RecoveryRoutesByDocumentKindTests(TestCase):
    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]
        self._seq = 0

    def _original(self) -> Invoice:
        self._seq += 1
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"FCT-0010{self._seq}",
            status="draft",
            issued_at=timezone.now(),
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
            issuer_provider=ISSUER_SMARTBILL,
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

    def _correction(self, original: Invoice, amount_cents: int) -> FiscalCorrection:
        refund = h.pending_refund(
            invoice=original, status="completed", amount_cents=amount_cents, refund_type="partial"
        )
        correction = record_obligation(refund)
        assert correction is not None
        return correction

    def _deferred_credit_note(
        self, state: str = IssuanceState.PENDING.value, *, original: Invoice | None = None
    ) -> tuple[Invoice, Invoice, FiscalCorrection]:
        original = original or self._original()
        correction = self._correction(original, 12100)
        credit_note = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=None,
            status="draft",
            document_kind=DOCUMENT_KIND_CREDIT_NOTE,
            reverses_invoice=original,
            issuer_provider=ISSUER_SMARTBILL,
            subtotal_cents=-10000,
            tax_cents=-2100,
            total_cents=-12100,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
        )
        ProviderIssuance.objects.create(
            invoice=credit_note, provider=ISSUER_SMARTBILL, state=state, fiscal_correction=correction
        )
        return original, credit_note, correction

    def _unnumbered_invoice(self) -> Invoice:
        self._seq += 1
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=None,
            status="draft",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
            issuer_provider=ISSUER_SMARTBILL,
        )
        ProviderIssuance.objects.create(invoice=invoice, provider=ISSUER_SMARTBILL, state=IssuanceState.PENDING.value)
        return invoice

    def test_two_pending_reversals_on_one_original_are_each_resumed_by_their_correction(self) -> None:
        """Pacing left both pending. Resumed by their original, both resolved to the first credit
        note that original carried, and the other was never sent; resumed by correction, each is."""
        original, _first_note, first = self._deferred_credit_note()
        _same, _second_note, second = self._deferred_credit_note(original=original)

        issuance_calls: list[int] = []
        correction_calls: list[str] = []
        with (
            patch(
                "apps.billing.issuers.tasks.queue_invoice_issuance",
                side_effect=lambda pk: issuance_calls.append(pk) or "t",
            ),
            patch.object(
                fiscal_correction_worker,
                "queue_fiscal_correction",
                side_effect=lambda pk: correction_calls.append(str(pk)),
            ),
        ):
            sweep_pending_issuances()

        self.assertEqual(sorted(correction_calls), sorted([str(first.pk), str(second.pk)]))
        self.assertEqual(issuance_calls, [], "a reversal must never reach the issuance task")

    def test_a_reversal_whose_enqueue_failed_is_counted_as_skipped(self) -> None:
        """A queue outage must show in the sweep's result, not read as work handed on."""
        self._deferred_credit_note()

        with patch("django_q.tasks.async_task", side_effect=RuntimeError("broker down")):
            results = sweep_pending_issuances()

        self.assertEqual((results["queued"], results["skipped"]), (0, 1))

    def test_an_unnumbered_invoice_still_goes_to_the_issuance_task(self) -> None:
        """The regression guard."""
        invoice = self._unnumbered_invoice()

        issuance_calls: list[int] = []
        with (
            patch(
                "apps.billing.issuers.tasks.queue_invoice_issuance",
                side_effect=lambda pk: issuance_calls.append(pk) or "t",
            ),
            patch.object(fiscal_correction_worker, "queue_fiscal_correction", side_effect=AssertionError),
        ):
            sweep_pending_issuances()

        self.assertEqual(issuance_calls, [invoice.pk])


class FailedWorkIsRetriedButNotForeverTests(TestCase):
    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]

    def _failed_issuance(self, submissions: int) -> Invoice:
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=None,
            status="draft",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
            issuer_provider=ISSUER_SMARTBILL,
        )
        ProviderIssuance.objects.create(
            invoice=invoice,
            provider=ISSUER_SMARTBILL,
            state=IssuanceState.FAILED.value,
            submissions=submissions,
        )
        return invoice

    def test_a_refused_issuance_is_picked_up_again(self) -> None:
        """REJECTED is only ever assigned from a recognised refusal envelope, which is
        the classifier's guarantee that nothing was created."""
        invoice = self._failed_issuance(submissions=1)

        queued: list[int] = []
        with patch(
            "apps.billing.issuers.tasks.queue_invoice_issuance", side_effect=lambda pk: queued.append(pk) or "t"
        ):
            sweep_pending_issuances()

        self.assertEqual(queued, [invoice.pk])

    def test_it_stops_after_the_submission_cap(self) -> None:
        """Otherwise a permanent validation error is resubmitted forever against a
        rate-limited third party."""
        self._failed_issuance(submissions=MAX_SUBMISSIONS)

        queued: list[int] = []
        with patch(
            "apps.billing.issuers.tasks.queue_invoice_issuance", side_effect=lambda pk: queued.append(pk) or "t"
        ):
            sweep_pending_issuances()

        self.assertEqual(queued, [], "an exhausted row needs an operator, not another POST")


class SubmissionCounterTests(TransactionTestCase):
    """Drives the real issuance path, which refuses to run inside a transaction."""

    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]

    def test_the_counter_advances_only_when_a_request_was_sent(self) -> None:
        """`attempts` increments on claim, before pacing, so it cannot be the cap:
        a deferral would consume a budget without anything leaving the machine."""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=None,
            status="draft",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
            issuer_provider=ISSUER_SMARTBILL,
        )
        ProviderIssuance.objects.create(invoice=invoice, provider=ISSUER_SMARTBILL)

        with (
            patch(
                "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.prepare",
                return_value=Ok(PreparedDocument(payload={"x": 1}, digest="d")),
            ),
            patch(
                "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.submit", side_effect=RateGateWait(timezone.now())
            ),
        ):
            issue_invoice_externally(invoice.pk)

        paced = ProviderIssuance.objects.get(invoice=invoice)
        self.assertEqual(paced.submissions, 0, "pacing sent nothing, so it costs no budget")
        self.assertEqual(paced.attempts, 1, "but it did consume a claim")

        with (
            patch(
                "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.prepare",
                return_value=Ok(PreparedDocument(payload={"x": 1}, digest="d")),
            ),
            patch(
                "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.submit",
                return_value=Issued(number="000700", series="FCT"),
            ),
        ):
            issue_invoice_externally(invoice.pk)

        sent = ProviderIssuance.objects.get(invoice=invoice)
        self.assertEqual(sent.submissions, 1, "this one actually reached the provider")
