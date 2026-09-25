"""The retry budget lived only in the sweep's WHERE clause, so nothing enforced it.

`MAX_SUBMISSIONS` decided which rows `sweep_pending_issuances` picked up, but `_claim` -
the one place that takes exclusive ownership before a provider call - never looked at
it. Two sweeps running before a worker drains the queue enqueue the same row twice,
and each enqueued task claims and submits, so the count walks past the cap. The budget
exists because a permanent validation error would otherwise be resubmitted forever
against a rate-limited third party.

The cap is checked AFTER the issued / outcome_unknown / claimed branches on purpose: a
row that may already have created a document at the provider needs a human regardless
of how much budget it has left, and a refusal to claim must never displace that.
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase, TransactionTestCase
from django.urls import reverse
from django.utils import timezone

from apps.billing.invoice_models import ISSUER_SMARTBILL, Currency, Invoice
from apps.billing.issuers.base import PreparedDocument, Rejected
from apps.billing.issuers.models import MAX_SUBMISSIONS, IssuanceState, ProviderIssuance
from apps.billing.issuers.service import issue_invoice_externally
from apps.billing.issuers.smartbill.client import RateGateWait
from apps.common.types import Ok
from tests.factories.billing_factories import CustomerFactory, InvoiceLineFactory
from tests.factories.core_factories import create_admin_user


def _currency() -> Currency:
    obj, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})
    return obj


def _unnumbered_invoice(customer: object, currency: Currency) -> Invoice:
    invoice = Invoice.objects.create(
        customer=customer,
        currency=currency,
        number=None,
        status="draft",
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


class SubmissionBudgetTests(TransactionTestCase):
    """The service refuses to run inside a transaction, so this cannot be a TestCase."""

    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.invoice = _unnumbered_invoice(self.customer, _currency())

    def _issuance(self, *, state: str, submissions: int) -> ProviderIssuance:
        issuance = ProviderIssuance.objects.create(
            invoice=self.invoice,
            provider=ISSUER_SMARTBILL,
            state=state,
            last_error="Provider refused: seriesName is required",
        )
        ProviderIssuance.objects.filter(pk=issuance.pk).update(submissions=submissions)
        return ProviderIssuance.objects.get(pk=issuance.pk)

    def _attempt(self) -> tuple[object, object]:
        """Drive the real entry point; the provider call is the thing that must not happen."""
        with (
            patch(
                "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.prepare",
                return_value=Ok(PreparedDocument(payload={"seriesName": "TEST"}, digest="abc123")),
            ),
            patch(
                "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.submit",
                # A real refusal rather than a bare mock: when the claim IS admitted the
                # flow runs on into `_finalize`, which exhausts the outcome union and
                # would otherwise fail on the mock instead of on the assertion under test.
                return_value=Rejected(errors=("seriesName is required",)),
            ) as submit,
        ):
            return issue_invoice_externally(self.invoice.pk), submit

    def test_a_spent_budget_refuses_the_claim(self) -> None:
        self._issuance(state=IssuanceState.FAILED.value, submissions=MAX_SUBMISSIONS)

        result, submit = self._attempt()

        self.assertTrue(result.is_err(), "a spent budget must not reach the provider")
        submit.assert_not_called()
        self.assertIn(
            "submission attempts",
            str(result.error),
            f"the operator has to be told WHICH guard fired; got {result.error}",
        )

    def test_the_refusal_leaves_the_evidence_untouched(self) -> None:
        """An operator decides what happens next, so the counters and the provider's
        own words have to survive the refusal intact."""
        self._issuance(state=IssuanceState.FAILED.value, submissions=MAX_SUBMISSIONS)

        self._attempt()

        unchanged = ProviderIssuance.objects.get(invoice=self.invoice)
        self.assertEqual(unchanged.state, IssuanceState.FAILED.value)
        self.assertEqual(unchanged.submissions, MAX_SUBMISSIONS)
        self.assertIn("seriesName is required", unchanged.last_error)

    def test_a_budget_still_remaining_claims_normally(self) -> None:
        """The regression guard: the cap must not refuse a row that has attempts left."""
        self._issuance(state=IssuanceState.FAILED.value, submissions=MAX_SUBMISSIONS - 1)

        _result, submit = self._attempt()

        submit.assert_called_once()

    def test_an_uncertain_outcome_outranks_the_budget(self) -> None:
        """Both refuse, so what matters is WHICH reason the operator is given.

        A row that may hold a document at the provider needs reconciliation, not a
        note about retries; asserting only "it was refused" would pass either way.
        """
        self._issuance(state=IssuanceState.OUTCOME_UNKNOWN.value, submissions=MAX_SUBMISSIONS)

        result, _submit = self._attempt()

        self.assertIn("reconcile", str(result.error).lower(), f"got {result.error}")

    def test_an_abandoned_claim_at_the_cap_is_still_quarantined(self) -> None:
        """Quarantine is a state change, so a cap check placed too early would skip it."""
        issuance = self._issuance(state=IssuanceState.CLAIMED.value, submissions=MAX_SUBMISSIONS)
        ProviderIssuance.objects.filter(pk=issuance.pk).update(
            claim_expires_at=timezone.now() - timezone.timedelta(hours=2)
        )

        self._attempt()

        quarantined = ProviderIssuance.objects.get(pk=issuance.pk)
        self.assertEqual(quarantined.state, IssuanceState.OUTCOME_UNKNOWN.value)


    def test_pacing_does_not_spend_the_budget(self) -> None:
        """A deferral is not a submission, and the cap must not count it as one.

        `RateGateWait` is raised BEFORE anything leaves the machine, so the claim is
        handed back and the sweep retries. `submissions` is incremented in `_finalize`,
        which a deferral never reaches - that placement is what keeps an ordinary
        rate-limited burst, exactly what the gate exists to absorb, from filling the
        operator queue instead. Nothing pinned it, so moving the increment into
        `claim()` would leave every test green.
        """
        for _ in range(MAX_SUBMISSIONS + 2):
            with (
                patch(
                    "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.prepare",
                    return_value=Ok(PreparedDocument(payload={"seriesName": "TEST"}, digest="abc123")),
                ),
                patch(
                    "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.submit",
                    side_effect=RateGateWait(timezone.now() + timezone.timedelta(minutes=5)),
                ),
            ):
                issue_invoice_externally(self.invoice.pk)

        paced = ProviderIssuance.objects.get(invoice=self.invoice)
        self.assertEqual(paced.submissions, 0, "pacing sent nothing, so it costs no budget")
        self.assertEqual(paced.state, IssuanceState.PENDING.value, "the claim must be handed back")

class ExhaustedRowVisibilityTests(TestCase):
    """A refusal the sweep has stopped picking up appears on no screen at all.

    It is excluded from the sweep by the same cap that stops it retrying, so no further
    `_claim` may ever happen for it - visibility cannot wait for one. It is NOT relabelled
    `outcome_unknown`: a known rejection created nothing, and an uncertain issuance may
    have created a real fiscal document. Those need different operator actions.
    """

    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = _currency()
        self.client.force_login(create_admin_user(username="budget_admin"))

    def _exhausted(self) -> ProviderIssuance:
        invoice = _unnumbered_invoice(self.customer, self.currency)
        issuance = ProviderIssuance.objects.create(
            invoice=invoice,
            provider=ISSUER_SMARTBILL,
            state=IssuanceState.FAILED.value,
            last_error="Provider refused: seriesName is required",
        )
        ProviderIssuance.objects.filter(pk=issuance.pk).update(submissions=MAX_SUBMISSIONS)
        return issuance

    def test_an_exhausted_row_is_listed(self) -> None:
        self._exhausted()

        response = self.client.get(reverse("billing:provider_reconciliation_queue"))

        self.assertContains(response, "seriesName is required")

    def test_a_row_with_budget_left_is_not_listed(self) -> None:
        """The regression guard: the queue is work an operator must do, not a log."""
        issuance = self._exhausted()
        ProviderIssuance.objects.filter(pk=issuance.pk).update(submissions=MAX_SUBMISSIONS - 1)

        response = self.client.get(reverse("billing:provider_reconciliation_queue"))

        self.assertNotContains(response, "seriesName is required")
