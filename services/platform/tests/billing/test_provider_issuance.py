"""Issuing an invoice through an external provider, and surviving not knowing.

The hazard this whole phase exists for: SmartBill has no idempotency key and no way
to look up a document by our reference. A timeout means an invoice may or may not
exist, with a real number, addressed to a real customer, possibly already forwarded
to ANAF. Retrying that automatically is how one order becomes two legally numbered
invoices — and an invoice that is not last in its series can never be deleted, only
cancelled or reversed.

`TransactionTestCase` throughout: the service refuses to run inside a transaction
(ADR-0045), because the claim must COMMIT before the provider call.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from decimal import Decimal
from unittest.mock import patch

from django.db import transaction
from django.test import TransactionTestCase
from django.utils import timezone

from apps.billing.invoice_models import ISSUER_BUILTIN, ISSUER_SMARTBILL, Currency, Invoice
from apps.billing.issuers.base import Ambiguous, Issued, PreparedDocument, Rejected
from apps.billing.issuers.models import IssuanceState, ProviderIssuance
from apps.billing.issuers.service import (
    IssuanceTransactionError,
    issue_invoice_externally,
    reconcile_confirmed_issued,
)
from apps.billing.issuers.smartbill.client import RateGateWait
from apps.common.types import Ok
from tests.factories.billing_factories import CustomerFactory, InvoiceLineFactory


def _currency(code: str = "RON") -> Currency:
    obj, _ = Currency.objects.get_or_create(code=code, defaults={"symbol": "L", "decimals": 2})
    return obj


class IssuanceTestBase(TransactionTestCase):
    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = _currency()
        self.invoice = Invoice.objects.create(
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
        InvoiceLineFactory(
            invoice=self.invoice,
            description="Hosting",
            quantity=Decimal("1"),
            unit_price_cents=10000,
            tax_rate=Decimal("0.2100"),
            tax_cents=2100,
            line_total_cents=12100,
        )

    def _issue_returning(self, outcome: object) -> object:
        from apps.billing.issuers.base import PreparedDocument  # noqa: PLC0415

        with (
            patch(
                "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.prepare",
                return_value=Ok(PreparedDocument(payload={"seriesName": "TEST"}, digest="abc123")),
            ),
            patch(
                "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.submit",
                return_value=outcome,
            ),
        ):
            return issue_invoice_externally(self.invoice.pk)


class SuccessfulIssuanceTests(IssuanceTestBase):
    def test_the_provider_number_becomes_the_invoice_number(self) -> None:
        result = self._issue_returning(Issued(number="000123", series="FCT", provider_document_id="20363"))

        self.assertTrue(result.is_ok(), msg=getattr(result, "error", ""))
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.number, "FCT-000123")
        self.assertEqual(self.invoice.status, "issued")

    def test_the_attempt_is_recorded_as_issued(self) -> None:
        self._issue_returning(Issued(number="000123", series="FCT"))

        issuance = ProviderIssuance.objects.get(invoice=self.invoice)
        self.assertEqual(issuance.state, IssuanceState.ISSUED.value)
        self.assertEqual(issuance.provider_number, "000123")
        self.assertIsNone(issuance.claim_expires_at, msg="a finished attempt must release its lease")

    def test_an_already_numbered_invoice_is_not_issued_twice(self) -> None:
        """Re-running the task must not create a second legal document."""
        self._issue_returning(Issued(number="000123", series="FCT"))
        before = ProviderIssuance.objects.get(invoice=self.invoice).attempts

        result = issue_invoice_externally(self.invoice.pk)

        self.assertTrue(result.is_ok())
        self.assertEqual(ProviderIssuance.objects.get(invoice=self.invoice).attempts, before)


class RefusedIssuanceTests(IssuanceTestBase):
    def test_a_refusal_leaves_the_invoice_unnumbered_and_retryable(self) -> None:
        result = self._issue_returning(Rejected(errors=("Seria nu a fost gasita!",)))

        self.assertTrue(result.is_err())
        self.invoice.refresh_from_db()
        self.assertIsNone(self.invoice.number)
        self.assertEqual(self.invoice.status, "draft")
        self.assertEqual(ProviderIssuance.objects.get(invoice=self.invoice).state, IssuanceState.FAILED.value)

    def test_a_refused_attempt_may_be_retried(self) -> None:
        """REJECTED means provably nothing was created, so a fix-and-retry is safe."""
        self._issue_returning(Rejected(errors=("bad series",)))
        result = self._issue_returning(Issued(number="000124", series="FCT"))

        self.assertTrue(result.is_ok())
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.number, "FCT-000124")


class UnknownOutcomeTests(IssuanceTestBase):
    """The state this whole model exists for."""

    def test_an_ambiguous_outcome_stops_and_waits_for_a_human(self) -> None:
        result = self._issue_returning(Ambiguous(reason="read timeout after POST"))

        self.assertTrue(result.is_err())
        issuance = ProviderIssuance.objects.get(invoice=self.invoice)
        self.assertEqual(issuance.state, IssuanceState.OUTCOME_UNKNOWN.value)
        self.assertTrue(issuance.needs_human_reconciliation)

    def test_it_is_never_retried_automatically(self) -> None:
        """THE discriminator.

        A second attempt after a lost response is exactly how one order becomes two
        legally numbered invoices. The refusal must come from the state machine, not
        from a caller remembering to check.
        """
        self._issue_returning(Ambiguous(reason="read timeout after POST"))

        result = self._issue_returning(Issued(number="000999", series="FCT"))

        self.assertTrue(result.is_err())
        self.assertIn("reconcile", result.error.lower())
        self.invoice.refresh_from_db()
        self.assertIsNone(self.invoice.number, msg="a second POST must not have happened")

    def test_no_sweep_can_reclaim_it(self) -> None:
        """`abandoned()` finds crashed workers, and must never find this."""
        self._issue_returning(Ambiguous(reason="read timeout after POST"))
        issuance = ProviderIssuance.objects.get(invoice=self.invoice)
        ProviderIssuance.objects.filter(pk=issuance.pk).update(
            claim_expires_at=timezone.now() - timezone.timedelta(hours=1)
        )

        self.assertNotIn(issuance.pk, set(ProviderIssuance.abandoned().values_list("pk", flat=True)))

    def test_an_operator_can_adopt_a_number_they_found(self) -> None:
        """The only way out, and deliberately manual: the provider offers no lookup."""
        self._issue_returning(Ambiguous(reason="read timeout after POST"))
        issuance = ProviderIssuance.objects.get(invoice=self.invoice)

        result = reconcile_confirmed_issued(
            issuance.pk, series="FCT", number="000123", operator_note="found in SmartBill UI"
        )

        self.assertTrue(result.is_ok(), msg=getattr(result, "error", ""))
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.number, "FCT-000123")
        self.assertEqual(self.invoice.status, "issued")


class TransactionBoundaryTests(IssuanceTestBase):
    def test_issuance_refuses_to_run_inside_a_transaction(self) -> None:
        """ADR-0045: the claim must commit BEFORE the provider call.

        Inside an enclosing atomic block the claim is only a savepoint, so a
        rollback would erase PRAHO's record of a call the provider already saw —
        leaving an invoice at SmartBill that PRAHO believes never happened.
        """
        with self.assertRaises(IssuanceTransactionError), transaction.atomic():
            issue_invoice_externally(self.invoice.pk)

    def test_nothing_is_written_when_the_guard_fires(self) -> None:
        try:
            with transaction.atomic():
                issue_invoice_externally(self.invoice.pk)
        except IssuanceTransactionError:
            pass

        self.assertFalse(ProviderIssuance.objects.filter(invoice=self.invoice).exists())


class ClaimTests(IssuanceTestBase):
    def test_a_live_claim_blocks_a_second_worker(self) -> None:
        ProviderIssuance.objects.create(
            invoice=self.invoice,
            provider=ISSUER_SMARTBILL,
            state=IssuanceState.CLAIMED.value,
            claim_token=uuid.uuid4(),
            claim_expires_at=timezone.now() + timezone.timedelta(minutes=5),
        )

        result = self._issue_returning(Issued(number="000999", series="FCT"))

        self.assertTrue(result.is_err())
        self.assertIn("live claim", result.error)

    def test_an_abandoned_claim_is_quarantined_not_retried(self) -> None:
        """THE correction that matters most in this phase.

        A crash immediately BEFORE the POST and one immediately AFTER the provider
        created the document leave identical durable state. Lease expiry therefore
        proves nothing, and retrying on it is how a duplicate fiscal invoice gets
        created. The abandoned claim goes to a human instead.
        """
        ProviderIssuance.objects.create(
            invoice=self.invoice,
            provider=ISSUER_SMARTBILL,
            state=IssuanceState.CLAIMED.value,
            claim_token=uuid.uuid4(),
            claim_expires_at=timezone.now() - timezone.timedelta(minutes=1),
        )

        result = self._issue_returning(Issued(number="000999", series="FCT"))

        self.assertTrue(result.is_err())
        issuance = ProviderIssuance.objects.get(invoice=self.invoice)
        self.assertEqual(issuance.state, IssuanceState.OUTCOME_UNKNOWN.value)
        self.invoice.refresh_from_db()
        self.assertIsNone(self.invoice.number, msg="an abandoned claim must not be re-POSTed")


class AuditTests(IssuanceTestBase):
    def test_every_issuance_attempt_is_audited(self) -> None:
        """Provenance changes who assigns the number, not what must be reconstructable."""
        from apps.audit.models import AuditEvent  # noqa: PLC0415

        self._issue_returning(Issued(number="000123", series="FCT"))

        actions = set(AuditEvent.objects.filter(action__startswith="invoice_provider").values_list("action", flat=True))
        self.assertIn("invoice_provider_issue_attempted", actions)
        self.assertIn("invoice_provider_issued", actions)

    def test_an_unknown_outcome_is_audited_as_such(self) -> None:
        from apps.audit.models import AuditEvent  # noqa: PLC0415

        self._issue_returning(Ambiguous(reason="read timeout after POST"))

        self.assertTrue(
            AuditEvent.objects.filter(action="invoice_provider_outcome_unknown").exists(),
            msg="an outcome nobody knows must be the most visible event of all",
        )


class BuiltinIsUnaffectedTests(IssuanceTestBase):
    def test_a_builtin_invoice_still_issues_locally(self) -> None:
        """The contrast: this path does not go near a provider or a claim row."""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="INV-LOCAL-0001",
            status="draft",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
            issuer_provider=ISSUER_BUILTIN,
        )
        invoice.issue()
        invoice.save()

        invoice.refresh_from_db()
        self.assertEqual(invoice.status, "issued")
        self.assertFalse(ProviderIssuance.objects.filter(invoice=invoice).exists())


class DeferredConversionTests(TransactionTestCase):
    """Conversion under an external issuer: unnumbered, paid, and recoverable."""

    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = _currency()

    def test_an_external_invoice_is_created_unnumbered_with_a_pending_record(self) -> None:
        """The work item must commit WITH the invoice.

        `on_commit` fires in-process. A crash between the conversion commit and the
        callback would otherwise leave an unnumbered invoice and no record that
        anything was meant to issue it.
        """
        from apps.billing.issuers.models import ProviderIssuance  # noqa: PLC0415

        with transaction.atomic():
            invoice = Invoice.objects.create(
                customer=self.customer,
                currency=self.currency,
                number=None,
                status="draft",
                subtotal_cents=10000,
                tax_cents=2100,
                total_cents=12100,
                bill_to_name="Test Company SRL",
                issuer_provider=ISSUER_SMARTBILL,
            )
            ProviderIssuance.objects.get_or_create(invoice=invoice, defaults={"provider": ISSUER_SMARTBILL})

        issuance = ProviderIssuance.objects.get(invoice=invoice)
        self.assertEqual(issuance.state, IssuanceState.PENDING.value)
        self.assertIsNone(invoice.number)

    def test_the_sweep_finds_work_whose_callback_never_ran(self) -> None:
        from apps.billing.issuers.models import ProviderIssuance  # noqa: PLC0415
        from apps.billing.issuers.tasks import sweep_pending_issuances  # noqa: PLC0415

        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=None,
            status="draft",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
            issuer_provider=ISSUER_SMARTBILL,
        )
        ProviderIssuance.objects.create(invoice=invoice, provider=ISSUER_SMARTBILL)

        with patch("apps.billing.issuers.tasks.queue_invoice_issuance", return_value="task-1") as queue:
            result = sweep_pending_issuances()

        queue.assert_called_once_with(invoice.pk)
        self.assertEqual(result["queued"], 1)

    def test_the_sweep_ignores_quarantined_attempts(self) -> None:
        """`outcome_unknown` is never swept by anything. That is its entire purpose."""
        from apps.billing.issuers.models import ProviderIssuance  # noqa: PLC0415
        from apps.billing.issuers.tasks import sweep_pending_issuances  # noqa: PLC0415

        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=None,
            status="draft",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
            issuer_provider=ISSUER_SMARTBILL,
        )
        ProviderIssuance.objects.create(
            invoice=invoice,
            provider=ISSUER_SMARTBILL,
            state=IssuanceState.OUTCOME_UNKNOWN.value,
        )

        with patch("apps.billing.issuers.tasks.queue_invoice_issuance") as queue:
            sweep_pending_issuances()

        queue.assert_not_called()


class ReconciliationGuardTests(IssuanceTestBase):
    def _quarantined(self) -> object:
        self._issue_returning(Ambiguous(reason="read timeout after POST"))
        return ProviderIssuance.objects.get(invoice=self.invoice)

    def test_a_number_is_required(self) -> None:
        result = reconcile_confirmed_issued(self._quarantined().pk, series="FCT", number="   ", operator_note="checked")
        self.assertTrue(result.is_err())

    def test_a_note_is_required(self) -> None:
        """What was checked at the provider is the evidence for the whole decision."""
        result = reconcile_confirmed_issued(self._quarantined().pk, series="FCT", number="000123", operator_note="")
        self.assertTrue(result.is_err())

    def test_the_same_document_cannot_be_adopted_twice(self) -> None:
        """Otherwise two PRAHO invoices would claim one legal number."""
        Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="FCT-000123",
            status="draft",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Other SRL",
        )

        result = reconcile_confirmed_issued(
            self._quarantined().pk, series="FCT", number="000123", operator_note="checked"
        )

        self.assertTrue(result.is_err())
        self.assertIn("already adopted", result.error)


class PacingDoesNotPoisonTheClaimTests(TransactionTestCase):
    """An ordinary burst must cost a wait, not a person.

    The rate gate refuses before anything is sent. If the claim were simply left
    behind, its lease would expire and the sweep would quarantine it into
    `outcome_unknown` - a state only an operator can leave. Traffic the gate exists
    to absorb would then generate manual reconciliation per invoice.
    """

    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})
        self.available_at = timezone.now() + timedelta(seconds=30)

    def _invoice(self) -> Invoice:
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=None,
            status="draft",
            issued_at=timezone.now(),
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
            issuer_provider=ISSUER_SMARTBILL,
            vat_evidence={"version": 1, "scenario": "romania_b2b", "category": "S", "is_business": True},
        )
        ProviderIssuance.objects.create(invoice=invoice, provider=ISSUER_SMARTBILL)
        return invoice

    def test_a_paced_call_returns_the_claim_instead_of_quarantining_it(self) -> None:
        invoice = self._invoice()

        with (
            patch(
                "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.prepare",
                return_value=Ok(PreparedDocument(payload={"x": 1}, digest="d")),
            ),
            patch(
                "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.submit",
                side_effect=RateGateWait(self.available_at),
            ),
        ):
            result = issue_invoice_externally(invoice.pk)

        self.assertTrue(result.is_err())
        issuance = ProviderIssuance.objects.get(invoice=invoice)
        self.assertEqual(
            issuance.state,
            IssuanceState.PENDING.value,
            "pacing must hand the claim back so the sweep retries it",
        )
        self.assertIsNone(issuance.claim_token)
        self.assertNotEqual(issuance.state, IssuanceState.OUTCOME_UNKNOWN.value)

    def test_a_failure_that_might_have_been_sent_never_releases_the_claim(self) -> None:
        """The other direction, and the dangerous one.

        Returning a claim to `pending` is safe for pacing ONLY because the gate
        refuses before anything leaves the machine. A timeout, a reset connection or
        a dead worker look identical whether or not the provider created a document,
        so releasing there would let a retry mint a second legally numbered invoice
        against an API with no idempotency key. Such a failure must leave the claim
        held, to be quarantined rather than retried.
        """
        invoice = self._invoice()

        with (
            patch(
                "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.prepare",
                return_value=Ok(PreparedDocument(payload={"x": 1}, digest="d")),
            ),
            patch(
                "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.submit",
                side_effect=ConnectionResetError("died mid-POST"),
            ),
            self.assertRaises(ConnectionResetError),
        ):
            issue_invoice_externally(invoice.pk)

        issuance = ProviderIssuance.objects.get(invoice=invoice)
        self.assertEqual(
            issuance.state,
            IssuanceState.CLAIMED.value,
            "a failure that may have reached the provider must keep the claim, not hand it back",
        )
        self.assertIsNotNone(issuance.claim_token)
