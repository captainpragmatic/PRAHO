"""The abandoned-claim sweep logged a count, not which documents it quarantined.

The identical quarantine in `_claim` names the invoice, and both call sites pass the same
`reason=` string, so they are one event logged two ways - one of them answerable at 3am and one
of them not. `outcome_unknown` means a fiscal document may exist at the provider that PRAHO
cannot look up, so "quarantined 4" without the four invoice ids is the wrong half of the
information.

The rollup stays at `warning` deliberately. It is a gauge over a standing backlog, which is why
the exhausted count beside it was downgraded from error with the note "A gauge, not an event".
The per-row line is the event, and it matches `_claim`'s wording so the two cannot drift.

Scope note, because the finding arrived overstated: it was reported as emitting no audit event
at all. That is wrong. `mark_outcome_unknown()` + `save()` fires the `post_save` receiver
`handle_issuance_audit`, which maps the state to `invoice_provider_outcome_unknown`, names the
invoice and records the frozen payload hash. The audit trail exists; only the log line was
anonymous. The one real gap - the quarantine REASON lives in the mutable `last_error` and not in
the audit payload - is deliberately not addressed here: wiring it in would change the payload of
every issuance transition, which is a wider blast radius than this warrants.
"""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from uuid import uuid4

from django.test import TestCase
from django.utils import timezone

from apps.billing.invoice_models import ISSUER_SMARTBILL, Currency, Invoice
from apps.billing.issuers.models import IssuanceState, ProviderIssuance
from apps.billing.issuers.tasks import sweep_abandoned_claims
from tests.factories.billing_factories import CustomerFactory, InvoiceLineFactory

LOGGER = "apps.billing.issuers.tasks"


class AbandonedClaimLogTests(TestCase):
    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]
        self._seq = 0

    def _abandoned(self) -> ProviderIssuance:
        self._seq += 1
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=None,
            status="draft",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name=f"Customer {self._seq}",
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
        issuance = ProviderIssuance.objects.create(invoice=invoice, provider=ISSUER_SMARTBILL)
        ProviderIssuance.objects.filter(pk=issuance.pk).update(
            state=IssuanceState.CLAIMED.value,
            claim_token=uuid4(),
            claimed_at=timezone.now() - timedelta(hours=1),
            claim_expires_at=timezone.now() - timedelta(minutes=50),
        )
        return ProviderIssuance.objects.get(pk=issuance.pk)

    def test_each_quarantined_document_is_named(self) -> None:
        first = self._abandoned()
        second = self._abandoned()

        with self.assertLogs(LOGGER, level="ERROR") as captured:
            sweep_abandoned_claims()

        emitted = "\n".join(captured.output)
        self.assertIn(str(first.invoice_id), emitted)
        self.assertIn(str(second.invoice_id), emitted)

    def test_the_per_row_line_matches_the_claim_paths_wording(self) -> None:
        """One event, two call sites; wording that drifts is how they stop being one event."""
        issuance = self._abandoned()

        with self.assertLogs(LOGGER, level="ERROR") as captured:
            sweep_abandoned_claims()

        self.assertIn("had an abandoned claim", "\n".join(captured.output))
        self.assertEqual(
            ProviderIssuance.objects.get(pk=issuance.pk).state,
            IssuanceState.OUTCOME_UNKNOWN.value,
        )

    def test_the_rollup_stays_a_warning(self) -> None:
        """A gauge over a standing backlog, not an event - the same call the exhausted count is."""
        self._abandoned()

        with self.assertLogs(LOGGER, level="WARNING") as captured:
            sweep_abandoned_claims()

        rollup = [line for line in captured.output if "Quarantined" in line]
        self.assertEqual(len(rollup), 1)
        self.assertTrue(rollup[0].startswith("WARNING"), rollup[0])

    def test_a_live_claim_is_left_alone_and_logs_nothing(self) -> None:
        issuance = self._abandoned()
        ProviderIssuance.objects.filter(pk=issuance.pk).update(
            claim_expires_at=timezone.now() + timedelta(minutes=10)
        )

        with self.assertNoLogs(LOGGER, level="ERROR"):
            result = sweep_abandoned_claims()

        self.assertEqual(result["quarantined"], 0)
        self.assertEqual(ProviderIssuance.objects.get(pk=issuance.pk).state, IssuanceState.CLAIMED.value)
