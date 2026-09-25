"""A worker that dies mid-flight must reach an operator without being asked twice.

`sweep_pending_issuances` selects only `pending` and `failed`, and the reconciliation
queue lists only `outcome_unknown`. A row left in `claimed` by a crashed worker is in
neither, so nothing enqueues it and nothing shows it.

Quarantine happened only when another attempt for the same invoice reached `_claim` -
which depends on a redelivery that may never come, and which `prepare` can fail before,
returning an ordinary task result while the expired claim stays invisible. The existing
coverage reaches that branch by calling `issue_invoice_externally` directly, which is
the one path no scheduler ever takes; that is why the gap survived.

`ProviderIssuance.abandoned()` was written for exactly this and had no caller.
"""

from __future__ import annotations

import uuid
from decimal import Decimal

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.billing.invoice_models import ISSUER_SMARTBILL, Currency, Invoice
from apps.billing.issuers.models import IssuanceState, ProviderIssuance
from apps.billing.issuers.tasks import sweep_abandoned_claims
from tests.factories.billing_factories import CustomerFactory, InvoiceLineFactory
from tests.factories.core_factories import create_admin_user


class AbandonedClaimSweepTests(TestCase):
    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]
        self._seq = 0

    def _claimed(self, *, expired: bool) -> ProviderIssuance:
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
        InvoiceLineFactory(
            invoice=invoice,
            description="Hosting",
            quantity=Decimal("1"),
            unit_price_cents=10000,
            tax_rate=Decimal("0.2100"),
            tax_cents=2100,
            line_total_cents=12100,
        )
        offset = timezone.timedelta(minutes=-30 if expired else 30)
        return ProviderIssuance.objects.create(
            invoice=invoice,
            provider=ISSUER_SMARTBILL,
            state=IssuanceState.CLAIMED.value,
            claim_token=uuid.uuid4(),
            claimed_at=timezone.now(),
            claim_expires_at=timezone.now() + offset,
            request_payload={"seriesName": "TEST"},
            request_hash=f"hash-{self._seq}",
        )

    def test_an_expired_claim_is_quarantined_without_another_attempt(self) -> None:
        """Nothing here calls `issue_invoice_externally`; that is the point."""
        issuance = self._claimed(expired=True)

        result = sweep_abandoned_claims()

        self.assertEqual(result["quarantined"], 1)
        swept = ProviderIssuance.objects.get(pk=issuance.pk)
        self.assertEqual(swept.state, IssuanceState.OUTCOME_UNKNOWN.value)

    def test_a_live_claim_is_left_alone(self) -> None:
        """The regression guard: a worker still inside its lease owns that row."""
        issuance = self._claimed(expired=False)

        result = sweep_abandoned_claims()

        self.assertEqual(result["quarantined"], 0)
        self.assertEqual(
            ProviderIssuance.objects.get(pk=issuance.pk).state,
            IssuanceState.CLAIMED.value,
        )

    def test_the_sweep_never_spends_a_submission(self) -> None:
        """Quarantine is not a retry. Expiry proves nothing about what the provider holds:
        a crash immediately before the POST and one immediately after it created the
        document leave identical durable state."""
        issuance = self._claimed(expired=True)

        sweep_abandoned_claims()

        swept = ProviderIssuance.objects.get(pk=issuance.pk)
        self.assertEqual(swept.submissions, 0)
        self.assertEqual(swept.request_hash, issuance.request_hash, "the frozen payload is the evidence")

    def test_a_quarantined_claim_reaches_the_operator_queue(self) -> None:
        """Visibility is the whole point; a state change nobody can see is not recovery."""
        self._claimed(expired=True)
        sweep_abandoned_claims()
        self.client.force_login(create_admin_user(username="sweep_admin"))

        response = self.client.get(reverse("billing:provider_reconciliation_queue"))

        self.assertContains(response, "abandoned")
