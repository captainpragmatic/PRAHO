"""The evidence of a refused gateway fact survives the refusal's rollback (#751 follow-up, M9b).

A payment_intent.succeeded whose amount does not match the local payment is refused (and, since no
redelivery can fix it, acknowledged). The structured payment_gateway_fact_mismatch audit row was written
inside the webhook executor's savepoint and rolled back with it whenever the handler refused. Refusal evidence is now written after the rollback; the
state-change audits of the refused work stay transaction-bound.
"""

from __future__ import annotations

from django.test import TestCase

from apps.audit.models import AuditEvent
from apps.billing.models import Currency
from apps.billing.payment_models import Payment
from apps.customers.models import Customer
from apps.integrations.models import WebhookEvent
from apps.integrations.webhooks.stripe import StripeWebhookProcessor


class RefusalEvidenceTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        customer = Customer.objects.create(
            name="Mismatch SRL", customer_type="company", status="active", primary_email="mismatch@test.ro"
        )
        self.payment = Payment.objects.create(
            customer=customer, currency=currency, amount_cents=12100, payment_method="stripe",
            gateway_txn_id="pi_amount_mismatch",
        )

    def test_a_gateway_mismatch_keeps_its_evidence_after_the_refusal(self) -> None:
        event = WebhookEvent.objects.create(
            source="stripe", event_id="evt_amount_mismatch", event_type="payment_intent.succeeded", status="pending",
            payload={
                "type": "payment_intent.succeeded",
                "data": {"object": {"id": "pi_amount_mismatch", "amount_received": 999, "currency": "ron"}},
            },
        )

        result = StripeWebhookProcessor()._execute_locked(event)

        self.assertTrue(result.success, "acknowledged: no redelivery can fix a mismatch")
        self.payment.refresh_from_db()
        self.assertEqual(self.payment.status, "pending", "the refused fact is not applied")
        evidence = AuditEvent.objects.filter(
            action="payment_gateway_fact_mismatch", metadata__payment_id=str(self.payment.id)
        )
        self.assertEqual(evidence.count(), 1, "the evidence of the refusal is kept, once")
