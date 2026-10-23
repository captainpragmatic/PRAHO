"""Stripe outcomes a replay can never fix are acknowledged, recorded and escalated (#751 follow-up, M10/M11).

A dispute with no PaymentIntent, a dispute for a payment PRAHO does not have, a dispute on a refunded or
failed payment, and a success whose facts do not match the local payment were failed and retried until
the retries ran out. Nothing a redelivery carries can change them. They are now acknowledged with the
reason recorded; disputes always send the urgent dispute alert, with the amount and reason, and the
mismatch keeps its evidence row.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from django.test import TestCase

from apps.audit.models import AuditEvent
from apps.billing.models import Currency
from apps.billing.payment_models import Payment
from apps.customers.models import Customer
from apps.integrations.webhooks.stripe import StripeWebhookProcessor
from tests.helpers.fsm_helpers import force_status


class UnfixableOutcomeCase(TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.customer = Customer.objects.create(
            name="Dispute SRL", customer_type="company", status="active", primary_email="dispute@test.ro"
        )

    def _payment(self, gateway_txn_id: str, status: str = "pending") -> Payment:
        payment = Payment.objects.create(
            customer=self.customer, currency=self.currency, amount_cents=12100, payment_method="stripe",
            gateway_txn_id=gateway_txn_id,
        )
        if status != "pending":
            force_status(payment, status)
        return payment

    def _deliver(self, event_type: str, data: dict[str, Any], event_id: str) -> tuple[bool, Any]:
        processor = StripeWebhookProcessor()
        with (
            patch.object(processor, "verify_signature", return_value=True),
            patch("apps.notifications.services.NotificationService.send_admin_alert", return_value=True) as alert,
        ):
            success, _message, event = processor.process_webhook(
                {"id": event_id, "type": event_type, "created": 100, "data": {"object": data}}, signature="ok"
            )
        event.refresh_from_db()
        self.assertEqual((success, event.status), (True, "processed"), "acknowledged: a replay cannot fix it")
        return success, alert


class DisputeTests(UnfixableOutcomeCase):
    def _dispute(self, **fields: Any) -> dict[str, Any]:
        return {"id": "dp_1", "amount": 12100, "currency": "ron", "reason": "fraudulent", **fields}

    def _assert_urgent(self, alert: Any) -> None:
        self.assertEqual(alert.call_count, 1)
        kwargs = alert.call_args.kwargs
        self.assertTrue(kwargs["subject"].startswith("URGENT"))
        self.assertIn("fraudulent", kwargs["message"])
        self.assertIn("121.00", kwargs["message"])

    def test_a_dispute_on_a_refunded_payment_is_escalated(self) -> None:
        self._payment("pi_refunded", status="refunded")

        _success, alert = self._deliver("charge.dispute.created", self._dispute(payment_intent="pi_refunded"), "evt_d1")

        self._assert_urgent(alert)

    def test_a_dispute_without_a_payment_intent_is_escalated(self) -> None:
        _success, alert = self._deliver("charge.dispute.created", self._dispute(), "evt_d2")

        self._assert_urgent(alert)

    def test_an_escalation_that_was_not_delivered_is_retried(self) -> None:
        processor = StripeWebhookProcessor()
        payload = {"id": "evt_d4", "type": "charge.dispute.created", "created": 100, "data": {"object": self._dispute()}}
        with (
            patch.object(processor, "verify_signature", return_value=True),
            patch("apps.notifications.services.NotificationService.send_admin_alert", return_value=False),
        ):
            success, _message, event = processor.process_webhook(payload, signature="ok")

        event.refresh_from_db()
        self.assertEqual((success, event.status), (False, "failed"), "the urgent alert must reach staff")
        self.assertIsNotNone(event.next_retry_at)

    def test_a_dispute_for_a_payment_praho_does_not_have_is_escalated(self) -> None:
        _success, alert = self._deliver("charge.dispute.created", self._dispute(payment_intent="pi_unknown"), "evt_d3")

        self._assert_urgent(alert)


class MismatchTests(UnfixableOutcomeCase):
    def test_a_success_whose_amount_does_not_match_is_acknowledged_with_its_evidence(self) -> None:
        payment = self._payment("pi_mismatch_ack")

        self._deliver(
            "payment_intent.succeeded", {"id": "pi_mismatch_ack", "amount_received": 999, "currency": "ron"}, "evt_m1"
        )

        payment.refresh_from_db()
        self.assertEqual(payment.status, "pending", "the refused fact is not applied")
        self.assertTrue(
            AuditEvent.objects.filter(action="payment_gateway_fact_mismatch", metadata__payment_id=str(payment.id)).exists()
        )

    def test_a_mismatch_found_while_recovering_an_unlinked_attempt_stays_permanent(self) -> None:
        from apps.billing.payment_convergence import PaymentSuccessService  # noqa: PLC0415
        from apps.common.types import Err, Retriability, retriability_of  # noqa: PLC0415

        refused = Err("Gateway amount mismatch", retriability=Retriability.NOT_RETRIABLE)
        with patch.object(PaymentSuccessService, "recover_unlinked_recurring_attempt", return_value=refused):
            result = PaymentSuccessService.converge_gateway_success("pi_unlinked", {"amount_received": 1})

        self.assertIs(retriability_of(result), Retriability.NOT_RETRIABLE, "a webhook acknowledges it, not retries")
