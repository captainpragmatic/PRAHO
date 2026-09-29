"""Funding and delivery state changes are auditable without bearer credentials."""

from unittest.mock import patch

from django.contrib.contenttypes.models import ContentType
from django.test import TestCase

from apps.audit.models import AuditEvent
from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.promotions.gift_cards import create_purchase, record_bank_funding, start_funding
from apps.promotions.gift_refunds import record_bank_refund, reserve_funding_refund
from apps.promotions.models import GiftCardDelivery, GiftCardFundingAttempt
from apps.promotions.tasks import reconcile_gift_funding
from apps.users.models import User


class GiftRecordAuditTests(TestCase):
    def setUp(self) -> None:
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "RON"})[0]
        self.customer = Customer.objects.create(name="Audit buyer", primary_email="buyer@example.test")
        self.actor = User.objects.create_user(email="billing@example.test", staff_role="billing")
        self.purchase = create_purchase(
            self.customer, self.currency, 5000, "audit-gift", actor=self.actor,
            recipient={"email": "private-recipient@example.test", "name": "Recipient", "message": "Private gift message"},
        )
        with patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.create_payment_intent.return_value = {
                "success": True, "payment_intent_id": "pi_gift_audit",
                "client_secret": "gift-client-secret-canary", "error": None,
            }
            start_funding(self.purchase)
        self.attempt = GiftCardFundingAttempt.objects.get(purchase=self.purchase)

    def _events(self, record):
        return AuditEvent.objects.filter(
            content_type=ContentType.objects.get_for_model(record), object_id=str(record.pk),
        ).order_by("timestamp")

    def _assert_private_values_absent(self, events):
        captured = str(list(events.values("description", "new_values", "old_values", "metadata")))
        for private in (self.purchase.gift_card.code, "gift-client-secret-canary",
                        "private-recipient@example.test", "Private gift message"):
            self.assertNotIn(private, captured)

    def test_funding_attempt_creation_and_provider_state_are_audited_without_client_secret(self) -> None:
        self.attempt.status = "processing"
        self.attempt.save(update_fields=["status"])
        events = self._events(self.attempt)
        self.assertGreaterEqual(events.count(), 2)
        event = events.last()
        self.assertEqual(event.new_values["purchase_id"], str(self.purchase.pk))
        self.assertEqual(event.new_values["currency_id"], "RON")
        self.assertEqual(event.new_values["amount_cents"], 5000)
        self.assertEqual(event.new_values["status"], "processing")
        self.assertNotIn("request_metadata", event.new_values)
        self._assert_private_values_absent(events)

    def test_invalid_recovery_is_audited_when_the_attempt_requires_review(self) -> None:
        with patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.confirm_payment.return_value = {
                "success": True, "status": "succeeded", "amount": 5000, "amount_received": 4999,
                "currency": "ron", "metadata": self.attempt.request_metadata,
            }
            report = reconcile_gift_funding()
        self.assertEqual(report["needs_review"], 1)
        self.assertEqual(self._events(self.attempt).last().new_values["status"], "needs_review")

    def test_delivery_state_is_audited_without_address_or_message(self) -> None:
        delivery = GiftCardDelivery.objects.create(
            purchase=self.purchase, purpose="voucher", target_email=self.purchase.gift_card.recipient_email,
        )
        delivery.status = "failed"
        delivery.error_code = "provider_unavailable"
        delivery.attempt_count = 1
        delivery.save(update_fields=["status", "error_code", "attempt_count"])
        events = self._events(delivery)
        self.assertEqual(events.count(), 2)
        self.assertEqual(events.last().new_values["purpose"], "voucher")
        self.assertEqual(events.last().new_values["attempt_count"], 1)
        self.assertEqual(events.last().new_values["error_code"], "provider_unavailable")
        self._assert_private_values_absent(events)

    def test_refund_hold_and_bank_confirmation_actor_have_safe_audit_fields(self) -> None:
        purchase = create_purchase(self.customer, self.currency, 5000, "bank-audit", method="bank", actor=self.actor)
        record_bank_funding(purchase.pk, reference="QA-FUNDED", actor=self.actor)
        refund = reserve_funding_refund(purchase.pk, 3000, "audit-refund", actor=self.actor)
        confirmer = User.objects.create_user(email="confirmer@example.test", staff_role="billing")
        record_bank_refund(refund.pk, reference="QA-REFUNDED", actor=confirmer)
        events = self._events(refund)
        self.assertEqual(events.count(), 2)
        self.assertEqual(events.first().new_values["held_cents"], 3000)
        self.assertEqual(events.last().new_values["held_cents"], 0)
        self.assertEqual(events.last().new_values["applied_cents"], 3000)
        self.assertEqual(events.last().new_values["currency_id"], "RON")
        self.assertEqual(events.last().new_values["confirmed_by_id"], confirmer.pk)
        self.assertEqual(events.last().user_id, confirmer.pk)
        self._assert_private_values_absent(events)
        self.assertNotIn(purchase.gift_card.code, str(list(events.values("description", "new_values"))))
