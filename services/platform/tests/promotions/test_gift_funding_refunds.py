"""Local holds and verified facts preserve original gift funding and dispute freezes."""

from decimal import Decimal
from unittest.mock import patch

from django.core.exceptions import PermissionDenied, ValidationError
from django.test import TestCase
from django.utils import timezone

from apps.billing.currency_policy import get_selling_currency_policy
from apps.billing.models import Currency, FXRate
from apps.billing.refund_service import RefundConvergenceService
from apps.common.types import Retriability, retriability_of
from apps.customers.models import Customer
from apps.integrations.webhooks.stripe import StripeWebhookProcessor
from apps.promotions.gift_cards import activate_verified_purchase, create_purchase, preview_value, record_bank_funding
from apps.promotions.gift_refunds import converge_gift_refund, record_bank_refund, reserve_funding_refund
from apps.promotions.models import GiftCardTransaction
from apps.settings.services import SettingsService
from apps.users.models import User


class GiftFundingRefundTests(TestCase):
    def setUp(self) -> None:
        self.currencies = {
            code: Currency.objects.get_or_create(code=code, defaults={"symbol": code})[0]
            for code in ("RON", "EUR", "USD")
        }
        for code in ("EUR", "USD"):
            FXRate.objects.create(
                base_code=self.currencies[code], quote_code=self.currencies["RON"], rate=Decimal("5"),
                as_of=timezone.localdate(), source="bnr", source_reference="https://bnr.ro/rate",
                fetched_at=timezone.now(),
            )
        self.customer = Customer.objects.create(
            name="Refund buyer", customer_type="individual", primary_email="buyer@example.test"
        )
        self.staff = User.objects.create_user(email="refund-staff@example.test", staff_role="billing")
        self.buyer = User.objects.create_user(email="buyer@example.test")
        self.purchase = self._fund("RON")

    def _fund(self, currency, method="stripe"):
        purchase = create_purchase(self.customer, self.currencies[currency], 5000, currency + method, method=method)
        if method == "bank":
            return record_bank_funding(purchase.pk, reference="BANK-FUND", actor=self.staff)
        payment = purchase.funding_payment
        payment.succeed()
        payment.gateway_txn_id = f"pi_refund_{currency}"
        payment.meta = {"stripe_amount_received": 5000, "stripe_currency": currency.lower()}
        payment.save()
        return activate_verified_purchase(purchase.pk)

    def _reserve(self, amount=3000, key="refund", purchase=None):
        return reserve_funding_refund((purchase or self.purchase).pk, amount, key, actor=self.staff)

    def _facts(self, *, amount=3000, status="succeeded", refund_id="re_gift", purchase=None, **extra):
        purchase = purchase or self.purchase
        refund = purchase.funding_refunds.filter(amount_cents=amount, created_by__isnull=False).first()
        return {
            "refund_id": refund_id, "payment_intent_id": purchase.funding_payment.gateway_txn_id,
            "amount_cents": amount, "currency": purchase.gift_card.currency_id.lower(), "status": status,
            "metadata": {"gift_refund_id": str(refund.pk)} if refund else {}, **extra,
        }

    def test_reserved_value_cannot_be_spent_and_verified_failure_releases_once(self) -> None:
        refund = self._reserve()
        self.assertEqual(refund.status, "reserved")
        self.assertEqual(preview_value(self.purchase.gift_card.code, "RON", 5000)["amount_cents"], 2000)
        for _ in range(2):
            self.assertTrue(converge_gift_refund(self._facts(status="failed")).is_ok())
        self.purchase.gift_card.refresh_from_db()
        self.assertEqual((self.purchase.gift_card.current_balance_cents, self.purchase.gift_card.refund_held_cents), (5000, 0))

    def test_success_captures_once_in_each_original_currency_after_real_default_switch(self) -> None:
        SettingsService.update_setting("billing.default_currency", "EUR")
        self.assertEqual(get_selling_currency_policy().currency_code, "EUR")
        for code in ("RON", "EUR", "USD"):
            with self.subTest(currency=code):
                purchase = self.purchase if code == "RON" else self._fund(code)
                refund = self._reserve(key=code, purchase=purchase)
                for _ in range(2):
                    result = RefundConvergenceService.converge_gateway_refund(
                        self._facts(purchase=purchase, refund_id=f"re_{code}")
                    )
                    self.assertTrue(result.is_ok())
                refund.refresh_from_db()
                self.assertEqual((refund.status, refund.currency_id), ("succeeded", code))
                purchase.gift_card.refresh_from_db()
                self.assertEqual((purchase.gift_card.current_balance_cents, purchase.gift_card.refund_held_cents), (2000, 0))
                self.assertEqual(GiftCardTransaction.objects.filter(operation_key=f"funding-refund:{refund.pk}").count(), 1)

    def test_pending_holds_limit_additional_refunds_and_reject_changed_replay(self) -> None:
        original = self._reserve()
        self.assertTrue(converge_gift_refund(self._facts(status="pending")).is_ok())
        self.assertEqual(self._reserve().pk, original.pk)
        with self.assertRaises(ValidationError):
            self._reserve(amount=3000, key="too-much")
        with self.assertRaises(ValidationError):
            self._reserve(amount=2000)
        self.purchase.gift_card.refresh_from_db()
        self.assertEqual(self.purchase.gift_card.refund_held_cents, 3000)

    def test_wrong_currency_amount_or_metadata_cannot_release_or_capture_local_hold(self) -> None:
        self._reserve()
        for changes in ({"currency": "usd"}, {"amount_cents": 2999},
                        {"metadata": {"gift_refund_id": "00000000-0000-0000-0000-000000000001"}}):
            with self.subTest(changes=changes):
                result = converge_gift_refund(self._facts(**changes))
                self.assertTrue(result.is_err())
                self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)
        self.purchase.gift_card.refresh_from_db()
        self.assertEqual((self.purchase.gift_card.current_balance_cents, self.purchase.gift_card.refund_held_cents), (5000, 3000))

    def test_external_refund_after_spending_freezes_shortfall_for_review(self) -> None:
        card = self.purchase.gift_card
        card.current_balance_cents = 2000
        card.status = "partially_used"
        card.save(update_fields=["current_balance_cents", "status"])
        result = converge_gift_refund(self._facts(amount=5000))
        self.assertTrue(result.is_ok())
        card.refresh_from_db()
        self.assertEqual(card.current_balance_cents, 0)
        self.assertIsNotNone(card.spending_frozen_at)
        self.assertIn("refund", card.spending_freeze_reason)
        self.assertEqual(result.unwrap().shortfall_cents, 3000)

    def test_bank_confirmation_requires_staff_and_never_calls_gateway(self) -> None:
        purchase = self._fund("USD", method="bank")
        with patch("apps.billing.gateways.PaymentGatewayFactory.create_gateway") as factory:
            refund = self._reserve(purchase=purchase)
            self.assertEqual(refund.status, "awaiting_bank_transfer")
            with self.assertRaises(PermissionDenied):
                record_bank_refund(refund.pk, reference="BANK-REFUND", actor=self.buyer)
            confirmed = record_bank_refund(refund.pk, reference="BANK-REFUND", actor=self.staff)
            self.assertEqual(record_bank_refund(refund.pk, reference="BANK-REFUND", actor=self.staff).pk, refund.pk)
            factory.assert_not_called()
        self.assertEqual((confirmed.status, confirmed.bank_reference), ("succeeded", "BANK-REFUND"))
        purchase.gift_card.refresh_from_db()
        self.assertEqual((purchase.gift_card.current_balance_cents, purchase.gift_card.refund_held_cents), (2000, 0))

    def test_dispute_freeze_survives_ordinary_card_status_restoration(self) -> None:
        with patch("apps.notifications.services.NotificationService.send_admin_alert"):
            accepted, _message = StripeWebhookProcessor().handle_charge_event("charge.dispute.created", {
                "data": {"object": {"id": "dp_gift", "payment_intent": "pi_refund_RON", "amount": 5000, "currency": "ron"}}
            })
        self.assertTrue(accepted)
        card = self.purchase.gift_card
        card.refresh_from_db()
        self.assertIsNotNone(card.spending_frozen_at)
        card.status = "active"
        card.save(update_fields=["status"])
        with self.assertRaises(ValidationError):
            preview_value(card.code, "RON", 5000)

    def test_late_failed_refund_restores_only_its_recorded_debit_once(self) -> None:
        self._reserve()
        now = int(timezone.now().timestamp())
        self.assertTrue(converge_gift_refund(self._facts(event_created=now)).is_ok())
        for _ in range(2):
            self.assertTrue(converge_gift_refund(self._facts(status="failed", event_created=now + 1)).is_ok())
        self.assertTrue(converge_gift_refund(self._facts(event_created=now)).is_ok())
        self.purchase.gift_card.refresh_from_db()
        self.assertEqual(self.purchase.gift_card.current_balance_cents, 5000)

    def test_verified_refund_webhook_binds_the_exact_local_record(self) -> None:
        refund = self._reserve()
        for _ in range(2):
            accepted, _message = StripeWebhookProcessor().handle_refund_event("refund.updated", {
                "id": "evt_gift_refund", "created": int(timezone.now().timestamp()),
                "data": {"object": {
                    "id": "re_webhook", "payment_intent": "pi_refund_RON", "amount": 3000,
                    "currency": "ron", "status": "succeeded", "metadata": {"gift_refund_id": str(refund.pk)},
                }},
            })
            self.assertTrue(accepted)
        refund.refresh_from_db()
        self.assertEqual((refund.gateway_refund_id, refund.status, refund.applied_cents), ("re_webhook", "succeeded", 3000))

    def test_full_refund_hold_and_independent_freeze_disable_reveal(self) -> None:
        self.purchase.refresh_from_db()
        self.assertTrue(self.purchase.can_reveal_code)
        self._reserve(amount=5000)
        self.purchase.refresh_from_db()
        self.assertFalse(self.purchase.can_reveal_code)
        self.assertTrue(converge_gift_refund(self._facts(amount=5000, status="failed")).is_ok())
        self.purchase.refresh_from_db()
        self.assertTrue(self.purchase.can_reveal_code)
        card = self.purchase.gift_card
        card.spending_frozen_at = timezone.now()
        card.spending_freeze_reason = "funding_dispute:dp_test"
        card.save(update_fields=["spending_frozen_at", "spending_freeze_reason"])
        self.purchase.refresh_from_db()
        self.assertFalse(self.purchase.can_reveal_code)
