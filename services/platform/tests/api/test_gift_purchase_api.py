"""Public voucher purchases enforce signed billing roles and recorded money."""

from datetime import timedelta
from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.models import Currency, FXRate
from apps.customers.models import Customer
from apps.promotions.gift_cards import create_purchase, record_bank_funding
from apps.promotions.gift_funding import converge_gift_funding
from apps.promotions.gift_refunds import reserve_funding_refund
from apps.promotions.models import GiftCardFundingAttempt, GiftCardPurchase
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService
from apps.users.models import CustomerMembership, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
class GiftPurchaseAPITests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        self.ron = Currency.objects.get_or_create(code="RON", defaults={"symbol": "RON"})[0]
        self.eur = Currency.objects.get_or_create(code="EUR", defaults={"symbol": "EUR"})[0]
        FXRate.objects.create(
            base_code=self.eur, quote_code=self.ron, rate=Decimal("4.97"), as_of=timezone.localdate(),
            source=FXRate.Source.BNR, source_reference="gift-api-test", fetched_at=timezone.now(),
        )
        self.customer = Customer.objects.create(name="Voucher buyer", primary_email="account@example.test", status="active")
        self.actor = User.objects.create_user(email="buyer@example.test")
        self.membership = CustomerMembership.objects.create(customer=self.customer, user=self.actor, role="owner")
        for key, value, kind in (
            ("promotions.gift_card_sales_enabled", True, "boolean"),
            ("promotions.gift_card_denominations", {"RON": [5000], "EUR": [1000]}, "json"),
            ("promotions.gift_card_payment_methods", ["bank"], "list"),
            ("billing.bank_accounts", {
                code: {"beneficiary": "QA Seller", "bank_name": "QA Bank", "iban": "RO49AAAA1B31007593840000"}
                for code in ("RON", "EUR")
            }, "json"),
        ):
            SystemSetting.objects.update_or_create(
                key=key, defaults={"value": value, "default_value": value, "category": "billing", "data_type": kind,
                                   "name": key, "description": "Gift API test configuration"}
            )
            self.addCleanup(SettingsService._clear_setting_cache, key)
        self.payload = {
            "currency": "RON", "currency_revision": 1, "amount_cents": 5000,
            "payment_method": "bank", "idempotency_key": "gift-api-purchase",
            "is_gift": False, "recipient": {"email": "", "name": "", "message": ""},
        }

    def post(self, action: str, payload: dict | None = None):
        return self.portal_post(f"/api/billing/gift-cards/{action}/", {
            "customer_id": self.customer.pk, "user_id": self.actor.pk, **(payload or {}),
        })

    def create(self):
        response = self.post("create", self.payload)
        self.assertEqual(response.status_code, 201, response.content)
        return GiftCardPurchase.objects.get(pk=response.json()["purchase"]["id"])

    def test_unsigned_requests_and_nonbilling_members_are_denied(self) -> None:
        paths = ("catalog", "purchases", "create", "detail", "funding", "refresh", "reveal", "resend")
        for path in paths:
            with self.subTest(path=path):
                response = self.client.post(f"/api/billing/gift-cards/{path}/", data={}, content_type="application/json")
                self.assertEqual(response.status_code, 401)
        for role in ("viewer", "tech"):
            self.membership.role = role
            self.membership.save()
            for path in paths:
                with self.subTest(role=role, path=path):
                    response = self.post(path, self.payload)
                    self.assertEqual(response.status_code, 403, response.content)
        self.assertFalse(GiftCardPurchase.objects.exists())

    def test_catalog_and_bank_purchase_use_configured_currency_without_revealing_code(self) -> None:
        catalog = self.post("catalog")
        self.assertEqual(catalog.status_code, 200, catalog.content)
        self.assertEqual(catalog.json()["denominations"], [5000])
        self.assertEqual(catalog.json()["selling_currency"], "RON")
        purchase = self.create()
        self.assertEqual(purchase.buyer_email, self.actor.email)
        self.assertEqual(purchase.gift_card.current_balance_cents, 0)
        for action in ("detail", "purchases", "funding"):
            response = self.post(action, {"purchase_id": str(purchase.pk)})
            self.assertEqual(response.status_code, 200, response.content)
            self.assertNotIn(purchase.gift_card.code, response.content.decode())
        details = self.post("detail", {"purchase_id": str(purchase.pk)}).json()
        self.assertEqual(details["bank_details"]["currency"], "RON")
        self.assertFalse(details["purchase"]["can_reveal"])

    def test_changed_cart_requires_review_but_exact_retry_recovers_original_purchase(self) -> None:
        purchase = self.create()
        switched = SettingsService.update_setting("billing.default_currency", "EUR")
        self.assertTrue(switched.is_ok(), switched)
        replay = self.post("create", self.payload)
        self.assertEqual(replay.status_code, 201, replay.content)
        self.assertEqual(replay.json()["purchase"]["id"], str(purchase.pk))
        stale = self.post("create", {**self.payload, "idempotency_key": "new-stale-request"})
        self.assertEqual(stale.status_code, 409, stale.content)
        self.assertEqual(stale.json()["code"], "currency_changed")
        self.assertEqual(stale.json()["selling_currency"], "EUR")
        self.assertEqual(GiftCardPurchase.objects.count(), 1)

    def test_changed_recipient_or_coupon_funding_is_rejected(self) -> None:
        purchase = self.create()
        changed = self.post("create", {
            **self.payload, "is_gift": True, "recipient": {"email": "other@example.test"},
        })
        self.assertEqual(changed.status_code, 400, changed.content)
        for forbidden in ("coupon_codes", "gift_code"):
            response = self.post("create", {**self.payload, forbidden: "SOMETHING"})
            self.assertEqual(response.status_code, 400, response.content)
        purchase.refresh_from_db()
        self.assertEqual(purchase.gift_card.recipient_email, "")
        self.assertEqual(GiftCardPurchase.objects.count(), 1)

    def test_all_owned_actions_reject_other_customer_purchase(self) -> None:
        other = Customer.objects.create(name="Other buyer", primary_email="other@example.test")
        purchase = create_purchase(other, self.ron, 5000, "other-gift", method="bank")
        for action in ("detail", "funding", "refresh", "reveal", "resend"):
            with self.subTest(action=action):
                response = self.post(action, {"purchase_id": str(purchase.pk)})
                self.assertEqual(response.status_code, 404, response.content)
                self.assertNotIn(purchase.gift_card.code, response.content.decode())
        self.assertEqual(self.post("purchases").json()["purchases"], [])

    def test_unfunded_code_cannot_be_revealed_or_delivered(self) -> None:
        purchase = self.create()
        for action in ("reveal", "resend"):
            response = self.post(action, {"purchase_id": str(purchase.pk)})
            self.assertEqual(response.status_code, 400, response.content)
            self.assertNotIn(purchase.gift_card.code, response.content.decode())

    def test_sales_off_preserves_history_without_admitting_new_purchase(self) -> None:
        purchase = self.create()
        self.assertTrue(SettingsService.update_setting("promotions.gift_card_sales_enabled", False).is_ok())
        catalog = self.post("catalog")
        self.assertFalse(catalog.json()["sales_enabled"])
        self.assertEqual(self.post("purchases").json()["purchases"][0]["id"], str(purchase.pk))
        response = self.post("create", {**self.payload, "idempotency_key": "another"})
        self.assertEqual(response.status_code, 400)

    def test_provider_unavailable_is_not_reported_as_a_successful_refresh(self) -> None:
        purchase = create_purchase(self.customer, self.ron, 5000, "refresh-unavailable", method="stripe")
        with (
            patch("apps.promotions.gift_funding.refresh_funding", return_value={
                "success": False, "error": "Payment verification is temporarily unavailable.",
            }),
            patch("apps.api.billing.gift_views._details", return_value={"success": True, "purchase": {"status": "pending"}}),
        ):
            response = self.post("refresh", {"purchase_id": str(purchase.pk)})
        self.assertEqual(response.status_code, 503, response.content)
        self.assertFalse(response.json()["success"])
        purchase.refresh_from_db()
        self.assertIsNone(purchase.funded_at)

    def test_refresh_before_starting_card_payment_is_a_controlled_error(self) -> None:
        purchase = create_purchase(self.customer, self.ron, 5000, "refresh-not-started", method="stripe")
        response = self.post("refresh", {"purchase_id": str(purchase.pk)})
        self.assertEqual(response.status_code, 400, response.content)
        self.assertFalse(response.json()["success"])

    def test_detail_reports_recorded_available_and_held_value_separately(self) -> None:
        staff = User.objects.create_user(email="staff-api@example.test", staff_role="billing")
        purchase = record_bank_funding(self.create().pk, reference="QA-bank", actor=staff)
        reserve_funding_refund(purchase.pk, 1500, "partial-refund", actor=staff)
        card = purchase.gift_card
        card.refresh_from_db()
        card.reserved_cents = 500
        card.save(update_fields=["reserved_cents"])
        data = self.post("detail", {"purchase_id": str(purchase.pk)}).json()["purchase"]
        self.assertEqual((data["current_balance_cents"], data["available_balance_cents"],
                          data["reserved_cents"], data["refund_held_cents"]), (5000, 3000, 500, 1500))
        self.assertEqual(data["currency_code"], "RON")
        card.spending_frozen_at = timezone.now()
        card.save(update_fields=["spending_frozen_at"])
        data = self.post("detail", {"purchase_id": str(purchase.pk)}).json()["purchase"]
        self.assertEqual(data["available_balance_cents"], 0)
        self.assertTrue(data["spending_frozen"])
        self.assertFalse(data["can_reveal"])
        self.assertFalse(data["can_resend"])

    def test_resend_readiness_tracks_pending_delivery_and_recent_attempt(self) -> None:
        staff = User.objects.create_user(email="delivery-api@example.test", staff_role="billing")
        purchase = record_bank_funding(self.create().pk, reference="QA-bank", actor=staff)
        payload = {"purchase_id": str(purchase.pk)}
        pending = self.post("detail", payload).json()["purchase"]
        self.assertFalse(pending["can_resend"])
        self.assertTrue(pending["delivery_queued"])
        delivery = purchase.deliveries.get(purpose="voucher")
        delivery.status = "sent"
        delivery.sent_at = timezone.now()
        delivery.save(update_fields=["status", "sent_at"])
        recent = self.post("detail", payload).json()["purchase"]
        self.assertFalse(recent["can_resend"])
        self.assertTrue(recent["resend_available_at"])
        delivery.sent_at -= timedelta(minutes=6)
        delivery.save(update_fields=["sent_at"])
        self.assertTrue(self.post("detail", payload).json()["purchase"]["can_resend"])

    def test_verified_canceled_funding_disables_payment_but_declined_intent_can_retry(self) -> None:
        purchase = create_purchase(self.customer, self.ron, 5000, "closed-state", method="stripe")
        attempt = GiftCardFundingAttempt(
            purchase=purchase, amount_cents=5000, currency=self.ron, idempotency_key="closed-state-attempt",
            gateway_intent_id="pi_closed_state", status="requires_payment_method",
        )
        attempt.request_metadata = {"source": "gift_card_funding", "purchase_id": str(purchase.pk),
                                    "customer_id": str(self.customer.pk), "gift_funding_attempt_id": str(attempt.pk)}
        attempt.save()
        payload = {"purchase_id": str(purchase.pk)}
        declined = self.post("detail", payload).json()["purchase"]
        self.assertTrue(declined["can_pay"])
        self.assertTrue(declined["can_refresh"])
        result = converge_gift_funding(attempt.gateway_intent_id, {
            "status": "canceled", "amount": 5000, "currency": "ron", "metadata": attempt.request_metadata,
        })
        self.assertTrue(result.is_ok(), result)
        closed = self.post("detail", payload).json()["purchase"]
        self.assertEqual(closed["funding_status"], "canceled")
        self.assertFalse(closed["can_pay"])
        self.assertFalse(closed["can_refresh"])
        self.assertTrue(closed["payment_closed"])

    def test_expired_unbound_attempt_needs_review_without_inviting_new_payment(self) -> None:
        purchase = create_purchase(self.customer, self.ron, 5000, "expired-state", method="stripe")
        GiftCardFundingAttempt.objects.create(
            purchase=purchase, amount_cents=5000, currency=self.ron, idempotency_key="expired-state-attempt",
            status="unknown", first_submitted_at=timezone.now() - timedelta(hours=24),
        )
        data = self.post("detail", {"purchase_id": str(purchase.pk)}).json()["purchase"]
        self.assertTrue(data["funding_needs_review"])
        self.assertFalse(data["payment_closed"])
        self.assertFalse(data["can_pay"])
        self.assertFalse(data["can_refresh"])
