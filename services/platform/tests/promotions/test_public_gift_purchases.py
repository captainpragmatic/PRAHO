"""New public purchases use configured terms; replay retains the original snapshot."""

from decimal import Decimal

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone

from apps.billing.currency_policy import get_selling_currency_policy
from apps.billing.models import Currency, FXRate
from apps.customers.models import Customer
from apps.promotions import gift_cards
from apps.promotions.models import GiftCardPurchase
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService
from apps.users.models import User


class PublicGiftPurchaseTests(TestCase):
    def setUp(self) -> None:
        self.ron = Currency.objects.get_or_create(code="RON", defaults={"symbol": "RON"})[0]
        self.eur = Currency.objects.get_or_create(code="EUR", defaults={"symbol": "EUR"})[0]
        FXRate.objects.get_or_create(
            base_code=self.eur, quote_code=self.ron, as_of=timezone.localdate(),
            defaults={"rate": Decimal("5"), "source": "bnr", "source_reference": "https://bnr.ro/rate",
                      "fetched_at": timezone.now()},
        )
        self.customer = Customer.objects.create(
            name="Gift buyer", customer_type="individual", primary_email="account@example.test"
        )
        self.actor = User.objects.create_user(email="signed-buyer@example.test")
        self._setting("promotions.gift_card_sales_enabled", True, "boolean")
        self._setting("promotions.gift_card_denominations", {"RON": [5000], "EUR": [2000]}, "json")
        self._setting("promotions.gift_card_payment_methods", ["bank"], "list")
        self._setting("billing.bank_accounts", {
            code: {"beneficiary": "PRAHO", "iban": "RO49AAAA1B31007593840000", "bank_name": "QA Bank"}
            for code in ("RON", "EUR")
        }, "json")

    def _setting(self, key, value, data_type):
        SystemSetting.objects.update_or_create(
            key=key, defaults={"value": value, "default_value": value, "category": "billing", "data_type": data_type}
        )

    def _purchase(self, **overrides):
        parameters = {
            "policy_revision": get_selling_currency_policy().revision, "currency_code": "RON", "method": "bank",
            "recipient": {"email": "", "name": "", "message": ""}, "is_gift": False, "actor": self.actor,
        }
        parameters.update(overrides)
        return gift_cards.create_public_purchase(self.customer, 5000, "public-gift", **parameters)

    def test_for_me_snapshots_signed_buyer_email_and_keeps_card_unfunded(self) -> None:
        purchase = self._purchase()
        self.assertEqual(purchase.buyer_email, "signed-buyer@example.test")
        self.assertFalse(purchase.is_gift)
        self.assertEqual(purchase.gift_card.current_balance_cents, 0)
        self.actor.email = "changed@example.test"
        self.actor.save(update_fields=["email"])
        purchase.refresh_from_db()
        self.assertEqual(purchase.buyer_email, "signed-buyer@example.test")

    def test_exact_replay_after_actor_email_change_retains_original_delivery_address(self) -> None:
        purchase = self._purchase()
        self.actor.email = "new-login@example.test"
        self.actor.save(update_fields=["email"])
        replay = self._purchase()
        self.assertEqual(replay.pk, purchase.pk)
        self.assertEqual(replay.buyer_email, "signed-buyer@example.test")

    def test_replay_from_a_different_authenticated_actor_is_rejected(self) -> None:
        self._purchase()
        other = User.objects.create_user(email="other-buyer@example.test")
        with self.assertRaises(ValidationError):
            self._purchase(actor=other)

    def test_disabled_sales_and_unconfigured_values_cannot_create_purchase(self) -> None:
        self._setting("promotions.gift_card_sales_enabled", False, "boolean")
        with self.assertRaises(ValidationError):
            self._purchase()
        self._setting("promotions.gift_card_sales_enabled", True, "boolean")
        self._setting("promotions.gift_card_denominations", {"RON": [10000]}, "json")
        with self.assertRaises(ValidationError):
            self._purchase()
        self.assertFalse(GiftCardPurchase.objects.exists())

    def test_stale_revision_and_unconfigured_method_are_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            self._purchase(policy_revision=0)
        with self.assertRaises(ValidationError):
            self._purchase(method="stripe")
        self.assertFalse(GiftCardPurchase.objects.exists())

    def test_exact_replay_recovers_original_purchase_after_currency_switch_and_disable(self) -> None:
        revision = get_selling_currency_policy().revision
        purchase = self._purchase(policy_revision=revision)
        self.assertTrue(SettingsService.update_setting("billing.default_currency", "EUR"))
        self.assertEqual(get_selling_currency_policy().currency_code, "EUR")
        self._setting("promotions.gift_card_sales_enabled", False, "boolean")
        replay = self._purchase(policy_revision=revision)
        self.assertEqual(replay.pk, purchase.pk)
        self.assertEqual(replay.gift_card.currency_id, "RON")
        self.assertEqual(GiftCardPurchase.objects.count(), 1)

    def test_replay_compares_recipient_mode_before_returning_existing_purchase(self) -> None:
        self._purchase()
        with self.assertRaises(ValidationError):
            self._purchase(is_gift=True, recipient={"email": "recipient@example.test", "name": "", "message": ""})

    def test_gift_recipient_requires_a_valid_address_and_bounded_message(self) -> None:
        for recipient in ({"email": "not-email"}, {"email": "recipient@example.test", "message": "x" * 2001}):
            with self.subTest(recipient=recipient), self.assertRaises(ValidationError):
                self._purchase(is_gift=True, recipient=recipient)
