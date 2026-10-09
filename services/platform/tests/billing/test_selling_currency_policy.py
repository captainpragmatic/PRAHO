"""One selling currency, with explicit prices and stable historical money."""

import json
from decimal import Decimal

from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIRequestFactory

from apps.api.billing.views import currencies_api
from apps.api.orders.views import product_list
from apps.billing.currency_models import Currency, FXRate
from apps.billing.currency_policy import get_selling_currency_policy
from apps.billing.models import BillingCycle, Subscription
from apps.billing.subscription_service import SubscriptionService
from apps.billing.views import api_stripe_config
from apps.common.types import Err, Ok
from apps.customers.models import Customer
from apps.products.models import Product, ProductPrice
from apps.promotions.models import Coupon
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService, SettingUpdate


class SellingCurrencyPolicyTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.factory = APIRequestFactory()
        get_selling_currency_policy(lock=True)
        for code in ("RON", "EUR", "USD"):
            Currency.objects.get_or_create(code=code, defaults={"symbol": code, "name": code})
            if code != "RON":
                FXRate.objects.create(
                    base_code_id=code,
                    quote_code_id="RON",
                    rate=Decimal("4.97000000"),
                    as_of=timezone.localdate(),
                    source=FXRate.Source.BNR,
                    source_reference="currency-policy-test",
                    fetched_at=timezone.now(),
                )

    def product(self, *, prices: tuple[str, ...] = ("RON", "EUR", "USD")) -> Product:
        product = Product.objects.create(name="Hosting", slug="hosting", product_type="shared_hosting")
        for index, code in enumerate(prices):
            ProductPrice.objects.create(product=product, currency_id=code, monthly_price_cents=1000 + index * 100)
        return product

    def test_currency_metadata_uses_real_model_fields_and_exposes_policy(self) -> None:
        response = currencies_api(self.factory.get("/api/billing/currencies/"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual({row["code"] for row in response.data["currencies"]}, {"RON", "EUR", "USD"})
        self.assertEqual(response.data["selling_currency"], "RON")
        self.assertGreaterEqual(response.data["currency_revision"], 1)

    def test_stripe_public_configuration_tracks_current_selling_currency(self) -> None:
        self.assertIsInstance(SettingsService.update_setting("integrations.stripe_enabled", True), Ok)
        self.assertIsInstance(SettingsService.update_setting("integrations.stripe_publishable_key", "pk_test_123"), Ok)
        for code in ("EUR", "USD", "RON"):
            with self.subTest(code=code):
                self.assertIsInstance(SettingsService.update_setting("billing.default_currency", code), Ok)
                request = self.factory.get("/api/billing/stripe-config/")
                request._portal_authenticated = True  # what PortalServiceHMACMiddleware sets
                response = api_stripe_config(request)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(json.loads(response.content)["config"]["currency"], code)

    def test_new_subscription_without_explicit_order_currency_uses_selling_price(self) -> None:
        product = self.product()
        customer = Customer.objects.create(name="Current-currency subscription buyer", customer_type="individual")
        self.assertIsInstance(SettingsService.update_setting("billing.default_currency", "EUR"), Ok)
        result = SubscriptionService.create_subscription(customer, product, {"billing_cycle": "monthly"})
        self.assertIsInstance(result, Ok)
        self.assertEqual((result.unwrap().currency_id, result.unwrap().unit_price_cents), ("EUR", 1100))

    @override_settings(BILLING_DEFAULT_CURRENCY="EUR")
    def test_upgrade_does_not_activate_previously_ignored_environment_value(self) -> None:
        self.assertEqual(get_selling_currency_policy().currency_code, "RON")

    def test_runtime_switch_changes_only_catalog_currency(self) -> None:
        product = self.product()
        for code in ("EUR", "USD", "RON"):
            with self.subTest(code=code), self.captureOnCommitCallbacks(execute=True):
                result = SettingsService.update_setting("billing.default_currency", code)
                self.assertIsInstance(result, Ok)
                response = product_list(self.factory.get("/api/orders/products/"))
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.data["selling_currency"], code)
                prices = response.data["results"][0]["prices"]
                self.assertEqual(len(prices), 1)
                self.assertEqual(prices[0]["currency"], code)
        self.assertEqual(product.prices.count(), 3)
        self.assertEqual(product.prices.get(currency_id="RON").monthly_price_cents, 1000)

    def test_inactive_target_price_does_not_satisfy_switch_preflight(self) -> None:
        product = self.product()
        ProductPrice.objects.filter(product=product, currency_id="EUR").update(is_active=False)
        result = SettingsService.update_setting("billing.default_currency", "EUR")
        self.assertIsInstance(result, Err)
        self.assertIn("Hosting", result.error.message)

    def test_missing_price_blocks_single_and_bulk_settings_writers(self) -> None:
        self.product(prices=("RON",))
        result = SettingsService.update_setting("billing.default_currency", "EUR")
        self.assertIsInstance(result, Err)
        self.assertIn("EUR", result.error.message)
        self.assertIn("Hosting", result.error.message)
        result = SettingsService.bulk_update_settings([SettingUpdate(key="billing.default_currency", value="USD")])
        self.assertIsInstance(result, Err)

    def test_direct_model_write_cannot_bypass_price_guard(self) -> None:
        self.product(prices=("RON",))
        setting = SystemSetting.objects.get(key="billing.default_currency")
        setting.value = "EUR"
        with self.assertRaises(ValidationError):
            setting.save(update_fields=["value", "updated_at"])
        setting.refresh_from_db()
        self.assertEqual(setting.value, "RON")

    def test_unpublished_unused_product_does_not_block_switch(self) -> None:
        product = self.product(prices=("RON",))
        product.is_public = False
        product.save(update_fields=["is_public"])
        self.assertIsInstance(SettingsService.update_setting("billing.default_currency", "EUR"), Ok)

    def test_unprovenanced_fx_blocks_switch_without_relabeling_default(self) -> None:
        FXRate.objects.filter(base_code_id="EUR").update(source=FXRate.Source.LEGACY_UNKNOWN)
        result = SettingsService.update_setting("billing.default_currency", "EUR")
        self.assertIsInstance(result, Err)
        self.assertIn("exchange rate", result.error.message)
        self.assertEqual(SystemSetting.objects.get(key="billing.default_currency").value, "RON")

    def test_revision_advances_only_when_the_selling_currency_changes(self) -> None:
        before = get_selling_currency_policy()
        with self.captureOnCommitCallbacks(execute=True):
            self.assertIsInstance(SettingsService.update_setting("billing.default_currency", "EUR"), Ok)
        after = get_selling_currency_policy()
        self.assertEqual(after.revision, before.revision + 1)
        with self.captureOnCommitCallbacks(execute=True):
            self.assertIsInstance(SettingsService.update_setting("billing.default_currency", "EUR"), Ok)
        self.assertEqual(get_selling_currency_policy(), after)

    def test_unknown_and_empty_currencies_cannot_be_saved(self) -> None:
        for value in ("GBP", "", None):
            with self.subTest(value=value):
                self.assertIsInstance(SettingsService.update_setting("billing.default_currency", value), Err)

    def test_legacy_offer_with_money_but_unknown_currency_blocks_switch(self) -> None:
        coupon = Coupon.objects.create(
            code="LEGACY-BOUND", name="Legacy capped offer", discount_type="percent",
            discount_percent=Decimal("10"), max_discount_cents=1000, currency_id="RON",
        )
        # Represents existing unresolved data, without assuming the current default.
        Coupon.objects.filter(pk=coupon.pk).update(currency=None)
        result = SettingsService.update_setting("billing.default_currency", "EUR")
        self.assertIsInstance(result, Err)
        self.assertIn("Legacy capped offer", result.error.message)
        self.assertEqual(get_selling_currency_policy().currency_code, "RON")

    def test_unreviewed_legacy_active_period_blocks_currency_switch(self) -> None:
        now = timezone.now()
        subscription = Subscription.objects.create(
            customer=Customer.objects.create(name="Legacy usage customer", customer_type="individual"),
            product=self.product(), currency_id="RON", subscription_number="SUB-LEGACY-USAGE",
            status="active", unit_price_cents=1000, current_period_start=now,
            current_period_end=now + timezone.timedelta(days=30), next_billing_date=now,
        )
        # A historical row from before snapshots were introduced, with no immutable evidence.
        BillingCycle.objects.bulk_create([BillingCycle(
            subscription=subscription, status="active", period_start=now,
            period_end=subscription.current_period_end,
        )])
        result = SettingsService.update_setting("billing.default_currency", "EUR")
        self.assertIsInstance(result, Err)
        self.assertIn("Historical cycle", result.error.message)
        self.assertEqual(get_selling_currency_policy().currency_code, "RON")

    def test_unbounded_percentage_offer_and_inactive_unknown_offer_allow_switch(self) -> None:
        Coupon.objects.create(code="PERCENT", name="Pure percent", discount_type="percent", discount_percent=10)
        coupon = Coupon.objects.create(
            code="INACTIVE-BOUND", name="Inactive capped offer", discount_type="percent",
            discount_percent=10, max_discount_cents=1000, currency_id="RON", is_active=False,
        )
        Coupon.objects.filter(pk=coupon.pk).update(currency=None)
        self.assertIsInstance(SettingsService.update_setting("billing.default_currency", "EUR"), Ok)
