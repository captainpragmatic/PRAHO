"""A target currency must have prices for each actual renewal term."""

from datetime import timedelta
from decimal import Decimal

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone

from apps.billing.currency_models import Currency, FXRate
from apps.billing.subscription_models import Subscription
from apps.common.types import Err, Ok
from apps.customers.models import Customer
from apps.products.models import Product, ProductPrice
from apps.settings.services import SettingsService


class SellingCurrencyRenewalPriceTests(TestCase):
    def setUp(self) -> None:
        for code in ("RON", "EUR"):
            Currency.objects.get_or_create(code=code, defaults={"symbol": code})
        FXRate.objects.create(
            base_code_id="EUR", quote_code_id="RON", rate=Decimal("4.97"), as_of=timezone.localdate(),
            source=FXRate.Source.BNR, source_reference="renewal-pricing-test", fetched_at=timezone.now(),
        )
        self.customer = Customer.objects.create(name="Renewal prices", primary_email="renewal-prices@example.test")
        self.product = Product.objects.create(name="Retired custom service", slug="retired-custom", is_public=False)
        self.price = ProductPrice.objects.create(product=self.product, currency_id="EUR", monthly_price_cents=1000)

    def subscription(self, period: str, days: int | None = None) -> Subscription:
        return Subscription.objects.create(
            customer=self.customer, product=self.product, subscription_number=f"PRICING-{period}",
            status="active", billing_cycle=period, custom_cycle_days=days, currency_id="RON",
            unit_price_cents=5000, current_period_start=timezone.now(),
            current_period_end=timezone.now() + timedelta(days=30),
            next_billing_date=timezone.now() + timedelta(days=30),
        )

    def test_quarterly_renewal_requires_an_explicit_target_term_price(self) -> None:
        self.subscription("quarterly")
        result = SettingsService.update_setting("billing.default_currency", "EUR")
        self.assertIsInstance(result, Err)
        self.assertIn("quarterly", result.error.message)
        self.price.quarterly_price_cents = 2800
        self.price.save()
        self.assertIsInstance(SettingsService.update_setting("billing.default_currency", "EUR"), Ok)
        self.assertEqual(self.price.get_price_cents_for_period("quarterly"), 2800)

    def test_custom_renewal_requires_the_exact_number_of_days(self) -> None:
        self.subscription("custom", 42)
        self.price.custom_period_prices = {"41": 1500}
        self.price.save()
        result = SettingsService.update_setting("billing.default_currency", "EUR")
        self.assertIsInstance(result, Err)
        self.assertIn("42", result.error.message)
        self.price.custom_period_prices = {"41": 1500, "42": 0}
        self.price.save()
        self.assertIsInstance(SettingsService.update_setting("billing.default_currency", "EUR"), Ok)
        self.assertEqual(self.price.get_price_cents_for_period("custom", custom_cycle_days=42), 0)

    def test_durable_renewal_offer_excludes_transient_promotion(self) -> None:
        self.price.promo_price_cents = 500
        self.price.promo_valid_until = timezone.now() + timedelta(days=1)
        self.price.save()
        self.assertEqual(self.price.get_price_cents_for_period("monthly"), 500)
        self.assertEqual(self.price.get_price_cents_for_period("monthly", include_promotions=False), 1000)
        self.assertEqual(self.price.get_price_cents_for_period("yearly", include_promotions=False), 12000)

    def test_invalid_custom_term_configuration_cannot_be_saved(self) -> None:
        for value in ({"42": -1}, {"42": True}, {"0": 50}, {"42": "100"}, {"bad": 50}, []):
            with self.subTest(value=value):
                self.price.custom_period_prices = value
                with self.assertRaises(ValidationError):
                    self.price.save(update_fields=["custom_period_prices"])
