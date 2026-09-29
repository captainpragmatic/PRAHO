"""A recorded order uses the review limit in its own currency."""

from decimal import Decimal

from django.utils import timezone

from apps.billing.models import Currency, FXRate
from apps.orders.services import OrderPaymentConfirmationService
from apps.products.models import ProductPrice
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService
from tests.helpers.fsm_helpers import force_status
from tests.orders.test_review_gate import ReviewGateTestBase


class CurrencyReviewThresholdTests(ReviewGateTestBase):
    def setUp(self) -> None:
        super().setUp()
        for code in ("EUR", "USD"):
            currency = Currency.objects.get_or_create(code=code, defaults={"symbol": code})[0]
            FXRate.objects.create(
                base_code=currency, quote_code=self.currency, rate=Decimal("4.97"), as_of=timezone.localdate(),
                source=FXRate.Source.BNR, source_reference="review-threshold-test", fetched_at=timezone.now(),
            )
            ProductPrice.objects.create(product=self.product, currency=currency, monthly_price_cents=1000)

    def thresholds(self, values) -> None:
        key = "orders.review_thresholds_cents"
        SystemSetting.objects.update_or_create(key=key, defaults={
            "value": values, "default_value": {}, "category": "orders", "data_type": "json",
        })
        SettingsService._clear_setting_cache(key)
        self.addCleanup(SettingsService._clear_setting_cache, key)

    def test_foreign_order_without_explicit_threshold_requires_staff_review(self) -> None:
        self.currency = Currency.objects.get_or_create(code="EUR", defaults={"symbol": "EUR"})[0]
        self.thresholds({"RON": 500000})
        order = self._create_order_exact(1000)
        force_status(order, "awaiting_payment")
        self.assertTrue(OrderPaymentConfirmationService.confirm_order(order).is_ok())
        order.refresh_from_db()
        self.assertEqual(order.status, "in_review")

    def test_each_recorded_currency_uses_its_explicit_review_limit(self) -> None:
        self.thresholds({"RON": 500000, "EUR": 900, "USD": 20000})
        for code in ("EUR", "USD"):
            self.currency = Currency.objects.get_or_create(code=code, defaults={"symbol": code})[0]
            order = self._create_order_exact(1000)
            force_status(order, "awaiting_payment")
            result = OrderPaymentConfirmationService.confirm_order(order)
            self.assertTrue(result.is_ok(), result)
            order.refresh_from_db()
            self.assertEqual(order.status, "in_review" if code == "EUR" else "provisioning")

    def test_invalid_foreign_threshold_does_not_fall_back_to_ron(self) -> None:
        for values in ({"EUR": "500000"}, {"EUR": True}, {}, [500000]):
            with self.subTest(values=values):
                self.thresholds(values)
                self.assertEqual(OrderPaymentConfirmationService._get_review_threshold("EUR"), 0)
