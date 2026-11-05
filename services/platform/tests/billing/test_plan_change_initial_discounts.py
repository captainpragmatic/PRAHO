"""Coverage reconstructs the actual frozen checkout order of service/setup discounts."""

from datetime import timedelta
from decimal import Decimal

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone

from apps.billing.models import Currency, ProformaSequence
from apps.billing.plan_change_coverage import _initial_period_net
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from apps.promotions.engine import freeze_order, quote_order
from apps.promotions.models import Coupon, PromotionApplication
from apps.settings.services import SettingsService
from tests.helpers.task_queue import quiet_task_queue


class InitialOrderDiscountCoverageTests(TestCase):
    def setUp(self) -> None:
        quiet_task_queue(self)
        self.assertTrue(SettingsService.update_setting("promotions.new_offers_enabled", True).is_ok())
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
        ProformaSequence.objects.get_or_create(scope="default")
        customer = Customer.objects.create(name="Original offer", customer_type="individual")
        product = Product.objects.create(name="Original hosting", slug="initial-discount", product_type="hosting")
        self.order = Order.objects.create(customer=customer, currency=self.currency)
        self.item = OrderItem.objects.create(
            order=self.order,
            product=product,
            product_name=product.name,
            product_type=product.product_type,
            quantity=1,
            unit_price_cents=1000,
            setup_cents=500,
            tax_rate=Decimal("0.21"),
            billing_period="monthly",
        )
        self.order.calculate_totals()
        half = Coupon.objects.create(
            code="HALF-FIRST",
            name="Half first",
            discount_type="percent",
            discount_percent=50,
            is_stackable=True,
            stacking_priority=10,
        )
        setup = Coupon.objects.create(
            code="SETUP-SECOND",
            name="Setup second",
            discount_type="free_setup",
            is_stackable=True,
            stacking_priority=20,
        )
        codes = [half.code, setup.code]
        quote = quote_order(self.order, list(self.order.items.all()), codes)
        self.assertEqual([offer["kind"] for offer in quote["offers"]], ["percent", "free_setup"])
        self.assertEqual(quote["discount_cents"], 1000)
        freeze_order(self.order, codes, quote["quote_token"])
        self.item.refresh_from_db()

    def test_real_frozen_checkout_separates_service_from_setup(self) -> None:
        self.assertEqual(_initial_period_net(self.item), 500)

    def test_row_timestamps_cannot_replace_the_frozen_offer_order(self) -> None:
        # Structural normalization: timestamps are not contract evidence. This
        # deliberately reorders metadata, rather than claiming a public writer
        # currently reaches an incorrectly ordered frozen checkout.
        ordered = list(self.order.promotion_applications.order_by("created_at", "pk"))
        self.assertEqual(len(ordered), 2)
        for position, application in enumerate(ordered):
            PromotionApplication.objects.filter(pk=application.pk).update(
                created_at=timezone.now() + timedelta(seconds=2 - position)
            )
        self.assertEqual(_initial_period_net(self.item), 500)

    def test_missing_frozen_offer_order_requires_review(self) -> None:
        Order.objects.filter(pk=self.order.pk).update(meta={})
        with self.assertRaises(ValidationError):
            _initial_period_net(self.item)
