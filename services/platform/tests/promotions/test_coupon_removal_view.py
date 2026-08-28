"""RemoveCouponView idempotency (#485 review).

Removal is an idempotent operation: once no applied redemption matches, the
desired end-state holds. When remove_coupon started returning the reversed
COUNT, the view's truthiness branch turned an idempotent replay (retry after a
lost response, or a concurrent removal winning the race) into
'Failed to remove coupon' — for a coupon that was in fact removed.
"""

from __future__ import annotations

from decimal import Decimal

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from apps.promotions.models import Coupon, PromotionCampaign
from apps.promotions.services import CouponService

User = get_user_model()


class RemoveCouponViewIdempotencyTests(TestCase):
    def setUp(self) -> None:
        self.user = User.objects.create_user(
            email="coupon-remove-staff@example.test",
            password="StrongPass123!",
            staff_role="support",
        )
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.customer = Customer.objects.create(
            name="Removal Customer",
            customer_type="individual",
            status="active",
        )
        self.product = Product.objects.create(
            slug="removal-hosting",
            name="Removal Hosting",
            product_type="shared_hosting",
        )
        self.order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email="removal@example.test",
            customer_name="Removal Customer",
            subtotal_cents=10000,
            total_cents=10000,
        )
        OrderItem.objects.create(
            order=self.order,
            product=self.product,
            product_name="Removal Hosting",
            product_type="shared_hosting",
            billing_period="monthly",
            quantity=1,
            unit_price_cents=10000,
            setup_cents=0,
            line_total_cents=10000,
        )
        self.campaign = PromotionCampaign.objects.create(
            name="Removal Campaign",
            slug="removal-campaign",
            campaign_type="seasonal",
            start_date=timezone.now() - timezone.timedelta(days=1),
            budget_cents=100000,
            spent_cents=0,
            status="active",
            is_active=True,
        )
        self.coupon = Coupon.objects.create(
            code="REMOVEME",
            name="Removal Test",
            discount_type="percent",
            discount_percent=Decimal("20.00"),
            status="active",
            is_active=True,
            valid_from=timezone.now(),
            campaign=self.campaign,
        )
        result = CouponService.apply_coupon(code="REMOVEME", order=self.order, customer=self.customer)
        assert result.success, result
        self.redemption_id = result.redemption_id
        self.client = Client()
        self.client.force_login(self.user)
        self.url = reverse("promotions:api_remove_coupon")

    def _post_remove(self):
        return self.client.post(
            self.url,
            {"order_id": str(self.order.pk), "redemption_id": str(self.redemption_id)},
        )

    def test_repeated_removal_is_idempotent_success(self) -> None:
        first = self._post_remove()
        self.assertTrue(first.json()["success"], first.json())

        second = self._post_remove()
        payload = second.json()
        self.assertTrue(
            payload["success"],
            f"Idempotent replay must report success — the coupon IS removed: {payload}",
        )
