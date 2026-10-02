"""A staff manual price on an order item is a price override, and the override policy is enforced (#542).

The staff item endpoints admit any staff role, so the price a support agent submits used to be written
verbatim. A price that differs from the catalog reference for the item's billing period is now an override:
only `can_manage_financial_data` users may make one, and it is bounded by the
`orders.max_price_override_cents` cap and the `orders.max_price_override_multiplier` ratio. Every rejection
here asserts that neither the item nor the order totals moved.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse

from apps.audit.models import AuditEvent
from apps.audit.services import OrdersAuditService
from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product, ProductPrice

User = get_user_model()

PRICE_CENTS = 1_000
SETUP_CENTS = 500


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class PriceOverrideTestBase(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.customer = Customer.objects.create(
            name="Price Override SRL", customer_type="company", status="active", primary_email="po@example.test"
        )
        self.product = self.make_product("override-hosting", monthly=PRICE_CENTS, setup=SETUP_CENTS)
        self.other_product = self.make_product("override-vps", monthly=3_000, setup=0)
        self.unpriced_product = Product.objects.create(
            slug="override-unpriced", name="Unpriced", product_type="hosting", is_active=True
        )
        self.order = Order.objects.create(
            customer=self.customer, currency=self.currency, status="draft", order_number="PO-542-001"
        )
        self.support = self.make_user("support@example.test", staff_role="support")
        self.billing = self.make_user("billing@example.test", staff_role="billing")

    def make_product(self, slug: str, *, monthly: int, setup: int) -> Product:
        product = Product.objects.create(slug=slug, name=slug.title(), product_type="hosting", is_active=True)
        ProductPrice.objects.create(
            product=product,
            currency=self.currency,
            monthly_price_cents=monthly,
            setup_cents=setup,
            annual_discount_percent=0,
            is_active=True,
        )
        return product

    def make_user(self, email: str, *, staff_role: str = "", is_superuser: bool = False) -> Any:
        user = User.objects.create_user(email=email, password="unused-pass-542", is_staff=True)
        user.staff_role = staff_role
        user.is_superuser = is_superuser
        user.save()
        return user

    def payload(self, *, product: Product | None = None, unit: int = PRICE_CENTS, setup: int = SETUP_CENTS,
                quantity: int = 1, config: dict[str, Any] | None = None) -> dict[str, Any]:
        return {
            "product": str((product or self.product).pk),
            "quantity": str(quantity),
            "unit_price_cents": str(unit),
            "setup_cents": str(setup),
            "config": json.dumps(config or {}),
            "domain_name": "",
        }

    def create_item(self, user: Any, **kwargs: Any) -> Any:
        self.client.force_login(user)
        return self.client.post(reverse("orders:add_item", kwargs={"pk": self.order.pk}), self.payload(**kwargs))

    def edit_item(self, user: Any, item: OrderItem, **kwargs: Any) -> Any:
        self.client.force_login(user)
        url = reverse("orders:update_item", kwargs={"pk": self.order.pk, "item_pk": item.pk})
        return self.client.post(url, self.payload(**kwargs))

    def totals(self) -> tuple[int, int, int]:
        self.order.refresh_from_db()
        return (self.order.subtotal_cents, self.order.tax_cents, self.order.total_cents)

    def assert_rejected(self, response: Any, message: str) -> None:
        self.assertEqual(response.status_code, 400, response.content)
        body = response.json()
        self.assertFalse(body["success"])
        self.assertIn(message, body["message"])

    def existing_item(self, *, unit: int = PRICE_CENTS, setup: int = SETUP_CENTS) -> OrderItem:
        item = OrderItem.objects.create(
            order=self.order,
            product=self.product,
            product_name=self.product.name,
            product_type=self.product.product_type,
            quantity=1,
            unit_price_cents=unit,
            setup_cents=setup,
        )
        self.order.calculate_totals()
        return item


class CreatePriceOverrideTests(PriceOverrideTestBase):
    def assert_create_rejected(self, response: Any, message: str, totals: tuple[int, int, int]) -> None:
        self.assert_rejected(response, message)
        self.assertFalse(self.order.items.exists())
        self.assertEqual(self.totals(), totals)

    def test_support_cannot_create_at_a_non_catalog_unit_price(self) -> None:
        before = self.totals()
        response = self.create_item(self.support, unit=5_000)
        self.assert_create_rejected(response, "Insufficient permissions for price override", before)

    def test_support_may_create_at_the_catalog_price(self) -> None:
        response = self.create_item(self.support)
        self.assertEqual(response.status_code, 302, response.content)
        item = self.order.items.get()
        self.assertEqual((item.unit_price_cents, item.setup_cents), (PRICE_CENTS, SETUP_CENTS))

    def test_unit_price_zero_falls_back_to_the_catalog_price(self) -> None:
        response = self.create_item(self.support, unit=0)
        self.assertEqual(response.status_code, 302, response.content)
        self.assertEqual(self.order.items.get().unit_price_cents, PRICE_CENTS)

    def test_support_cannot_waive_the_setup_fee(self) -> None:
        before = self.totals()
        response = self.create_item(self.support, setup=0)
        self.assert_create_rejected(response, "Insufficient permissions for price override", before)

    def test_support_cannot_raise_the_setup_fee(self) -> None:
        before = self.totals()
        response = self.create_item(self.support, setup=900)
        self.assert_create_rejected(response, "Insufficient permissions for price override", before)

    def test_billing_may_waive_the_setup_fee(self) -> None:
        response = self.create_item(self.billing, setup=0)
        self.assertEqual(response.status_code, 302, response.content)
        self.assertEqual(self.order.items.get().setup_cents, 0)

    def test_every_financial_role_may_override_and_is_audited_as_the_actor(self) -> None:
        users = [
            self.billing,
            self.make_user("manager@example.test", staff_role="manager"),
            self.make_user("admin@example.test", staff_role="admin"),
            self.make_user("root@example.test", is_superuser=True),
        ]
        for user in users:
            with self.subTest(user=user.email):
                OrderItem.objects.filter(order=self.order).delete()
                response = self.create_item(user, unit=5_000)
                self.assertEqual(response.status_code, 302, response.content)
                item = self.order.items.get()
                self.assertEqual(item.unit_price_cents, 5_000)
                event = AuditEvent.objects.filter(action="order_pricing_updated", object_id=str(item.pk)).get()
                self.assertEqual(event.user, user)
                self.assertEqual(event.new_values["unit_price_cents"], 5_000)
                self.assertEqual(event.old_values["catalog_unit_price_cents"], PRICE_CENTS)

    def test_multiplier_bounds_a_financial_override(self) -> None:
        before = self.totals()
        response = self.create_item(self.billing, unit=PRICE_CENTS * 10 + 1)
        self.assert_create_rejected(response, "Price override cannot exceed 10x original price", before)
        response = self.create_item(self.billing, unit=PRICE_CENTS * 10)
        self.assertEqual(response.status_code, 302, response.content)

    def test_absolute_cap_bounds_a_financial_override(self) -> None:
        pricey = self.make_product("override-dedicated", monthly=10_000_000, setup=0)
        admin = self.make_user("admin@example.test", staff_role="admin")
        before = self.totals()
        response = self.create_item(admin, product=pricey, unit=50_000_001, setup=0)
        self.assert_create_rejected(response, "Price cannot exceed 50000000 cents", before)
        response = self.create_item(admin, product=pricey, unit=50_000_000, setup=0)
        self.assertEqual(response.status_code, 302, response.content)

    def test_any_price_on_an_unpriced_product_is_an_override(self) -> None:
        before = self.totals()
        response = self.create_item(self.support, product=self.unpriced_product, unit=5_000, setup=0)
        self.assert_create_rejected(response, "Insufficient permissions for price override", before)
        response = self.create_item(self.billing, product=self.unpriced_product, unit=5_000, setup=0)
        self.assertEqual(response.status_code, 302, response.content)
        self.assertEqual(self.order.items.get().unit_price_cents, 5_000)

    def test_an_override_audit_failure_rolls_the_item_back(self) -> None:
        original = OrdersAuditService.log_order_item_event

        def fail_pricing_event(event_data: Any) -> Any:
            if event_data.event_type == "order_pricing_updated":
                raise RuntimeError("audit store unavailable")
            return original(event_data)

        before = self.totals()
        with patch.object(OrdersAuditService, "log_order_item_event", side_effect=fail_pricing_event):
            response = self.create_item(self.billing, unit=5_000)
        self.assert_create_rejected(response, "Failed to add item to order", before)


class EditPriceOverrideTests(PriceOverrideTestBase):
    def assert_edit_rejected(self, response: Any, message: str, item: OrderItem, before: tuple[int, int, int]) -> None:
        self.assert_rejected(response, message)
        snapshot = (item.product_id, item.unit_price_cents, item.setup_cents, item.quantity)
        item.refresh_from_db()
        self.assertEqual((item.product_id, item.unit_price_cents, item.setup_cents, item.quantity), snapshot)
        self.assertEqual(self.totals(), before)

    def test_support_cannot_change_the_unit_price(self) -> None:
        item = self.existing_item()
        before = self.totals()
        response = self.edit_item(self.support, item, unit=2_000)
        self.assert_edit_rejected(response, "Insufficient permissions for price override", item, before)

    def test_support_cannot_change_the_setup_fee(self) -> None:
        item = self.existing_item()
        before = self.totals()
        response = self.edit_item(self.support, item, setup=0)
        self.assert_edit_rejected(response, "Insufficient permissions for price override", item, before)

    def test_setup_fee_edit_is_capped_for_financial_staff(self) -> None:
        item = self.existing_item()
        before = self.totals()
        response = self.edit_item(self.billing, item, setup=50_000_001)
        self.assert_edit_rejected(response, "Price cannot exceed 50000000 cents", item, before)

    def test_unit_price_cannot_be_edited_to_zero(self) -> None:
        item = self.existing_item()
        before = self.totals()
        response = self.edit_item(self.billing, item, unit=0)
        self.assert_edit_rejected(response, "Price must be at least 1 cents", item, before)

    def test_support_cannot_keep_old_prices_on_a_switch_to_an_unpriced_product(self) -> None:
        item = self.existing_item()
        before = self.totals()
        response = self.edit_item(self.support, item, product=self.unpriced_product)
        self.assert_edit_rejected(response, "Insufficient permissions for price override", item, before)

    def test_product_change_reprices_from_the_catalog(self) -> None:
        item = self.existing_item()
        response = self.edit_item(self.support, item, product=self.other_product)
        self.assertEqual(response.status_code, 200, response.content)
        item.refresh_from_db()
        self.assertEqual((item.product_id, item.unit_price_cents, item.setup_cents), (self.other_product.pk, 3_000, 0))

    def test_billing_period_change_reprices_from_the_catalog(self) -> None:
        item = self.existing_item()
        response = self.edit_item(self.support, item, config={"billing_period": "annual"})
        self.assertEqual(response.status_code, 200, response.content)
        item.refresh_from_db()
        self.assertEqual(item.unit_price_cents, PRICE_CENTS * 12)

    def test_quantity_only_edit_keeps_an_accepted_override(self) -> None:
        item = self.existing_item(unit=5_000)
        response = self.edit_item(self.support, item, unit=5_000, quantity=2)
        self.assertEqual(response.status_code, 200, response.content)
        item.refresh_from_db()
        self.assertEqual((item.unit_price_cents, item.quantity), (5_000, 2))

    def test_financial_override_on_edit_is_audited(self) -> None:
        item = self.existing_item()
        response = self.edit_item(self.billing, item, unit=2_000)
        self.assertEqual(response.status_code, 200, response.content)
        item.refresh_from_db()
        self.assertEqual(item.unit_price_cents, 2_000)
        event = AuditEvent.objects.filter(action="order_pricing_updated", object_id=str(item.pk)).get()
        self.assertEqual(event.user, self.billing)
