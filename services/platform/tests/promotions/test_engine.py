"""Quotes and reservations are checked against real order and campaign state."""

from decimal import Decimal

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.billing.models import Currency
from apps.billing.proforma_service import ProformaService
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from apps.promotions.engine import freeze_order, preview_cart, quote_order, release_order, settle_order
from apps.promotions.models import Coupon, GiftCard, PromotionApplication, PromotionCampaign, PromotionRule
from apps.settings.services import SettingsService
from apps.users.models import CustomerMembership


class PromotionEngineTests(TestCase):
    def setUp(self) -> None:
        result = SettingsService.update_setting(
            "promotions.new_offers_enabled", True, reason="Promotion regression tests"
        )
        self.assertTrue(result.is_ok(), result)
        self.addCleanup(SettingsService._clear_setting_cache, "promotions.new_offers_enabled")

    @classmethod
    def setUpTestData(cls) -> None:
        cls.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"name": "Romanian Leu", "symbol": "lei"})
        cls.customer = Customer.objects.create(
            name="Promotion buyer", customer_type="individual", primary_email="promotion-buyer@example.test"
        )
        cls.product = Product.objects.create(
            name="Promotion hosting", slug="promotion-hosting", product_type="shared_hosting"
        )

    def order(self) -> Order:
        order = Order.objects.create(customer=self.customer, currency=self.currency)
        OrderItem.objects.create(
            order=order,
            product=self.product,
            product_name=self.product.name,
            product_type=self.product.product_type,
            quantity=1,
            unit_price_cents=1000,
            setup_cents=500,
            tax_rate=Decimal("0.21"),
            billing_period="monthly",
        )
        order.calculate_totals()
        return order

    def test_unpublished_historical_rules_do_not_activate(self) -> None:
        PromotionRule.objects.create(name="Historic inactive engine", discount_type="percent", discount_percent=50)
        order = self.order()
        self.assertEqual(quote_order(order, list(order.items.all()), [])["discount_cents"], 0)

    def test_checkout_reserves_existing_gift_balance_without_reducing_tax(self) -> None:
        SettingsService.update_setting("promotions.new_offers_enabled", False, reason="Disable new offers only")
        card = GiftCard.objects.create(
            code="CHECKOUT-GIFT",
            currency=self.currency,
            status="active",
            initial_value_cents=1000,
            current_balance_cents=1000,
        )
        order = self.order()
        quote = quote_order(order, list(order.items.all()), [], gift_code=card.code)
        self.assertEqual((quote["total_cents"], quote["tax_cents"], quote["cash_due_cents"]), (1815, 315, 815))
        self.assertNotIn(card.code, str(quote))
        freeze_order(order, [], quote["quote_token"], gift_code=card.code)
        card.refresh_from_db()
        order.refresh_from_db()
        self.assertEqual((card.current_balance_cents, card.reserved_cents), (1000, 1000))
        self.assertEqual((order.discount_cents, order.proforma.total_cents), (0, 1815))
        self.assertEqual(order.proforma.gift_card_reservations.get().amount_cents, 1000)
        from apps.billing.proforma_service import ProformaPaymentService  # noqa: PLC0415

        converted = ProformaPaymentService.record_payment_and_convert(
            proforma_id=str(order.proforma_id), amount_cents=815, payment_method="bank", reference="QUOTE-SETTLEMENT"
        )
        self.assertTrue(converted.is_ok(), converted)
        invoice = converted.unwrap()
        self.assertEqual((invoice.total_cents, invoice.tax_cents), (1815, 315))
        self.assertEqual(invoice.status, "paid")

    def test_gift_balance_change_requires_a_fresh_quote_and_leaves_no_hold(self) -> None:
        card = GiftCard.objects.create(
            code="CHANGED-GIFT",
            currency=self.currency,
            status="active",
            initial_value_cents=1000,
            current_balance_cents=1000,
        )
        order = self.order()
        quote = quote_order(order, list(order.items.all()), [], gift_code=card.code)
        card.current_balance_cents = 500
        card.save(update_fields=["current_balance_cents"])
        with self.assertRaisesMessage(ValidationError, "PROMOTION_QUOTE_CHANGED"):
            freeze_order(order, [], quote["quote_token"], gift_code=card.code)
        card.refresh_from_db()
        order.refresh_from_db()
        self.assertEqual(card.reserved_cents, 0)
        self.assertIsNone(order.proforma_id)

    def test_quote_freeze_and_settlement_reserve_then_spend_exact_budget(self) -> None:
        campaign = PromotionCampaign.objects.create(
            name="Budget",
            slug="budget",
            start_date=timezone.now(),
            status="active",
            budget_cents=1000,
            budget_currency=self.currency,
        )
        coupon = Coupon.objects.create(
            code="BUDGET", name="Budget", discount_type="percent", discount_percent=20, campaign=campaign
        )
        order = self.order()
        quote = quote_order(order, list(order.items.all()), [coupon.code])
        self.assertEqual(quote["discount_cents"], 300)
        self.assertEqual(quote["tax_cents"], 252)
        freeze_order(order, [coupon.code], quote["quote_token"])
        campaign.refresh_from_db()
        self.assertEqual((campaign.reserved_cents, campaign.spent_cents), (300, 0))
        settle_order(order)
        settle_order(order)
        campaign.refresh_from_db()
        self.assertEqual((campaign.reserved_cents, campaign.spent_cents), (0, 300))
        self.assertEqual(PromotionApplication.objects.filter(order=order, status="settled").count(), 1)
        self.assertEqual(AuditEvent.objects.filter(
            content_type__model="promotionapplication", object_id=str(order.promotion_applications.get().pk),
            new_values__status="settled",
        ).count(), 1)

    def test_price_change_and_wrong_customer_invalidate_quote_without_reservation(self) -> None:
        coupon = Coupon.objects.create(code="CHANGING", name="Changing", discount_type="percent", discount_percent=10)
        order = self.order()
        quote = quote_order(order, list(order.items.all()), [coupon.code])
        coupon.discount_percent = 20
        coupon.save()
        with self.assertRaisesMessage(ValidationError, "PROMOTION_QUOTE_CHANGED"):
            freeze_order(order, [coupon.code], quote["quote_token"])
        self.assertFalse(order.promotion_applications.exists())
        coupon.refresh_from_db()
        self.assertEqual(coupon.total_uses, 0)

    def test_budget_reserves_future_months_and_release_is_idempotent(self) -> None:
        campaign = PromotionCampaign.objects.create(
            name="Renewals",
            slug="renewals",
            start_date=timezone.now(),
            status="active",
            budget_cents=3000,
            budget_currency=self.currency,
        )
        coupon = Coupon.objects.create(
            code="MONTHS", name="Months", discount_type="free_months", free_months=3, campaign=campaign
        )
        order = self.order()
        quote = quote_order(order, list(order.items.all()), [coupon.code])
        freeze_order(order, [coupon.code], quote["quote_token"])
        campaign.refresh_from_db()
        self.assertEqual(campaign.reserved_cents, 3000)
        self.assertEqual(order.promotion_applications.get().benefits.get().remaining_cents, 2000)
        release_order(order)
        release_order(order)
        campaign.refresh_from_db()
        coupon.refresh_from_db()
        self.assertEqual((campaign.reserved_cents, campaign.spent_cents, coupon.total_uses), (0, 0, 0))
        self.assertEqual(AuditEvent.objects.filter(
            content_type__model="promotionapplication", object_id=str(order.promotion_applications.get().pk),
            new_values__status="released",
        ).count(), 1)

    def test_reserved_customer_limit_applies_before_payment(self) -> None:
        coupon = Coupon.objects.create(
            code="PERSONAL", name="Personal", discount_type="percent", discount_percent=10, max_uses_per_customer=1
        )
        first = self.order()
        quote = quote_order(first, list(first.items.all()), [coupon.code])
        freeze_order(first, [coupon.code], quote["quote_token"])
        second = self.order()
        with self.assertRaises(ValidationError):
            quote_order(second, list(second.items.all()), [coupon.code])

    def test_undiscounted_quote_freeze_and_proforma_preserve_line_vat(self) -> None:

        order = self.order()
        item = order.items.get()
        item.unit_price_cents = 50
        item.setup_cents = 0
        item.save()
        OrderItem.objects.create(
            order=order,
            product=self.product,
            product_name=self.product.name,
            product_type=self.product.product_type,
            unit_price_cents=50,
            tax_rate=Decimal("0.21"),
            billing_period="monthly",
        )
        order.calculate_totals()
        items = list(order.items.all())
        preview = preview_cart(
            self.customer,
            self.currency,
            [
                {
                    "product_id": item.product_id,
                    "product_type": item.product_type,
                    "quantity": item.quantity,
                    "unit_price_cents": item.unit_price_cents,
                    "setup_cents": item.setup_cents,
                    "billing_period": item.billing_period,
                }
                for item in items
            ],
            [],
            Decimal("0.21"),
        )
        self.assertEqual((preview["tax_cents"], preview["total_cents"]), (20, 120))
        freeze_order(order, [], preview["quote_token"])
        result = ProformaService.create_from_order(order)
        self.assertTrue(result.is_ok(), result)
        proforma = result.unwrap()
        self.assertEqual((order.total_cents, proforma.tax_cents, proforma.total_cents), (120, 20, 120))

    def test_another_customers_signed_quote_cannot_be_reused(self) -> None:
        first = self.order()
        quote = quote_order(first, list(first.items.all()), [])
        second = self.order()
        second.customer = Customer.objects.create(name="Another buyer", customer_type="individual")
        second.save(update_fields=["customer"])
        with self.assertRaisesMessage(ValidationError, "PROMOTION_QUOTE_CHANGED"):
            freeze_order(second, [], quote["quote_token"])
        self.assertFalse(second.promotion_applications.exists())

    def test_public_quote_uses_display_name_and_counts_only_eligible_quantity(self) -> None:
        rule = PromotionRule.objects.create(
            name="Internal retention cohort",
            display_name="Hosting offer",
            discount_type="percent",
            discount_percent=10,
            published_at=timezone.now(),
            applies_to_all_products=False,
            product_restrictions={"product_types": [self.product.product_type]},
            conditions={"min_items": 5},
        )
        order = self.order()
        OrderItem.objects.create(
            order=order,
            product=self.product,
            product_name="Excluded service",
            product_type="domain",
            unit_price_cents=1,
            quantity=4,
            tax_rate=Decimal("0.21"),
        )
        order.calculate_totals()
        self.assertEqual(quote_order(order, list(order.items.all()), [])["discount_cents"], 0)
        item = order.items.get(product_type=self.product.product_type)
        item.quantity = 5
        item.save()
        order.calculate_totals()
        quote = quote_order(order, list(order.items.all()), [])
        self.assertEqual(quote["offers"][0]["label"], rule.display_name)
        self.assertEqual(quote["discount_cents"], 550)

    def test_staff_cannot_change_items_after_quote_reservation(self) -> None:
        staff = get_user_model().objects.create_user(
            email="frozen-orders@example.test", is_staff=True, staff_role="admin"
        )
        self.client.force_login(staff)
        CustomerMembership.objects.create(user=staff, customer=self.customer, role="owner", is_primary=True)
        order = self.order()
        coupon = Coupon.objects.create(code="FROZEN", name="Frozen", discount_type="percent", discount_percent=50)
        quote = quote_order(order, list(order.items.all()), [coupon.code])
        freeze_order(order, [coupon.code], quote["quote_token"])
        item = order.items.get()
        data = {
            "product": str(self.product.pk),
            "quantity": "2",
            "unit_price_cents": "500",
            "setup_cents": "0",
            "config": "{}",
            "domain_name": "",
        }
        for route in ["order_item_edit", "order_item_delete", "order_item_create"]:
            with self.subTest(route=route):
                kwargs = {"pk": order.pk}
                if route != "order_item_create":
                    kwargs["item_pk"] = item.pk
                response = self.client.post(reverse(f"orders:{route}", kwargs=kwargs), data)
                self.assertEqual(response.status_code, 400, response.content)
                self.assertEqual(order.items.count(), 1)
                item.refresh_from_db()
                self.assertEqual((item.quantity, item.unit_price_cents, item.setup_cents), (1, 1000, 500))
        for route in ("cart_update", "cart_remove"):
            with self.subTest(route=route):
                response = self.client.post(reverse(f"orders:{route}"), {"item_id": str(item.pk), "quantity": "2"})
                self.assertEqual(response.status_code, 400)
                item.refresh_from_db()
                self.assertEqual(item.quantity, 1)
