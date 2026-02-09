"""
Tests for the Promotions app services.
"""

from decimal import Decimal
from unittest.mock import MagicMock, patch

from django.test import TestCase
from django.utils import timezone

from apps.promotions.models import (
    Coupon,
    CouponRedemption,
    CustomerLoyalty,
    GiftCard,
    LoyaltyProgram,
    LoyaltyTier,
    PromotionCampaign,
    PromotionRule,
    ReferralCode,
)
from apps.promotions.services import (
    ApplyResult,
    CouponService,
    DiscountResult,
    GiftCardService,
    LoyaltyService,
    PromotionRuleService,
    ReferralService,
    ValidationResult,
)


class CouponServiceTests(TestCase):
    """Tests for CouponService."""

    def setUp(self):
        """Set up test fixtures."""
        from apps.billing.models import Currency
        from apps.customers.models import Customer
        from apps.orders.models import Order, OrderItem
        from apps.products.models import Product

        # Create currency
        self.currency = Currency.objects.create(
            code="RON",
            name="Romanian Leu",
            symbol="lei",
        )

        # Create customer
        self.customer = Customer.objects.create(
            name="Test Customer",
            customer_type="individual",
            status="active",
        )

        # Create product
        self.product = Product.objects.create(
            slug="shared-hosting",
            name="Shared Hosting",
            product_type="shared_hosting",
        )

        # Create order
        self.order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email="test@example.com",
            customer_name="Test Customer",
            subtotal_cents=10000,  # 100.00
            total_cents=10000,
        )

        # Create order item (required for discount calculations)
        self.order_item = OrderItem.objects.create(
            order=self.order,
            product=self.product,
            product_name="Shared Hosting",
            product_type="shared_hosting",
            billing_period="monthly",
            quantity=1,
            unit_price_cents=10000,
            setup_cents=0,
            line_total_cents=10000,
        )

        # Create coupon
        self.coupon = Coupon.objects.create(
            code="TEST20",
            name="Test Coupon",
            discount_type="percent",
            discount_percent=Decimal("20.00"),
            status="active",
            is_active=True,
            valid_from=timezone.now() - timezone.timedelta(days=1),
        )

    def test_normalize_code(self):
        """Test code normalization."""
        self.assertEqual(CouponService.normalize_code("test20"), "TEST20")
        self.assertEqual(CouponService.normalize_code("  TEST20  "), "TEST20")
        self.assertEqual(CouponService.normalize_code("Test20"), "TEST20")

    def test_get_coupon_by_code(self):
        """Test getting coupon by code."""
        coupon = CouponService.get_coupon_by_code("TEST20")
        self.assertIsNotNone(coupon)
        self.assertEqual(coupon.code, "TEST20")

    def test_get_coupon_by_code_case_insensitive(self):
        """Test case-insensitive coupon lookup."""
        coupon = CouponService.get_coupon_by_code("test20")
        self.assertIsNotNone(coupon)
        self.assertEqual(coupon.code, "TEST20")

    def test_get_coupon_by_code_not_found(self):
        """Test getting non-existent coupon."""
        coupon = CouponService.get_coupon_by_code("INVALID")
        self.assertIsNone(coupon)

    def test_validate_coupon_valid(self):
        """Test validating a valid coupon."""
        result = CouponService.validate_coupon(
            code="TEST20",
            order=self.order,
            customer=self.customer,
        )
        self.assertTrue(result.is_valid)
        self.assertEqual(result.error_message, "")

    def test_validate_coupon_invalid_code(self):
        """Test validating an invalid code."""
        result = CouponService.validate_coupon(
            code="INVALID",
            order=self.order,
            customer=self.customer,
        )
        self.assertFalse(result.is_valid)
        self.assertEqual(result.error_code, "INVALID_CODE")

    def test_validate_coupon_inactive(self):
        """Test validating an inactive coupon."""
        self.coupon.is_active = False
        self.coupon.save()

        result = CouponService.validate_coupon(
            code="TEST20",
            order=self.order,
            customer=self.customer,
        )
        self.assertFalse(result.is_valid)
        self.assertEqual(result.error_code, "COUPON_INVALID")

    def test_validate_coupon_expired(self):
        """Test validating an expired coupon."""
        self.coupon.valid_until = timezone.now() - timezone.timedelta(days=1)
        self.coupon.save()

        result = CouponService.validate_coupon(
            code="TEST20",
            order=self.order,
            customer=self.customer,
        )
        self.assertFalse(result.is_valid)
        self.assertEqual(result.error_code, "COUPON_INVALID")

    def test_validate_coupon_min_order_not_met(self):
        """Test validating when minimum order not met."""
        self.coupon.min_order_cents = 50000  # 500.00
        self.coupon.save()

        result = CouponService.validate_coupon(
            code="TEST20",
            order=self.order,  # Order is only 100.00
            customer=self.customer,
        )
        self.assertFalse(result.is_valid)
        self.assertEqual(result.error_code, "MIN_ORDER_NOT_MET")

    def test_validate_coupon_already_applied(self):
        """Test validating coupon already applied to order."""
        CouponRedemption.objects.create(
            coupon=self.coupon,
            order=self.order,
            customer=self.customer,
            status="applied",
            discount_type="percent",
            discount_value=Decimal("20.00"),
            discount_cents=2000,
            order_subtotal_cents=10000,
            order_total_cents=8000,
        )

        result = CouponService.validate_coupon(
            code="TEST20",
            order=self.order,
            customer=self.customer,
        )
        self.assertFalse(result.is_valid)
        self.assertEqual(result.error_code, "ALREADY_APPLIED")

    def test_calculate_discount_percent(self):
        """Test calculating percentage discount."""
        result = CouponService.calculate_discount(
            coupon=self.coupon,
            order=self.order,
        )
        self.assertEqual(result.discount_cents, 2000)  # 20% of 10000
        self.assertEqual(result.discount_type, "percent")

    def test_calculate_discount_fixed(self):
        """Test calculating fixed discount."""
        fixed_coupon = Coupon.objects.create(
            code="FIXED10",
            name="Fixed Discount",
            discount_type="fixed",
            discount_amount_cents=1000,  # 10.00
            status="active",
            is_active=True,
            valid_from=timezone.now(),
            currency=self.currency,
        )
        result = CouponService.calculate_discount(
            coupon=fixed_coupon,
            order=self.order,
        )
        self.assertEqual(result.discount_cents, 1000)
        self.assertEqual(result.discount_type, "fixed")

    def test_calculate_discount_capped(self):
        """Test discount capping."""
        self.coupon.max_discount_cents = 1500  # Cap at 15.00
        self.coupon.save()

        result = CouponService.calculate_discount(
            coupon=self.coupon,
            order=self.order,
        )
        self.assertEqual(result.discount_cents, 1500)  # Capped, not 2000

    def test_calculate_discount_free_shipping(self):
        """Test free shipping discount."""
        free_shipping_coupon = Coupon.objects.create(
            code="FREESHIP",
            name="Free Shipping",
            discount_type="free_shipping",
            status="active",
            is_active=True,
            valid_from=timezone.now(),
        )
        result = CouponService.calculate_discount(
            coupon=free_shipping_coupon,
            order=self.order,
        )
        self.assertTrue(result.free_shipping)
        self.assertEqual(result.discount_cents, 0)

    def test_apply_coupon_success(self):
        """Test successfully applying a coupon."""
        result = CouponService.apply_coupon(
            code="TEST20",
            order=self.order,
            customer=self.customer,
        )
        self.assertTrue(result.success)
        self.assertEqual(result.discount_cents, 2000)
        self.assertIsNotNone(result.redemption_id)

        # Verify order was updated
        self.order.refresh_from_db()
        self.assertEqual(self.order.discount_cents, 2000)

        # Verify redemption was created
        redemption = CouponRedemption.objects.get(id=result.redemption_id)
        self.assertEqual(redemption.status, "applied")
        self.assertEqual(redemption.discount_cents, 2000)

        # Verify coupon usage was updated
        self.coupon.refresh_from_db()
        self.assertEqual(self.coupon.total_uses, 1)
        self.assertEqual(self.coupon.total_discount_cents, 2000)

    def test_apply_coupon_invalid(self):
        """Test applying an invalid coupon."""
        result = CouponService.apply_coupon(
            code="INVALID",
            order=self.order,
            customer=self.customer,
        )
        self.assertFalse(result.success)
        self.assertIsNotNone(result.error_message)

    def test_remove_coupon(self):
        """Test removing a coupon from an order."""
        # First apply the coupon
        apply_result = CouponService.apply_coupon(
            code="TEST20",
            order=self.order,
            customer=self.customer,
        )
        self.assertTrue(apply_result.success)

        # Then remove it
        success = CouponService.remove_coupon(
            order=self.order,
            redemption_id=apply_result.redemption_id,
        )
        self.assertTrue(success)

        # Verify order discount was removed
        self.order.refresh_from_db()
        self.assertEqual(self.order.discount_cents, 0)

        # Verify redemption was reversed
        redemption = CouponRedemption.objects.get(id=apply_result.redemption_id)
        self.assertEqual(redemption.status, "reversed")

        # Verify coupon usage was decremented
        self.coupon.refresh_from_db()
        self.assertEqual(self.coupon.total_uses, 0)


class GiftCardServiceTests(TestCase):
    """Tests for GiftCardService."""

    def setUp(self):
        """Set up test fixtures."""
        from apps.billing.models import Currency
        from apps.customers.models import Customer
        from apps.orders.models import Order

        self.currency = Currency.objects.create(
            code="RON",
            name="Romanian Leu",
            symbol="lei",
        )

        self.customer = Customer.objects.create(
            name="Test Customer",
            customer_type="individual",
            status="active",
        )

        self.order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email="test@example.com",
            customer_name="Test Customer",
            subtotal_cents=10000,
            total_cents=10000,
        )

        self.gift_card = GiftCard.objects.create(
            code="TEST-1234-5678-9012",
            initial_value_cents=10000,
            current_balance_cents=10000,
            currency=self.currency,
            status="active",
            is_active=True,
        )

    def test_validate_gift_card_valid(self):
        """Test validating a valid gift card."""
        result = GiftCardService.validate_gift_card("TEST-1234-5678-9012")
        self.assertTrue(result.is_valid)

    def test_validate_gift_card_invalid_code(self):
        """Test validating an invalid code."""
        result = GiftCardService.validate_gift_card("INVALID-CODE")
        self.assertFalse(result.is_valid)
        self.assertEqual(result.error_code, "INVALID_CODE")

    def test_validate_gift_card_depleted(self):
        """Test validating a depleted gift card."""
        self.gift_card.current_balance_cents = 0
        self.gift_card.status = "depleted"
        self.gift_card.save()

        result = GiftCardService.validate_gift_card("TEST-1234-5678-9012")
        self.assertFalse(result.is_valid)
        self.assertEqual(result.error_code, "DEPLETED")

    def test_redeem_gift_card_full(self):
        """Test full redemption of gift card."""
        result = GiftCardService.redeem_gift_card(
            code="TEST-1234-5678-9012",
            order=self.order,
            customer=self.customer,
        )
        self.assertTrue(result.success)
        self.assertEqual(result.discount_cents, 10000)

        # Verify gift card was updated
        self.gift_card.refresh_from_db()
        self.assertEqual(self.gift_card.current_balance_cents, 0)
        self.assertEqual(self.gift_card.status, "depleted")

    def test_redeem_gift_card_partial(self):
        """Test partial redemption of gift card."""
        result = GiftCardService.redeem_gift_card(
            code="TEST-1234-5678-9012",
            order=self.order,
            amount_cents=5000,
            customer=self.customer,
        )
        self.assertTrue(result.success)
        self.assertEqual(result.discount_cents, 5000)

        # Verify gift card was updated
        self.gift_card.refresh_from_db()
        self.assertEqual(self.gift_card.current_balance_cents, 5000)
        self.assertEqual(self.gift_card.status, "partially_used")


class LoyaltyServiceTests(TestCase):
    """Tests for LoyaltyService."""

    def setUp(self):
        """Set up test fixtures."""
        from apps.billing.models import Currency
        from apps.customers.models import Customer
        from apps.orders.models import Order

        self.currency = Currency.objects.create(
            code="RON",
            name="Romanian Leu",
            symbol="lei",
        )

        self.customer = Customer.objects.create(
            name="Test Customer",
            customer_type="individual",
            status="active",
        )

        self.program = LoyaltyProgram.objects.create(
            name="PRAHO Rewards",
            points_per_currency_unit=Decimal("1.00"),
            points_per_discount_unit=100,
            min_points_to_redeem=100,
            max_discount_percent=Decimal("50.00"),
            currency=self.currency,
        )

        self.bronze_tier = LoyaltyTier.objects.create(
            program=self.program,
            name="Bronze",
            slug="bronze",
            min_points_lifetime=0,
            points_multiplier=Decimal("1.00"),
            sort_order=0,
        )

        self.silver_tier = LoyaltyTier.objects.create(
            program=self.program,
            name="Silver",
            slug="silver",
            min_points_lifetime=1000,
            points_multiplier=Decimal("1.25"),
            sort_order=1,
        )

        self.order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email="test@example.com",
            customer_name="Test Customer",
            subtotal_cents=10000,
            total_cents=10000,
        )

    def test_get_or_create_membership(self):
        """Test getting or creating loyalty membership."""
        membership = LoyaltyService.get_or_create_membership(
            customer=self.customer,
            program=self.program,
        )
        self.assertIsNotNone(membership)
        self.assertEqual(membership.customer, self.customer)
        self.assertEqual(membership.program, self.program)
        self.assertEqual(membership.current_tier, self.bronze_tier)

    def test_earn_points(self):
        """Test earning points."""
        membership = LoyaltyService.get_or_create_membership(
            customer=self.customer,
            program=self.program,
        )

        points = LoyaltyService.earn_points(
            membership=membership,
            order=self.order,
        )

        self.assertEqual(points, 100)  # 10000 cents = 100 currency units = 100 points

        membership.refresh_from_db()
        self.assertEqual(membership.points_balance, 100)
        self.assertEqual(membership.points_lifetime, 100)
        self.assertEqual(membership.total_orders, 1)

    def test_redeem_points(self):
        """Test redeeming points."""
        membership = LoyaltyService.get_or_create_membership(
            customer=self.customer,
            program=self.program,
        )
        membership.points_balance = 500
        membership.save()

        result = LoyaltyService.redeem_points(
            membership=membership,
            points=200,
            order=self.order,
        )

        self.assertEqual(result.discount_cents, 200)  # 200 points / 100 = 2.00

        membership.refresh_from_db()
        self.assertEqual(membership.points_balance, 300)
        self.assertEqual(membership.points_redeemed, 200)


class PromotionRuleServiceTests(TestCase):
    """Tests for PromotionRuleService."""

    def setUp(self):
        """Set up test fixtures."""
        from apps.billing.models import Currency
        from apps.customers.models import Customer
        from apps.orders.models import Order, OrderItem
        from apps.products.models import Product

        self.currency = Currency.objects.create(
            code="RON",
            name="Romanian Leu",
            symbol="lei",
        )

        self.customer = Customer.objects.create(
            name="Test Customer",
            customer_type="individual",
            status="active",
        )

        self.product = Product.objects.create(
            slug="premium-hosting",
            name="Premium Hosting",
            product_type="shared_hosting",
        )

        self.order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email="test@example.com",
            customer_name="Test Customer",
            subtotal_cents=50000,  # 500.00
            total_cents=50000,
        )

        # Create order item (required for discount calculations)
        self.order_item = OrderItem.objects.create(
            order=self.order,
            product=self.product,
            product_name="Premium Hosting",
            product_type="shared_hosting",
            billing_period="monthly",
            quantity=1,
            unit_price_cents=50000,
            setup_cents=0,
            line_total_cents=50000,
        )

        self.rule = PromotionRule.objects.create(
            name="10% off orders over 200 RON",
            rule_type="threshold",
            discount_type="percent",
            discount_percent=Decimal("10.00"),
            conditions={"min_order_cents": 20000},
            is_active=True,
            valid_from=timezone.now() - timezone.timedelta(days=1),
        )

    def test_get_applicable_rules(self):
        """Test getting applicable rules."""
        rules = PromotionRuleService.get_applicable_rules(self.order)
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0], self.rule)

    def test_rule_not_applicable_below_threshold(self):
        """Test rule not applicable below threshold."""
        self.order.subtotal_cents = 10000  # Below threshold
        self.order.save()

        rules = PromotionRuleService.get_applicable_rules(self.order)
        self.assertEqual(len(rules), 0)

    def test_calculate_rule_discount(self):
        """Test calculating rule discount."""
        result = PromotionRuleService.calculate_rule_discount(
            rule=self.rule,
            order=self.order,
        )
        self.assertEqual(result.discount_cents, 5000)  # 10% of 50000
