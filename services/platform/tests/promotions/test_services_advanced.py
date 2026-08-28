"""
Additional comprehensive tests for the Promotions app services.
Covers edge cases, stacking rules, customer restrictions, and more.
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
    Referral,
    ReferralCode,
)
from apps.promotions.services import (
    CouponService,
    GiftCardService,
    LoyaltyService,
    ReferralService,
    ValidationResult,
)


class CouponCustomerRestrictionsTests(TestCase):
    """Tests for customer-specific coupon restrictions."""

    def setUp(self):
        """Set up test fixtures."""
        from apps.billing.models import Currency
        from apps.customers.models import Customer
        from apps.orders.models import Order

        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"name": "Romanian Leu", "symbol": "lei"}
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

    def test_new_customer_only_valid_for_new_customer(self):
        """Test new customer coupon works for customers without orders."""
        coupon = Coupon.objects.create(
            code="NEWCUST",
            name="New Customer",
            discount_type="percent",
            discount_percent=Decimal("15.00"),
            status="active",
            is_active=True,
            valid_from=timezone.now(),
            customer_target="new",
        )

        result = CouponService.validate_coupon(
            code="NEWCUST",
            order=self.order,
            customer=self.customer,
        )
        # Customer has no completed orders, so should be valid
        self.assertTrue(result.is_valid)

    def test_new_customer_only_invalid_for_existing_customer(self):
        """Test new customer coupon fails for customers with orders."""
        from apps.orders.models import Order

        # Create a completed order
        Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email="test@example.com",
            customer_name="Test Customer",
            subtotal_cents=5000,
            total_cents=5000,
            status="completed",  # Not draft
        )

        coupon = Coupon.objects.create(
            code="NEWCUST2",
            name="New Customer",
            discount_type="percent",
            discount_percent=Decimal("15.00"),
            status="active",
            is_active=True,
            valid_from=timezone.now(),
            customer_target="new",
        )

        result = CouponService.validate_coupon(
            code="NEWCUST2",
            order=self.order,
            customer=self.customer,
        )
        self.assertFalse(result.is_valid)
        self.assertEqual(result.error_code, "CUSTOMER_INELIGIBLE")

    def test_first_order_only_coupon(self):
        """Test first order only restriction."""
        from apps.orders.models import Order

        # Create a completed order first
        Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email="test@example.com",
            customer_name="Test Customer",
            subtotal_cents=5000,
            total_cents=5000,
            status="completed",
        )

        coupon = Coupon.objects.create(
            code="FIRSTORDER",
            name="First Order",
            discount_type="percent",
            discount_percent=Decimal("10.00"),
            status="active",
            is_active=True,
            valid_from=timezone.now(),
            first_order_only=True,
        )

        result = CouponService.validate_coupon(
            code="FIRSTORDER",
            order=self.order,
            customer=self.customer,
        )
        self.assertFalse(result.is_valid)

    def test_per_customer_usage_limit(self):
        """Test per-customer usage limit enforcement."""
        coupon = Coupon.objects.create(
            code="LIMITED",
            name="Limited Use",
            discount_type="percent",
            discount_percent=Decimal("10.00"),
            status="active",
            is_active=True,
            valid_from=timezone.now(),
            usage_limit_type="per_customer",
            max_uses_per_customer=1,
        )

        # First use should work
        result1 = CouponService.apply_coupon(
            code="LIMITED",
            order=self.order,
            customer=self.customer,
        )
        self.assertTrue(result1.success)

        # Create a new order for second attempt
        from apps.orders.models import Order
        order2 = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email="test@example.com",
            customer_name="Test Customer",
            subtotal_cents=10000,
            total_cents=10000,
        )

        # Second use should fail
        result2 = CouponService.validate_coupon(
            code="LIMITED",
            order=order2,
            customer=self.customer,
        )
        self.assertFalse(result2.is_valid)
        self.assertEqual(result2.error_code, "CUSTOMER_INELIGIBLE")

    def test_assigned_customer_coupon_valid(self):
        """Test personal coupon works for assigned customer."""
        coupon = Coupon.objects.create(
            code="PERSONAL",
            name="Personal Discount",
            discount_type="percent",
            discount_percent=Decimal("25.00"),
            status="active",
            is_active=True,
            valid_from=timezone.now(),
            customer_target="specific",
            assigned_customer=self.customer,
        )

        result = CouponService.validate_coupon(
            code="PERSONAL",
            order=self.order,
            customer=self.customer,
        )
        self.assertTrue(result.is_valid)

    def test_assigned_customer_coupon_invalid_for_others(self):
        """Test personal coupon fails for other customers."""
        from apps.customers.models import Customer

        other_customer = Customer.objects.create(
            name="Other Customer",
            customer_type="individual",
            status="active",
        )

        coupon = Coupon.objects.create(
            code="PERSONAL2",
            name="Personal Discount",
            discount_type="percent",
            discount_percent=Decimal("25.00"),
            status="active",
            is_active=True,
            valid_from=timezone.now(),
            customer_target="specific",
            assigned_customer=self.customer,  # Assigned to original customer
        )

        result = CouponService.validate_coupon(
            code="PERSONAL2",
            order=self.order,
            customer=other_customer,  # Different customer trying to use
        )
        self.assertFalse(result.is_valid)
        self.assertEqual(result.error_code, "CUSTOMER_INELIGIBLE")


class CouponStackingRulesTests(TestCase):
    """Tests for coupon stacking rules."""

    def setUp(self):
        """Set up test fixtures."""
        from apps.billing.models import Currency
        from apps.customers.models import Customer
        from apps.orders.models import Order, OrderItem
        from apps.products.models import Product

        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"name": "Romanian Leu", "symbol": "lei"}
        )
        self.customer = Customer.objects.create(
            name="Test Customer",
            customer_type="individual",
            status="active",
        )
        self.product = Product.objects.create(
            slug="shared-hosting",
            name="Shared Hosting",
            product_type="shared_hosting",
        )
        self.order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email="test@example.com",
            customer_name="Test Customer",
            subtotal_cents=20000,
            total_cents=20000,
        )
        # Create order item (required for discount calculations)
        self.order_item = OrderItem.objects.create(
            order=self.order,
            product=self.product,
            product_name="Shared Hosting",
            product_type="shared_hosting",
            billing_period="monthly",
            quantity=1,
            unit_price_cents=20000,
            setup_cents=0,
            line_total_cents=20000,
        )

    def test_exclusive_coupon_prevents_other_coupons(self):
        """Test exclusive coupon blocks other coupons."""
        exclusive = Coupon.objects.create(
            code="EXCLUSIVE",
            name="Exclusive",
            discount_type="percent",
            discount_percent=Decimal("30.00"),
            status="active",
            is_active=True,
            valid_from=timezone.now(),
            is_exclusive=True,
        )

        regular = Coupon.objects.create(
            code="REGULAR",
            name="Regular",
            discount_type="percent",
            discount_percent=Decimal("10.00"),
            status="active",
            is_active=True,
            valid_from=timezone.now(),
            is_stackable=True,
        )

        # Apply exclusive first
        result1 = CouponService.apply_coupon(
            code="EXCLUSIVE",
            order=self.order,
            customer=self.customer,
        )
        self.assertTrue(result1.success)

        # Try to apply regular - should fail
        result2 = CouponService.validate_coupon(
            code="REGULAR",
            order=self.order,
            customer=self.customer,
        )
        self.assertFalse(result2.is_valid)
        self.assertEqual(result2.error_code, "EXISTING_EXCLUSIVE")

    def test_non_stackable_coupon_blocks_additional(self):
        """Test non-stackable coupon blocks additional coupons."""
        coupon1 = Coupon.objects.create(
            code="FIRST",
            name="First",
            discount_type="percent",
            discount_percent=Decimal("10.00"),
            status="active",
            is_active=True,
            valid_from=timezone.now(),
            is_stackable=False,  # Not stackable
        )

        coupon2 = Coupon.objects.create(
            code="SECOND",
            name="Second",
            discount_type="percent",
            discount_percent=Decimal("5.00"),
            status="active",
            is_active=True,
            valid_from=timezone.now(),
            is_stackable=True,
        )

        # Apply first
        result1 = CouponService.apply_coupon(
            code="FIRST",
            order=self.order,
            customer=self.customer,
        )
        self.assertTrue(result1.success)

        # Try to apply second - should fail (first is non-stackable)
        result2 = CouponService.validate_coupon(
            code="SECOND",
            order=self.order,
            customer=self.customer,
        )
        self.assertFalse(result2.is_valid)
        self.assertEqual(result2.error_code, "EXISTING_NOT_STACKABLE")

    def test_exclusive_cannot_stack_on_existing(self):
        """Test exclusive coupon can't be added if coupons already applied."""
        regular = Coupon.objects.create(
            code="REGULAR",
            name="Regular",
            discount_type="percent",
            discount_percent=Decimal("10.00"),
            status="active",
            is_active=True,
            valid_from=timezone.now(),
            is_stackable=True,
        )

        exclusive = Coupon.objects.create(
            code="EXCLUSIVE",
            name="Exclusive",
            discount_type="percent",
            discount_percent=Decimal("30.00"),
            status="active",
            is_active=True,
            valid_from=timezone.now(),
            is_exclusive=True,
        )

        # Apply regular first
        result1 = CouponService.apply_coupon(
            code="REGULAR",
            order=self.order,
            customer=self.customer,
        )
        self.assertTrue(result1.success)

        # Try to apply exclusive - should fail
        result2 = CouponService.validate_coupon(
            code="EXCLUSIVE",
            order=self.order,
            customer=self.customer,
        )
        self.assertFalse(result2.is_valid)
        self.assertEqual(result2.error_code, "EXCLUSIVE_CONFLICT")


class CouponDiscountEdgeCasesTests(TestCase):
    """Tests for edge cases in discount calculation."""

    def setUp(self):
        """Set up test fixtures."""
        from apps.billing.models import Currency
        from apps.customers.models import Customer
        from apps.orders.models import Order, OrderItem
        from apps.products.models import Product

        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"name": "Romanian Leu", "symbol": "lei"}
        )
        self.customer = Customer.objects.create(
            name="Test Customer",
            customer_type="individual",
            status="active",
        )
        self.product = Product.objects.create(
            slug="basic-hosting",
            name="Basic Hosting",
            product_type="shared_hosting",
        )
        self.order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email="test@example.com",
            customer_name="Test Customer",
            subtotal_cents=5000,  # 50.00
            total_cents=5000,
        )
        # Create order item (required for discount calculations)
        self.order_item = OrderItem.objects.create(
            order=self.order,
            product=self.product,
            product_name="Basic Hosting",
            product_type="shared_hosting",
            billing_period="monthly",
            quantity=1,
            unit_price_cents=5000,
            setup_cents=0,
            line_total_cents=5000,
        )

    def test_discount_cannot_exceed_order_total(self):
        """Test that discount is capped at order total."""
        coupon = Coupon.objects.create(
            code="BIG",
            name="Big Discount",
            discount_type="fixed",
            discount_amount_cents=10000,  # 100.00 - more than order
            status="active",
            is_active=True,
            valid_from=timezone.now(),
            currency=self.currency,
        )

        result = CouponService.calculate_discount(
            coupon=coupon,
            order=self.order,
        )
        # Should be capped at order subtotal
        self.assertEqual(result.discount_cents, 5000)
        self.assertTrue(result.breakdown.get("limited_to_order_value"))

    def test_100_percent_discount(self):
        """Test 100% discount works correctly."""
        coupon = Coupon.objects.create(
            code="FREE",
            name="100% Off",
            discount_type="percent",
            discount_percent=Decimal("100.00"),
            status="active",
            is_active=True,
            valid_from=timezone.now(),
        )

        result = CouponService.calculate_discount(
            coupon=coupon,
            order=self.order,
        )
        self.assertEqual(result.discount_cents, 5000)

    def test_zero_order_discount(self):
        """Test discount calculation on zero-value order."""
        from apps.orders.models import Order

        zero_order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email="test@example.com",
            customer_name="Test Customer",
            subtotal_cents=0,
            total_cents=0,
        )

        coupon = Coupon.objects.create(
            code="ZERO",
            name="Zero Order",
            discount_type="percent",
            discount_percent=Decimal("20.00"),
            status="active",
            is_active=True,
            valid_from=timezone.now(),
        )

        result = CouponService.calculate_discount(
            coupon=coupon,
            order=zero_order,
        )
        self.assertEqual(result.discount_cents, 0)


class CampaignBudgetTests(TestCase):
    """Tests for campaign budget enforcement."""

    def setUp(self):
        """Set up test fixtures."""
        from apps.billing.models import Currency
        from apps.customers.models import Customer
        from apps.orders.models import Order, OrderItem
        from apps.products.models import Product

        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"name": "Romanian Leu", "symbol": "lei"}
        )
        self.customer = Customer.objects.create(
            name="Test Customer",
            customer_type="individual",
            status="active",
        )
        self.product = Product.objects.create(
            slug="campaign-hosting",
            name="Campaign Hosting",
            product_type="shared_hosting",
        )
        self.order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email="test@example.com",
            customer_name="Test Customer",
            subtotal_cents=10000,
            total_cents=10000,
        )
        # Create order item (required for discount calculations)
        self.order_item = OrderItem.objects.create(
            order=self.order,
            product=self.product,
            product_name="Campaign Hosting",
            product_type="shared_hosting",
            billing_period="monthly",
            quantity=1,
            unit_price_cents=10000,
            setup_cents=0,
            line_total_cents=10000,
        )

    def test_campaign_with_exhausted_budget(self):
        """Test coupon fails when campaign budget is exhausted."""
        campaign = PromotionCampaign.objects.create(
            name="Limited Budget",
            slug="limited-budget",
            campaign_type="flash_sale",
            start_date=timezone.now() - timezone.timedelta(days=1),
            budget_cents=10000,  # 100.00 budget
            spent_cents=10000,  # Already spent all
            status="active",
            is_active=True,
        )

        coupon = Coupon.objects.create(
            code="BUDGET",
            name="Budget Coupon",
            discount_type="percent",
            discount_percent=Decimal("10.00"),
            status="active",
            is_active=True,
            valid_from=timezone.now(),
            campaign=campaign,
        )

        result = CouponService.validate_coupon(
            code="BUDGET",
            order=self.order,
            customer=self.customer,
        )
        self.assertFalse(result.is_valid)
        self.assertEqual(result.error_code, "COUPON_INVALID")

    def test_campaign_spending_updates_on_redemption(self):
        """Test that campaign spending is tracked on redemption."""
        campaign = PromotionCampaign.objects.create(
            name="Tracking Budget",
            slug="tracking-budget",
            campaign_type="seasonal",
            start_date=timezone.now() - timezone.timedelta(days=1),
            budget_cents=100000,  # 1000.00 budget
            spent_cents=0,
            status="active",
            is_active=True,
        )

        coupon = Coupon.objects.create(
            code="TRACK",
            name="Tracked Coupon",
            discount_type="percent",
            discount_percent=Decimal("10.00"),
            status="active",
            is_active=True,
            valid_from=timezone.now(),
            campaign=campaign,
        )

        result = CouponService.apply_coupon(
            code="TRACK",
            order=self.order,
            customer=self.customer,
        )
        self.assertTrue(result.success)

        campaign.refresh_from_db()
        self.assertEqual(campaign.spent_cents, 1000)  # 10% of 10000


class LoyaltyTierUpgradeTests(TestCase):
    """Tests for loyalty tier upgrade functionality."""

    def setUp(self):
        """Set up test fixtures."""
        from apps.billing.models import Currency
        from apps.customers.models import Customer
        from apps.orders.models import Order

        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"name": "Romanian Leu", "symbol": "lei"}
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

        self.bronze = LoyaltyTier.objects.create(
            program=self.program,
            name="Bronze",
            slug="bronze",
            min_points_lifetime=0,
            points_multiplier=Decimal("1.00"),
            sort_order=0,
        )

        self.silver = LoyaltyTier.objects.create(
            program=self.program,
            name="Silver",
            slug="silver",
            min_points_lifetime=500,
            points_multiplier=Decimal("1.25"),
            sort_order=1,
        )

        self.gold = LoyaltyTier.objects.create(
            program=self.program,
            name="Gold",
            slug="gold",
            min_points_lifetime=2000,
            points_multiplier=Decimal("1.50"),
            sort_order=2,
        )

    def test_tier_upgrade_on_points_earned(self):
        """Test automatic tier upgrade when points threshold is reached."""
        from apps.orders.models import Order

        membership = LoyaltyService.get_or_create_membership(
            customer=self.customer,
            program=self.program,
        )
        self.assertEqual(membership.current_tier, self.bronze)

        # Create a large order to earn 600 points (cross silver threshold)
        order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email="test@example.com",
            customer_name="Test Customer",
            subtotal_cents=60000,  # 600.00 = 600 points
            total_cents=60000,
        )

        points = LoyaltyService.earn_points(membership=membership, order=order)
        self.assertEqual(points, 600)

        membership.refresh_from_db()
        self.assertEqual(membership.current_tier, self.silver)

    def test_tier_multiplier_applies_to_points(self):
        """Test that tier multiplier increases points earned."""
        from apps.orders.models import Order

        membership = LoyaltyService.get_or_create_membership(
            customer=self.customer,
            program=self.program,
        )
        # Manually set to silver tier
        membership.current_tier = self.silver
        membership.save()

        order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email="test@example.com",
            customer_name="Test Customer",
            subtotal_cents=10000,  # 100.00 = base 100 points
            total_cents=10000,
        )

        points = LoyaltyService.earn_points(membership=membership, order=order)
        # Silver tier has 1.25x multiplier
        self.assertEqual(points, 125)


class ReferralServiceTests(TestCase):
    """Tests for referral service functionality."""

    def setUp(self):
        """Set up test fixtures."""
        from apps.customers.models import Customer

        self.referrer = Customer.objects.create(
            name="Referrer",
            customer_type="individual",
            status="active",
        )
        self.referee = Customer.objects.create(
            name="Referee",
            customer_type="individual",
            status="active",
        )

    def test_create_referral_code(self):
        """Test creating a referral code for a customer."""
        code = ReferralService.get_or_create_referral_code(self.referrer)
        self.assertIsNotNone(code)
        self.assertEqual(code.owner, self.referrer)
        self.assertTrue(code.code.startswith("R"))  # Initials

    def test_create_referral_relationship(self):
        """Test creating a referral relationship."""
        referral_code = ReferralService.get_or_create_referral_code(self.referrer)

        referral = ReferralService.create_referral(
            referral_code=referral_code,
            referred_customer=self.referee,
        )

        self.assertIsNotNone(referral)
        self.assertEqual(referral.referral_code, referral_code)
        self.assertEqual(referral.referred_customer, self.referee)
        self.assertEqual(referral.status, "pending")

        # Verify stats updated
        referral_code.refresh_from_db()
        self.assertEqual(referral_code.total_referrals, 1)

    def test_cannot_self_refer(self):
        """Test that customer cannot refer themselves."""
        referral_code = ReferralService.get_or_create_referral_code(self.referrer)

        referral = ReferralService.create_referral(
            referral_code=referral_code,
            referred_customer=self.referrer,  # Same as owner
        )

        self.assertIsNone(referral)

    def test_cannot_refer_twice(self):
        """Test that a customer can only be referred once."""
        referral_code = ReferralService.get_or_create_referral_code(self.referrer)

        # First referral
        referral1 = ReferralService.create_referral(
            referral_code=referral_code,
            referred_customer=self.referee,
        )
        self.assertIsNotNone(referral1)

        # Second referral attempt
        referral2 = ReferralService.create_referral(
            referral_code=referral_code,
            referred_customer=self.referee,
        )
        self.assertIsNone(referral2)


class CouponRedemptionReveralTests(TestCase):
    """Tests for coupon redemption reversal (order cancellation)."""

    def setUp(self):
        """Set up test fixtures."""
        from apps.billing.models import Currency
        from apps.customers.models import Customer
        from apps.orders.models import Order, OrderItem
        from apps.products.models import Product

        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"name": "Romanian Leu", "symbol": "lei"}
        )
        self.customer = Customer.objects.create(
            name="Test Customer",
            customer_type="individual",
            status="active",
        )
        self.product = Product.objects.create(
            slug="reversal-hosting",
            name="Reversal Hosting",
            product_type="shared_hosting",
        )
        self.order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email="test@example.com",
            customer_name="Test Customer",
            subtotal_cents=10000,
            total_cents=10000,
        )
        # Create order item (required for discount calculations)
        self.order_item = OrderItem.objects.create(
            order=self.order,
            product=self.product,
            product_name="Reversal Hosting",
            product_type="shared_hosting",
            billing_period="monthly",
            quantity=1,
            unit_price_cents=10000,
            setup_cents=0,
            line_total_cents=10000,
        )

        self.campaign = PromotionCampaign.objects.create(
            name="Test Campaign",
            slug="test-campaign",
            campaign_type="seasonal",
            start_date=timezone.now() - timezone.timedelta(days=1),
            budget_cents=100000,
            spent_cents=0,
            status="active",
            is_active=True,
        )

        self.coupon = Coupon.objects.create(
            code="REVERSAL",
            name="Reversal Test",
            discount_type="percent",
            discount_percent=Decimal("20.00"),
            status="active",
            is_active=True,
            valid_from=timezone.now(),
            campaign=self.campaign,
        )

    def test_reversal_restores_coupon_usage(self):
        """Test that reversing redemption restores coupon usage count."""
        # Apply coupon
        result = CouponService.apply_coupon(
            code="REVERSAL",
            order=self.order,
            customer=self.customer,
        )
        self.assertTrue(result.success)

        self.coupon.refresh_from_db()
        self.assertEqual(self.coupon.total_uses, 1)
        self.assertEqual(self.coupon.total_discount_cents, 2000)

        # Remove coupon
        CouponService.remove_coupon(
            order=self.order,
            redemption_id=result.redemption_id,
        )

        self.coupon.refresh_from_db()
        self.assertEqual(self.coupon.total_uses, 0)
        self.assertEqual(self.coupon.total_discount_cents, 0)

    def test_reversal_restores_campaign_budget(self):
        """Test that reversing redemption restores campaign spending."""
        result = CouponService.apply_coupon(
            code="REVERSAL",
            order=self.order,
            customer=self.customer,
        )
        self.assertTrue(result.success)

        self.campaign.refresh_from_db()
        self.assertEqual(self.campaign.spent_cents, 2000)

        # Remove coupon
        CouponService.remove_coupon(
            order=self.order,
            redemption_id=result.redemption_id,
        )

        self.campaign.refresh_from_db()
        self.assertEqual(self.campaign.spent_cents, 0)

    def test_reversal_decrements_the_charged_campaign_not_the_current_one(self):
        """#481: Coupon.campaign is admin-editable. A redemption applied while the
        coupon belonged to campaign A must reverse against A even after the coupon
        moves to campaign B — otherwise A stays charged forever and B silently
        drifts negative (spent_cents has no >= 0 DB constraint)."""
        campaign_b = PromotionCampaign.objects.create(
            name="Successor Campaign",
            slug="successor-campaign",
            campaign_type="seasonal",
            start_date=timezone.now() - timezone.timedelta(days=1),
            budget_cents=50000,
            spent_cents=0,
            status="active",
            is_active=True,
        )

        result = CouponService.apply_coupon(code="REVERSAL", order=self.order, customer=self.customer)
        self.assertTrue(result.success)
        self.campaign.refresh_from_db()
        self.assertEqual(self.campaign.spent_cents, 2000)

        self.coupon.campaign = campaign_b
        self.coupon.save(update_fields=["campaign"])

        CouponService.remove_coupon(order=self.order, redemption_id=result.redemption_id)

        self.campaign.refresh_from_db()
        campaign_b.refresh_from_db()
        self.assertEqual(self.campaign.spent_cents, 0)
        self.assertEqual(campaign_b.spent_cents, 0)

    def test_mark_applied_snapshots_the_charged_campaign(self):
        result = CouponService.apply_coupon(code="REVERSAL", order=self.order, customer=self.customer)
        self.assertTrue(result.success)

        redemption = CouponRedemption.objects.get(pk=result.redemption_id)
        self.assertEqual(redemption.charged_campaign_id, self.campaign.pk)

    def test_reversal_without_snapshot_decrements_no_campaign(self):
        """A legacy-shaped row with no snapshot must not guess a campaign to
        decrement — the 0003 data migration makes the snapshot authoritative,
        so a NULL snapshot means 'nothing provably charged'."""
        result = CouponService.apply_coupon(code="REVERSAL", order=self.order, customer=self.customer)
        self.assertTrue(result.success)
        CouponRedemption.objects.filter(pk=result.redemption_id).update(charged_campaign_id=None)

        CouponService.remove_coupon(order=self.order, redemption_id=result.redemption_id)

        self.campaign.refresh_from_db()
        self.coupon.refresh_from_db()
        # Campaign untouched (no provable charge target)...
        self.assertEqual(self.campaign.spent_cents, 2000)
        # ...but coupon usage counters are still restored.
        self.assertEqual(self.coupon.total_uses, 0)

    def test_migration_backfills_snapshot_from_current_coupon_campaign(self):
        """0003's data function fills applied rows' snapshot from the coupon's
        current campaign — the best available approximation at migration time."""
        import importlib  # noqa: PLC0415  # migration-module import is test-local by design

        from django.db import connection  # noqa: PLC0415
        from django.db.migrations.loader import MigrationLoader  # noqa: PLC0415

        result = CouponService.apply_coupon(code="REVERSAL", order=self.order, customer=self.customer)
        self.assertTrue(result.success)
        CouponRedemption.objects.filter(pk=result.redemption_id).update(charged_campaign_id=None)

        module = importlib.import_module("apps.promotions.migrations.0003_couponredemption_charged_campaign")
        loader = MigrationLoader(connection)
        state = loader.project_state(("promotions", "0003_couponredemption_charged_campaign"))
        module.backfill_charged_campaign(state.apps, None)

        redemption = CouponRedemption.objects.get(pk=result.redemption_id)
        self.assertEqual(redemption.charged_campaign_id, self.campaign.pk)

    def test_concurrent_reversal_decrements_counters_exactly_once(self):
        """#421: two removals racing the same redemption must not double-decrement.

        mark_reversed() guarded on an in-memory ``self.status`` read and then wrote
        blindly, so two callers holding separate instances of the SAME row both passed
        the guard and both issued ``-1`` / ``-discount_cents``. Fetching the row twice
        reproduces that interleaving deterministically on any backend (select_for_update
        is a no-op on SQLite, so a thread-based test would prove nothing here).
        """
        result = CouponService.apply_coupon(
            code="REVERSAL",
            order=self.order,
            customer=self.customer,
        )
        self.assertTrue(result.success)

        self.coupon.refresh_from_db()
        self.campaign.refresh_from_db()
        self.assertEqual(self.coupon.total_uses, 1)
        self.assertEqual(self.coupon.total_discount_cents, 2000)
        self.assertEqual(self.campaign.spent_cents, 2000)

        # Two independent instances of the same row — the shape of two concurrent
        # remove_coupon() calls that both read status='applied' before either wrote.
        first = CouponRedemption.objects.get(id=result.redemption_id)
        second = CouponRedemption.objects.get(id=result.redemption_id)

        first.mark_reversed()
        second.mark_reversed()

        self.coupon.refresh_from_db()
        self.campaign.refresh_from_db()
        self.assertEqual(self.coupon.total_uses, 0, "total_uses decremented twice")
        self.assertEqual(self.coupon.total_discount_cents, 0, "total_discount_cents decremented twice")
        self.assertEqual(self.campaign.spent_cents, 0, "campaign spend decremented twice")

    def test_counters_never_go_negative_on_repeated_reversal(self):
        """The observable damage: counters driven below zero are not recoverable."""
        result = CouponService.apply_coupon(
            code="REVERSAL",
            order=self.order,
            customer=self.customer,
        )
        self.assertTrue(result.success)

        for _ in range(3):
            CouponRedemption.objects.get(id=result.redemption_id).mark_reversed()

        self.coupon.refresh_from_db()
        self.campaign.refresh_from_db()
        self.assertGreaterEqual(self.coupon.total_uses, 0)
        self.assertGreaterEqual(self.coupon.total_discount_cents, 0)
        self.assertGreaterEqual(self.campaign.spent_cents, 0)

    def test_reversal_is_idempotent_and_reports_whether_it_acted(self):
        """mark_reversed() must tell the caller whether THIS call did the reversal."""
        result = CouponService.apply_coupon(
            code="REVERSAL",
            order=self.order,
            customer=self.customer,
        )
        redemption = CouponRedemption.objects.get(id=result.redemption_id)

        self.assertTrue(redemption.mark_reversed(), "first reversal should report success")
        self.assertFalse(
            CouponRedemption.objects.get(id=result.redemption_id).mark_reversed(),
            "second reversal should report that it did nothing",
        )

    def test_stale_instance_reversal_refreshes_local_state(self):
        """A caller holding a stale instance must not be left thinking it is 'applied'."""
        result = CouponService.apply_coupon(
            code="REVERSAL",
            order=self.order,
            customer=self.customer,
        )
        stale = CouponRedemption.objects.get(id=result.redemption_id)
        CouponRedemption.objects.get(id=result.redemption_id).mark_reversed()

        self.assertFalse(stale.mark_reversed())
        self.assertEqual(stale.status, "reversed")
        self.assertIsNotNone(stale.reversed_at)
        # The three assertions above all pass against the OLD implementation too — it set
        # both attributes in memory before saving. What actually distinguishes the CAS is
        # that the LOSER performed no work: the counters moved exactly once, and only one
        # reversal was recorded.
        coupon = Coupon.objects.get(code="REVERSAL")
        self.assertEqual(coupon.total_uses, 0)
        self.assertEqual(coupon.total_discount_cents, 0)

    def test_remove_coupon_does_not_subtract_a_discount_it_did_not_reverse(self) -> None:
        """The service-level half of the fix, which nothing else covers.

        Every other test here calls mark_reversed() on model instances directly, so
        reverting `if redemption.mark_reversed():` to the old unconditional subtraction
        leaves the whole suite green while the customer-visible bug ships: the discount
        deducted twice, dropping the order total below what was actually discounted.

        The redemption queryset already filters status="applied", so a row reversed
        BEFORE the query never reaches the loop — the guard exists for the row reversed
        after materialization. That window is what this test drives, using the coupon
        lock as the seam, since it sits between materialization and the loop.
        """
        result = CouponService.apply_coupon(code="REVERSAL", order=self.order, customer=self.customer)
        self.order.refresh_from_db()
        self.assertGreater(self.order.discount_cents, 0, "fixture must actually discount the order")

        original_select_for_update = Coupon.objects.select_for_update

        def reverse_then_lock(*args: object, **kwargs: object) -> object:
            # A concurrent caller wins the CAS after this call materialized its queryset.
            CouponRedemption.objects.get(id=result.redemption_id).mark_reversed()
            return original_select_for_update(*args, **kwargs)

        with patch.object(Coupon.objects, "select_for_update", side_effect=reverse_then_lock):
            CouponService.remove_coupon(order=self.order, redemption_id=result.redemption_id)

        self.order.refresh_from_db()
        # The winner owns the subtraction. This call must leave the figure alone rather
        # than deducting the same discount a second time.
        self.assertEqual(self.order.discount_cents, 2000)
        coupon = Coupon.objects.get(code="REVERSAL")
        self.assertEqual(coupon.total_uses, 0, "counters must move exactly once")
        self.assertEqual(coupon.total_discount_cents, 0)

    def test_successful_reversal_is_audited(self) -> None:
        """The CAS uses QuerySet.update(), which fires neither pre_save nor post_save.

        The receiver that emitted coupon_redemption_reversed therefore stopped running.
        That is worse than a plain gap: mark_applied() still uses save(), so the trail
        would show every application with no matching reversal, and anyone reconciling
        discounts from it would conclude the discount is still live on the order.
        """
        from apps.audit.models import AuditEvent  # noqa: PLC0415

        result = CouponService.apply_coupon(code="REVERSAL", order=self.order, customer=self.customer)
        redemption = CouponRedemption.objects.get(id=result.redemption_id)

        self.assertTrue(redemption.mark_reversed())

        events = AuditEvent.objects.filter(action="coupon_redemption_reversed")
        self.assertEqual(events.count(), 1, "a reversal must leave exactly one audit event")
        event = events.get()
        self.assertEqual(event.old_values.get("status"), "applied")
        self.assertEqual(event.new_values.get("status"), "reversed")

    def test_a_lost_reversal_race_records_no_second_audit_event(self) -> None:
        """The loser changed nothing, so it must not claim it did."""
        from apps.audit.models import AuditEvent  # noqa: PLC0415

        result = CouponService.apply_coupon(code="REVERSAL", order=self.order, customer=self.customer)
        stale = CouponRedemption.objects.get(id=result.redemption_id)
        CouponRedemption.objects.get(id=result.redemption_id).mark_reversed()

        self.assertFalse(stale.mark_reversed())

        self.assertEqual(AuditEvent.objects.filter(action="coupon_redemption_reversed").count(), 1)
