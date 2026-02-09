"""
Tests for the Promotions app models.
"""

from decimal import Decimal
from unittest.mock import MagicMock

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone

from apps.promotions.models import (
    Coupon,
    CouponRedemption,
    CustomerLoyalty,
    GiftCard,
    GiftCardTransaction,
    LoyaltyProgram,
    LoyaltyTier,
    LoyaltyTransaction,
    PromotionCampaign,
    PromotionRule,
    Referral,
    ReferralCode,
)


class PromotionCampaignModelTests(TestCase):
    """Tests for PromotionCampaign model."""

    def test_campaign_creation(self):
        """Test creating a campaign."""
        campaign = PromotionCampaign.objects.create(
            name="Summer Sale",
            slug="summer-sale-2024",
            description="Summer promotion campaign",
            campaign_type="seasonal",
            start_date=timezone.now(),
            status="active",
        )
        self.assertEqual(campaign.name, "Summer Sale")
        self.assertEqual(campaign.status, "active")
        self.assertTrue(campaign.is_active)

    def test_campaign_is_within_dates(self):
        """Test campaign date validation."""
        now = timezone.now()
        campaign = PromotionCampaign(
            name="Test",
            slug="test",
            start_date=now - timezone.timedelta(days=1),
            end_date=now + timezone.timedelta(days=1),
        )
        self.assertTrue(campaign.is_within_dates)

    def test_campaign_not_yet_started(self):
        """Test campaign that hasn't started."""
        campaign = PromotionCampaign(
            name="Test",
            slug="test",
            start_date=timezone.now() + timezone.timedelta(days=1),
        )
        self.assertFalse(campaign.is_within_dates)

    def test_campaign_ended(self):
        """Test campaign that has ended."""
        campaign = PromotionCampaign(
            name="Test",
            slug="test",
            start_date=timezone.now() - timezone.timedelta(days=2),
            end_date=timezone.now() - timezone.timedelta(days=1),
        )
        self.assertFalse(campaign.is_within_dates)

    def test_campaign_budget_tracking(self):
        """Test budget tracking."""
        campaign = PromotionCampaign(
            name="Test",
            slug="test",
            start_date=timezone.now(),
            budget_cents=100000,  # 1000.00
            spent_cents=50000,  # 500.00
        )
        self.assertEqual(campaign.remaining_budget_cents, 50000)
        self.assertTrue(campaign.is_within_budget)

    def test_campaign_budget_exceeded(self):
        """Test when budget is exceeded."""
        campaign = PromotionCampaign(
            name="Test",
            slug="test",
            start_date=timezone.now(),
            budget_cents=100000,
            spent_cents=100000,
        )
        self.assertEqual(campaign.remaining_budget_cents, 0)
        self.assertFalse(campaign.is_within_budget)


class CouponModelTests(TestCase):
    """Tests for Coupon model."""

    def test_coupon_creation(self):
        """Test creating a coupon."""
        coupon = Coupon.objects.create(
            code="SUMMER20",
            name="Summer Discount",
            discount_type="percent",
            discount_percent=Decimal("20.00"),
        )
        self.assertEqual(coupon.code, "SUMMER20")
        self.assertEqual(coupon.discount_type, "percent")
        self.assertEqual(coupon.discount_percent, Decimal("20.00"))

    def test_coupon_code_normalized(self):
        """Test that coupon code is normalized to uppercase."""
        coupon = Coupon.objects.create(
            code="summer20",
            name="Test",
            discount_type="percent",
            discount_percent=Decimal("20.00"),
        )
        self.assertEqual(coupon.code, "SUMMER20")

    def test_coupon_code_generation(self):
        """Test automatic code generation."""
        code1 = Coupon.generate_code()
        code2 = Coupon.generate_code()
        self.assertNotEqual(code1, code2)
        self.assertEqual(len(code1), 12)

    def test_coupon_code_with_prefix(self):
        """Test code generation with prefix."""
        code = Coupon.generate_code(prefix="SALE")
        self.assertTrue(code.startswith("SALE"))

    def test_coupon_basic_validity(self):
        """Test basic coupon validity check."""
        coupon = Coupon(
            code="TEST",
            name="Test",
            discount_type="percent",
            discount_percent=Decimal("10.00"),
            status="active",
            is_active=True,
            valid_from=timezone.now() - timezone.timedelta(days=1),
        )
        can_use, reason = coupon.can_be_used()
        self.assertTrue(can_use)

    def test_coupon_inactive(self):
        """Test inactive coupon."""
        coupon = Coupon(
            code="TEST",
            name="Test",
            discount_type="percent",
            discount_percent=Decimal("10.00"),
            status="active",
            is_active=False,
            valid_from=timezone.now(),
        )
        can_use, reason = coupon.can_be_used()
        self.assertFalse(can_use)
        self.assertEqual(reason, "Coupon is inactive")

    def test_coupon_expired(self):
        """Test expired coupon."""
        coupon = Coupon(
            code="TEST",
            name="Test",
            discount_type="percent",
            discount_percent=Decimal("10.00"),
            status="active",
            is_active=True,
            valid_from=timezone.now() - timezone.timedelta(days=10),
            valid_until=timezone.now() - timezone.timedelta(days=1),
        )
        can_use, reason = coupon.can_be_used()
        self.assertFalse(can_use)
        self.assertEqual(reason, "Coupon has expired")

    def test_coupon_not_yet_valid(self):
        """Test coupon that's not yet valid."""
        coupon = Coupon(
            code="TEST",
            name="Test",
            discount_type="percent",
            discount_percent=Decimal("10.00"),
            status="active",
            is_active=True,
            valid_from=timezone.now() + timezone.timedelta(days=1),
        )
        can_use, reason = coupon.can_be_used()
        self.assertFalse(can_use)
        self.assertEqual(reason, "Coupon is not yet valid")

    def test_coupon_depleted_single_use(self):
        """Test depleted single-use coupon."""
        coupon = Coupon(
            code="TEST",
            name="Test",
            discount_type="percent",
            discount_percent=Decimal("10.00"),
            status="active",
            is_active=True,
            valid_from=timezone.now(),
            usage_limit_type="single_use",
            total_uses=1,
        )
        can_use, reason = coupon.can_be_used()
        self.assertFalse(can_use)
        self.assertEqual(reason, "Coupon usage limit reached")

    def test_coupon_remaining_uses(self):
        """Test remaining uses calculation."""
        coupon = Coupon(
            code="TEST",
            name="Test",
            discount_type="percent",
            discount_percent=Decimal("10.00"),
            usage_limit_type="limited",
            max_total_uses=100,
            total_uses=30,
        )
        self.assertEqual(coupon.remaining_uses, 70)

    def test_coupon_unlimited_remaining_uses(self):
        """Test unlimited coupon has no remaining uses count."""
        coupon = Coupon(
            code="TEST",
            name="Test",
            discount_type="percent",
            discount_percent=Decimal("10.00"),
            usage_limit_type="unlimited",
        )
        self.assertIsNone(coupon.remaining_uses)

    def test_coupon_percent_validation(self):
        """Test percentage discount validation."""
        coupon = Coupon(
            code="TEST",
            name="Test",
            discount_type="percent",
            discount_percent=Decimal("150.00"),  # Invalid
        )
        with self.assertRaises(ValidationError):
            coupon.clean()

    def test_coupon_fixed_requires_amount(self):
        """Test fixed discount requires amount."""
        coupon = Coupon(
            code="TEST",
            name="Test",
            discount_type="fixed",
            # Missing discount_amount_cents
        )
        with self.assertRaises(ValidationError):
            coupon.clean()

    def test_coupon_date_validation(self):
        """Test date range validation."""
        coupon = Coupon(
            code="TEST",
            name="Test",
            discount_type="percent",
            discount_percent=Decimal("10.00"),
            valid_from=timezone.now(),
            valid_until=timezone.now() - timezone.timedelta(days=1),  # Invalid
        )
        with self.assertRaises(ValidationError):
            coupon.clean()

    def test_batch_coupon_creation(self):
        """Test batch coupon creation."""
        coupons = Coupon.generate_batch(
            count=5,
            prefix="BATCH",
            name="Batch Coupon",
            discount_type="percent",
            discount_percent=Decimal("15.00"),
        )
        self.assertEqual(len(coupons), 5)
        for coupon in coupons:
            self.assertTrue(coupon.code.startswith("BATCH"))


class GiftCardModelTests(TestCase):
    """Tests for GiftCard model."""

    def setUp(self):
        """Set up test fixtures."""
        from apps.billing.models import Currency
        self.currency = Currency.objects.create(
            code="RON",
            name="Romanian Leu",
            symbol="lei",
        )

    def test_gift_card_creation(self):
        """Test creating a gift card."""
        gift_card = GiftCard.objects.create(
            code=GiftCard.generate_code(),
            initial_value_cents=10000,
            current_balance_cents=10000,
            currency=self.currency,
            status="active",
        )
        self.assertEqual(gift_card.initial_value_cents, 10000)
        self.assertEqual(gift_card.current_balance_cents, 10000)

    def test_gift_card_code_format(self):
        """Test gift card code format."""
        code = GiftCard.generate_code()
        # Format: XXXX-XXXX-XXXX-XXXX
        self.assertEqual(len(code), 19)
        self.assertEqual(code.count("-"), 3)

    def test_gift_card_is_valid(self):
        """Test gift card validity check."""
        gift_card = GiftCard(
            code="TEST-1234-5678-9012",
            initial_value_cents=10000,
            current_balance_cents=5000,
            currency=self.currency,
            status="partially_used",
            is_active=True,
        )
        self.assertTrue(gift_card.is_valid)

    def test_gift_card_depleted(self):
        """Test depleted gift card."""
        gift_card = GiftCard(
            code="TEST-1234-5678-9012",
            initial_value_cents=10000,
            current_balance_cents=0,
            currency=self.currency,
            status="depleted",
            is_active=True,
        )
        self.assertFalse(gift_card.is_valid)

    def test_gift_card_expired(self):
        """Test expired gift card."""
        gift_card = GiftCard(
            code="TEST-1234-5678-9012",
            initial_value_cents=10000,
            current_balance_cents=5000,
            currency=self.currency,
            status="active",
            is_active=True,
            valid_until=timezone.now() - timezone.timedelta(days=1),
        )
        self.assertFalse(gift_card.is_valid)


class ReferralCodeModelTests(TestCase):
    """Tests for ReferralCode model."""

    def setUp(self):
        """Set up test fixtures."""
        from apps.customers.models import Customer
        self.customer = Customer.objects.create(
            name="John Doe",
            customer_type="individual",
            status="active",
        )

    def test_referral_code_generation(self):
        """Test referral code generation."""
        code = ReferralCode.generate_code_for_customer(self.customer)
        # Should start with initials
        self.assertTrue(code.startswith("JD"))


class LoyaltyProgramModelTests(TestCase):
    """Tests for LoyaltyProgram model."""

    def setUp(self):
        """Set up test fixtures."""
        from apps.billing.models import Currency
        self.currency = Currency.objects.create(
            code="RON",
            name="Romanian Leu",
            symbol="lei",
        )

    def test_loyalty_program_creation(self):
        """Test creating a loyalty program."""
        program = LoyaltyProgram.objects.create(
            name="PRAHO Rewards",
            points_per_currency_unit=Decimal("1.00"),
            points_per_discount_unit=100,
            min_points_to_redeem=100,
            max_discount_percent=Decimal("50.00"),
            currency=self.currency,
        )
        self.assertEqual(program.name, "PRAHO Rewards")
        self.assertTrue(program.is_active)

    def test_loyalty_tier_creation(self):
        """Test creating loyalty tiers."""
        program = LoyaltyProgram.objects.create(
            name="Rewards",
            currency=self.currency,
        )
        bronze = LoyaltyTier.objects.create(
            program=program,
            name="Bronze",
            slug="bronze",
            min_points_lifetime=0,
            points_multiplier=Decimal("1.00"),
            sort_order=0,
        )
        silver = LoyaltyTier.objects.create(
            program=program,
            name="Silver",
            slug="silver",
            min_points_lifetime=1000,
            points_multiplier=Decimal("1.25"),
            sort_order=1,
        )
        gold = LoyaltyTier.objects.create(
            program=program,
            name="Gold",
            slug="gold",
            min_points_lifetime=5000,
            points_multiplier=Decimal("1.50"),
            sort_order=2,
        )

        self.assertEqual(program.tiers.count(), 3)
        self.assertEqual(gold.min_points_lifetime, 5000)


class PromotionRuleModelTests(TestCase):
    """Tests for PromotionRule model."""

    def test_rule_creation(self):
        """Test creating a promotion rule."""
        rule = PromotionRule.objects.create(
            name="10% off orders over 500 RON",
            rule_type="threshold",
            discount_type="percent",
            discount_percent=Decimal("10.00"),
            conditions={"min_order_cents": 50000},
        )
        self.assertEqual(rule.name, "10% off orders over 500 RON")
        self.assertTrue(rule.is_active)

    def test_rule_validity(self):
        """Test rule validity check."""
        rule = PromotionRule(
            name="Test",
            rule_type="automatic",
            discount_type="percent",
            discount_percent=Decimal("10.00"),
            valid_from=timezone.now() - timezone.timedelta(days=1),
            is_active=True,
        )
        self.assertTrue(rule.is_valid)

    def test_rule_not_active(self):
        """Test inactive rule."""
        rule = PromotionRule(
            name="Test",
            rule_type="automatic",
            discount_type="percent",
            discount_percent=Decimal("10.00"),
            valid_from=timezone.now(),
            is_active=False,
        )
        self.assertFalse(rule.is_valid)

    def test_tiered_rule(self):
        """Test tiered discount rule."""
        rule = PromotionRule.objects.create(
            name="Tiered Discount",
            rule_type="tiered",
            discount_type="tiered_percent",
            tiers=[
                {"threshold": 10000, "threshold_type": "amount", "percent": 5},
                {"threshold": 25000, "threshold_type": "amount", "percent": 10},
                {"threshold": 50000, "threshold_type": "amount", "percent": 15},
            ],
        )
        self.assertEqual(len(rule.tiers), 3)
