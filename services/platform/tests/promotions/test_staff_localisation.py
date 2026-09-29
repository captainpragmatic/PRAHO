"""Promotion dates use the staff request's date format and timezone."""

from datetime import UTC, datetime

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order
from apps.promotions.models import (
    Coupon,
    CouponRedemption,
    CustomerLoyalty,
    GiftCard,
    GiftCardTransaction,
    LoyaltyProgram,
    LoyaltyTransaction,
    PromotionCampaign,
    Referral,
    ReferralCode,
)
from apps.users.models import UserProfile


class PromotionStaffLocalisationTests(TestCase):
    @classmethod
    def setUpTestData(cls) -> None:
        cls.instant = datetime(2025, 12, 31, 22, 30, tzinfo=UTC)
        cls.staff = get_user_model().objects.create_user(email="promo-dates@example.test", staff_role="billing")
        cls.profile, _ = UserProfile.objects.get_or_create(user=cls.staff)
        cls.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"name": "Leu", "symbol": "lei"})
        cls.customer = Customer.objects.create(name="Date display buyer", customer_type="individual")
        cls.campaign = PromotionCampaign.objects.create(
            name="Localised campaign", slug="localised", start_date=cls.instant, end_date=cls.instant
        )
        cls.coupon = Coupon.objects.create(
            code="LOCALDATES", name="Localised coupon", campaign=cls.campaign,
            discount_type="percent", discount_percent=10, valid_until=cls.instant,
        )
        order = Order.objects.create(customer=cls.customer, currency=cls.currency, order_number="ORD-LOCALDATES")
        CouponRedemption.objects.create(
            coupon=cls.coupon, order=order, customer=cls.customer, discount_type="percent", discount_value=10,
            order_subtotal_cents=1000, order_total_cents=900, discount_cents=100, status="applied",
            applied_at=cls.instant,
        )
        cls.gift = GiftCard.objects.create(
            code="LOCAL-GIFT", initial_value_cents=1000, current_balance_cents=0, currency=cls.currency
        )
        gift_entry = GiftCardTransaction.objects.create(
            gift_card=cls.gift, transaction_type="purchase", amount_cents=1000, balance_after_cents=1000
        )
        GiftCardTransaction.objects.filter(pk=gift_entry.pk).update(created_at=cls.instant)
        program = LoyaltyProgram.objects.create(name="Localised loyalty", currency=cls.currency)
        loyalty = CustomerLoyalty.objects.create(customer=cls.customer, program=program)
        loyalty_entry = LoyaltyTransaction.objects.create(
            customer_loyalty=loyalty, transaction_type="earn", points=10, balance_after=10
        )
        LoyaltyTransaction.objects.filter(pk=loyalty_entry.pk).update(created_at=cls.instant)
        referral_code = ReferralCode.objects.create(code="LOCAL-REFERRAL", owner=cls.customer)
        referral = Referral.objects.create(referral_code=referral_code, referred_customer=cls.customer)
        Referral.objects.filter(pk=referral.pk).update(created_at=cls.instant)

    def setUp(self) -> None:
        self.client.force_login(self.staff)

    def test_all_promotion_dates_follow_request_preferences_across_midnight(self) -> None:
        routes = (
            ("campaign_list", None, 2),
            ("campaign_detail", self.campaign.pk, 3),
            ("coupon_detail", self.coupon.pk, 2),
            ("gift_card_detail", self.gift.pk, 1),
            ("loyalty_dashboard", None, 1),
            ("referral_list", None, 1),
            ("dashboard", None, 1),
        )
        for zone, pattern, expected in (
            ("Europe/Bucharest", "%Y-%m-%d", "2026-01-01 00:30"),
            ("America/New_York", "%m/%d/%Y", "12/31/2025 17:30"),
        ):
            self.profile.timezone = zone
            self.profile.date_format = pattern
            self.profile.save(update_fields=["timezone", "date_format"])
            for route, pk, count in routes:
                with self.subTest(zone=zone, route=route), timezone.override("UTC"):
                    response = self.client.get(reverse(f"promotions:{route}", kwargs={"pk": pk} if pk else None))
                    self.assertContains(response, expected, count=count)
                    self.assertEqual(timezone.get_current_timezone_name(), "UTC")

    def test_missing_promotion_dates_keep_their_placeholder(self) -> None:
        self.campaign.end_date = None
        self.campaign.save(update_fields=["end_date"])
        self.coupon.valid_until = None
        self.coupon.save(update_fields=["valid_until"])
        for route, pk in (("campaign_detail", self.campaign.pk), ("coupon_detail", self.coupon.pk)):
            with self.subTest(route=route):
                response = self.client.get(reverse(f"promotions:{route}", kwargs={"pk": pk}))
                self.assertContains(response, "—")
                self.assertNotContains(response, "None")
