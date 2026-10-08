"""Coverage additions for each promotion list using the shared presentation context."""

from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.promotions.models import Coupon, GiftCard, PromotionCampaign, PromotionRule, Referral, ReferralCode
from apps.promotions.views import (
    CampaignListView,
    CouponListView,
    GiftCardListView,
    PromotionRuleListView,
    ReferralListView,
)
from apps.users.models import User
from tests.common.pagination_assertions import SEARCH, assert_next_query


class PromotionPaginationQueryTests(TestCase):
    def setUp(self) -> None:
        staff = User.objects.create_user(email="promo-pagination@example.test", is_staff=True, staff_role="admin")
        self.client.force_login(staff)
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        owner = Customer.objects.create(name="Referral owner", primary_email="owner@example.test")
        code = ReferralCode.objects.create(code="PAGING", owner=owner)
        for number in range(2):
            PromotionCampaign.objects.create(
                name=f"Campaign {number}", slug=f"paging-{number}", start_date=timezone.now()
            )
            Coupon.objects.create(code=f"PAGING{number}", name="Paging", discount_type="percent", discount_percent=10)
            GiftCard.objects.create(
                code=f"PAGING-{number}", initial_value_cents=1000, current_balance_cents=0, currency=currency
            )
            PromotionRule.objects.create(name=f"Rule {number}", discount_type="percent", discount_percent=10)
            customer = Customer.objects.create(
                name=f"Referral {number}", primary_email=f"referral-{number}@example.test"
            )
            Referral.objects.create(referral_code=code, referred_customer=customer)

    def check_page(self, route: str) -> None:
        response = self.client.get(reverse(f"promotions:{route}"), {"q": SEARCH, "facet": ["one", "two"], "page": "1"})
        assert_next_query(self, response, {"q": [SEARCH], "facet": ["one", "two"]})

    def test_campaign_list_next_link_round_trips_filters(self) -> None:
        with patch.object(CampaignListView, "paginate_by", 1):
            self.check_page("campaign_list")

    def test_coupon_list_next_link_round_trips_filters(self) -> None:
        with patch.object(CouponListView, "paginate_by", 1):
            self.check_page("coupon_list")

    def test_gift_card_list_next_link_round_trips_filters(self) -> None:
        with patch.object(GiftCardListView, "paginate_by", 1):
            self.check_page("gift_card_list")

    def test_rule_list_next_link_round_trips_filters(self) -> None:
        with patch.object(PromotionRuleListView, "paginate_by", 1):
            self.check_page("rule_list")

    def test_referral_list_next_link_round_trips_filters(self) -> None:
        with patch.object(ReferralListView, "paginate_by", 1):
            self.check_page("referral_list")
