"""
URL configuration for the Promotions app.
"""

from django.urls import path

from . import views

app_name = "promotions"

urlpatterns = [
    # =========================================================================
    # API Endpoints (for HTMX/AJAX)
    # =========================================================================
    path("api/validate/", views.ValidateCouponView.as_view(), name="api_validate_coupon"),
    path("api/apply/", views.ApplyCouponView.as_view(), name="api_apply_coupon"),
    path("api/remove/", views.RemoveCouponView.as_view(), name="api_remove_coupon"),
    path("api/available/", views.AvailableCouponsView.as_view(), name="api_available_coupons"),
    # Gift card API
    path("api/gift-card/validate/", views.ValidateGiftCardView.as_view(), name="api_validate_gift_card"),
    path("api/gift-card/redeem/", views.RedeemGiftCardView.as_view(), name="api_redeem_gift_card"),
    # =========================================================================
    # Staff Admin - Dashboard
    # =========================================================================
    path("admin/", views.PromotionsDashboardView.as_view(), name="dashboard"),
    # =========================================================================
    # Staff Admin - Campaigns
    # =========================================================================
    path("admin/campaigns/", views.CampaignListView.as_view(), name="campaign_list"),
    path("admin/campaigns/create/", views.CampaignCreateView.as_view(), name="campaign_create"),
    path("admin/campaigns/<uuid:pk>/", views.CampaignDetailView.as_view(), name="campaign_detail"),
    path("admin/campaigns/<uuid:pk>/edit/", views.CampaignUpdateView.as_view(), name="campaign_update"),
    # =========================================================================
    # Staff Admin - Coupons
    # =========================================================================
    path("admin/coupons/", views.CouponListView.as_view(), name="coupon_list"),
    path("admin/coupons/create/", views.CouponCreateView.as_view(), name="coupon_create"),
    path("admin/coupons/batch/", views.CouponBatchCreateView.as_view(), name="coupon_batch_create"),
    path("admin/coupons/<uuid:pk>/", views.CouponDetailView.as_view(), name="coupon_detail"),
    path("admin/coupons/<uuid:pk>/edit/", views.CouponUpdateView.as_view(), name="coupon_update"),
    # =========================================================================
    # Staff Admin - Gift Cards
    # =========================================================================
    path("admin/gift-cards/", views.GiftCardListView.as_view(), name="gift_card_list"),
    path("admin/gift-cards/create/", views.GiftCardCreateView.as_view(), name="gift_card_create"),
    path("admin/gift-cards/<uuid:pk>/", views.GiftCardDetailView.as_view(), name="gift_card_detail"),
    # =========================================================================
    # Staff Admin - Referrals
    # =========================================================================
    path("admin/referrals/", views.ReferralListView.as_view(), name="referral_list"),
    # =========================================================================
    # Staff Admin - Loyalty
    # =========================================================================
    path("admin/loyalty/", views.LoyaltyDashboardView.as_view(), name="loyalty_dashboard"),
    # =========================================================================
    # Staff Admin - Promotion Rules
    # =========================================================================
    path("admin/rules/", views.PromotionRuleListView.as_view(), name="rule_list"),
    path("admin/rules/create/", views.PromotionRuleCreateView.as_view(), name="rule_create"),
    path("admin/rules/<uuid:pk>/edit/", views.PromotionRuleUpdateView.as_view(), name="rule_update"),
]
