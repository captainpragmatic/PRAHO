"""
Views for the Promotions app.
Handles coupon validation, application, and promotion management.
"""

from __future__ import annotations

import logging
from typing import Any

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.db.models import Count, F, Q, Sum
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.http import require_POST
from django.views.generic import (
    CreateView,
    DeleteView,
    DetailView,
    ListView,
    TemplateView,
    UpdateView,
)
from ratelimit.decorators import ratelimit

from .models import (
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
from .services import (
    ApplyResult,
    CouponService,
    GiftCardService,
    LoyaltyService,
    PromotionRuleService,
    ReferralService,
)

logger = logging.getLogger(__name__)


# ===============================================================================
# Staff Mixin
# ===============================================================================


class StaffRequiredMixin(LoginRequiredMixin, UserPassesTestMixin):
    """Mixin requiring user to be staff."""

    def test_func(self) -> bool:
        return self.request.user.is_staff


# ===============================================================================
# API Views (for HTMX/AJAX)
# ===============================================================================


def _get_customer_from_request(request: HttpRequest) -> Any:
    """
    Get the customer associated with the authenticated user.
    Returns None if user is not authenticated or has no customer membership.
    DRY helper to avoid repeating this logic in every view.
    """
    if not request.user.is_authenticated:
        return None
    if hasattr(request.user, "customer_memberships"):
        membership = request.user.customer_memberships.filter(is_primary=True).first()
        if membership:
            return membership.customer
    return None


def _user_can_access_order(request: HttpRequest, order: Any) -> bool:
    """
    Check if the user has permission to access an order.
    Staff can access all orders, customers can only access their own.

    SECURITY: Prevents unauthorized order access by validating ownership.
    """
    if not request.user.is_authenticated:
        # Anonymous users can only access their own session's draft orders
        # For now, we allow this as draft orders are tied to sessions
        return order.status == "draft"

    # Staff can access all orders
    if request.user.is_staff:
        return True

    # Check if user is associated with the order's customer
    customer = _get_customer_from_request(request)
    if customer and order.customer_id == customer.id:
        return True

    return False


@method_decorator(ratelimit(key="ip", rate="30/m", method="POST", block=False), name="dispatch")  # type: ignore[misc]
@method_decorator(ratelimit(key="post:code", rate="10/m", method="POST", block=False), name="dispatch")  # type: ignore[misc]
class ValidateCouponView(View):
    """
    API endpoint for validating a coupon code.
    Returns JSON with validation result.

    Rate limited to prevent brute-force attacks on coupon codes.
    """

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> JsonResponse:
        from apps.orders.models import Order

        # Check rate limit
        if getattr(request, "limited", False):
            logger.warning(
                "Rate limit exceeded for coupon validation from IP %s",
                request.META.get("REMOTE_ADDR"),
            )
            return JsonResponse({
                "valid": False,
                "error": "Too many requests. Please try again later.",
                "error_code": "RATE_LIMITED",
            }, status=429)

        code = request.POST.get("code", "").strip()
        order_id = request.POST.get("order_id")

        if not code:
            return JsonResponse({
                "valid": False,
                "error": "Please enter a coupon code",
                "error_code": "EMPTY_CODE",
            })

        if not order_id:
            return JsonResponse({
                "valid": False,
                "error": "Order not found",
                "error_code": "NO_ORDER",
            })

        try:
            order = Order.objects.select_related("customer", "currency").get(id=order_id)
        except Order.DoesNotExist:
            return JsonResponse({
                "valid": False,
                "error": "Order not found",
                "error_code": "ORDER_NOT_FOUND",
            })

        # SECURITY: Verify user has permission to access this order
        if not _user_can_access_order(request, order):
            logger.warning(
                "Unauthorized order access attempt: user=%s order=%s",
                request.user.id if request.user.is_authenticated else "anonymous",
                order_id,
            )
            return JsonResponse({
                "valid": False,
                "error": "Order not found",
                "error_code": "ORDER_NOT_FOUND",
            }, status=404)

        # Get customer from request (DRY helper)
        customer = _get_customer_from_request(request)

        # Validate coupon
        validation = CouponService.validate_coupon(code, order, customer)

        if not validation.is_valid:
            return JsonResponse({
                "valid": False,
                "error": validation.error_message,
                "error_code": validation.error_code,
            })

        # Get discount preview
        coupon = CouponService.get_coupon_by_code(code)
        if coupon:
            discount = CouponService.calculate_discount(coupon, order)
            return JsonResponse({
                "valid": True,
                "coupon": {
                    "code": coupon.code,
                    "name": coupon.name,
                    "description": coupon.description,
                    "discount_type": coupon.discount_type,
                },
                "discount": {
                    "amount_cents": discount.discount_cents,
                    "amount_display": f"{discount.discount_cents / 100:.2f}",
                    "description": discount.discount_description,
                },
                "warnings": validation.warnings,
            })

        return JsonResponse({
            "valid": False,
            "error": "Coupon not found",
            "error_code": "NOT_FOUND",
        })


@method_decorator(ratelimit(key="ip", rate="20/m", method="POST", block=False), name="dispatch")  # type: ignore[misc]
@method_decorator(ratelimit(key="post:code", rate="5/m", method="POST", block=False), name="dispatch")  # type: ignore[misc]
class ApplyCouponView(View):
    """
    API endpoint for applying a coupon to an order.

    Rate limited more strictly than validation to prevent abuse.
    """

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> JsonResponse:
        from apps.orders.models import Order

        # Check rate limit
        if getattr(request, "limited", False):
            logger.warning(
                "Rate limit exceeded for coupon application from IP %s",
                request.META.get("REMOTE_ADDR"),
            )
            return JsonResponse({
                "success": False,
                "error": "Too many requests. Please try again later.",
            }, status=429)

        code = request.POST.get("code", "").strip()
        order_id = request.POST.get("order_id")

        if not code or not order_id:
            return JsonResponse({
                "success": False,
                "error": "Missing required parameters",
            }, status=400)

        try:
            order = Order.objects.select_related("customer", "currency").get(id=order_id)
        except Order.DoesNotExist:
            return JsonResponse({
                "success": False,
                "error": "Order not found",
            }, status=404)

        # SECURITY: Verify user has permission to access this order
        if not _user_can_access_order(request, order):
            logger.warning(
                "Unauthorized order modification attempt: user=%s order=%s",
                request.user.id if request.user.is_authenticated else "anonymous",
                order_id,
            )
            return JsonResponse({
                "success": False,
                "error": "Order not found",
            }, status=404)

        # Get customer from request (DRY helper)
        customer = _get_customer_from_request(request)

        # Get user for audit
        user = request.user if request.user.is_authenticated else None

        # Apply coupon
        result = CouponService.apply_coupon(
            code=code,
            order=order,
            customer=customer,
            user=user,
            source_ip=request.META.get("REMOTE_ADDR"),
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
        )

        if result.success:
            return JsonResponse({
                "success": True,
                "discount_cents": result.discount_cents,
                "discount_display": f"{result.discount_cents / 100:.2f}",
                "new_total_cents": order.total_cents,
                "new_total_display": f"{order.total_cents / 100:.2f}",
                "warnings": result.warnings,
            })
        else:
            return JsonResponse({
                "success": False,
                "error": result.error_message,
            })


@method_decorator(ratelimit(key="ip", rate="30/m", method="POST", block=False), name="dispatch")  # type: ignore[misc]
class RemoveCouponView(View):
    """
    API endpoint for removing a coupon from an order.
    """

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> JsonResponse:
        from apps.orders.models import Order

        # Check rate limit
        if getattr(request, "limited", False):
            return JsonResponse({
                "success": False,
                "error": "Too many requests. Please try again later.",
            }, status=429)

        order_id = request.POST.get("order_id")
        redemption_id = request.POST.get("redemption_id")

        if not order_id:
            return JsonResponse({
                "success": False,
                "error": "Missing order ID",
            }, status=400)

        try:
            order = Order.objects.get(id=order_id)
        except Order.DoesNotExist:
            return JsonResponse({
                "success": False,
                "error": "Order not found",
            }, status=404)

        # SECURITY: Verify user has permission to modify this order
        if not _user_can_access_order(request, order):
            logger.warning(
                "Unauthorized order modification attempt (remove coupon): user=%s order=%s",
                request.user.id if request.user.is_authenticated else "anonymous",
                order_id,
            )
            return JsonResponse({
                "success": False,
                "error": "Order not found",
            }, status=404)

        success = CouponService.remove_coupon(
            order=order,
            redemption_id=redemption_id,
        )

        if success:
            return JsonResponse({
                "success": True,
                "new_total_cents": order.total_cents,
                "new_total_display": f"{order.total_cents / 100:.2f}",
            })
        else:
            return JsonResponse({
                "success": False,
                "error": "Failed to remove coupon",
            })


class AvailableCouponsView(View):
    """
    API endpoint for getting available coupons for an order.
    """

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> JsonResponse:
        from apps.orders.models import Order

        order_id = request.GET.get("order_id")

        if not order_id:
            return JsonResponse({"coupons": []})

        try:
            order = Order.objects.get(id=order_id)
        except Order.DoesNotExist:
            return JsonResponse({"coupons": []})

        # SECURITY: Verify user has permission to access this order
        if not _user_can_access_order(request, order):
            # Return empty list for unauthorized access (no info leak)
            return JsonResponse({"coupons": []})

        # Get customer using DRY helper
        customer = _get_customer_from_request(request)

        coupons = CouponService.get_available_coupons_for_order(
            order=order,
            customer=customer,
            include_private=False,
        )

        return JsonResponse({
            "coupons": [
                {
                    "code": c.code,
                    "name": c.name,
                    "description": c.description,
                    "discount_type": c.discount_type,
                    "discount_value": (
                        float(c.discount_percent) if c.discount_percent
                        else c.discount_amount_cents
                    ),
                }
                for c in coupons
            ]
        })


# ===============================================================================
# Gift Card Views
# ===============================================================================


@method_decorator(ratelimit(key="ip", rate="30/m", method="POST", block=False), name="dispatch")  # type: ignore[misc]
@method_decorator(ratelimit(key="post:code", rate="10/m", method="POST", block=False), name="dispatch")  # type: ignore[misc]
class ValidateGiftCardView(View):
    """
    API endpoint for validating a gift card.

    Rate limited to prevent brute-force attacks on gift card codes.
    """

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> JsonResponse:
        # Check rate limit
        if getattr(request, "limited", False):
            logger.warning(
                "Rate limit exceeded for gift card validation from IP %s",
                request.META.get("REMOTE_ADDR"),
            )
            return JsonResponse({
                "valid": False,
                "error": "Too many requests. Please try again later.",
            }, status=429)

        code = request.POST.get("code", "").strip()

        if not code:
            return JsonResponse({
                "valid": False,
                "error": "Please enter a gift card code",
            })

        validation = GiftCardService.validate_gift_card(code)

        if validation.is_valid:
            gift_card = GiftCard.objects.get(code=code.upper().strip())
            return JsonResponse({
                "valid": True,
                "balance_cents": gift_card.current_balance_cents,
                "balance_display": f"{gift_card.current_balance_cents / 100:.2f}",
                "currency": gift_card.currency.code,
            })
        else:
            return JsonResponse({
                "valid": False,
                "error": validation.error_message,
            })


@method_decorator(ratelimit(key="ip", rate="20/m", method="POST", block=False), name="dispatch")  # type: ignore[misc]
@method_decorator(ratelimit(key="post:code", rate="5/m", method="POST", block=False), name="dispatch")  # type: ignore[misc]
class RedeemGiftCardView(View):
    """API endpoint for redeeming a gift card."""

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> JsonResponse:
        from apps.orders.models import Order

        # Check rate limit
        if getattr(request, "limited", False):
            logger.warning(
                "Rate limit exceeded for gift card redemption from IP %s",
                request.META.get("REMOTE_ADDR"),
            )
            return JsonResponse({
                "success": False,
                "error": "Too many requests. Please try again later.",
            }, status=429)

        code = request.POST.get("code", "").strip()
        order_id = request.POST.get("order_id")
        amount_cents = request.POST.get("amount_cents")

        if not code or not order_id:
            return JsonResponse({
                "success": False,
                "error": "Missing required parameters",
            }, status=400)

        try:
            order = Order.objects.get(id=order_id)
        except Order.DoesNotExist:
            return JsonResponse({
                "success": False,
                "error": "Order not found",
            }, status=404)

        # SECURITY: Verify user has permission to modify this order
        if not _user_can_access_order(request, order):
            logger.warning(
                "Unauthorized order modification attempt (gift card): user=%s order=%s",
                request.user.id if request.user.is_authenticated else "anonymous",
                order_id,
            )
            return JsonResponse({
                "success": False,
                "error": "Order not found",
            }, status=404)

        # Get customer using DRY helper
        customer = _get_customer_from_request(request)

        user = request.user if request.user.is_authenticated else None

        result = GiftCardService.redeem_gift_card(
            code=code,
            order=order,
            amount_cents=int(amount_cents) if amount_cents else None,
            customer=customer,
            user=user,
        )

        if result.success:
            return JsonResponse({
                "success": True,
                "discount_cents": result.discount_cents,
                "new_total_cents": order.total_cents,
            })
        else:
            return JsonResponse({
                "success": False,
                "error": result.error_message,
            })


# ===============================================================================
# Staff Admin Views - Campaigns
# ===============================================================================


class CampaignListView(StaffRequiredMixin, ListView):
    """List all promotion campaigns."""

    model = PromotionCampaign
    template_name = "promotions/admin/campaign_list.html"
    context_object_name = "campaigns"
    paginate_by = 25

    def get_queryset(self):
        queryset = super().get_queryset()

        # Filter by status
        status = self.request.GET.get("status")
        if status:
            queryset = queryset.filter(status=status)

        # Filter by campaign type
        campaign_type = self.request.GET.get("type")
        if campaign_type:
            queryset = queryset.filter(campaign_type=campaign_type)

        # Search
        search = self.request.GET.get("search")
        if search:
            queryset = queryset.filter(
                Q(name__icontains=search) | Q(slug__icontains=search)
            )

        return queryset.annotate(
            coupon_count=Count("coupons"),
            total_redemptions=Sum("coupons__total_uses"),
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["statuses"] = PromotionCampaign.STATUS_CHOICES
        context["campaign_types"] = PromotionCampaign.CAMPAIGN_TYPES
        return context


class CampaignDetailView(StaffRequiredMixin, DetailView):
    """Campaign detail view with analytics."""

    model = PromotionCampaign
    template_name = "promotions/admin/campaign_detail.html"
    context_object_name = "campaign"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        campaign = self.object

        # Get coupons with stats
        context["coupons"] = campaign.coupons.annotate(
            redemption_count=Count("redemptions", filter=Q(redemptions__status="applied"))
        ).order_by("-created_at")[:20]

        # Get recent redemptions
        context["recent_redemptions"] = CouponRedemption.objects.filter(
            coupon__campaign=campaign,
            status="applied",
        ).select_related("coupon", "order", "customer").order_by("-applied_at")[:10]

        # Calculate stats
        context["stats"] = {
            "total_coupons": campaign.coupons.count(),
            "active_coupons": campaign.coupons.filter(status="active", is_active=True).count(),
            "total_redemptions": CouponRedemption.objects.filter(
                coupon__campaign=campaign, status="applied"
            ).count(),
            "total_discount_cents": campaign.spent_cents,
            "budget_utilization": (
                (campaign.spent_cents / campaign.budget_cents * 100)
                if campaign.budget_cents else 0
            ),
        }

        return context


class CampaignCreateView(StaffRequiredMixin, CreateView):
    """Create a new campaign."""

    model = PromotionCampaign
    template_name = "promotions/admin/campaign_form.html"
    fields = [
        "name", "slug", "description", "campaign_type",
        "start_date", "end_date", "budget_cents",
        "utm_source", "utm_medium", "utm_campaign",
    ]
    success_url = reverse_lazy("promotions:campaign_list")

    def form_valid(self, form):
        form.instance.created_by = self.request.user
        messages.success(self.request, f"Campaign '{form.instance.name}' created successfully.")
        return super().form_valid(form)


class CampaignUpdateView(StaffRequiredMixin, UpdateView):
    """Update a campaign."""

    model = PromotionCampaign
    template_name = "promotions/admin/campaign_form.html"
    fields = [
        "name", "slug", "description", "campaign_type",
        "start_date", "end_date", "budget_cents", "status", "is_active",
        "utm_source", "utm_medium", "utm_campaign",
    ]

    def get_success_url(self):
        return reverse("promotions:campaign_detail", kwargs={"pk": self.object.pk})

    def form_valid(self, form):
        messages.success(self.request, f"Campaign '{form.instance.name}' updated successfully.")
        return super().form_valid(form)


# ===============================================================================
# Staff Admin Views - Coupons
# ===============================================================================


class CouponListView(StaffRequiredMixin, ListView):
    """List all coupons."""

    model = Coupon
    template_name = "promotions/admin/coupon_list.html"
    context_object_name = "coupons"
    paginate_by = 50

    def get_queryset(self):
        queryset = super().get_queryset().select_related("campaign", "currency")

        # Filter by status
        status = self.request.GET.get("status")
        if status:
            queryset = queryset.filter(status=status)

        # Filter by discount type
        discount_type = self.request.GET.get("discount_type")
        if discount_type:
            queryset = queryset.filter(discount_type=discount_type)

        # Filter by campaign
        campaign = self.request.GET.get("campaign")
        if campaign:
            queryset = queryset.filter(campaign_id=campaign)

        # Search
        search = self.request.GET.get("search")
        if search:
            queryset = queryset.filter(
                Q(code__icontains=search) | Q(name__icontains=search)
            )

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["statuses"] = Coupon.STATUS_CHOICES
        context["discount_types"] = Coupon.DISCOUNT_TYPES
        context["campaigns"] = PromotionCampaign.objects.filter(is_active=True)
        return context


class CouponDetailView(StaffRequiredMixin, DetailView):
    """Coupon detail view with redemption history."""

    model = Coupon
    template_name = "promotions/admin/coupon_detail.html"
    context_object_name = "coupon"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        coupon = self.object

        # Get recent redemptions
        context["redemptions"] = coupon.redemptions.select_related(
            "order", "customer"
        ).order_by("-created_at")[:50]

        # Calculate stats
        applied_redemptions = coupon.redemptions.filter(status="applied")
        context["stats"] = {
            "total_redemptions": applied_redemptions.count(),
            "total_discount_cents": applied_redemptions.aggregate(
                total=Sum("discount_cents")
            )["total"] or 0,
            "unique_customers": applied_redemptions.values("customer").distinct().count(),
            "average_discount_cents": (
                applied_redemptions.aggregate(avg=Sum("discount_cents") / Count("id"))["avg"] or 0
            ),
        }

        return context


class CouponCreateView(StaffRequiredMixin, CreateView):
    """Create a new coupon."""

    model = Coupon
    template_name = "promotions/admin/coupon_form.html"
    fields = [
        "code", "name", "description", "campaign",
        "discount_type", "discount_percent", "discount_amount_cents",
        "max_discount_cents", "min_order_cents", "min_order_items",
        "valid_from", "valid_until",
        "usage_limit_type", "max_total_uses", "max_uses_per_customer",
        "customer_target", "first_order_only",
        "is_stackable", "is_exclusive", "stacking_priority",
        "is_active", "is_public", "currency",
    ]
    success_url = reverse_lazy("promotions:coupon_list")

    def get_form(self, form_class=None):
        form = super().get_form(form_class)
        # Generate a code if not provided
        if not form.data.get("code"):
            form.initial["code"] = Coupon.generate_code()
        return form

    def form_valid(self, form):
        form.instance.created_by = self.request.user
        messages.success(self.request, f"Coupon '{form.instance.code}' created successfully.")
        return super().form_valid(form)


class CouponUpdateView(StaffRequiredMixin, UpdateView):
    """Update a coupon."""

    model = Coupon
    template_name = "promotions/admin/coupon_form.html"
    fields = [
        "name", "description", "campaign",
        "discount_type", "discount_percent", "discount_amount_cents",
        "max_discount_cents", "min_order_cents", "min_order_items",
        "valid_from", "valid_until",
        "usage_limit_type", "max_total_uses", "max_uses_per_customer",
        "customer_target", "first_order_only",
        "is_stackable", "is_exclusive", "stacking_priority",
        "status", "is_active", "is_public",
    ]

    def get_success_url(self):
        return reverse("promotions:coupon_detail", kwargs={"pk": self.object.pk})

    def form_valid(self, form):
        messages.success(self.request, f"Coupon '{form.instance.code}' updated successfully.")
        return super().form_valid(form)


class CouponBatchCreateView(StaffRequiredMixin, TemplateView):
    """Create a batch of coupons."""

    template_name = "promotions/admin/coupon_batch_form.html"
    MAX_BATCH_SIZE = 1000  # Maximum coupons per batch for security

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        # Validate and sanitize count input
        try:
            count = int(request.POST.get("count", 10))
        except (ValueError, TypeError):
            messages.error(request, "Invalid count value. Please enter a number.")
            return redirect("promotions:coupon_batch_create")

        # Enforce limits
        if count < 1:
            messages.error(request, "Count must be at least 1.")
            return redirect("promotions:coupon_batch_create")
        if count > self.MAX_BATCH_SIZE:
            messages.error(
                request,
                f"Count exceeds maximum batch size of {self.MAX_BATCH_SIZE}. "
                "Please create multiple batches for larger quantities."
            )
            return redirect("promotions:coupon_batch_create")

        # Validate and sanitize prefix (alphanumeric only, limited length)
        prefix = request.POST.get("prefix", "")
        if prefix:
            prefix = "".join(c for c in prefix if c.isalnum())[:10]

        # Get common coupon settings from form
        coupon_defaults = {
            "name": request.POST.get("name", f"Batch {timezone.now().strftime('%Y%m%d')}"),
            "discount_type": request.POST.get("discount_type", "percent"),
            "discount_percent": request.POST.get("discount_percent"),
            "discount_amount_cents": request.POST.get("discount_amount_cents"),
            "usage_limit_type": "single_use",
            "created_by": request.user,
        }

        # Clean up None values
        coupon_defaults = {k: v for k, v in coupon_defaults.items() if v is not None}

        # Generate batch
        coupons = Coupon.generate_batch(
            count=count,
            prefix=prefix,
            **coupon_defaults,
        )

        messages.success(request, f"Created {len(coupons)} coupons successfully.")
        return redirect("promotions:coupon_list")


# ===============================================================================
# Staff Admin Views - Gift Cards
# ===============================================================================


class GiftCardListView(StaffRequiredMixin, ListView):
    """List all gift cards."""

    model = GiftCard
    template_name = "promotions/admin/gift_card_list.html"
    context_object_name = "gift_cards"
    paginate_by = 50

    def get_queryset(self):
        queryset = super().get_queryset().select_related("currency", "purchased_by", "redeemed_by")

        status = self.request.GET.get("status")
        if status:
            queryset = queryset.filter(status=status)

        search = self.request.GET.get("search")
        if search:
            queryset = queryset.filter(code__icontains=search)

        return queryset


class GiftCardDetailView(StaffRequiredMixin, DetailView):
    """Gift card detail view with transaction history."""

    model = GiftCard
    template_name = "promotions/admin/gift_card_detail.html"
    context_object_name = "gift_card"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["transactions"] = self.object.transactions.select_related(
            "order", "customer", "created_by"
        ).order_by("-created_at")
        return context


class GiftCardCreateView(StaffRequiredMixin, CreateView):
    """Create a new gift card."""

    model = GiftCard
    template_name = "promotions/admin/gift_card_form.html"
    fields = [
        "initial_value_cents", "currency", "card_type",
        "recipient_email", "recipient_name", "personal_message",
        "valid_until",
    ]
    success_url = reverse_lazy("promotions:gift_card_list")

    def form_valid(self, form):
        form.instance.code = GiftCard.generate_code()
        form.instance.current_balance_cents = form.instance.initial_value_cents
        form.instance.status = "pending"
        messages.success(self.request, f"Gift card created with code: {form.instance.code}")
        return super().form_valid(form)


# ===============================================================================
# Staff Admin Views - Referrals
# ===============================================================================


class ReferralListView(StaffRequiredMixin, ListView):
    """List all referrals."""

    model = Referral
    template_name = "promotions/admin/referral_list.html"
    context_object_name = "referrals"
    paginate_by = 50

    def get_queryset(self):
        queryset = super().get_queryset().select_related(
            "referral_code", "referral_code__owner", "referred_customer", "qualifying_order"
        )

        status = self.request.GET.get("status")
        if status:
            queryset = queryset.filter(status=status)

        return queryset


# ===============================================================================
# Staff Admin Views - Loyalty
# ===============================================================================


class LoyaltyDashboardView(StaffRequiredMixin, TemplateView):
    """Loyalty program dashboard."""

    template_name = "promotions/admin/loyalty_dashboard.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Get active program
        program = LoyaltyProgram.objects.filter(is_active=True).first()
        context["program"] = program

        if program:
            context["tiers"] = program.tiers.annotate(
                member_count=Count("members")
            ).order_by("sort_order")

            context["total_members"] = CustomerLoyalty.objects.filter(
                program=program, is_active=True
            ).count()

            context["total_points_issued"] = CustomerLoyalty.objects.filter(
                program=program
            ).aggregate(total=Sum("points_lifetime"))["total"] or 0

            context["total_points_redeemed"] = CustomerLoyalty.objects.filter(
                program=program
            ).aggregate(total=Sum("points_redeemed"))["total"] or 0

            # Recent transactions
            context["recent_transactions"] = LoyaltyTransaction.objects.filter(
                customer_loyalty__program=program
            ).select_related(
                "customer_loyalty__customer", "order"
            ).order_by("-created_at")[:20]

        return context


# ===============================================================================
# Staff Admin Views - Promotion Rules
# ===============================================================================


class PromotionRuleListView(StaffRequiredMixin, ListView):
    """List all promotion rules."""

    model = PromotionRule
    template_name = "promotions/admin/rule_list.html"
    context_object_name = "rules"
    paginate_by = 25

    def get_queryset(self):
        return super().get_queryset().select_related("campaign").order_by("priority", "-created_at")


class PromotionRuleCreateView(StaffRequiredMixin, CreateView):
    """Create a new promotion rule."""

    model = PromotionRule
    template_name = "promotions/admin/rule_form.html"
    fields = [
        "name", "description", "campaign", "rule_type",
        "discount_type", "discount_percent", "discount_amount_cents",
        "max_discount_cents", "valid_from", "valid_until",
        "is_stackable", "priority", "is_active",
        "display_name", "display_badge",
    ]
    success_url = reverse_lazy("promotions:rule_list")

    def form_valid(self, form):
        form.instance.created_by = self.request.user
        messages.success(self.request, f"Promotion rule '{form.instance.name}' created.")
        return super().form_valid(form)


class PromotionRuleUpdateView(StaffRequiredMixin, UpdateView):
    """Update a promotion rule."""

    model = PromotionRule
    template_name = "promotions/admin/rule_form.html"
    fields = [
        "name", "description", "campaign", "rule_type",
        "discount_type", "discount_percent", "discount_amount_cents",
        "max_discount_cents", "valid_from", "valid_until",
        "is_stackable", "priority", "is_active",
        "display_name", "display_badge",
    ]
    success_url = reverse_lazy("promotions:rule_list")


# ===============================================================================
# Promotions Dashboard
# ===============================================================================


class PromotionsDashboardView(StaffRequiredMixin, TemplateView):
    """Main promotions dashboard for staff."""

    template_name = "promotions/admin/dashboard.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        now = timezone.now()

        # Campaign stats
        context["active_campaigns"] = PromotionCampaign.objects.filter(
            status="active", is_active=True
        ).count()

        context["campaigns_ending_soon"] = PromotionCampaign.objects.filter(
            status="active",
            end_date__lte=now + timezone.timedelta(days=7),
            end_date__gte=now,
        ).count()

        # Coupon stats
        context["active_coupons"] = Coupon.objects.filter(
            status="active", is_active=True
        ).count()

        context["expiring_coupons"] = Coupon.objects.filter(
            status="active",
            valid_until__lte=now + timezone.timedelta(days=7),
            valid_until__gte=now,
        ).count()

        # Today's redemptions
        today = now.date()
        context["todays_redemptions"] = CouponRedemption.objects.filter(
            applied_at__date=today,
            status="applied",
        ).count()

        context["todays_discount_cents"] = CouponRedemption.objects.filter(
            applied_at__date=today,
            status="applied",
        ).aggregate(total=Sum("discount_cents"))["total"] or 0

        # Top coupons this week
        week_ago = now - timezone.timedelta(days=7)
        context["top_coupons"] = Coupon.objects.filter(
            redemptions__applied_at__gte=week_ago,
            redemptions__status="applied",
        ).annotate(
            week_uses=Count("redemptions"),
            week_discount=Sum("redemptions__discount_cents"),
        ).order_by("-week_uses")[:5]

        # Recent redemptions
        context["recent_redemptions"] = CouponRedemption.objects.filter(
            status="applied"
        ).select_related(
            "coupon", "order", "customer"
        ).order_by("-applied_at")[:10]

        return context
