"""
Views for the Promotions app.
Handles coupon validation, application, and promotion management.
"""

from __future__ import annotations

import logging
from typing import Any, cast

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.db.models import Count, Q, QuerySet, Sum
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.translation import gettext_lazy as _
from django.views import View
from django.views.generic import (
    CreateView,
    DetailView,
    FormView,
    ListView,
    TemplateView,
    UpdateView,
)

from apps.common.rate_limiting import rate_limit

from .forms import CampaignForm, CouponBatchForm, CouponForm, GiftCardForm, PromotionRuleForm
from .models import (
    Coupon,
    CouponRedemption,
    CustomerLoyalty,
    GiftCard,
    LoyaltyProgram,
    LoyaltyTransaction,
    PromotionCampaign,
    PromotionRule,
    Referral,
)
from .presentation import staff_context
from .services import (
    CouponService,
    GiftCardService,
)

logger = logging.getLogger(__name__)


# ===============================================================================
# Staff Mixin
# ===============================================================================


class StaffRequiredMixin(LoginRequiredMixin, UserPassesTestMixin):
    """Mixin requiring user to be staff."""

    def test_func(self) -> bool:
        return bool(getattr(self.request.user, "is_staff_user", False))

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        return staff_context(self.request, super().get_context_data(**kwargs))


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
        # Anonymous users cannot access orders without proper session binding
        # TODO: Implement session-cart binding for anonymous checkout if needed
        return False

    # Staff can access all orders
    if getattr(request.user, "is_staff_user", False):
        return True

    # Check if user is associated with the order's customer
    customer = _get_customer_from_request(request)
    return bool(customer and order.customer_id == customer.id)


@method_decorator(rate_limit(key="ip", rate="45/m", method="POST"), name="dispatch")
@method_decorator(rate_limit(key="post:code", rate="15/m", method="POST"), name="dispatch")
class ValidateCouponView(View):
    """
    API endpoint for validating a coupon code.
    Returns JSON with validation result.

    Rate limited to prevent brute-force attacks on coupon codes.
    """

    def post(  # noqa: PLR0911  # Complexity: multi-step business logic
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> JsonResponse:  # Complexity: multi-step workflow  # Complexity: multi-step business logic
        from apps.orders.models import Order  # Circular: cross-app  # noqa: PLC0415  # Deferred: avoids circular import

        # Check rate limit
        if getattr(request, "limited", False):
            logger.warning(
                "Rate limit exceeded for coupon validation from IP %s",
                request.META.get("REMOTE_ADDR"),
            )
            return JsonResponse(
                {
                    "valid": False,
                    "error": "Too many requests. Please try again later.",
                    "error_code": "RATE_LIMITED",
                },
                status=429,
            )

        code = request.POST.get("code", "").strip()
        order_id = request.POST.get("order_id")

        if not code:
            return JsonResponse(
                {
                    "valid": False,
                    "error": "Please enter a coupon code",
                    "error_code": "EMPTY_CODE",
                }
            )

        if not order_id:
            return JsonResponse(
                {
                    "valid": False,
                    "error": "Order not found",
                    "error_code": "NO_ORDER",
                }
            )

        try:
            order = Order.objects.select_related("customer", "currency").get(id=order_id)
        except Order.DoesNotExist:
            return JsonResponse(
                {
                    "valid": False,
                    "error": "Order not found",
                    "error_code": "ORDER_NOT_FOUND",
                }
            )

        # SECURITY: Verify user has permission to access this order
        if not _user_can_access_order(request, order):
            logger.warning(
                "Unauthorized order access attempt: user=%s order=%s",
                request.user.id if request.user.is_authenticated else "anonymous",
                order_id,
            )
            return JsonResponse(
                {
                    "valid": False,
                    "error": "Order not found",
                    "error_code": "ORDER_NOT_FOUND",
                },
                status=404,
            )

        # Get customer from request (DRY helper)
        customer = _get_customer_from_request(request)

        # Validate coupon
        validation = CouponService.validate_coupon(code, order, customer)

        if not validation.is_valid:
            return JsonResponse(
                {
                    "valid": False,
                    "error": validation.error_message,
                    "error_code": validation.error_code,
                }
            )

        # Get discount preview
        coupon = CouponService.get_coupon_by_code(code)
        if coupon:
            discount = CouponService.calculate_discount(coupon, order)
            return JsonResponse(
                {
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
                }
            )

        return JsonResponse(
            {
                "valid": False,
                "error": "Coupon not found",
                "error_code": "NOT_FOUND",
            }
        )


@method_decorator(rate_limit(key="ip", rate="30/m", method="POST"), name="dispatch")
@method_decorator(rate_limit(key="post:code", rate="8/m", method="POST"), name="dispatch")
class ApplyCouponView(View):
    """
    API endpoint for applying a coupon to an order.

    Rate limited more strictly than validation to prevent abuse.
    """

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> JsonResponse:
        from apps.orders.models import Order  # Circular: cross-app  # noqa: PLC0415  # Deferred: avoids circular import

        # Check rate limit
        if getattr(request, "limited", False):
            logger.warning(
                "Rate limit exceeded for coupon application from IP %s",
                request.META.get("REMOTE_ADDR"),
            )
            return JsonResponse(
                {
                    "success": False,
                    "error": "Too many requests. Please try again later.",
                },
                status=429,
            )

        code = request.POST.get("code", "").strip()
        order_id = request.POST.get("order_id")

        if not code or not order_id:
            return JsonResponse(
                {
                    "success": False,
                    "error": "Missing required parameters",
                },
                status=400,
            )

        try:
            order = Order.objects.select_related("customer", "currency").get(id=order_id)
        except Order.DoesNotExist:
            return JsonResponse(
                {
                    "success": False,
                    "error": "Order not found",
                },
                status=404,
            )

        # SECURITY: Verify user has permission to access this order
        if not _user_can_access_order(request, order):
            logger.warning(
                "Unauthorized order modification attempt: user=%s order=%s",
                request.user.id if request.user.is_authenticated else "anonymous",
                order_id,
            )
            return JsonResponse(
                {
                    "success": False,
                    "error": "Order not found",
                },
                status=404,
            )

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
            return JsonResponse(
                {
                    "success": True,
                    "discount_cents": result.discount_cents,
                    "discount_display": f"{result.discount_cents / 100:.2f}",
                    "new_total_cents": order.total_cents,
                    "new_total_display": f"{order.total_cents / 100:.2f}",
                    "warnings": result.warnings,
                }
            )
        else:
            return JsonResponse(
                {
                    "success": False,
                    "error": result.error_message,
                }
            )


@method_decorator(rate_limit(key="ip", rate="45/m", method="POST"), name="dispatch")
class RemoveCouponView(View):
    """
    API endpoint for removing a coupon from an order.
    """

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> JsonResponse:
        from apps.orders.models import Order  # Circular: cross-app  # noqa: PLC0415  # Deferred: avoids circular import

        # Check rate limit
        if getattr(request, "limited", False):
            return JsonResponse(
                {
                    "success": False,
                    "error": "Too many requests. Please try again later.",
                },
                status=429,
            )

        order_id = request.POST.get("order_id")
        redemption_id = request.POST.get("redemption_id")

        if not order_id:
            return JsonResponse(
                {
                    "success": False,
                    "error": "Missing order ID",
                },
                status=400,
            )

        try:
            order = Order.objects.get(id=order_id)
        except Order.DoesNotExist:
            return JsonResponse(
                {
                    "success": False,
                    "error": "Order not found",
                },
                status=404,
            )

        # SECURITY: Verify user has permission to modify this order
        if not _user_can_access_order(request, order):
            logger.warning(
                "Unauthorized order modification attempt (remove coupon): user=%s order=%s",
                request.user.id if request.user.is_authenticated else "anonymous",
                order_id,
            )
            return JsonResponse(
                {
                    "success": False,
                    "error": "Order not found",
                },
                status=404,
            )

        removed_count = CouponService.remove_coupon(
            order=order,
            redemption_id=redemption_id,
        )

        # Removal is idempotent: remove_coupon returning at all means the desired
        # end-state holds (no applied redemption matches the selector). A zero
        # count is a replay — a retry after a lost response, or a concurrent
        # cancellation/removal that won the race — and must still be success;
        # real failures raise (#485 review).
        return JsonResponse(
            {
                "success": True,
                "removed": removed_count,
                "new_total_cents": order.total_cents,
                "new_total_display": f"{order.total_cents / 100:.2f}",
            }
        )


class AvailableCouponsView(View):
    """
    API endpoint for getting available coupons for an order.
    """

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> JsonResponse:
        from apps.orders.models import Order  # Circular: cross-app  # noqa: PLC0415  # Deferred: avoids circular import

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

        return JsonResponse(
            {
                "coupons": [
                    {
                        "code": c.code,
                        "name": c.name,
                        "description": c.description,
                        "discount_type": c.discount_type,
                        "discount_value": (
                            float(c.discount_percent) if c.discount_percent else c.discount_amount_cents
                        ),
                    }
                    for c in coupons
                ]
            }
        )


# ===============================================================================
# Gift Card Views
# ===============================================================================


@method_decorator(rate_limit(key="ip", rate="45/m", method="POST"), name="dispatch")
@method_decorator(rate_limit(key="post:code", rate="15/m", method="POST"), name="dispatch")
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
            return JsonResponse(
                {
                    "valid": False,
                    "error": "Too many requests. Please try again later.",
                },
                status=429,
            )

        code = request.POST.get("code", "").strip()

        if not code:
            return JsonResponse(
                {
                    "valid": False,
                    "error": "Please enter a gift card code",
                }
            )

        validation = GiftCardService.validate_gift_card(code)

        if validation.is_valid:
            gift_card = GiftCard.objects.get(code=code.upper().strip())
            return JsonResponse(
                {
                    "valid": True,
                    "balance_cents": gift_card.current_balance_cents,
                    "balance_display": f"{gift_card.current_balance_cents / 100:.2f}",
                    "currency": gift_card.currency.code,
                }
            )
        else:
            return JsonResponse(
                {
                    "valid": False,
                    "error": validation.error_message,
                }
            )


@method_decorator(rate_limit(key="ip", rate="30/m", method="POST"), name="dispatch")
@method_decorator(rate_limit(key="post:code", rate="8/m", method="POST"), name="dispatch")
class RedeemGiftCardView(View):
    """API endpoint for redeeming a gift card."""

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> JsonResponse:
        from apps.orders.models import Order  # Circular: cross-app  # noqa: PLC0415  # Deferred: avoids circular import

        # Check rate limit
        if getattr(request, "limited", False):
            logger.warning(
                "Rate limit exceeded for gift card redemption from IP %s",
                request.META.get("REMOTE_ADDR"),
            )
            return JsonResponse(
                {
                    "success": False,
                    "error": "Too many requests. Please try again later.",
                },
                status=429,
            )

        code = request.POST.get("code", "").strip()
        order_id = request.POST.get("order_id")
        amount_cents = request.POST.get("amount_cents")

        if not code or not order_id:
            return JsonResponse(
                {
                    "success": False,
                    "error": "Missing required parameters",
                },
                status=400,
            )

        try:
            order = Order.objects.get(id=order_id)
        except Order.DoesNotExist:
            return JsonResponse(
                {
                    "success": False,
                    "error": "Order not found",
                },
                status=404,
            )

        # SECURITY: Verify user has permission to modify this order
        if not _user_can_access_order(request, order):
            logger.warning(
                "Unauthorized order modification attempt (gift card): user=%s order=%s",
                request.user.id if request.user.is_authenticated else "anonymous",
                order_id,
            )
            return JsonResponse(
                {
                    "success": False,
                    "error": "Order not found",
                },
                status=404,
            )

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
            return JsonResponse(
                {
                    "success": True,
                    "discount_cents": result.discount_cents,
                    "new_total_cents": order.total_cents,
                }
            )
        else:
            return JsonResponse(
                {
                    "success": False,
                    "error": result.error_message,
                }
            )


# ===============================================================================
# Staff Admin Views - Campaigns
# ===============================================================================


class CampaignListView(StaffRequiredMixin, ListView):
    """List all promotion campaigns."""

    model = PromotionCampaign
    template_name = "promotions/admin/campaign_list.html"
    context_object_name = "campaigns"
    paginate_by = 25

    def get_queryset(self) -> QuerySet[PromotionCampaign]:
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
            queryset = queryset.filter(Q(name__icontains=search) | Q(slug__icontains=search))

        return queryset.annotate(  # type: ignore[no-any-return]
            coupon_count=Count("coupons"),
            total_redemptions=Sum("coupons__total_uses"),
        )

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        context = super().get_context_data(**kwargs)
        context["statuses"] = [{"value": value, "label": label} for value, label in PromotionCampaign.STATUS_CHOICES]
        context["campaign_types"] = [
            {"value": value, "label": label} for value, label in PromotionCampaign.CAMPAIGN_TYPES
        ]
        return context


class CampaignDetailView(StaffRequiredMixin, DetailView):
    """Campaign detail view with analytics."""

    model = PromotionCampaign
    template_name = "promotions/admin/campaign_detail.html"
    context_object_name = "campaign"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        context = super().get_context_data(**kwargs)
        campaign = self.object

        # Get coupons with stats
        context["coupons"] = campaign.coupons.annotate(
            redemption_count=Count("redemptions", filter=Q(redemptions__status="applied"))
        ).order_by("-created_at")[:20]

        # Get recent redemptions
        context["recent_redemptions"] = (
            CouponRedemption.objects.filter(
                coupon__campaign=campaign,
                status="applied",
            )
            .select_related("coupon", "order", "customer")
            .order_by("-applied_at")[:10]
        )

        # Calculate stats
        context["stats"] = {
            "total_coupons": campaign.coupons.count(),
            "active_coupons": campaign.coupons.filter(status="active", is_active=True).count(),
            "total_redemptions": CouponRedemption.objects.filter(coupon__campaign=campaign, status="applied").count(),
            "total_discount_cents": campaign.spent_cents,
            "budget_utilization": (
                (campaign.spent_cents / campaign.budget_cents * 100) if campaign.budget_cents else 0
            ),
        }

        return context


class FinancialStaffRequiredMixin(StaffRequiredMixin):
    def test_func(self) -> bool:
        return bool(self.request.user.can_manage_financial_data)


class LockedPromotionUpdateMixin:
    """Rebind editable fields after locking so staff saves cannot overwrite counters."""

    object: Any

    def form_valid(self, form: Any) -> HttpResponse:
        with transaction.atomic():
            locked = self.model.objects.select_for_update().get(pk=self.object.pk)
            current = self.form_class(self.request.POST, instance=locked)
            if not current.is_valid():
                return cast(HttpResponse, self.form_invalid(current))
            current.instance._audit_actor = self.request.user
            self.object = current.save()
        messages.success(self.request, _("Promotion updated successfully."))
        return redirect(self.get_success_url())


class CampaignCreateView(FinancialStaffRequiredMixin, CreateView):
    """Create a new campaign."""

    model = PromotionCampaign
    template_name = "promotions/admin/campaign_form.html"
    form_class = CampaignForm
    success_url = reverse_lazy("promotions:campaign_list")

    def form_valid(self, form: Any) -> HttpResponse:
        form.instance.created_by = self.request.user
        messages.success(self.request, f"Campaign '{form.instance.name}' created successfully.")
        return super().form_valid(form)


class CampaignUpdateView(FinancialStaffRequiredMixin, UpdateView):
    """Update a campaign."""

    model = PromotionCampaign
    template_name = "promotions/admin/campaign_form.html"
    form_class = CampaignForm

    def get_success_url(self) -> str:
        return reverse("promotions:campaign_detail", kwargs={"pk": self.object.pk})

    def form_valid(self, form: CampaignForm) -> HttpResponse:
        with transaction.atomic():
            locked = PromotionCampaign.objects.select_for_update().get(pk=self.object.pk)
            current = CampaignForm(self.request.POST, instance=locked)
            if not current.is_valid():
                return self.form_invalid(current)
            current.instance._audit_actor = self.request.user
            self.object = current.save()
        messages.success(self.request, _("Campaign updated successfully."))
        return redirect(self.get_success_url())


# ===============================================================================
# Staff Admin Views - Coupons
# ===============================================================================


class CouponListView(StaffRequiredMixin, ListView):
    """List all coupons."""

    model = Coupon
    template_name = "promotions/admin/coupon_list.html"
    context_object_name = "coupons"
    paginate_by = 50

    def get_queryset(self) -> QuerySet[Coupon]:
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
            try:
                queryset = queryset.filter(campaign_id=campaign)
            except ValidationError:
                queryset = queryset.none()

        # Search
        search = self.request.GET.get("search")
        if search:
            queryset = queryset.filter(Q(code__icontains=search) | Q(name__icontains=search))

        return queryset

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        # StaffRequiredMixin builds filter options while preparing the shared context.
        kwargs["campaigns"] = PromotionCampaign.objects.filter(is_active=True)
        context = super().get_context_data(**kwargs)
        context["statuses"] = [{"value": value, "label": label} for value, label in Coupon.STATUS_CHOICES]
        context["discount_types"] = [{"value": value, "label": label} for value, label in Coupon.DISCOUNT_TYPES]
        return context


class CouponDetailView(StaffRequiredMixin, DetailView):
    """Coupon detail view with redemption history."""

    model = Coupon
    template_name = "promotions/admin/coupon_detail.html"
    context_object_name = "coupon"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        context = super().get_context_data(**kwargs)
        coupon = self.object

        # Get recent redemptions
        context["redemptions"] = coupon.redemptions.select_related("order", "customer").order_by("-created_at")[:50]

        # Calculate stats
        applied_redemptions = coupon.redemptions.filter(status="applied")
        context["stats"] = {
            "total_redemptions": applied_redemptions.count(),
            "total_discount_cents": applied_redemptions.aggregate(total=Sum("discount_cents"))["total"] or 0,
            "unique_customers": applied_redemptions.values("customer").distinct().count(),
            "average_discount_cents": (
                applied_redemptions.aggregate(avg=Sum("discount_cents") / Count("id"))["avg"] or 0
            ),
        }

        return context


class CouponCreateView(FinancialStaffRequiredMixin, CreateView):
    """Create a new coupon."""

    model = Coupon
    template_name = "promotions/admin/coupon_form.html"
    form_class = CouponForm
    success_url = reverse_lazy("promotions:coupon_list")

    def get_form(self, form_class: Any = None) -> Any:
        form = super().get_form(form_class)
        # Generate a code if not provided
        if not form.data.get("code"):
            form.initial["code"] = Coupon.generate_code()
        return form

    def form_valid(self, form: Any) -> HttpResponse:
        form.instance.created_by = self.request.user
        messages.success(self.request, f"Coupon '{form.instance.code}' created successfully.")
        return super().form_valid(form)


class CouponUpdateView(LockedPromotionUpdateMixin, FinancialStaffRequiredMixin, UpdateView):
    """Update a coupon."""

    model = Coupon
    template_name = "promotions/admin/coupon_form.html"
    form_class = CouponForm

    def get_success_url(self) -> str:
        return reverse("promotions:coupon_detail", kwargs={"pk": self.object.pk})


class CouponBatchCreateView(FinancialStaffRequiredMixin, FormView):
    """Validate the complete batch before atomically creating and auditing it."""

    template_name = "promotions/admin/coupon_batch_form.html"
    form_class = CouponBatchForm
    success_url = reverse_lazy("promotions:coupon_list")

    def form_valid(self, form: CouponBatchForm) -> HttpResponse:
        from apps.audit.services import AuditService  # noqa: PLC0415

        data = form.cleaned_data
        try:
            with transaction.atomic():
                coupons = Coupon.generate_batch(
                    count=data["count"],
                    prefix=data["prefix"].upper(),
                    name=data["name"],
                    discount_type=data["discount_type"],
                    discount_percent=data["discount_percent"],
                    discount_amount_cents=data["discount_amount_cents"],
                    currency=data["currency"],
                    usage_limit_type="single_use",
                    created_by=self.request.user,
                )
                AuditService.log_simple_event(
                    "coupon_batch_created",
                    user=self.request.user,
                    description=_("Created %(count)s coupons.") % {"count": len(coupons)},
                    metadata={"coupon_ids": [str(coupon.pk) for coupon in coupons], "count": len(coupons)},
                )
        except ValidationError as exc:
            form.add_error(None, exc)
            return self.form_invalid(form)
        except IntegrityError:
            logger.exception("Coupon batch could not be saved")
            form.add_error(None, _("The batch could not be saved. No coupons were created; please try again."))
            return self.form_invalid(form)
        messages.success(self.request, _("Created %(count)s coupons.") % {"count": len(coupons)})
        return super().form_valid(form)


# ===============================================================================
# Staff Admin Views - Gift Cards
# ===============================================================================


class GiftCardListView(StaffRequiredMixin, ListView):
    """List all gift cards."""

    model = GiftCard
    template_name = "promotions/admin/gift_card_list.html"
    context_object_name = "gift_cards"
    paginate_by = 50

    def get_queryset(self) -> QuerySet[GiftCard]:
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

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        context = super().get_context_data(**kwargs)
        context["transactions"] = self.object.transactions.select_related("order", "customer", "created_by").order_by(
            "-created_at"
        )
        return context


class GiftCardCreateView(FinancialStaffRequiredMixin, CreateView):
    """Create a new gift card."""

    model = GiftCard
    template_name = "promotions/admin/gift_card_form.html"
    form_class = GiftCardForm
    success_url = reverse_lazy("promotions:gift_card_list")

    def form_valid(self, form: Any) -> HttpResponse:
        import uuid  # noqa: PLC0415

        from .gift_cards import create_purchase  # noqa: PLC0415

        data = form.cleaned_data
        purchase = create_purchase(
            data["purchased_by"],
            data["currency"],
            data["initial_value_cents"],
            uuid.uuid4().hex,
            method=data["payment_method"],
            recipient={
                "email": data["recipient_email"],
                "name": data["recipient_name"],
                "message": data["personal_message"],
            },
            actor=self.request.user,
        )
        self.object = purchase.gift_card
        self.object.card_type = data["card_type"]
        self.object.valid_until = data["valid_until"]
        self.object.save(update_fields=["card_type", "valid_until", "updated_at"])
        messages.success(self.request, _("Gift-card purchase created. Payment is required before activation."))
        return redirect("promotions:gift_card_detail", pk=self.object.pk)


class GiftCardRecordBankPaymentView(FinancialStaffRequiredMixin, View):
    def post(self, request: HttpRequest, pk: Any) -> HttpResponse:
        from .gift_cards import record_bank_funding  # noqa: PLC0415

        card = get_object_or_404(GiftCard, pk=pk, ledger_version=2)
        try:
            record_bank_funding(card.purchase.pk, reference=request.POST.get("reference", ""), actor=request.user)
        except ValidationError as exc:
            messages.error(request, "; ".join(exc.messages))
        else:
            messages.success(request, _("Bank payment recorded and gift card activated."))
        return redirect("promotions:gift_card_detail", pk=pk)


# ===============================================================================
# Staff Admin Views - Referrals
# ===============================================================================


class ReferralListView(StaffRequiredMixin, ListView):
    """List all referrals."""

    model = Referral
    template_name = "promotions/admin/referral_list.html"
    context_object_name = "referrals"
    paginate_by = 50

    def get_queryset(self) -> QuerySet[Referral]:
        queryset = (
            super()
            .get_queryset()
            .select_related("referral_code", "referral_code__owner", "referred_customer", "qualifying_order")
        )

        status = self.request.GET.get("status")
        if status:
            queryset = queryset.filter(status=status)

        search = self.request.GET.get("search", "").strip()
        if search:
            queryset = queryset.filter(
                Q(referral_code__code__icontains=search) | Q(referred_customer__name__icontains=search)
            )
        return queryset


# ===============================================================================
# Staff Admin Views - Loyalty
# ===============================================================================


class LoyaltyDashboardView(StaffRequiredMixin, TemplateView):
    """Loyalty program dashboard."""

    template_name = "promotions/admin/loyalty_dashboard.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        context = super().get_context_data(**kwargs)

        # Get active program
        program = LoyaltyProgram.objects.filter(is_active=True).first()
        context["program"] = program

        if program:
            context["tiers"] = program.tiers.annotate(member_count=Count("members")).order_by("sort_order")

            context["total_members"] = CustomerLoyalty.objects.filter(program=program, is_active=True).count()

            context["total_points_issued"] = (
                CustomerLoyalty.objects.filter(program=program).aggregate(total=Sum("points_lifetime"))["total"] or 0
            )

            context["total_points_redeemed"] = (
                CustomerLoyalty.objects.filter(program=program).aggregate(total=Sum("points_redeemed"))["total"] or 0
            )

            # Recent transactions
            context["recent_transactions"] = (
                LoyaltyTransaction.objects.filter(customer_loyalty__program=program)
                .select_related("customer_loyalty__customer", "order")
                .order_by("-created_at")[:20]
            )

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

    def get_queryset(self) -> QuerySet[PromotionRule]:
        queryset = super().get_queryset().select_related("campaign").order_by("priority", "-created_at")
        search = self.request.GET.get("search", "").strip()
        return queryset.filter(name__icontains=search) if search else queryset


class PromotionRuleCreateView(FinancialStaffRequiredMixin, CreateView):
    """Create a new promotion rule."""

    model = PromotionRule
    template_name = "promotions/admin/rule_form.html"
    form_class = PromotionRuleForm
    success_url = reverse_lazy("promotions:rule_list")

    def form_valid(self, form: Any) -> HttpResponse:
        form.instance.created_by = self.request.user
        messages.success(self.request, f"Promotion rule '{form.instance.name}' created.")
        return super().form_valid(form)


class PromotionRuleUpdateView(LockedPromotionUpdateMixin, FinancialStaffRequiredMixin, UpdateView):
    """Update a promotion rule."""

    model = PromotionRule
    template_name = "promotions/admin/rule_form.html"
    form_class = PromotionRuleForm
    success_url = reverse_lazy("promotions:rule_list")


# ===============================================================================
# Promotions Dashboard
# ===============================================================================


class PromotionsDashboardView(StaffRequiredMixin, TemplateView):
    """Main promotions dashboard for staff."""

    template_name = "promotions/admin/dashboard.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        context = super().get_context_data(**kwargs)
        now = timezone.now()

        # Campaign stats
        context["active_campaigns"] = PromotionCampaign.objects.filter(status="active", is_active=True).count()

        context["campaigns_ending_soon"] = PromotionCampaign.objects.filter(
            status="active",
            end_date__lte=now + timezone.timedelta(days=7),
            end_date__gte=now,
        ).count()

        # Coupon stats
        context["active_coupons"] = Coupon.objects.filter(status="active", is_active=True).count()

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

        context["todays_discount_cents"] = (
            CouponRedemption.objects.filter(
                applied_at__date=today,
                status="applied",
            ).aggregate(total=Sum("discount_cents"))["total"]
            or 0
        )

        # Top coupons this week
        week_ago = now - timezone.timedelta(days=7)
        context["top_coupons"] = (
            Coupon.objects.filter(
                redemptions__applied_at__gte=week_ago,
                redemptions__status="applied",
            )
            .annotate(
                week_uses=Count("redemptions"),
                week_discount=Sum("redemptions__discount_cents"),
            )
            .order_by("-week_uses")[:5]
        )

        # Recent redemptions
        context["recent_redemptions"] = (
            CouponRedemption.objects.filter(status="applied")
            .select_related("coupon", "order", "customer")
            .order_by("-applied_at")[:10]
        )

        return context
