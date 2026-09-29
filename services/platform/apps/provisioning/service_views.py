# ===============================================================================
# SERVICE MANAGEMENT VIEWS - CRUD OPERATIONS FOR HOSTING SERVICES
# ===============================================================================

from __future__ import annotations

from decimal import Decimal
from typing import Any, cast

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import QuerySet
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext_lazy as _
from django_fsm import ConcurrentTransition, TransitionNotAllowed

from apps.billing.currency_policy import (
    SellingCurrencyChangedError,
    get_selling_currency_policy,
    require_current_selling_policy,
)
from apps.common.decorators import staff_required_strict
from apps.customers.models import Customer
from apps.users.models import User

from .service_models import Service, ServicePlan, ServicePlanPrice


def _plan_options(currency_code: str) -> list[dict[str, Any]]:
    prices = (
        ServicePlanPrice.objects.filter(
            currency_id=currency_code,
            is_active=True,
            service_plan__is_active=True,
        )
        .select_related("service_plan")
        .order_by("service_plan__sort_order", "service_plan__name")
    )
    return [
        {
            "id": price.service_plan_id,
            "name": price.service_plan.name,
            "price": Decimal(price.monthly_price_cents) / 100,
            "currency": currency_code,
        }
        for price in prices
    ]


def _get_accessible_customer_ids(user: User) -> list[int]:
    """Helper to get customer IDs that user can access"""
    accessible_customers = user.get_accessible_customers()

    if isinstance(accessible_customers, QuerySet):
        return list(accessible_customers.values_list("id", flat=True))
    else:
        return [c.id for c in accessible_customers] if accessible_customers else []


@login_required
def service_list(request: HttpRequest) -> HttpResponse:
    """🚀 Display hosting services for user's customers"""
    # Type guard: @login_required ensures authenticated user
    user = cast(User, request.user)
    customer_ids = _get_accessible_customer_ids(user)
    services = (
        Service.objects.filter(customer_id__in=customer_ids)
        .select_related("customer", "service_plan")
        .order_by("-created_at")
    )

    # Filter by specific customer (for "View all" links from customer detail)
    customer_filter = request.GET.get("customer")
    if customer_filter and customer_filter.isdigit():
        customer_id = int(customer_filter)
        if customer_id in customer_ids:
            services = services.filter(customer_id=customer_id)

    # Filter by status
    status_filter = request.GET.get("status")
    filtered_services = services
    if status_filter:
        filtered_services = services.filter(status=status_filter)

    # Pagination
    paginator = Paginator(filtered_services, 25)
    page_number = request.GET.get("page")
    services_page = paginator.get_page(page_number)

    # Only staff can manage services (edit/suspend)
    can_manage_services = user.is_staff_user

    # For filtered views, show filtered count as "active" count in header
    if status_filter:
        # When filtering, show filtered count instead of active count
        active_count = filtered_services.count()
        display_status = status_filter
    else:
        # For "All Services", show actual active count
        active_count = services.filter(status="active").count()
        display_status = "active"

    context = {
        "services": services_page,
        "status_filter": status_filter,
        "active_count": active_count,
        "display_status": display_status,
        "total_count": services.count(),  # Always total from unfiltered
        "can_manage_services": can_manage_services,
    }

    return render(request, "provisioning/service_list.html", context)


@login_required
def service_detail(request: HttpRequest, pk: int) -> HttpResponse:
    """🚀 Display service details and configuration"""
    # Type guard: @login_required ensures authenticated user
    user = cast(User, request.user)
    service = get_object_or_404(Service, pk=pk)

    # Security check
    if not user.can_access_customer(service.customer):
        messages.error(request, _("❌ You do not have permission to access this service."))
        return redirect("provisioning:services")

    # Only staff can manage services (edit/suspend)
    can_manage = user.is_staff_user and service.status in ["active", "suspended"]

    context = {
        "service": service,
        "can_manage": can_manage,
    }

    return render(request, "provisioning/service_detail.html", context)


@staff_required_strict
def service_create(request: HttpRequest) -> HttpResponse:
    """+ Create new hosting service"""
    # Type guard: @staff_required_strict ensures authenticated user
    user = cast(User, request.user)
    # Get user's customers for dropdown
    accessible_customers = user.get_accessible_customers()
    if hasattr(accessible_customers, "all"):
        customers = accessible_customers.all()
    elif isinstance(accessible_customers, list | tuple):
        customers = Customer.objects.filter(id__in=[c.id for c in accessible_customers])
    else:
        customers = accessible_customers  # type: ignore[unreachable]
    policy = get_selling_currency_policy()
    response_status = 200

    if request.method == "POST":
        customer_id = request.POST.get("customer_id")
        plan_id = request.POST.get("plan_id")
        domain = request.POST.get("domain")

        if customer_id and plan_id and domain:
            customer = get_object_or_404(Customer, pk=customer_id)

            # Security check
            accessible_customer_ids = _get_accessible_customer_ids(user)
            if int(customer_id) not in accessible_customer_ids:
                messages.error(request, _("❌ You do not have permission to create services for this customer."))
                return redirect("provisioning:services")
            plan = get_object_or_404(ServicePlan, pk=plan_id)

            # Generate a unique username for the service
            base_username = f"srv_{customer.id}_{domain.replace('.', '_').replace('-', '_')}"[:90]
            username = base_username
            counter = 1
            while Service.objects.filter(username=username).exists():
                username = f"{base_username}_{counter}"[:100]
                counter += 1

            try:
                try:
                    revision = int(request.POST.get("currency_revision", ""))
                except (TypeError, ValueError):
                    revision = None
                with transaction.atomic():
                    policy = require_current_selling_policy(request.POST.get("currency", ""), revision)
                    price = plan.get_price_for_currency(policy.currency_code)
                    if not plan.is_active or price is None:
                        raise ValidationError(_("This plan has no current price. Select an available plan."))
                    service = Service.objects.create(
                        customer=customer,
                        service_plan=plan,
                        currency_id=policy.currency_code,
                        service_name=f"{plan.name} - {domain}",
                        domain=domain,
                        username=username,
                        price=Decimal(price.monthly_price_cents) / 100,
                        status="pending",
                    )
                messages.success(request, _("✅ Service for {domain} has been created!").format(domain=domain))
                return redirect("provisioning:service_detail", pk=service.pk)
            except ValidationError as exc:
                messages.error(request, " ".join(exc.messages))
                response_status = 409 if isinstance(exc, SellingCurrencyChangedError) else 400
                policy = get_selling_currency_policy()
        else:
            messages.error(request, _("❌ All fields are required."))

    context = {
        "customers": customers,
        "plan_options": _plan_options(policy.currency_code),
        **policy.as_dict(),
    }

    return render(request, "provisioning/service_form.html", context, status=response_status)


@staff_required_strict
def service_edit(request: HttpRequest, pk: int) -> HttpResponse:
    """✏️ Edit existing hosting service"""
    # Type guard: @staff_required_strict ensures authenticated user
    user = cast(User, request.user)
    service = get_object_or_404(Service, pk=pk)

    # Security check
    if not user.can_access_customer(service.customer):
        messages.error(request, _("❌ You do not have permission to edit this service."))
        return redirect("provisioning:services")

    # Get user's customers for dropdown
    accessible_customers = user.get_accessible_customers()
    if hasattr(accessible_customers, "all"):
        customers = accessible_customers.all()
    elif isinstance(accessible_customers, list | tuple):
        customers = Customer.objects.filter(id__in=[c.id for c in accessible_customers])
    else:
        customers = accessible_customers  # type: ignore[unreachable]
    plans = ServicePlan.objects.filter(is_active=True)

    if request.method == "POST":
        customer_id = request.POST.get("customer_id")
        plan_id = request.POST.get("plan_id")
        domain = request.POST.get("domain")

        if customer_id and plan_id and domain:
            customer = get_object_or_404(Customer, pk=customer_id)

            # Security check
            accessible_customer_ids = _get_accessible_customer_ids(user)
            if int(customer_id) not in accessible_customer_ids:
                messages.error(request, _("❌ You do not have permission to move services to this customer."))
                return redirect("provisioning:service_detail", pk=pk)

            plan = get_object_or_404(ServicePlan, pk=plan_id)

            # Update service
            service.customer = customer
            service.service_plan = plan
            service.domain = domain
            service.save()

            messages.success(request, _("✅ Service {domain} has been updated!").format(domain=domain))
            return redirect("provisioning:service_detail", pk=service.pk)
        else:
            messages.error(request, _("❌ All fields are required."))

    context = {
        "service": service,
        "customers": customers,
        "plans": plans,
        "plan_options": _plan_options(service.currency_id),
        "is_edit": True,
    }

    return render(request, "provisioning/service_form.html", context)


@staff_required_strict
def service_suspend(request: HttpRequest, pk: int) -> HttpResponse:
    """⏸️ Suspend hosting service"""
    # Type guard: @staff_required_strict ensures authenticated user
    user = cast(User, request.user)
    service = get_object_or_404(Service, pk=pk)

    # Security check
    if not user.can_access_customer(service.customer):
        messages.error(request, _("❌ You do not have permission to suspend this service."))
        return redirect("provisioning:services")

    if request.method == "POST":
        reason = request.POST.get("reason", "Staff suspension")
        try:
            service.suspend(reason=reason)
            service.save(update_fields=["status", "suspended_at", "suspension_reason", "updated_at"])
        except TransitionNotAllowed:
            messages.error(
                request,
                _("❌ Service {domain} cannot be suspended from status '{status}'.").format(
                    domain=service.domain, status=service.status
                ),
            )
            return redirect("provisioning:service_detail", pk=pk)
        except ConcurrentTransition:
            messages.error(
                request,
                _("❌ Service {domain} was modified concurrently. Please try again.").format(domain=service.domain),
            )
            return redirect("provisioning:service_detail", pk=pk)

        messages.success(request, _("⏸️ Service {domain} has been suspended!").format(domain=service.domain))
        return redirect("provisioning:service_detail", pk=pk)

    return render(request, "provisioning/service_suspend.html", {"service": service})


@staff_required_strict
def service_activate(request: HttpRequest, pk: int) -> HttpResponse:
    """▶️ Activate suspended service"""
    # Type guard: @staff_required_strict ensures authenticated user
    user = cast(User, request.user)
    service = get_object_or_404(Service, pk=pk)

    # Security check
    if not user.can_access_customer(service.customer):
        messages.error(request, _("❌ You do not have permission to activate this service."))
        return redirect("provisioning:services")

    if request.method == "POST":
        try:
            service.activate()
            service.save(update_fields=["status", "activated_at", "suspended_at", "suspension_reason", "updated_at"])
        except TransitionNotAllowed:
            messages.error(
                request,
                _("❌ Service {domain} cannot be activated from status '{status}'.").format(
                    domain=service.domain, status=service.status
                ),
            )
            return redirect("provisioning:service_detail", pk=pk)
        except ConcurrentTransition:
            messages.error(
                request,
                _("❌ Service {domain} was modified concurrently. Please try again.").format(domain=service.domain),
            )
            return redirect("provisioning:service_detail", pk=pk)

        messages.success(request, _("▶️ Service {domain} has been activated!").format(domain=service.domain))
        return redirect("provisioning:service_detail", pk=pk)

    return render(request, "provisioning/service_activate.html", {"service": service})
