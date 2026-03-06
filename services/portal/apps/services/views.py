# ===============================================================================
# CUSTOMER HOSTING SERVICES VIEWS - PORTAL SERVICE 🔧
# ===============================================================================

import logging

from django.contrib import messages
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.utils.translation import gettext as _

from apps.common.pagination import PaginatorData, build_pagination_params
from apps.common.rate_limit_feedback import handle_platform_error, is_rate_limited_error

from .services import PlatformAPIError, services_api

logger = logging.getLogger(__name__)

# Tab configuration for service status filtering
SERVICE_STATUS_TABS = [
    {"value": "", "label": _("All Services"), "border_class": "border-blue-500", "text_class": "text-blue-400"},
    {"value": "active", "label": _("Active"), "border_class": "border-green-500", "text_class": "text-green-400"},
    {"value": "suspended", "label": _("Suspended"), "border_class": "border-red-500", "text_class": "text-red-400"},
    {"value": "pending", "label": _("Pending"), "border_class": "border-yellow-500", "text_class": "text-yellow-400"},
    {"value": "cancelled", "label": _("Cancelled"), "border_class": "border-red-500", "text_class": "text-red-400"},
]


def _filter_services_by_query(services: list[dict], query: str) -> list[dict]:
    """Client-side search filtering across all visible and detail fields."""
    query_lower = query.lower()
    return [
        s
        for s in services
        if query_lower in str(s.get("service_name", "")).lower()
        or query_lower in str(s.get("domain", "")).lower()
        or query_lower in str(s.get("service_plan_name", "")).lower()
        or query_lower in str(s.get("service_plan_type_display", "")).lower()
        or query_lower in str(s.get("status", "")).lower()
        or query_lower in str(s.get("monthly_price", "")).lower()
        or query_lower in str(s.get("server_ip", "")).lower()
        or query_lower in str(s.get("server_name", "")).lower()
        or query_lower in str(s.get("username", "")).lower()
        or query_lower in str(s.get("next_billing_date", "")).lower()
        or query_lower in str(s.get("created_at", "")).lower()
        or query_lower in str(s.get("billing_cycle", "")).lower()
    ]


def _services_base_context(
    status_filter: str = "",
    search_query: str = "",
    active_count: int = 0,
    total_count: int = 0,
) -> dict:
    """Build shared context for services list and search views."""
    return {
        "status_filter": status_filter,
        "search_query": search_query,
        "page_title": _("My Services"),
        "page_title_mobile": _("Services"),
        "page_subtitle": _("Manage your hosting services and resources"),
        "search_placeholder": _("Search by name, domain, plan, status, price, IP, server…"),
        "header_stats": [
            {"value": str(active_count), "label": _("Active"), "color": "text-green-400"},
            {"value": str(total_count), "label": _("Total"), "color": "text-white"},
        ],
        "filter_tabs": SERVICE_STATUS_TABS,
    }


def service_list(request: HttpRequest) -> HttpResponse:
    """
    Customer services list view - shows only customer's hosting services.
    Supports filtering by status and search.
    """
    customer_id = getattr(request, "customer_id", None) or request.session.get("customer_id")
    user_id = request.session.get("user_id")
    if not customer_id or not user_id:
        return redirect("/login/")

    status_filter = request.GET.get("status", "")
    search_query = request.GET.get("q", "").strip()
    try:
        page = int(request.GET.get("page", 1))
    except (ValueError, TypeError):
        page = 1

    try:
        response = services_api.get_customer_services(
            customer_id=customer_id, user_id=user_id, page=page, status=status_filter
        )

        services = response.get("results", [])
        total_count = response.get("count", 0)

        # Client-side search filtering across all visible and detail fields
        if search_query:
            services = _filter_services_by_query(services, search_query)
            total_count = len(services)

        summary = services_api.get_services_summary(customer_id, user_id)
        active_count = summary.get("active_services", 0)

        paginator_data = PaginatorData(total_count=total_count, current_page=page, page_size=20)
        pagination_params = build_pagination_params(status=status_filter, q=search_query)

        context = {
            "services": services,
            "paginator_data": paginator_data,
            "pagination_params": pagination_params,
            **_services_base_context(status_filter, search_query, active_count, summary.get("total_services", 0)),
        }

        logger.info(f"✅ [Services View] Loaded {len(services)} services for customer {customer_id}")

    except PlatformAPIError as e:
        error_ctx = handle_platform_error(
            request, e, logger, fallback_message=_("Unable to load hosting services. Please try again later.")
        )
        context = {
            "services": [],
            "error": True,
            "paginator_data": PaginatorData(total_count=0, current_page=1, page_size=20),
            "pagination_params": "",
            **_services_base_context(status_filter, search_query),
            **error_ctx,
        }

    return render(request, "services/service_list.html", context)


def service_search_api(request: HttpRequest) -> HttpResponse:
    """
    HTMX search endpoint for live service filtering.
    Returns filtered services table partial.
    """
    customer_id = getattr(request, "customer_id", None) or request.session.get("customer_id")
    user_id = request.session.get("user_id")
    if not customer_id or not user_id:
        return redirect("/login/")

    search_query = request.GET.get("q", "").strip()
    status_filter = request.GET.get("status", "")

    try:
        response = services_api.get_customer_services(
            customer_id=customer_id, user_id=user_id, page=1, status=status_filter
        )

        services = response.get("results", [])
        total_count = response.get("count", 0)

        if search_query:
            services = _filter_services_by_query(services, search_query)
            total_count = len(services)

        paginator_data = PaginatorData(total_count=total_count, current_page=1, page_size=20)
        pagination_params = build_pagination_params(status=status_filter, q=search_query)

        return render(
            request,
            "services/partials/services_table.html",
            {
                "services": services,
                "paginator_data": paginator_data,
                "pagination_params": pagination_params,
            },
        )

    except PlatformAPIError as e:
        error_ctx = handle_platform_error(request, e, logger)
        context = {
            "services": [],
            "paginator_data": PaginatorData(total_count=0, current_page=1, page_size=20),
            "pagination_params": "",
            **error_ctx,
        }
        return render(request, "services/partials/services_table.html", context)


def service_detail(request: HttpRequest, service_id: int) -> HttpResponse:
    """
    Customer service detail view - shows service info, usage, and management options.
    Only accessible by service owner (customer).
    """
    # Check authentication via Django session
    customer_id = getattr(request, "customer_id", None) or request.session.get("customer_id")
    user_id = request.session.get("user_id")
    if not customer_id or not user_id:
        return redirect("/login/")

    try:
        # Get service details
        service = services_api.get_service_detail(customer_id, user_id, service_id)

        # Get service usage statistics
        usage = services_api.get_service_usage(customer_id, user_id, service_id, period="30d")

        # Get associated domains
        domains = services_api.get_service_domains(customer_id, service_id)

        context = {
            "service": service,
            "service_id": service_id,  # Add service_id explicitly for URL reversing
            "usage": usage,
            "domains": domains,
            "can_manage": service.get("status")
            in ["active", "suspended"],  # Customer can manage active/suspended services
            "usage_period": "30d",
        }

        logger.info(f"✅ [Services View] Loaded service {service_id} details for customer {customer_id}")

    except PlatformAPIError as e:
        if is_rate_limited_error(e):
            raise
        logger.error(f"🔥 [Services View] Error loading service {service_id} for customer {customer_id}: {e}")
        messages.error(request, _("Service not found or access denied."))
        return redirect("services:list")

    return render(request, "services/service_detail.html", context)


def service_usage(request: HttpRequest, service_id: int) -> HttpResponse:
    # Check authentication via Django session
    customer_id = getattr(request, "customer_id", None) or request.session.get("customer_id")
    if not customer_id:
        return redirect("/login/")
    """
    HTMX endpoint for service usage data with different time periods.
    """
    customer_id = getattr(request, "customer_id", None) or request.session.get("customer_id")
    period = request.GET.get("period", "30d")

    # Validate period
    valid_periods = ["7d", "30d", "90d"]
    if period not in valid_periods:
        period = "30d"

    try:
        usage = services_api.get_service_usage(int(customer_id or 0), int(customer_id or 0), service_id, period=period)

        return render(
            request, "services/partials/usage_chart.html", {"usage": usage, "period": period, "service_id": service_id}
        )

    except PlatformAPIError as e:
        if is_rate_limited_error(e):
            raise
        logger.error(f"🔥 [Services View] Error loading usage for service {service_id}: {e}")
        return render(
            request,
            "services/partials/usage_chart.html",
            {"usage": {"error": True}, "period": period, "service_id": service_id},
        )


def service_request_action(request: HttpRequest, service_id: int) -> HttpResponse:
    """
    Customer service action request (upgrade, suspend request, etc.).
    Creates requests that require staff approval.
    """
    # Check authentication via Django session
    customer_id = getattr(request, "customer_id", None) or request.session.get("customer_id")
    user_id = request.session.get("user_id")
    if not customer_id or not user_id:
        return redirect("/login/")

    if request.method == "POST":
        action = request.POST.get("action", "")
        reason = request.POST.get("reason", "").strip()

        # Validate action
        allowed_actions = ["upgrade_request", "downgrade_request", "suspend_request", "cancel_request"]
        if action not in allowed_actions:
            messages.error(request, _("Invalid action requested."))
            return redirect("services:detail", service_id=service_id)

        if not reason and action in ["suspend_request", "cancel_request"]:
            messages.error(request, _("Reason is required for this request."))
            return redirect("services:detail", service_id=service_id)

        try:
            # Submit service request
            result = services_api.request_service_action(
                customer_id=customer_id, service_id=service_id, action=action, reason=reason
            )

            action_labels = {
                "upgrade_request": _("Upgrade Request"),
                "downgrade_request": _("Downgrade Request"),
                "suspend_request": _("Suspension Request"),
                "cancel_request": _("Cancellation Request"),
            }

            messages.success(
                request,
                _("{} submitted successfully. Request ID: #{}").format(
                    action_labels.get(action, action), result.get("request_id", "N/A")
                ),
            )

            logger.info(
                f"✅ [Services View] Submitted {action} request for service {service_id} by customer {customer_id}"
            )

        except PlatformAPIError as e:
            if is_rate_limited_error(e):
                raise
            logger.error(
                f"🔥 [Services View] Error submitting {action} request for service {service_id} by customer {customer_id}: {e}"
            )
            messages.error(request, _("Unable to submit service request. Please try again later."))

        return redirect("services:detail", service_id=service_id)

    # GET request - show action form
    try:
        service = services_api.get_service_detail(customer_id, user_id, service_id)
        available_plans = services_api.get_available_plans(customer_id, service.get("service_type", ""))

        context = {
            "service": service,
            "service_id": service_id,  # Add service_id explicitly for URL reversing
            "available_plans": available_plans,
            "action_types": [
                ("upgrade_request", _("Request Service Upgrade")),
                ("downgrade_request", _("Request Service Downgrade")),
                ("suspend_request", _("Request Service Suspension")),
                ("cancel_request", _("Request Service Cancellation")),
            ],
        }

        return render(request, "services/service_request_action.html", context)

    except PlatformAPIError as e:
        if is_rate_limited_error(e):
            raise
        logger.error(f"🔥 [Services View] Error loading service action form for service {service_id}: {e}")
        messages.error(request, _("Service not found or access denied."))
        return redirect("services:list")


def services_dashboard_widget(request: HttpRequest) -> HttpResponse:
    """
    Dashboard widget showing services summary for customer.
    Used in main dashboard view.
    """
    # Check authentication via Django session
    customer_id = getattr(request, "customer_id", None) or request.session.get("customer_id")
    user_id = request.session.get("user_id")
    if not customer_id or not user_id:
        return redirect("/login/")

    try:
        summary = services_api.get_services_summary(customer_id, user_id)

        # Get recent services (last 5)
        response = services_api.get_customer_services(customer_id, user_id, page=1)
        recent_services = response.get("results", [])[:5]

        context = {
            "summary": summary,
            "recent_services": recent_services,
        }

        return render(request, "services/partials/dashboard_widget.html", context)

    except PlatformAPIError as e:
        error_ctx = handle_platform_error(request, e, logger)
        return render(
            request,
            "services/partials/dashboard_widget.html",
            {"summary": {"total_services": 0, "active_services": 0}, "recent_services": [], "error": True, **error_ctx},
        )


def service_plans(request: HttpRequest) -> HttpResponse:
    # Check authentication via Django session
    customer_id = getattr(request, "customer_id", None) or request.session.get("customer_id")
    if not customer_id:
        return redirect("/login/")
    """
    View available hosting plans for customer (for new orders or upgrades).
    """
    customer_id = getattr(request, "customer_id", None) or request.session.get("customer_id")
    service_type = request.GET.get("type", "")

    try:
        plans = services_api.get_available_plans(int(customer_id or 0), service_type)

        context = {
            "plans": plans,
            "service_type": service_type,
            "service_types": [
                ("", _("All Plan Types")),
                ("shared_hosting", _("Shared Hosting")),
                ("vps", _("VPS Hosting")),
                ("dedicated", _("Dedicated Servers")),
                ("cloud", _("Cloud Hosting")),
                ("email", _("Email Services")),
            ],
        }

        return render(request, "services/plans_list.html", context)

    except PlatformAPIError as e:
        error_ctx = handle_platform_error(
            request, e, logger, fallback_message=_("Unable to load hosting plans. Please try again later.")
        )
        return render(request, "services/plans_list.html", {"plans": [], "error": True, **error_ctx})
