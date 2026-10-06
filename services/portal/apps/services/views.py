# ===============================================================================
# CUSTOMER HOSTING SERVICES VIEWS - PORTAL SERVICE 🔧
# ===============================================================================

import logging
from http import HTTPStatus
from typing import Any
from uuid import uuid4

from django.contrib import messages
from django.http import HttpRequest, HttpResponse, HttpResponseForbidden
from django.shortcuts import redirect, render
from django.utils.translation import gettext as _
from django.utils.translation import gettext_lazy
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods

from apps.common.decorators import _get_user_role_for_customer
from apps.common.pagination import PaginatorData, build_pagination_params
from apps.common.rate_limit_feedback import (
    build_maintenance_context,
    get_degraded_message,
    get_retry_after_from_error,
    handle_platform_error,
    is_rate_limited_error,
    is_unavailable_error,
    render_platform_unavailable,
)

from .services import PlatformAPIError, services_api

logger = logging.getLogger(__name__)

SERVICE_REQUEST_ACTIONS = [
    ("upgrade_request", gettext_lazy("Request Service Upgrade")),
    ("downgrade_request", gettext_lazy("Request Service Downgrade")),
    ("suspend_request", gettext_lazy("Request Service Suspension")),
    ("cancel_request", gettext_lazy("Request Service Cancellation")),
]
SERVICE_REQUEST_REASON_MAX_LENGTH = 4000
SERVICE_REQUEST_SUBMISSIONS_KEY = "service_request_submissions"

# Tab configuration for service status filtering.
# Mirrors the platform Service.STATUS_CHOICES (provisioning/service_models.py) so
# every real status is filterable — previously Provisioning/Failed/Terminated/Expired
# had no tab and "Cancelled" was a dead tab (no such status). (#101)
# Labels are lazy: module-level gettext would freeze them to the import-time locale.
SERVICE_STATUS_TABS = [
    {
        "value": "",
        "label": gettext_lazy("All Services"),
        "border_class": "aria-selected:border-blue-500",
        "text_class": "aria-selected:text-blue-400",
    },
    {
        "value": "active",
        "label": gettext_lazy("Active"),
        "border_class": "aria-selected:border-green-500",
        "text_class": "aria-selected:text-green-400",
    },
    {
        "value": "pending",
        "label": gettext_lazy("Pending"),
        "border_class": "aria-selected:border-yellow-500",
        "text_class": "aria-selected:text-yellow-400",
    },
    {
        "value": "provisioning",
        "label": gettext_lazy("Provisioning"),
        "border_class": "aria-selected:border-blue-500",
        "text_class": "aria-selected:text-blue-400",
    },
    {
        "value": "suspended",
        "label": gettext_lazy("Suspended"),
        "border_class": "aria-selected:border-red-500",
        "text_class": "aria-selected:text-red-400",
    },
    {
        "value": "failed",
        "label": gettext_lazy("Failed"),
        "border_class": "aria-selected:border-red-500",
        "text_class": "aria-selected:text-red-400",
    },
    {
        "value": "terminated",
        "label": gettext_lazy("Terminated"),
        "border_class": "aria-selected:border-gray-500",
        "text_class": "aria-selected:text-gray-400",
    },
    {
        "value": "expired",
        "label": gettext_lazy("Expired"),
        "border_class": "aria-selected:border-orange-500",
        "text_class": "aria-selected:text-orange-400",
    },
]

# Allowlist for the ?status= query param ("" = All tab).
_VALID_STATUS_FILTERS = {tab["value"] for tab in SERVICE_STATUS_TABS}


def _validated_status_filter(raw: str) -> str:
    """Allowlist ?status= against the known tabs.

    The value is attacker-influenced (query string) and gets echoed into the
    empty-state message and forwarded to the platform API — unknown values
    fall back to the All tab instead of being reflected.
    """
    return raw if raw in _VALID_STATUS_FILTERS else ""


def _report_platform_failure(request: HttpRequest, error: PlatformAPIError, *, subject: str, fallback: str) -> None:
    """Say whether the platform is degraded, or the service genuinely is not the customer's.

    Three handlers in this module asked that question and answered it identically. Folding them also
    took `service_request_action` back under the branch limit, which merging master pushed it over -
    the alternative was a `noqa` for duplication that did not need to exist.

    A window is NOT "Service not found or access denied". That sentence is a claim about the
    customer's own account, and during a window it is false.
    """
    if is_unavailable_error(error):
        logger.warning(f"⚠️ [Services View] {subject} unavailable, platform degraded: {error}")
        messages.warning(request, get_degraded_message(error))
    else:
        logger.error(f"🔥 [Services View] {subject} failed: {error}")
        messages.error(request, fallback)


def _get_session_identity(request: HttpRequest) -> tuple[int | None, int | None]:
    """Return validated customer and user IDs for authenticated Platform calls."""
    missing = object()
    raw_customer_id: Any = getattr(request, "customer_id", missing)
    if raw_customer_id is missing:
        raw_customer_id = request.session.get("customer_id")

    raw_user_id: Any = getattr(request, "user_id", missing)
    if raw_user_id is missing:
        raw_user_id = request.session.get("user_id")

    if raw_customer_id is None or raw_user_id is None:
        return None, None
    if isinstance(raw_customer_id, bool) or isinstance(raw_user_id, bool):
        return None, None

    try:
        customer_id = int(raw_customer_id)
        user_id = int(raw_user_id)
    except (TypeError, ValueError):
        return None, None

    if customer_id <= 0 or user_id <= 0:
        return None, None
    return customer_id, user_id


def _services_base_context(
    status_filter: str = "",
    search_query: str = "",
    active_count: int = 0,
    total_count: int = 0,
    status_counts: dict[str, int] | None = None,
) -> dict:
    """Build shared context for services list and search views."""
    tab_counts = status_counts or {}
    filter_tabs = (
        [
            {
                **tab,
                "count": total_count if tab["value"] == "" else tab_counts.get(str(tab["value"]), 0),
                "show_count": True,
            }
            for tab in SERVICE_STATUS_TABS
        ]
        if status_counts is not None
        else SERVICE_STATUS_TABS
    )
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
        "filter_tabs": filter_tabs,
    }


def service_list(request: HttpRequest) -> HttpResponse:
    """
    Customer services list view - shows only customer's hosting services.
    Supports filtering by status and search.
    """
    customer_id, user_id = _get_session_identity(request)
    if not customer_id or not user_id:
        return redirect("/login/")

    status_filter = _validated_status_filter(request.GET.get("status", ""))
    search_query = request.GET.get("q", "").strip()
    try:
        page = int(request.GET.get("page", 1))
    except (ValueError, TypeError):
        page = 1

    try:
        response = services_api.get_customer_services(
            customer_id=customer_id, user_id=user_id, page=page, status=status_filter, search=search_query
        )

        services = response.get("results", [])
        total_count = response.get("count", 0)

        summary = services_api.get_services_summary(customer_id, user_id)
        active_count = summary.get("active_services", 0)

        paginator_data = PaginatorData(total_count=total_count, current_page=page, page_size=20)
        pagination_params = build_pagination_params(status=status_filter, q=search_query)

        context = {
            "services": services,
            "paginator_data": paginator_data,
            "pagination_params": pagination_params,
            **_services_base_context(
                status_filter,
                search_query,
                active_count,
                summary.get("total_services", 0),
                status_counts=summary.get("status_counts"),
            ),
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
            # Counts are unknown on error — omit status_counts so badges hide
            # instead of claiming every status is 0.
            **_services_base_context(status_filter, search_query),
            **error_ctx,
        }

    return render(request, "services/service_list.html", context)


def service_search_api(request: HttpRequest) -> HttpResponse:
    """
    HTMX search endpoint for live service filtering.
    Returns filtered services table partial.
    """
    customer_id, user_id = _get_session_identity(request)
    if not customer_id or not user_id:
        return redirect("/login/")

    search_query = request.GET.get("q", "").strip()
    status_filter = _validated_status_filter(request.GET.get("status", ""))

    try:
        response = services_api.get_customer_services(
            customer_id=customer_id, user_id=user_id, page=1, status=status_filter, search=search_query
        )

        services = response.get("results", [])
        total_count = response.get("count", 0)

        paginator_data = PaginatorData(total_count=total_count, current_page=1, page_size=20)
        pagination_params = build_pagination_params(status=status_filter, q=search_query)

        return render(
            request,
            "services/partials/services_table.html",
            {
                "services": services,
                "paginator_data": paginator_data,
                "pagination_params": pagination_params,
                "status_filter": status_filter,
                "search_query": search_query,
            },
        )

    except PlatformAPIError as e:
        error_ctx = handle_platform_error(request, e, logger)
        context = {
            "services": [],
            "paginator_data": PaginatorData(total_count=0, current_page=1, page_size=20),
            "pagination_params": "",
            "status_filter": status_filter,
            "search_query": search_query,
            **error_ctx,
        }
        return render(request, "services/partials/services_table.html", context)


def service_detail(request: HttpRequest, service_id: int) -> HttpResponse:
    """
    Customer service detail view - shows service info, usage, and management options.
    Only accessible by service owner (customer).
    """
    # Check authentication via Django session
    customer_id, user_id = _get_session_identity(request)
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
            "can_manage": service.get("status") in {"active", "suspended"}
            and _get_user_role_for_customer(request, str(customer_id)) in {"owner", "billing", "tech"},
            "usage_period": "30d",
        }

        logger.info(f"✅ [Services View] Loaded service {service_id} details for customer {customer_id}")

    except PlatformAPIError as e:
        if is_rate_limited_error(e):
            raise
        if is_unavailable_error(e):
            return render_platform_unavailable(request, e)
        _report_platform_failure(
            request, e, subject=f"Service {service_id}", fallback=_("Service not found or access denied.")
        )
        return redirect("services:list")

    return render(request, "services/service_detail.html", context)


def service_usage(request: HttpRequest, service_id: int) -> HttpResponse:
    """HTMX endpoint for service usage data with different time periods."""
    customer_id, user_id = _get_session_identity(request)
    if not customer_id or not user_id:
        return redirect("/login/")

    period = request.GET.get("period", "30d")

    # Validate period
    valid_periods = ["7d", "30d", "90d"]
    if period not in valid_periods:
        period = "30d"

    try:
        usage = services_api.get_service_usage(customer_id, user_id, service_id, period=period)

        return render(
            request, "services/partials/usage_chart.html", {"usage": usage, "period": period, "service_id": service_id}
        )

    except PlatformAPIError as e:
        if is_rate_limited_error(e):
            raise
        if is_unavailable_error(e):
            # The partial gains the same `{% if maintenance %}` arm the tables have, rather than a
            # reworded error state: its generic arm is hardcoded "Unable to load usage data" in red,
            # which gives no cause and reads as our fault. `usage` is deliberately absent here.
            logger.warning(f"⚠️ [Services View] Usage for {service_id} unavailable, platform degraded: {e}")
            return render(
                request,
                "services/partials/usage_chart.html",
                {"period": period, "service_id": service_id, **build_maintenance_context(request, e)},
            )
        logger.error(f"🔥 [Services View] Error loading usage for service {service_id}: {e}")
        return render(
            request,
            "services/partials/usage_chart.html",
            {"usage": {"error": True}, "period": period, "service_id": service_id},
        )


def _service_submission_id(request: HttpRequest, customer_id: int, user_id: int, service_id: int) -> tuple[str, str]:
    """Keep accepted POSTs replayable; only a fresh GET starts the next request."""
    key = f"{customer_id}:{user_id}:{service_id}"
    submissions = dict(request.session.get(SERVICE_REQUEST_SUBMISSIONS_KEY, {}))
    submission = submissions.get(key)
    if isinstance(submission, str):
        submission = {"id": submission, "accepted": False}  # Existing pending sessions.
    if not isinstance(submission, dict) or (request.method == "GET" and submission.get("accepted")):
        submission = {"id": str(uuid4()), "accepted": False}
    if submissions.get(key) != submission:
        submissions[key] = submission
        request.session[SERVICE_REQUEST_SUBMISSIONS_KEY] = submissions
    return key, str(submission["id"])


def _service_request_form_error(request: HttpRequest, context: dict[str, Any]) -> tuple[str, int]:
    """Validate the bound form before sending a mutation to Platform."""
    if request.POST.get("submission_id") != context["submission_id"]:
        return _("This request form has expired. Review the details and submit this form again."), HTTPStatus.CONFLICT
    if context["selected_action"] not in {action for action, _label in SERVICE_REQUEST_ACTIONS}:
        return _("Invalid action requested."), HTTPStatus.BAD_REQUEST
    if not context["reason"] and context["selected_action"] in {"suspend_request", "cancel_request"}:
        return _("Reason is required for this request."), HTTPStatus.BAD_REQUEST
    if len(context["reason"]) > SERVICE_REQUEST_REASON_MAX_LENGTH:
        return _("The reason must contain no more than 4,000 characters."), HTTPStatus.BAD_REQUEST
    return "", HTTPStatus.OK


def _submit_service_request(
    request: HttpRequest, customer_id: int, user_id: int, submission_key: str, context: dict[str, Any]
) -> HttpResponse | None:
    """Return a ticket redirect only after Platform confirms a valid receipt."""
    context["form_error"], context["form_status"] = _service_request_form_error(request, context)
    if context["form_error"]:
        return None

    try:
        receipt = services_api.request_service_action(
            customer_id=customer_id,
            user_id=user_id,
            service_id=context["service_id"],
            action=context["selected_action"],
            reason=context["reason"],
            submission_id=context["submission_id"],
        )
    except PlatformAPIError as exc:
        if is_rate_limited_error(exc):
            raise
        if exc.status_code == HTTPStatus.CONFLICT:
            context["form_error"] = _(
                "This form was already submitted with different details. Check your tickets, "
                "or restore the original details and submit again to open the existing ticket."
            )
            context["form_status"] = HTTPStatus.CONFLICT
            context["submission_conflict"] = True
        elif is_unavailable_error(exc):
            context.update(build_maintenance_context(request, exc))
            context["form_error"] = get_degraded_message(exc)
        else:
            context["form_error"] = _("Unable to submit service request. Please try again later.")
        logger.warning("Service request for service %s was not confirmed: %s", context["service_id"], exc)
        return None

    submissions = dict(request.session.get(SERVICE_REQUEST_SUBMISSIONS_KEY, {}))
    submissions[submission_key] = {"id": context["submission_id"], "accepted": True}
    request.session[SERVICE_REQUEST_SUBMISSIONS_KEY] = submissions
    messages.success(
        request, _("Service request submitted. Ticket #%(number)s.") % {"number": receipt["ticket_number"]}
    )
    logger.info("Service request for service %s accepted as ticket %s", context["service_id"], receipt["ticket_id"])
    return redirect("tickets:detail", ticket_id=receipt["ticket_id"])


def _service_request_plans(service: dict[str, Any]) -> list[dict[str, Any]]:
    """Use detail-provided prices in the existing service currency, never new-sale prices."""
    currency_code = service.get("currency_code")
    plans = service.get("available_plans")
    if not isinstance(currency_code, str) or not currency_code or not isinstance(plans, list):
        return []
    return [plan for plan in plans if isinstance(plan, dict) and plan.get("currency_code") == currency_code]


def _service_request_load_error(request: HttpRequest, error: PlatformAPIError, context: dict[str, Any]) -> HttpResponse:
    """Keep an unsubmitted form recoverable when the service lookup is unavailable."""
    if is_rate_limited_error(error):
        raise error
    logger.warning("⚠️ [Services View] Service request form for %s unavailable: %s", context["service_id"], error)
    if request.method == "GET" and is_unavailable_error(error):
        return render_platform_unavailable(request, error)
    if request.method == "POST" and (
        error.status_code is None or error.status_code >= HTTPStatus.INTERNAL_SERVER_ERROR
    ):
        if is_unavailable_error(error):
            context.update(build_maintenance_context(request, error))
        context.update(
            service={"service_name": _("Hosting service")},
            service_details_unavailable=True,
            available_plans=[],
            form_error=get_degraded_message(error),
        )
        response = render(
            request,
            "services/service_request_action.html",
            context,
            status=HTTPStatus.OK if request.headers.get("HX-Request") == "true" else HTTPStatus.SERVICE_UNAVAILABLE,
        )
        retry_after = get_retry_after_from_error(error)
        if retry_after:
            response["Retry-After"] = str(retry_after)
        return response
    if is_unavailable_error(error):
        messages.warning(request, get_degraded_message(error))
    else:
        messages.error(request, _("Service not found or access denied."))
    return redirect("services:list")


@require_http_methods(["GET", "POST"])
@csrf_protect
def service_request_action(request: HttpRequest, service_id: int) -> HttpResponse:
    """Create a support ticket for staff review without changing the hosting service."""
    customer_id, user_id = _get_session_identity(request)
    if not customer_id or not user_id:
        return redirect("/login/")
    role = _get_user_role_for_customer(request, str(customer_id))
    billing_action = request.method == "POST" and request.POST.get("action") in {"suspend_request", "cancel_request"}
    if role not in {"owner", "billing", "tech"} or (billing_action and role == "tech"):
        return HttpResponseForbidden(_("You do not have permission to request service changes."))
    action_types = SERVICE_REQUEST_ACTIONS if role in {"owner", "billing"} else SERVICE_REQUEST_ACTIONS[:2]

    submission_key, submission_id = _service_submission_id(request, customer_id, user_id, service_id)
    context: dict[str, Any] = {
        "service_id": service_id,
        "submission_id": submission_id,
        "selected_action": request.POST.get("action", "") if request.method == "POST" else "upgrade_request",
        "reason": request.POST.get("reason", "").strip(),
        "action_types": action_types,
    }
    try:
        service = services_api.get_service_detail(customer_id, user_id, service_id)
        # Platform checks receipt identity before current status, including uncertain retries.
        bound_submission = request.method == "POST" and request.POST.get("submission_id") == submission_id
        if service.get("status") not in {"active", "suspended"} and not bound_submission:
            return HttpResponseForbidden(_("Requests are available for active or suspended services."))
        context["service"] = service
        if request.method == "POST":
            response = _submit_service_request(request, customer_id, user_id, submission_key, context)
            if response is not None:
                return response
        context["available_plans"] = _service_request_plans(service)
        return render(request, "services/service_request_action.html", context, status=context.get("form_status", 200))
    except PlatformAPIError as exc:
        return _service_request_load_error(request, exc, context)


def services_dashboard_widget(request: HttpRequest) -> HttpResponse:
    """
    Dashboard widget showing services summary for customer.
    Used in main dashboard view.
    """
    # Check authentication via Django session
    customer_id, user_id = _get_session_identity(request)
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
    """View available hosting plans for customer (for new orders or upgrades)."""
    customer_id, user_id = _get_session_identity(request)
    if not customer_id or not user_id:
        return redirect("/login/")

    service_type = request.GET.get("type", "")

    try:
        plans = services_api.get_available_plans(customer_id, service_type)

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
        if is_unavailable_error(e):
            return render_platform_unavailable(request, e, status=200)
        error_ctx = handle_platform_error(
            request, e, logger, fallback_message=_("Unable to load hosting plans. Please try again later.")
        )
        return render(request, "services/plans_list.html", {"plans": [], "error": True, **error_ctx})
