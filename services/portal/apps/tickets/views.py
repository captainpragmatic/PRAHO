# ===============================================================================
# CUSTOMER SUPPORT TICKETS VIEWS - PORTAL SERVICE 🎫
# ===============================================================================

import base64
import logging
from urllib.parse import quote

from django.contrib import messages
from django.http import Http404, HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils.translation import gettext as _
from django.utils.translation import gettext_lazy
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods

from apps.common.api_utils import DictAsObj
from apps.common.decorators import _get_user_role_for_customer, _render_role_check_degraded, require_support_access
from apps.common.pagination import PaginatorData, build_pagination_params
from apps.common.rate_limit_feedback import (
    handle_platform_error,
    is_rate_limited_error,
    is_unavailable_error,
    render_platform_unavailable,
)
from apps.services.services import services_api

from .services import TICKET_PAGE_SIZE, PlatformAPIError, TicketCreateRequest, TicketFilters, tickets_api

# Keep the JSON transport below the Platform request body limit.
MAX_REPLY_ATTACHMENTS = 5
MAX_REPLY_ATTACHMENT_BYTES = 1024 * 1024

# Tab configuration for ticket status filtering.
# Labels are lazy: module-level gettext would freeze them to the import-time locale.
TICKET_STATUS_TABS = [
    {
        "value": "",
        "label": gettext_lazy("All"),
        "border_class": "aria-selected:border-blue-500",
        "text_class": "aria-selected:text-blue-400",
    },
    {
        "value": "open",
        "label": gettext_lazy("Open"),
        "border_class": "aria-selected:border-blue-500",
        "text_class": "aria-selected:text-blue-400",
    },
    {
        "value": "in_progress",
        "label": gettext_lazy("In Progress"),
        "border_class": "aria-selected:border-purple-500",
        "text_class": "aria-selected:text-purple-400",
    },
    {
        "value": "waiting_on_customer",
        "label": gettext_lazy("Waiting on You"),
        "border_class": "aria-selected:border-yellow-500",
        "text_class": "aria-selected:text-yellow-400",
    },
    {
        "value": "closed",
        "label": gettext_lazy("Closed"),
        "border_class": "aria-selected:border-red-500",
        "text_class": "aria-selected:text-red-400",
    },
]

# ticket_create's category/priority <select> options, swapped from hardcoded template <option>
# tags to {% input_field type="select" options=... %} (Phase 4 TMPL003). Values match the
# template's own prior hardcoded options exactly, not the older "priorities"/"categories"
# context keys below the GET branch - those listed "urgent"/"domain"/"email", values the
# template itself never rendered as an <option>, so they were dead since before this change.
TICKET_CATEGORY_OPTIONS = [
    {"value": "", "label": gettext_lazy("Select category (optional)")},
    {"value": "technical", "label": gettext_lazy("Technical Support")},
    {"value": "billing", "label": gettext_lazy("Billing & Account")},
    {"value": "hosting", "label": gettext_lazy("Hosting Services")},
    {"value": "domains", "label": gettext_lazy("Domain Management")},
    {"value": "general", "label": gettext_lazy("General Inquiry")},
]

# "normal" is the template's historical default: the old hardcoded <option> selected it whenever
# priority was anything other than low/high/critical, including when priority was never set at
# all (GET). input_field selects by exact value match, so the view must pass "normal" explicitly
# rather than relying on an empty value happening to fall through.
TICKET_PRIORITY_OPTIONS = [
    {"value": "low", "label": gettext_lazy("Low")},
    {"value": "normal", "label": gettext_lazy("Normal")},
    {"value": "high", "label": gettext_lazy("High")},
    {"value": "critical", "label": gettext_lazy("Critical")},
]
_VALID_TICKET_PRIORITIES = {opt["value"] for opt in TICKET_PRIORITY_OPTIONS}


def _normalized_ticket_priority(raw: str) -> str:
    """Match the template's old fallback: anything other than low/high/critical selected
    "normal", including a submitted value of "urgent" (a real option before this swap's
    TICKET_PRIORITY_OPTIONS replaced it) or an empty/garbage one. input_field selects by exact
    value match, so an unrecognized value must be normalized here or the error re-render would
    select nothing and the browser would default to whichever option renders first (low)."""
    return raw if raw in _VALID_TICKET_PRIORITIES else "normal"


# Allowlist for the ?status= query param ("" = All tab). The value is echoed
# into rendered context and forwarded to the platform API, and the shared tab
# component's roving tabindex needs a matching tab — unknown values fall back
# to the All tab (mirrors apps/services/views.py).
_VALID_TICKET_STATUS_FILTERS = {tab["value"] for tab in TICKET_STATUS_TABS}


def _validated_status_filter(raw: str) -> str:
    return raw if raw in _VALID_TICKET_STATUS_FILTERS else ""


logger = logging.getLogger(__name__)


def _handle_ticket_error_response(
    request: HttpRequest, ticket_id: int, error_msg: str, status: int = 400
) -> HttpResponse:
    """Helper to handle error responses for HTMX or regular requests"""
    if request.headers.get("HX-Request"):
        return JsonResponse({"error": error_msg}, status=status)
    messages.error(request, error_msg)
    return redirect("tickets:detail", ticket_id=ticket_id)


def _handle_ticket_success_response(
    request: HttpRequest, ticket_id: int, success_msg: str, context: dict | None = None, template: str = ""
) -> HttpResponse:
    """Helper to handle success responses for HTMX or regular requests"""
    if request.headers.get("HX-Request") and context and template:
        return render(request, template, context)
    messages.success(request, success_msg)
    return redirect("tickets:detail", ticket_id=ticket_id)


def ticket_list(request: HttpRequest) -> HttpResponse:
    """
    Customer ticket list view - shows only customer's tickets.
    Supports filtering by status, priority, and search.
    """
    # Check authentication via Django session
    customer_id = getattr(request, "customer_id", None) or request.session.get("customer_id")
    user_id = request.session.get("user_id")
    if not customer_id or not user_id:
        return redirect("/login/")

    # Get filter parameters
    status_filter = _validated_status_filter(request.GET.get("status", ""))
    priority_filter = request.GET.get("priority", "")
    search_query = request.GET.get("q", "").strip()
    try:
        page = max(1, int(request.GET.get("page", 1)))
    except (ValueError, TypeError):
        page = 1

    try:
        # Create filters object
        filters = TicketFilters(page=page, status=status_filter, priority=priority_filter, search=search_query)

        # Get tickets from platform API
        response = tickets_api.get_customer_tickets(customer_id=customer_id, user_id=user_id, filters=filters)

        tickets = [DictAsObj(t) for t in response.get("results", [])]
        total_count = response.get("count", 0)

        # Get summary for header stats
        summary = tickets_api.get_tickets_summary(customer_id, user_id)
        open_count = summary.get("open_tickets", 0)

        # Pagination uses the same limit as the Platform request.
        paginator_data = PaginatorData(total_count=total_count, current_page=page, page_size=TICKET_PAGE_SIZE)
        pagination_params = build_pagination_params(
            q=quote(search_query, safe=""), status=status_filter, priority=quote(priority_filter, safe="")
        )

        context = {
            "tickets": tickets,
            "total_count": total_count,
            "open_count": open_count,
            "status_filter": status_filter,
            "priority_filter": priority_filter,
            "search_query": search_query,
            "page": page,
            # Shared pagination component data
            "paginator_data": paginator_data,
            "pagination_params": pagination_params,
            # Shared header component data
            "page_title": _("Tickets"),
            "page_title_mobile": _("Tickets"),
            "page_subtitle": _("Get help with your hosting services"),
            "search_placeholder": _("Search by ticket number, subject, description, or status…"),
            "header_stats": [
                {"value": str(open_count), "label": _("Open Tickets"), "color": "text-amber-400"},
                {"value": str(total_count), "label": _("Total Tickets"), "color": "text-white"},
            ],
            "filter_tabs": TICKET_STATUS_TABS,
        }

        logger.info(f"✅ [Tickets View] Loaded {len(tickets)} tickets for customer {customer_id}")

    except PlatformAPIError as e:
        error_ctx = handle_platform_error(
            request, e, logger, fallback_message=_("Unable to load support tickets. Please try again later.")
        )
        paginator_data = PaginatorData(total_count=0, current_page=1, page_size=TICKET_PAGE_SIZE)

        context = {
            "tickets": [],
            "total_count": 0,
            "open_count": 0,
            "status_filter": status_filter,
            "search_query": search_query,
            "error": True,
            "paginator_data": paginator_data,
            "pagination_params": "",
            # Shared template component data
            "page_title": _("Tickets"),
            "page_title_mobile": _("Tickets"),
            "page_subtitle": _("Get help with your hosting services"),
            "search_placeholder": _("Search by ticket number, subject, description, or status…"),
            "header_stats": [
                {"value": "0", "label": _("Open Tickets"), "color": "text-amber-400"},
                {"value": "0", "label": _("Total Tickets"), "color": "text-white"},
            ],
            "filter_tabs": TICKET_STATUS_TABS,
            **error_ctx,
        }

    return render(request, "tickets/ticket_list.html", context)


def ticket_detail(request: HttpRequest, ticket_id: int) -> HttpResponse:
    """
    Customer ticket detail view - shows ticket info and conversation.
    Only accessible by ticket owner (customer).
    """
    # Check authentication via Django session
    customer_id = getattr(request, "customer_id", None) or request.session.get("customer_id")
    user_id = request.session.get("user_id")
    if not customer_id or not user_id:
        return redirect("/login/")

    try:
        # Get ticket details (includes comments/replies)
        ticket_response = tickets_api.get_ticket_detail(customer_id, user_id, ticket_id)

        # Extract ticket data and replies from platform response
        if ticket_response.get("success") and "data" in ticket_response:
            ticket = ticket_response["data"].get("ticket", {})
            replies = ticket.get("comments", [])  # Replies are in comments field
        else:
            ticket = ticket_response
            replies = ticket.get("comments", [])  # Fallback if response format is different

        role = _get_user_role_for_customer(request, str(customer_id))
        context = {
            "ticket": ticket,
            "replies": replies,
            "can_reply": role in {"owner", "billing", "tech"} and ticket.get("status") not in ["closed", "resolved"],
        }

        logger.info(f"✅ [Tickets View] Loaded ticket {ticket_id} details for customer {customer_id}")

    except PlatformAPIError as e:
        if is_rate_limited_error(e):
            return _render_role_check_degraded(request, e)
        if is_unavailable_error(e):
            return render_platform_unavailable(request, e)
        logger.error(f"🔥 [Tickets View] Error loading ticket {ticket_id} for customer {customer_id}: {e}")
        messages.error(request, _("Ticket not found or access denied."))
        return redirect("tickets:list")

    return render(request, "tickets/ticket_detail.html", context)


@csrf_protect
@require_support_access()
def ticket_create(request: HttpRequest) -> HttpResponse:
    """
    Create new support ticket view.
    Only authenticated customers can create tickets.
    """
    # Check authentication via Django session
    customer_id = getattr(request, "customer_id", None) or request.session.get("customer_id")
    user_id = request.session.get("user_id")
    if not customer_id or not user_id:
        return redirect("/login/")

    if request.method == "POST":
        title = request.POST.get("title", "").strip()
        description = request.POST.get("description", "").strip()
        priority = request.POST.get("priority", "normal")
        category = request.POST.get("category", "")
        service_id_str = request.POST.get("service_id", "")
        service_name = request.POST.get("service_name", "")

        # Validation
        if not title or not description:
            messages.error(request, _("Title and description are required."))
            return render(
                request,
                "tickets/ticket_create.html",
                {
                    "title": title,
                    "description": description,
                    "priority": _normalized_ticket_priority(priority),
                    "category": category,
                    "service_id": service_id_str,
                    "service_name": service_name,
                    "category_options": TICKET_CATEGORY_OPTIONS,
                    "priority_options": TICKET_PRIORITY_OPTIONS,
                },
            )

        try:
            # Create ticket via platform API
            # contact_email and contact_person are automatically populated from authenticated customer
            ticket_request = TicketCreateRequest(
                title=title,
                description=description,
                priority=priority,
                category=category,
                related_service=int(service_id_str) if service_id_str else None,
            )
            ticket = tickets_api.create_ticket(customer_id, user_id, ticket_request)

            # Extract ticket identifier for redirect and messages
            ticket_id = ticket.get("id") or ticket.get("pk")
            ticket_number = ticket.get("ticket_number") or ticket_id

            messages.success(request, _("Support ticket created successfully. Ticket #{}.").format(ticket_number))

            logger.info(f"✅ [Tickets View] Created ticket {ticket_id} for customer {customer_id}")

            # Handle missing ticket ID gracefully
            if not ticket_id:
                logger.error(f"🔥 [Tickets View] No ticket ID returned from platform API: {ticket}")
                messages.error(
                    request, _("Ticket created but unable to redirect to details. Please check your tickets list.")
                )
            return redirect("tickets:detail", ticket_id=ticket_id) if ticket_id else redirect("tickets:list")

        except PlatformAPIError as e:
            if is_rate_limited_error(e):
                raise
            logger.error(f"🔥 [Tickets View] Error creating ticket for customer {customer_id}: {e}")
            messages.error(request, _("Unable to create support ticket. Please try again later."))
            # Preserve form data on API error
            return render(
                request,
                "tickets/ticket_create.html",
                {
                    "title": title,
                    "description": description,
                    "priority": _normalized_ticket_priority(priority),
                    "category": category,
                    "service_id": service_id_str,
                    "service_name": service_name,
                    "category_options": TICKET_CATEGORY_OPTIONS,
                    "priority_options": TICKET_PRIORITY_OPTIONS,
                },
            )

    # GET request - show create form
    # Resolve linked service if service_id provided
    service_id = request.GET.get("service_id", "")
    service_name = ""
    if service_id:
        try:
            svc = services_api.get_service_detail(customer_id, user_id, int(service_id))
            service_name = svc.get("service_name", "") or svc.get("name", "")
        except Exception as exc:
            if isinstance(exc, PlatformAPIError) and is_unavailable_error(exc):
                return render_platform_unavailable(request, exc)
            logger.warning(f"⚠️ [Tickets View] Could not resolve service {service_id}, passing ID only")
            # Keep service_id even if name resolution fails — Platform will validate on create

    context = {
        "category_options": TICKET_CATEGORY_OPTIONS,
        "priority_options": TICKET_PRIORITY_OPTIONS,
        "category": "",
        "priority": "normal",
        "service_id": service_id,
        "service_name": service_name,
    }

    return render(request, "tickets/ticket_create.html", context)


@require_http_methods(["GET"])
def ticket_attachment_download(request: HttpRequest, ticket_id: int, attachment_id: int) -> HttpResponse:
    """Proxy a customer-authorized download through the signed Platform client."""
    customer_id = getattr(request, "customer_id", None) or request.session.get("customer_id")
    user_id = request.session.get("user_id")
    if not customer_id or not user_id:
        return redirect("/login/")
    try:
        content, headers = tickets_api.download_ticket_attachment(customer_id, user_id, ticket_id, attachment_id)
    except PlatformAPIError as exc:
        if exc.status_code in (403, 404):
            raise Http404("Attachment not found") from exc
        if is_rate_limited_error(exc):
            raise
        if is_unavailable_error(exc):
            return render_platform_unavailable(request, exc)
        return HttpResponse(_("Attachment temporarily unavailable."), status=503)
    headers = {key.lower(): value for key, value in headers.items()}
    response = HttpResponse(content, content_type=headers.get("content-type", "application/octet-stream"))
    response["Content-Disposition"] = headers.get("content-disposition", "attachment")
    response["Cache-Control"] = "private, no-store"
    response["X-Content-Type-Options"] = "nosniff"
    return response


@require_http_methods(["POST"])
@require_support_access()
def ticket_reply(request: HttpRequest, ticket_id: int) -> HttpResponse:
    """
    Add customer reply to existing ticket.
    HTMX endpoint for dynamic conversation updates.
    """
    # Check authentication via Django session
    customer_id = getattr(request, "customer_id", None) or request.session.get("customer_id")
    user_id = request.session.get("user_id")
    if not customer_id or not user_id:
        return redirect("/login/")

    reply_text = request.POST.get("message", "").strip()

    if not reply_text:
        return _handle_ticket_error_response(request, ticket_id, _("Reply text is required."))

    # Handle file attachments
    attachments = []
    uploaded_files = request.FILES.getlist("attachments")
    if (
        len(uploaded_files) > MAX_REPLY_ATTACHMENTS
        or sum(file.size or 0 for file in uploaded_files) > MAX_REPLY_ATTACHMENT_BYTES
    ):
        return _handle_ticket_error_response(request, ticket_id, _("Attach at most 5 files, totaling at most 1 MiB."))
    if uploaded_files:
        # Process uploaded files for API transmission
        for uploaded_file in uploaded_files:
            # Convert file to base64 for API transmission
            file_content = uploaded_file.read()
            file_data = {
                "filename": uploaded_file.name,
                "content": base64.b64encode(file_content).decode("utf-8"),
                "content_type": uploaded_file.content_type or "application/octet-stream",
                "size": len(file_content),
            }
            attachments.append(file_data)

    try:
        # Only a failed write may re-offer the submitted reply.
        tickets_api.add_ticket_reply(
            customer_id=customer_id,
            user_id=user_id,
            ticket_id=ticket_id,
            message=reply_text,
            attachments=attachments if attachments else None,
        )
    except PlatformAPIError as e:
        if is_rate_limited_error(e):
            raise
        logger.error(f"🔥 [Tickets View] Error adding reply to ticket {ticket_id} for customer {customer_id}: {e}")
        htmx_form = request.headers.get("HX-Request") == "true"
        return (
            render_platform_unavailable(
                request,
                e,
                template_name="tickets/partials/status_and_comments.html" if htmx_form else None,
                extra_context={"ticket": {"id": ticket_id}, "reply_text": request.POST.get("message", "")}
                if htmx_form
                else None,
            )
            if is_unavailable_error(e)
            else _handle_ticket_error_response(
                request, ticket_id, _("Unable to add reply. Please try again later."), status=500
            )
        )

    logger.info(f"✅ [Tickets View] Added reply to ticket {ticket_id} for customer {customer_id}")

    if request.headers.get("HX-Request"):
        context: dict[str, object]
        try:
            ticket_response = tickets_api.get_ticket_detail(customer_id, user_id, ticket_id)
        except PlatformAPIError as error:
            logger.warning("⚠️ [Tickets View] Reply saved but ticket %s could not refresh: %s", ticket_id, error)
            context = {
                "ticket": {"id": ticket_id},
                "reply_text": "",
                "reply_sent": True,
                "maintenance": True,
                "maintenance_heading": _("Thread could not refresh"),
                "maintenance_message": _(
                    "Your reply was sent, but the thread could not refresh. Refresh the thread to see the latest replies."
                ),
                "maintenance_retry_url": reverse("tickets:detail", args=[ticket_id]),
            }
        else:
            if ticket_response.get("success") and "data" in ticket_response:
                ticket = ticket_response["data"].get("ticket", {})
            else:
                ticket = ticket_response
            context = {"ticket": ticket, "replies": ticket.get("comments", [])}

        return _handle_ticket_success_response(
            request,
            ticket_id,
            _("Reply added successfully."),
            context,
            "tickets/partials/status_and_comments.html",
        )

    return _handle_ticket_success_response(request, ticket_id, _("Reply added successfully."))


def ticket_search_api(request: HttpRequest) -> HttpResponse:
    """
    HTMX search endpoint for live ticket filtering.
    Returns filtered ticket list partial.
    """
    # Check authentication via Django session
    customer_id = getattr(request, "customer_id", None) or request.session.get("customer_id")
    user_id = request.session.get("user_id")
    if not customer_id or not user_id:
        return redirect("/login/")

    search_query = request.GET.get("q", "").strip()
    status_filter = _validated_status_filter(request.GET.get("status", ""))
    priority_filter = request.GET.get("priority", "")
    try:
        page = max(1, int(request.GET.get("page", 1)))
    except (ValueError, TypeError):
        page = 1

    try:
        response = tickets_api.get_customer_tickets(
            customer_id=customer_id,
            user_id=user_id,
            filters=TicketFilters(
                page=page,
                status=status_filter,
                priority=priority_filter,
                search=search_query,
            ),
        )

        tickets = [DictAsObj(t) for t in response.get("results", [])]
        total_count = response.get("count", 0)

        paginator_data = PaginatorData(total_count=total_count, current_page=page, page_size=TICKET_PAGE_SIZE)
        pagination_params = build_pagination_params(
            q=quote(search_query, safe=""), status=status_filter, priority=quote(priority_filter, safe="")
        )

        return render(
            request,
            "tickets/partials/tickets_table.html",
            {
                "tickets": tickets,
                "paginator_data": paginator_data,
                "pagination_params": pagination_params,
            },
        )

    except PlatformAPIError as e:
        error_ctx = handle_platform_error(request, e, logger)
        paginator_data = PaginatorData(total_count=0, current_page=1, page_size=TICKET_PAGE_SIZE)

        context = {
            "tickets": [],
            "paginator_data": paginator_data,
            "pagination_params": "",
            **error_ctx,
        }
        return render(request, "tickets/partials/tickets_table.html", context)


def tickets_dashboard_widget(request: HttpRequest) -> HttpResponse:
    """
    Dashboard widget showing ticket summary for customer.
    Used in main dashboard view.
    """
    # Check authentication via Django session
    customer_id = getattr(request, "customer_id", None) or request.session.get("customer_id")
    user_id = request.session.get("user_id")
    if not customer_id or not user_id:
        return redirect("/login/")

    try:
        summary = tickets_api.get_tickets_summary(customer_id, user_id)

        # Get recent tickets (last 5)
        response = tickets_api.get_customer_tickets(customer_id, user_id, filters=TicketFilters(page=1))
        recent_tickets = [DictAsObj(t) for t in response.get("results", [])[:5]]

        context = {
            "summary": summary,
            "recent_tickets": recent_tickets,
        }

        return render(request, "tickets/partials/dashboard_widget.html", context)

    except PlatformAPIError as e:
        error_ctx = handle_platform_error(request, e, logger)
        return render(
            request,
            "tickets/partials/dashboard_widget.html",
            {"summary": {"total_tickets": 0, "open_tickets": 0}, "recent_tickets": [], "error": True, **error_ctx},
        )
