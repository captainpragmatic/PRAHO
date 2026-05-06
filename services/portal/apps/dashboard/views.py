"""
Dashboard views for PRAHO Portal Service
Customer-facing dashboard with API integration - STATELESS ARCHITECTURE.
"""

import logging
import time
from typing import Any

from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.utils.translation import gettext as _

from apps.api_client.services import PlatformAPIError, api_client
from apps.billing.services import InvoiceViewService
from apps.common.api_utils import DictAsObj
from apps.common.rate_limit_feedback import (
    get_rate_limit_message,
    get_retry_after_from_error,
    handle_platform_error,
    is_rate_limited_error,
)
from apps.services.services import ServicesAPIClient
from apps.tickets.services import TicketFilters, TicketsAPIClient

logger = logging.getLogger(__name__)


def _empty_billing_summary() -> dict[str, Any]:
    """Return empty billing summary matching InvoiceViewService._empty_summary shape."""
    return {
        "total_invoices": 0,
        "draft_invoices": 0,
        "issued_invoices": 0,
        "overdue_invoices": 0,
        "paid_invoices": 0,
        "total_amount_due": 0,
        "recent_invoices": [],
    }


def _get_billing_data(
    invoice_service: InvoiceViewService, customer_id: str, user_id: int
) -> tuple[list[Any], dict[str, Any]]:
    """Get billing documents and invoice summary"""
    try:
        cid = int(customer_id)
        invoices = invoice_service.get_customer_invoices(cid, user_id)
        proformas = invoice_service.get_customer_proformas(cid, user_id)
        invoice_summary = invoice_service.get_invoice_summary(cid, user_id)

        # Recent documents (invoices and proformas combined): newest first, show 4
        recent_documents: list[Any] = []
        for invoice in invoices[:4]:
            invoice.document_type = "invoice"
            recent_documents.append(invoice)
        for proforma in proformas[:4]:
            proforma.document_type = "proforma"
            recent_documents.append(proforma)

        recent_documents.sort(key=lambda x: x.created_at, reverse=True)
        return recent_documents[:4], invoice_summary
    except PlatformAPIError as e:
        if is_rate_limited_error(e):
            raise
        logger.warning("⚠️ [Dashboard] Failed to load billing data: %s", e)
        return [], _empty_billing_summary()


def _get_customer_data(customer_id: str, user_id: int) -> tuple[list[Any], str | None]:
    """Get customer details and resolve greeting name"""
    customers = []
    greeting_name = None

    try:
        response = api_client.get_customer_details(int(customer_id), user_id)
        if response and response.get("success") and response.get("customer"):
            customer_obj = DictAsObj(response["customer"])
            customers = [customer_obj]
    except PlatformAPIError as e:
        if is_rate_limited_error(e):
            raise
        logger.warning(f"⚠️ [Dashboard] Failed to load customer details: {e}")

    # Resolve greeting name preference: profile.first_name > customer contact person > email
    try:
        profile = api_client.get_customer_profile(user_id)
        if profile and profile.get("first_name"):
            greeting_name = profile.get("first_name")
    except PlatformAPIError as e:
        if is_rate_limited_error(e):
            raise
        logger.debug(f"⚠️ [Dashboard] Failed to load profile for greeting name: {e}")

    if not greeting_name and customers:
        contact_person = getattr(customers[0], "contact_person", None)
        if isinstance(contact_person, DictAsObj):
            contact_first = getattr(contact_person, "first_name", None)
            if contact_first:
                greeting_name = contact_first

    return customers, greeting_name


def _get_ticket_data(
    tickets_api: TicketsAPIClient, customer_id: str, user_id: int
) -> tuple[list[Any], int, dict[str, Any]]:
    """Get recent tickets, open tickets count, and raw summary for session seeding."""
    recent_tickets = []
    tickets_summary: dict[str, Any] = {}
    try:
        ticket_response = tickets_api.get_customer_tickets(int(customer_id), user_id, TicketFilters(page=1))
        raw_tickets = ticket_response.get("results", [])[:4]
        recent_tickets = [DictAsObj(ticket) for ticket in raw_tickets]
        tickets_summary = tickets_api.get_tickets_summary(int(customer_id), user_id)
        open_tickets_count = tickets_summary.get("open_tickets", len(recent_tickets))
    except (PlatformAPIError, KeyError, TypeError, ValueError) as e:
        if is_rate_limited_error(e):
            raise
        logger.debug(f"⚠️ [Dashboard] Failed to load ticket data: {e}")
        open_tickets_count = len(recent_tickets)

    return recent_tickets, open_tickets_count, tickets_summary


def _get_services_data(services_api: ServicesAPIClient, customer_id: str, user_id: int) -> tuple[int, dict[str, Any]]:
    """Get active services count and raw summary for session seeding."""
    try:
        services_summary = services_api.get_services_summary(int(customer_id), user_id)
        return int(services_summary.get("active_services", 0)), services_summary
    except (PlatformAPIError, KeyError, TypeError, ValueError) as e:
        if is_rate_limited_error(e):
            raise
        logger.debug(f"⚠️ [Dashboard] Failed to load services summary: {e}")
        return 0, {}


def dashboard_view(request: HttpRequest) -> HttpResponse:  # noqa: C901, PLR0912, PLR0915
    """
    Protected customer dashboard view with data from platform API.
    Uses Django sessions for authentication.
    """

    # Check authentication and get selected customer ID (respects company switcher)
    customer_id = getattr(request, "customer_id", None) or request.session.get("customer_id")
    if not customer_id:
        return redirect("/login/")

    # Initialize context with safe defaults
    context = {
        "customer_id": customer_id,
        "customer_email": request.session.get("email"),
        "dashboard_data": {
            "customers": [],
            "recent_invoices": [],
            "recent_tickets": [],
            "stats": {
                "total_customers": 0,
                "active_services": 0,
                "open_tickets": 0,
                "total_invoices": 0,
            },
        },
        "platform_available": True,
    }

    # Per-section rate-limit tracking for partial data preservation
    sections_rate_limited: set[str] = set()
    retry_afters: list[int] = []

    invoice_service = InvoiceViewService()
    tickets_api = TicketsAPIClient()
    services_api = ServicesAPIClient()
    user_id = int(request.user.id)  # type: ignore[union-attr, arg-type]  # request.user may be AnonymousUser
    cid_str = str(customer_id)

    # --- Billing section ---
    try:
        recent_documents, invoice_summary = _get_billing_data(invoice_service, cid_str, user_id)
    except PlatformAPIError as e:
        if is_rate_limited_error(e):
            sections_rate_limited.add("billing")
            ra = get_retry_after_from_error(e)
            if ra:
                retry_afters.append(ra)
        else:
            logger.error("🔥 [Dashboard] Failed to load billing data for customer %s: %s", customer_id, e)
        recent_documents, invoice_summary = [], _empty_billing_summary()

    # --- Customer section ---
    try:
        customers, greeting_name = _get_customer_data(cid_str, user_id)
    except PlatformAPIError as e:
        if is_rate_limited_error(e):
            sections_rate_limited.add("customer")
            ra = get_retry_after_from_error(e)
            if ra:
                retry_afters.append(ra)
        else:
            logger.error("🔥 [Dashboard] Failed to load customer data for customer %s: %s", customer_id, e)
        customers, greeting_name = [], None

    # --- Tickets section ---
    tickets_summary: dict[str, Any] = {}
    try:
        recent_tickets, open_tickets_count, tickets_summary = _get_ticket_data(tickets_api, cid_str, user_id)
    except PlatformAPIError as e:
        if is_rate_limited_error(e):
            sections_rate_limited.add("tickets")
            ra = get_retry_after_from_error(e)
            if ra:
                retry_afters.append(ra)
        else:
            logger.error("🔥 [Dashboard] Failed to load ticket data for customer %s: %s", customer_id, e)
        recent_tickets, open_tickets_count = [], 0

    # --- Services section ---
    services_summary: dict[str, Any] = {}
    try:
        active_services, services_summary = _get_services_data(services_api, cid_str, user_id)
    except PlatformAPIError as e:
        if is_rate_limited_error(e):
            sections_rate_limited.add("services")
            ra = get_retry_after_from_error(e)
            if ra:
                retry_afters.append(ra)
        else:
            logger.error("🔥 [Dashboard] Failed to load services data for customer %s: %s", customer_id, e)
        active_services = 0

    # Seed account_health session cache so the context processor skips
    # redundant API calls for the same billing/services/tickets summaries.
    # Only seed when ALL three summaries succeeded — caching empty fallback
    # data after a partial failure suppresses the overdue/suspended/waiting
    # banners for ACCOUNT_HEALTH_CACHE_TTL (300s) even after the platform
    # recovers (PR #164 review finding H2).
    if not sections_rate_limited and invoice_summary and services_summary and tickets_summary:
        request.session["account_health_data"] = {
            "invoice": invoice_summary,
            "services": services_summary,
            "tickets": tickets_summary,
        }
        request.session["account_health_fetched_at"] = time.time()

    # Fallback for greeting name if not resolved
    if not greeting_name:
        greeting_name = None  # Template will handle showing just "Welcome" without name

    dashboard_data = {
        "customers": customers,
        "recent_documents": recent_documents,
        "recent_tickets": recent_tickets,
        "stats": {
            "total_customers": len(customers),
            "active_services": active_services,
            "open_tickets": open_tickets_count,
            "total_invoices": invoice_summary.get("total_invoices", 0),
        },
    }

    context["greeting_name"] = greeting_name
    context["dashboard_data"] = dashboard_data

    # Add per-section rate-limit context if any section was rate-limited
    if sections_rate_limited:
        retry_after = max(retry_afters) if retry_afters else None
        context.update(
            {
                "rate_limited": True,
                "sections_rate_limited": sections_rate_limited,
                "rate_limit_message": get_rate_limit_message(retry_after),
                "rate_limit_retry_url": request.get_full_path(),
            }
        )
        logger.warning(
            "⚠️ [Dashboard] Rate limited sections for customer %s: %s",
            customer_id,
            sections_rate_limited,
        )

    logger.debug("✅ [Dashboard] Loaded data for customer %s", customer_id)

    return render(request, "dashboard/dashboard.html", context)


def account_overview_view(request: HttpRequest) -> HttpResponse:
    """
    Protected account overview with detailed customer information.
    Uses Django sessions for authentication.
    """

    # Check authentication and get selected customer ID (respects company switcher)
    customer_id = getattr(request, "customer_id", None) or request.session.get("customer_id")
    if not customer_id:
        return redirect("/login/")

    context = {
        "customer_id": customer_id,
        "customer_email": request.session.get("email"),
        "customers": [],
        "account_info": {},
        "platform_available": True,
    }

    try:
        # Get customer information directly from API
        customer_details = api_client.get_customer_details(int(customer_id), int(request.user.id))  # type: ignore[union-attr, arg-type]
        context["account_info"] = customer_details
        context["customers"] = [customer_details]  # Single customer view

        logger.debug(f"✅ [Account] Loaded details for customer {customer_id}")

    except PlatformAPIError as e:
        error_ctx = handle_platform_error(
            request, e, logger, fallback_message=_("Could not load account information. Please try again later.")
        )
        context["platform_available"] = False
        context.update(error_ctx)

    return render(request, "dashboard/account_overview.html", context)
