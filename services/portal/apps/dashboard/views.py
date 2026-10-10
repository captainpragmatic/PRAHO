"""
Dashboard views for PRAHO Portal Service
Customer-facing dashboard with API integration - STATELESS ARCHITECTURE.
"""

import logging
from typing import Any

from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.utils.translation import gettext as _

from apps.api_client.services import PlatformAPIError, api_client
from apps.billing.services import InvoiceViewService
from apps.common.account_health import remember_account_health
from apps.common.api_utils import DictAsObj
from apps.common.rate_limit_feedback import (
    build_maintenance_context,
    get_rate_limit_message,
    get_retry_after_from_error,
    handle_platform_error,
    is_rate_limited_error,
    is_unavailable_error,
)
from apps.services.services import ServicesAPIClient
from apps.tickets.services import TicketFilters, TicketsAPIClient

logger = logging.getLogger(__name__)


def _empty_billing_summary() -> dict[str, Any]:
    """Return empty billing summary matching InvoiceViewService._empty_summary shape."""
    return InvoiceViewService._empty_summary()


# A dash rather than a number for a section whose data never arrived. `stat_tile` renders whatever it
# is handed, so a fabricated 0 is a claim the platform never made - which is the whole defect. An
# em-dash needs no translation and is the conventional "not known".
_UNKNOWN_STAT = "—"


def _reraise_if_degraded(error: Exception) -> None:
    """A throttle AND a window both have to reach `dashboard_view`'s per-section handler.

    Every helper below re-raised only a throttle, so a maintenance 503 was swallowed here and the view
    never learned of it: the section was flattened to its zero shape and the dashboard stated, in
    numbers, that the customer had nothing.

    Widening is safe at exactly these five sites, and that was checked rather than assumed: each helper
    has ONE caller, `dashboard_view`, and every call sits in its own `except PlatformAPIError` that
    classifies both states. The same widening applied without that check elsewhere on this branch
    turned a 302 into a 500.

    An ordinary failure still falls through to the graceful return, deliberately: a 500 has no
    customer-facing story better than the existing empty state, and inventing one is not this fix.
    """
    if is_rate_limited_error(error) or is_unavailable_error(error):
        raise error


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
        _reraise_if_degraded(e)
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
        _reraise_if_degraded(e)
        logger.warning(f"⚠️ [Dashboard] Failed to load customer details: {e}")

    # Resolve greeting name preference: profile.first_name > customer contact person > email
    try:
        profile = api_client.get_customer_profile(user_id)
        if profile and profile.get("first_name"):
            greeting_name = profile.get("first_name")
    except PlatformAPIError as e:
        _reraise_if_degraded(e)
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
        _reraise_if_degraded(e)
        logger.debug(f"⚠️ [Dashboard] Failed to load ticket data: {e}")
        open_tickets_count = len(recent_tickets)

    return recent_tickets, open_tickets_count, tickets_summary


def _get_services_data(services_api: ServicesAPIClient, customer_id: str, user_id: int) -> tuple[int, dict[str, Any]]:
    """Get active services count and raw summary for session seeding."""
    try:
        services_summary = services_api.get_services_summary(int(customer_id), user_id)
        return int(services_summary.get("active_services", 0)), services_summary
    except (PlatformAPIError, KeyError, TypeError, ValueError) as e:
        _reraise_if_degraded(e)
        logger.debug(f"⚠️ [Dashboard] Failed to load services summary: {e}")
        return 0, {}


# PLR0912 dropped from the noqa: folding the four duplicated per-section classification blocks
# into `classify_section` took this function back under the branch limit on its own.
def dashboard_view(request: HttpRequest) -> HttpResponse:  # noqa: C901, PLR0915
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

    # Per-section degradation, two states kept SEPARATE on purpose. Widening `sections_rate_limited`
    # to mean "degraded" would make one flag decide both whether the state is surfaced and what the
    # customer is told - which is how every 503 came to announce "scheduled maintenance, your data is
    # safe", including the ones that were real failures. Whether it is shown is one decision; what it
    # is called is another.
    sections_rate_limited: set[str] = set()
    sections_unavailable: set[str] = set()
    retry_afters: list[int] = []
    # The first window seen, kept so `build_maintenance_context` can produce the wording and the
    # Retry-After from a real error rather than a synthesised one.
    window: PlatformAPIError | None = None

    def classify_section(section: str, error: PlatformAPIError) -> None:
        """Record WHICH section is degraded and HOW, so the page can be specific about it."""
        nonlocal window
        if is_rate_limited_error(error):
            sections_rate_limited.add(section)
            retry_after = get_retry_after_from_error(error)
            if retry_after:
                retry_afters.append(retry_after)
        elif is_unavailable_error(error):
            sections_unavailable.add(section)
            context["platform_available"] = False
            # Warning, not error: paging someone about their own maintenance window is how alerts get
            # ignored. The same choice `handle_platform_error` makes, for the same reason.
            logger.warning("⚠️ [Dashboard] %s unavailable for customer %s: %s", section, customer_id, error)
            if window is None:
                window = error
        else:
            logger.error("🔥 [Dashboard] Failed to load %s data for customer %s: %s", section, customer_id, error)

    def stat(value: object, section: str) -> object:
        """A dash rather than a number when this section's data never arrived."""
        return _UNKNOWN_STAT if section in sections_unavailable else value

    invoice_service = InvoiceViewService()
    tickets_api = TicketsAPIClient()
    services_api = ServicesAPIClient()
    user_id = int(request.user.id)  # type: ignore[union-attr, arg-type]  # request.user may be AnonymousUser
    cid_str = str(customer_id)

    # --- Billing section ---
    try:
        recent_documents, invoice_summary = _get_billing_data(invoice_service, cid_str, user_id)
    except PlatformAPIError as e:
        classify_section("billing", e)
        recent_documents, invoice_summary = [], _empty_billing_summary()

    # --- Customer section ---
    try:
        customers, greeting_name = _get_customer_data(cid_str, user_id)
    except PlatformAPIError as e:
        classify_section("customer", e)
        customers, greeting_name = [], None

    # --- Tickets section ---
    tickets_summary: dict[str, Any] = {}
    try:
        recent_tickets, open_tickets_count, tickets_summary = _get_ticket_data(tickets_api, cid_str, user_id)
    except PlatformAPIError as e:
        classify_section("tickets", e)
        recent_tickets, open_tickets_count = [], 0

    # --- Services section ---
    services_summary: dict[str, Any] = {}
    try:
        active_services, services_summary = _get_services_data(services_api, cid_str, user_id)
    except PlatformAPIError as e:
        classify_section("services", e)
        active_services = 0

    # Seed account_health session cache so the context processor skips
    # redundant API calls for the same billing/services/tickets summaries.
    # Only seed when ALL three summaries succeeded — caching empty fallback
    # data after a partial failure suppresses the overdue/suspended/waiting
    # banners for ACCOUNT_HEALTH_CACHE_TTL (300s) even after the platform
    # recovers (PR #164 review finding H2).
    # `not sections_unavailable` as well, and it is load-bearing rather than symmetry: the truthiness
    # checks below cannot stand in for it, because `_empty_billing_summary()` returns a non-empty dict
    # and is therefore truthy after a failure. This guard has always depended on the flag, not on the
    # data, to notice a degraded billing section - so adding a second degraded state without teaching
    # this reader about it would cache the empty fallback for ACCOUNT_HEALTH_CACHE_TTL (300s) during a
    # window and suppress the overdue/suspended banners even after the platform recovered. That is
    # PR #164 review finding H2 exactly, re-created by the fix for a different bug.
    if (
        not sections_rate_limited
        and not sections_unavailable
        and invoice_summary
        and invoice_summary.get("summary_available", True)
        and services_summary
        and tickets_summary
    ):
        remember_account_health(request.session, customer_id, invoice_summary, services_summary, tickets_summary)

    # Fallback for greeting name if not resolved
    if not greeting_name:
        greeting_name = None  # Template will handle showing just "Welcome" without name

    dashboard_data = {
        "customers": customers,
        "recent_documents": recent_documents,
        "billing_summary": invoice_summary,
        "recent_tickets": recent_tickets,
        "stats": {
            "total_customers": len(customers),
            # Through `stat`, so a section whose data never arrived shows a dash instead of a zero.
            # Handing `stat_tile` a 0 is the defect itself: it renders whatever it is given, and the
            # customer reads "you have no services" as a fact the platform stated.
            "active_services": stat(active_services, "services"),
            "open_tickets": stat(open_tickets_count, "tickets"),
            "total_invoices": stat(invoice_summary.get("total_invoices", 0), "billing"),
        },
    }

    context["greeting_name"] = greeting_name
    context["dashboard_data"] = dashboard_data

    # Add per-section rate-limit context if any section was rate-limited
    if sections_unavailable and window is not None:
        # The shape every other degraded surface uses, so `dashboard.html` can include the same alert
        # component the tables do rather than growing a message of its own.
        context.update(build_maintenance_context(request, window))
        context["sections_unavailable"] = sections_unavailable

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
        customer = customer_details.get("customer", {})
        context["account_info"] = customer
        context["customers"] = [customer]  # Single customer view

        logger.debug(f"✅ [Account] Loaded details for customer {customer_id}")

    except PlatformAPIError as e:
        error_ctx = handle_platform_error(
            request, e, logger, fallback_message=_("Could not load account information. Please try again later.")
        )
        context["platform_available"] = False
        context.update(error_ctx)

    return render(request, "dashboard/account_overview.html", context)
