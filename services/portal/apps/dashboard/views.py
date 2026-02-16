"""
Dashboard views for PRAHO Portal Service
Customer-facing dashboard with API integration - STATELESS ARCHITECTURE.
"""

import logging
from typing import Any

from django.contrib import messages
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.utils.translation import gettext as _

from apps.api_client.services import PlatformAPIError, api_client
from apps.billing.services import InvoiceViewService
from apps.services.services import ServicesAPIClient
from apps.tickets.services import TicketAPIClient, TicketFilters

logger = logging.getLogger(__name__)


class DictAsObj:
    """Simple wrapper to allow dot notation access on dictionaries for Django templates"""

    def __init__(self, data: dict[str, Any]) -> None:
        for key, value in data.items():
            if isinstance(value, dict):
                setattr(self, key, DictAsObj(value))
            elif key in ("created_at", "updated_at") and isinstance(value, str):
                # Parse datetime strings for Django template date filters
                parsed_date = parse_datetime(value)
                if parsed_date:
                    if timezone.is_naive(parsed_date):
                        parsed_date = timezone.make_aware(parsed_date)
                    setattr(self, key, parsed_date)
                else:
                    setattr(self, key, value)
            else:
                setattr(self, key, value)


def _get_billing_data(
    invoice_service: InvoiceViewService, customer_id: str, user_id: int
) -> tuple[list[Any], dict[str, Any]]:
    """Get billing documents and invoice summary"""
    invoices = invoice_service.get_customer_invoices(customer_id, user_id)
    proformas = invoice_service.get_customer_proformas(customer_id, user_id)
    invoice_summary = invoice_service.get_invoice_summary(customer_id, user_id)

    # Recent documents (invoices and proformas combined): newest first, show 4
    recent_documents = []
    for invoice in invoices[:4]:
        invoice.document_type = "invoice"
        recent_documents.append(invoice)
    for proforma in proformas[:4]:
        proforma.document_type = "proforma"
        recent_documents.append(proforma)

    recent_documents.sort(key=lambda x: x.created_at, reverse=True)
    return recent_documents[:4], invoice_summary


def _get_customer_data(customer_id: str, user_id: int) -> tuple[list[Any], str | None]:
    """Get customer details and resolve greeting name"""
    customers = []
    greeting_name = None

    try:
        response = api_client.get_customer_details(customer_id, user_id)
        if response and response.get("success") and response.get("customer"):
            customer_obj = DictAsObj(response["customer"])
            customers = [customer_obj]
    except PlatformAPIError as e:
        logger.warning(f"⚠️ [Dashboard] Failed to load customer details: {e}")

    # Resolve greeting name preference: profile.first_name > customer contact person > email
    try:
        profile = api_client.get_customer_profile(user_id)
        if profile and profile.get("first_name"):
            greeting_name = profile.get("first_name")
    except PlatformAPIError as e:
        logger.debug(f"⚠️ [Dashboard] Failed to load profile for greeting name: {e}")

    if not greeting_name and customers:
        contact_person = getattr(customers[0], "contact_person", None)
        if isinstance(contact_person, DictAsObj):
            contact_first = getattr(contact_person, "first_name", None)
            if contact_first:
                greeting_name = contact_first

    return customers, greeting_name


def _get_ticket_data(ticket_api: TicketAPIClient, customer_id: str, user_id: int) -> tuple[list[Any], int]:
    """Get recent tickets and open tickets count"""
    recent_tickets = []
    try:
        ticket_response = ticket_api.get_customer_tickets(customer_id, user_id, TicketFilters(page=1))
        raw_tickets = ticket_response.get("results", [])[:4]
        recent_tickets = [DictAsObj(ticket) for ticket in raw_tickets]
        tickets_summary = ticket_api.get_tickets_summary(customer_id, user_id)
        open_tickets_count = tickets_summary.get("open_tickets", len(recent_tickets))
    except (PlatformAPIError, KeyError, TypeError, ValueError) as e:
        logger.debug(f"⚠️ [Dashboard] Failed to load ticket data: {e}")
        open_tickets_count = len(recent_tickets)

    return recent_tickets, open_tickets_count


def _get_services_data(services_api: ServicesAPIClient, customer_id: str, user_id: int) -> int:
    """Get active services count"""
    try:
        services_summary = services_api.get_services_summary(customer_id, user_id)
        return services_summary.get("active_services", 0)
    except (PlatformAPIError, KeyError, TypeError, ValueError) as e:
        logger.debug(f"⚠️ [Dashboard] Failed to load services summary: {e}")
        return 0


def dashboard_view(request: HttpRequest) -> HttpResponse:
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

    # Get dashboard data from platform API using helper functions
    try:
        invoice_service = InvoiceViewService()
        ticket_api = TicketAPIClient()
        services_api = ServicesAPIClient()
        user_id = request.user.id

        # Get all data using helper functions
        recent_documents, invoice_summary = _get_billing_data(invoice_service, customer_id, user_id)
        customers, greeting_name = _get_customer_data(customer_id, user_id)
        recent_tickets, open_tickets_count = _get_ticket_data(ticket_api, customer_id, user_id)
        active_services = _get_services_data(services_api, customer_id, user_id)

        # Fallback for greeting name if not resolved - use generic greeting instead of email
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

        logger.debug(f"✅ [Dashboard] Loaded data for customer {customer_id}")

    except Exception as e:
        logger.error(f"🔥 [Dashboard] Failed to load data for customer {customer_id}: {e}")
        context["platform_available"] = False
        messages.error(
            request,
            _("Could not load account information. Please try again later or contact support if the problem persists."),
        )

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
        customer_details = api_client.get_customer_details(customer_id, request.user.id)
        context["account_info"] = customer_details
        context["customers"] = [customer_details]  # Single customer view

        logger.debug(f"✅ [Account] Loaded details for customer {customer_id}")

    except PlatformAPIError as e:
        logger.error(f"🔥 [Account] Failed to load details for customer {customer_id}: {e}")
        context["platform_available"] = False
        messages.error(request, _("Could not load account information. Please try again later."))

    return render(request, "dashboard/account_overview.html", context)
