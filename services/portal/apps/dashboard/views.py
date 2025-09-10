"""
Dashboard views for PRAHO Portal Service
Customer-facing dashboard with API integration - STATELESS ARCHITECTURE.
"""

import logging

from django.contrib import messages
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.utils.translation import gettext as _

from apps.api_client.services import PlatformAPIError, api_client
from apps.billing.services import InvoiceViewService
from apps.services.services import ServicesAPIClient
from apps.tickets.services import TicketAPIClient

logger = logging.getLogger(__name__)


class DictAsObj:
    """Simple wrapper to allow dot notation access on dictionaries for Django templates"""
    def __init__(self, data):
        from django.utils import timezone
        from django.utils.dateparse import parse_datetime
        
        for key, value in data.items():
            if isinstance(value, dict):
                setattr(self, key, DictAsObj(value))
            elif key in ('created_at', 'updated_at') and isinstance(value, str):
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




def dashboard_view(request: HttpRequest) -> HttpResponse:
    """
    Protected customer dashboard view with data from platform API.
    Uses Django sessions for authentication.
    """
    
    # Check authentication via Django session
    customer_id = request.session.get('customer_id')
    if not customer_id:
        return redirect('/login/')
    
    # Initialize context with safe defaults
    context = {
        'customer_id': customer_id,
        'customer_email': request.session.get('email'),
        'dashboard_data': {
            'customers': [],
            'recent_invoices': [],
            'recent_tickets': [],
            'stats': {
                'total_customers': 0,
                'active_services': 0,
                'open_tickets': 0,
                'total_invoices': 0,
            }
        },
        'platform_available': True,
    }
    
    # Get dashboard data from platform API using billing/tickets/services clients
    try:
        invoice_service = InvoiceViewService()
        ticket_api = TicketAPIClient()
        services_api = ServicesAPIClient()
        
        # Get both invoices and proformas to match platform dashboard
        user_id = request.user.id
        invoices = invoice_service.get_customer_invoices(customer_id, user_id)
        proformas = invoice_service.get_customer_proformas(customer_id, user_id)
        invoice_summary = invoice_service.get_invoice_summary(customer_id, user_id)
        
        # Recent documents (invoices and proformas combined): newest first, show 4 to match platform dashboard  
        recent_documents = []
        for invoice in invoices[:4]:  # Limit invoices to 4
            invoice.document_type = 'invoice'
            recent_documents.append(invoice)
        for proforma in proformas[:4]:  # Limit proformas to 4
            proforma.document_type = 'proforma'
            recent_documents.append(proforma)
        
        # Sort combined list by created_at and limit to 4
        recent_documents.sort(key=lambda x: x.created_at, reverse=True)
        recent_documents = recent_documents[:4]

        # Customer details for Account Information card
        customers = []
        greeting_name = None
        try:
            response = api_client.get_customer_details(customer_id, user_id)
            if response and response.get('success') and response.get('customer'):
                # Wrap customer data for dot notation access in templates
                customer_obj = DictAsObj(response['customer'])
                customers = [customer_obj]
            else:
                customers = []
        except PlatformAPIError as e:
            logger.warning(f"⚠️ [Dashboard] Failed to load customer details: {e}")
            customers = []

        # Resolve greeting name preference: profile.first_name > customer contact person > email
        try:
            profile = api_client.get_customer_profile(user_id)
            if profile and profile.get('first_name'):
                greeting_name = profile.get('first_name')
        except Exception:
            greeting_name = None

        if not greeting_name:
            try:
                contact_first = (
                    customers and customers[0].get('contact_person', {}).get('first_name')
                )
                if contact_first:
                    greeting_name = contact_first
            except Exception:
                greeting_name = None

        if not greeting_name:
            greeting_name = context.get('customer_email') or ''

        # Tickets: recent + summary
        recent_tickets = []
        try:
            ticket_response = ticket_api.get_customer_tickets(customer_id, user_id, page=1)
            raw_tickets = ticket_response.get('results', [])[:4]
            # Wrap tickets with DictAsObj for date parsing and dot notation access
            recent_tickets = [DictAsObj(ticket) for ticket in raw_tickets]
            tickets_summary = ticket_api.get_tickets_summary(customer_id, user_id)
            open_tickets_count = tickets_summary.get('open_tickets', len(recent_tickets))
        except Exception:
            open_tickets_count = len(recent_tickets)

        # Services summary for active count
        active_services = 0
        try:
            services_summary = services_api.get_services_summary(customer_id, user_id)
            active_services = services_summary.get('active_services', 0)
        except Exception:
            active_services = 0
        
        dashboard_data = {
            'customers': customers,
            'recent_documents': recent_documents,
            'recent_tickets': recent_tickets,
            'stats': {
                'total_customers': len(customers),
                'active_services': active_services,
                'open_tickets': open_tickets_count,
                'total_invoices': invoice_summary.get('total_invoices', 0),
            }
        }
        # Pass greeting name for header
        context['greeting_name'] = greeting_name
        
        context['dashboard_data'] = dashboard_data
        
        logger.debug(f"✅ [Dashboard] Loaded data for customer {customer_id}")
        
    except Exception as e:
        logger.error(f"🔥 [Dashboard] Failed to load data for customer {customer_id}: {e}")
        context['platform_available'] = False
        messages.error(request, _("Could not load account information. Please try again later or contact support if the problem persists."))
    
    return render(request, "dashboard/dashboard.html", context)


def account_overview_view(request: HttpRequest) -> HttpResponse:
    """
    Protected account overview with detailed customer information.
    Uses Django sessions for authentication.
    """
    
    # Check authentication via Django session
    customer_id = request.session.get('customer_id')
    if not customer_id:
        return redirect('/login/')
    
    context = {
        'customer_id': customer_id,
        'customer_email': request.session.get('email'),
        'customers': [],
        'account_info': {},
        'platform_available': True,
    }
    
    try:
        # Get customer information directly from API
        customer_details = api_client.get_customer_details(customer_id, request.user.id)
        context['account_info'] = customer_details
        context['customers'] = [customer_details]  # Single customer view
        
        logger.debug(f"✅ [Account] Loaded details for customer {customer_id}")
        
    except PlatformAPIError as e:
        logger.error(f"🔥 [Account] Failed to load details for customer {customer_id}: {e}")
        context['platform_available'] = False
        messages.error(request, _("Could not load account information. Please try again later."))
    
    return render(request, "dashboard/account_overview.html", context)
