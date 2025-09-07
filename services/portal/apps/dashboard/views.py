"""
Dashboard views for PRAHO Portal Service
Customer-facing dashboard with API integration - STATELESS ARCHITECTURE.
"""

import logging
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render, redirect
from django.utils.translation import gettext as _
from django.contrib import messages

from apps.api_client.services import api_client, PlatformAPIError
from apps.billing.services import InvoiceViewService
from apps.users.views import check_authentication

logger = logging.getLogger(__name__)


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
    
    # Get dashboard data from platform API using billing service
    try:
        invoice_service = InvoiceViewService()
        
        # Get both invoices and proformas using the same method as billing page
        user_id = request.user.id
        invoices = invoice_service.get_customer_invoices(customer_id, user_id)
        proformas = invoice_service.get_customer_proformas(customer_id, user_id)
        invoice_summary = invoice_service.get_invoice_summary(customer_id, user_id)
        
        # Mix invoices and proformas, add document type, and sort by date
        documents = []
        
        # Add document type to each invoice
        for invoice in invoices:
            invoice.document_type = 'invoice'
        documents.extend(invoices)
        
        # Add document type to each proforma  
        for proforma in proformas:
            proforma.document_type = 'proforma'
        documents.extend(proformas)
        
        # Sort documents by creation date (newest first) and take last 5
        documents.sort(key=lambda x: x.created_at, reverse=True)
        recent_documents = documents[:5]
        
        # Get customer data (simplified for now)
        customers = []  # Could be populated from API if needed
        recent_tickets = []  # Could be populated from tickets API if implemented
        
        dashboard_data = {
            'customers': customers,
            'recent_invoices': recent_documents,  # Keep template compatibility by using 'recent_invoices'
            'recent_tickets': recent_tickets,
            'stats': {
                'total_customers': len(customers),
                'active_services': 0,  # Could be populated from services API
                'open_tickets': len(recent_tickets),
                'total_invoices': invoice_summary.get('total_invoices', 0),
            }
        }
        
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
        customer_details = api_client.get_customer_details(customer_id)
        context['account_info'] = customer_details
        context['customers'] = [customer_details]  # Single customer view
        
        logger.debug(f"✅ [Account] Loaded details for customer {customer_id}")
        
    except PlatformAPIError as e:
        logger.error(f"🔥 [Account] Failed to load details for customer {customer_id}: {e}")
        context['platform_available'] = False
        messages.error(request, _("Could not load account information. Please try again later."))
    
    return render(request, "dashboard/account_overview.html", context)


