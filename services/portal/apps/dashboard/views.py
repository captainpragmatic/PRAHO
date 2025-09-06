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
    
    # Get dashboard data from platform API
    try:
        dashboard_data = api_client.get_dashboard_data(customer_id)
        context['dashboard_data'] = dashboard_data
        
        logger.debug(f"✅ [Dashboard] Loaded data for customer {customer_id}")
        
    except PlatformAPIError as e:
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


