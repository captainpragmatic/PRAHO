# ===============================================================================
# CUSTOMER HOSTING SERVICES VIEWS - PORTAL SERVICE 🔧
# ===============================================================================

import logging
from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import JsonResponse, HttpRequest
from django.views.decorators.http import require_http_methods
from django.utils.translation import gettext as _
from .services import services_api, PlatformAPIError

logger = logging.getLogger(__name__)


def service_list(request: HttpRequest):
    """
    Customer services list view - shows only customer's hosting services.
    Supports filtering by status and service type.
    """
    # Check authentication via Django session
    customer_id = request.session.get('customer_id')
    user_id = request.session.get('user_id')
    if not customer_id or not user_id:
        return redirect('/login/')
    
    # Get filter parameters
    status_filter = request.GET.get('status', '')
    service_type_filter = request.GET.get('service_type', '')
    page = request.GET.get('page', 1)
    
    try:
        # Get services from platform API
        response = services_api.get_customer_services(
            customer_id=customer_id,
            user_id=user_id,
            page=page,
            status=status_filter,
            service_type=service_type_filter
        )
        
        services = response.get('results', [])
        total_count = response.get('count', 0)
        
        # Get summary for header stats
        summary = services_api.get_services_summary(customer_id, user_id)
        active_count = summary.get('active_services', 0)
        
        context = {
            'services': services,
            'total_count': total_count,
            'active_count': active_count,
            'status_filter': status_filter,
            'service_type_filter': service_type_filter,
            'page': page,
            'summary': summary,
            # Pagination info from API
            'has_next': response.get('next') is not None,
            'has_previous': response.get('previous') is not None,
            'current_page': page,
            # Filter options for UI
            'status_options': [
                ('', _('All Services')),
                ('active', _('Active')),
                ('suspended', _('Suspended')),
                ('pending', _('Pending')),
                ('cancelled', _('Cancelled')),
            ],
            'service_type_options': [
                ('', _('All Types')),
                ('shared_hosting', _('Shared Hosting')),
                ('vps', _('VPS')),
                ('dedicated', _('Dedicated Server')),
                ('cloud', _('Cloud Hosting')),
                ('email', _('Email Services')),
            ]
        }
        
        logger.info(f"✅ [Services View] Loaded {len(services)} services for customer {customer_id}")
        
    except PlatformAPIError as e:
        logger.error(f"🔥 [Services View] Error loading services for customer {customer_id}: {e}")
        messages.error(request, _('Unable to load hosting services. Please try again later.'))
        context = {
            'services': [],
            'total_count': 0,
            'active_count': 0,
            'status_filter': status_filter,
            'service_type_filter': service_type_filter,
            'error': True
        }
    
    return render(request, 'services/service_list.html', context)


def service_detail(request: HttpRequest, service_id: int):
    """
    Customer service detail view - shows service info, usage, and management options.
    Only accessible by service owner (customer).
    """
    # Check authentication via Django session
    customer_id = request.session.get('customer_id')
    user_id = request.session.get('user_id')
    if not customer_id or not user_id:
        return redirect('/login/')
    
    try:
        # Get service details
        service = services_api.get_service_detail(customer_id, user_id, service_id)
        
        # Get service usage statistics
        usage = services_api.get_service_usage(customer_id, service_id, period='30d')
        
        # Get associated domains
        domains = services_api.get_service_domains(customer_id, service_id)
        
        context = {
            'service': service,
            'service_id': service_id,  # Add service_id explicitly for URL reversing
            'usage': usage,
            'domains': domains,
            'can_manage': service.get('status') in ['active', 'suspended'],  # Customer can manage active/suspended services
            'usage_period': '30d'
        }
        
        logger.info(f"✅ [Services View] Loaded service {service_id} details for customer {customer_id}")
        
    except PlatformAPIError as e:
        logger.error(f"🔥 [Services View] Error loading service {service_id} for customer {customer_id}: {e}")
        messages.error(request, _('Service not found or access denied.'))
        return redirect('services:list')
    
    return render(request, 'services/service_detail.html', context)


def service_usage(request: HttpRequest, service_id: int):
    # Check authentication via Django session
    customer_id = request.session.get('customer_id')
    if not customer_id:
        return redirect('/login/')
    """
    HTMX endpoint for service usage data with different time periods.
    """
    customer_id = request.session.get('customer_id')
    period = request.GET.get('period', '30d')
    
    # Validate period
    valid_periods = ['7d', '30d', '90d']
    if period not in valid_periods:
        period = '30d'
    
    try:
        usage = services_api.get_service_usage(customer_id, service_id, period)
        
        return render(request, 'services/partials/usage_chart.html', {
            'usage': usage,
            'period': period,
            'service_id': service_id
        })
        
    except PlatformAPIError as e:
        logger.error(f"🔥 [Services View] Error loading usage for service {service_id}: {e}")
        return render(request, 'services/partials/usage_chart.html', {
            'usage': {'error': True},
            'period': period,
            'service_id': service_id
        })


def service_request_action(request: HttpRequest, service_id: int):
    """
    Customer service action request (upgrade, suspend request, etc.).
    Creates requests that require staff approval.
    """
    # Check authentication via Django session
    customer_id = request.session.get('customer_id')
    user_id = request.session.get('user_id')
    if not customer_id or not user_id:
        return redirect('/login/')
    
    if request.method == 'POST':
        action = request.POST.get('action', '')
        reason = request.POST.get('reason', '').strip()
        
        # Validate action
        allowed_actions = ['upgrade_request', 'downgrade_request', 'suspend_request', 'cancel_request']
        if action not in allowed_actions:
            messages.error(request, _('Invalid action requested.'))
            return redirect('services:detail', service_id=service_id)
        
        if not reason and action in ['suspend_request', 'cancel_request']:
            messages.error(request, _('Reason is required for this request.'))
            return redirect('services:detail', service_id=service_id)
        
        try:
            # Submit service request
            result = services_api.request_service_action(
                customer_id=customer_id,
                service_id=service_id,
                action=action,
                reason=reason
            )
            
            action_labels = {
                'upgrade_request': _('Upgrade Request'),
                'downgrade_request': _('Downgrade Request'),
                'suspend_request': _('Suspension Request'),
                'cancel_request': _('Cancellation Request'),
            }
            
            messages.success(request, _('{} submitted successfully. Request ID: #{}').format(
                action_labels.get(action, action),
                result.get('request_id', 'N/A')
            ))
            
            logger.info(f"✅ [Services View] Submitted {action} request for service {service_id} by customer {customer_id}")
            
        except PlatformAPIError as e:
            logger.error(f"🔥 [Services View] Error submitting {action} request for service {service_id} by customer {customer_id}: {e}")
            messages.error(request, _('Unable to submit service request. Please try again later.'))
        
        return redirect('services:detail', service_id=service_id)
    
    # GET request - show action form
    try:
        service = services_api.get_service_detail(customer_id, user_id, service_id)
        available_plans = services_api.get_available_plans(customer_id, service.get('service_type', ''))
        
        context = {
            'service': service,
            'available_plans': available_plans,
            'action_types': [
                ('upgrade_request', _('Request Service Upgrade')),
                ('downgrade_request', _('Request Service Downgrade')),
                ('suspend_request', _('Request Service Suspension')),
                ('cancel_request', _('Request Service Cancellation')),
            ]
        }
        
        return render(request, 'services/service_request_action.html', context)
        
    except PlatformAPIError as e:
        logger.error(f"🔥 [Services View] Error loading service action form for service {service_id}: {e}")
        messages.error(request, _('Service not found or access denied.'))
        return redirect('services:list')


def services_dashboard_widget(request: HttpRequest):
    """
    Dashboard widget showing services summary for customer.
    Used in main dashboard view.
    """
    # Check authentication via Django session
    customer_id = request.session.get('customer_id')
    user_id = request.session.get('user_id')
    if not customer_id or not user_id:
        return redirect('/login/')
    
    try:
        summary = services_api.get_services_summary(customer_id, user_id)
        
        # Get recent services (last 5)
        response = services_api.get_customer_services(customer_id, user_id, page=1)
        recent_services = response.get('results', [])[:5]
        
        context = {
            'summary': summary,
            'recent_services': recent_services,
        }
        
        return render(request, 'services/partials/dashboard_widget.html', context)
        
    except PlatformAPIError:
        # Return empty widget on error
        return render(request, 'services/partials/dashboard_widget.html', {
            'summary': {'total_services': 0, 'active_services': 0},
            'recent_services': [],
            'error': True
        })


def service_plans(request: HttpRequest):
    # Check authentication via Django session
    customer_id = request.session.get('customer_id')
    if not customer_id:
        return redirect('/login/')
    """
    View available hosting plans for customer (for new orders or upgrades).
    """
    customer_id = request.session.get('customer_id')
    service_type = request.GET.get('type', '')
    
    try:
        plans = services_api.get_available_plans(customer_id, service_type)
        
        context = {
            'plans': plans,
            'service_type': service_type,
            'service_types': [
                ('', _('All Plan Types')),
                ('shared_hosting', _('Shared Hosting')),
                ('vps', _('VPS Hosting')),
                ('dedicated', _('Dedicated Servers')),
                ('cloud', _('Cloud Hosting')),
                ('email', _('Email Services')),
            ]
        }
        
        return render(request, 'services/plans_list.html', context)
        
    except PlatformAPIError as e:
        logger.error(f"🔥 [Services View] Error loading plans for customer {customer_id}: {e}")
        messages.error(request, _('Unable to load hosting plans. Please try again later.'))
        return render(request, 'services/plans_list.html', {
            'plans': [],
            'error': True
        })