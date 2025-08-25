"""
Context processors for PRAHO Platform templates
Romanian business context and common template variables.
"""

from typing import Any

from django.conf import settings
from django.http import HttpRequest


def romanian_business_context(request: HttpRequest) -> dict[str, Any]:
    """Romanian business information for templates"""
    return {
        'company_name': 'PragmaticHost SRL',
        'company_cui': 'RO12345678',
        'company_address': 'Str. Exemplu 123, București, România',
        'company_phone': '+40.21.123.4567',
        'company_email': 'contact@pragmatichost.com',
        'vat_rate': 19,  # Romanian VAT rate
        'currency': 'RON',
        'currency_symbol': 'lei',
        'support_hours': '09:00 - 18:00 (Luni - Vineri)',
        'emergency_phone': '+40.21.987.6543',
    }


def feature_flags(request: HttpRequest) -> dict[str, Any]:
    """Feature flags for gradual rollout"""
    return {
        'features': {
            'billing_v2': getattr(settings, 'FEATURE_BILLING_V2', False),
            'advanced_monitoring': getattr(settings, 'FEATURE_MONITORING', True),
            'e_factura_integration': getattr(settings, 'FEATURE_E_FACTURA', False),
            'multi_tenant': getattr(settings, 'FEATURE_MULTI_TENANT', True),
            'api_v2': getattr(settings, 'FEATURE_API_V2', False),
        }
    }


def user_permissions(request: HttpRequest) -> dict[str, Any]:
    """User permissions and role information"""
    if not request.user.is_authenticated:
        return {
            'user_permissions': {},
            'user_role': 'anonymous',
            'can_access_admin': False,
        }

    return {
        'user_permissions': {
            'can_view_billing': request.user.has_perm('billing.view_invoice'),
            'can_manage_tickets': request.user.has_perm('tickets.change_ticket'),
            'can_manage_customers': request.user.has_perm('customers.change_customer'),
            'can_provision_services': request.user.has_perm('provisioning.add_service'),
            'can_view_audit': request.user.has_perm('audit.view_auditlog'),
        },
        'user_role': getattr(request.user, 'role', 'user'),
        'can_access_admin': request.user.is_staff,
    }


def navigation_context(request: HttpRequest) -> dict[str, Any]:
    """Navigation context for templates"""
    nav_items = [
        {
            'name': 'Dashboard',
            'url': '/',
            'icon': 'dashboard',
            'active': request.path == '/',
        },
        {
            'name': 'Clienți',
            'url': '/customers/',
            'icon': 'users',
            'active': request.path.startswith('/customers/'),
            'permission': 'customers.view_customer',
        },
        {
            'name': 'Facturare',
            'url': '/billing/',
            'icon': 'credit-card',
            'active': request.path.startswith('/billing/'),
            'permission': 'billing.view_invoice',
        },
        {
            'name': 'Tickete',
            'url': '/tickets/',
            'icon': 'message-circle',
            'active': request.path.startswith('/tickets/'),
            'permission': 'tickets.view_ticket',
        },
        {
            'name': 'Servicii',
            'url': '/provisioning/',
            'icon': 'server',
            'active': request.path.startswith('/provisioning/'),
            'permission': 'provisioning.view_service',
        },
    ]

    # Filter navigation by permissions
    if request.user.is_authenticated:
        # ⚡ PERFORMANCE: Use list comprehension for better performance
        nav_items = [
            item for item in nav_items 
            if 'permission' not in item or request.user.has_perm(item['permission'])
        ]
    else:
        # Anonymous users see limited navigation
        nav_items = [item for item in nav_items if 'permission' not in item]

    return {
        'nav_items': nav_items,
        'current_path': request.path,
    }


def system_status(request: HttpRequest) -> dict[str, Any]:
    """System status information"""
    return {
        'system_status': {
            'maintenance_mode': getattr(settings, 'MAINTENANCE_MODE', False),
            'read_only_mode': getattr(settings, 'READ_ONLY_MODE', False),
            'debug_mode': settings.DEBUG,
            'environment': getattr(settings, 'ENVIRONMENT', 'development'),
        }
    }


def current_customer(request: HttpRequest) -> dict[str, Any]:
    """
    Provide the current customer context for templates.
    Updated for new CustomerMembership model with hybrid approach.
    """
    if not getattr(request, 'user', None) or not request.user.is_authenticated:
        return {'current_customer': None}

    # For staff users (staff_role is set), they don't have a "current customer" by default
    staff_role = getattr(request.user, 'staff_role', None)
    if staff_role:
        # Staff can switch customer context via session
        customer_id = request.session.get('staff_customer_context')
        if customer_id:
            from apps.customers.models import Customer
            try:
                customer = Customer.objects.get(id=customer_id)
                return {'current_customer': customer}
            except Customer.DoesNotExist:
                pass
        return {'current_customer': None}

    # For customer users, get their primary customer
    primary_customer = getattr(request.user, 'primary_customer', None)
    return {'current_customer': primary_customer}


def gdpr_compliance(request: HttpRequest) -> dict[str, Any]:
    """GDPR compliance context"""
    return {
        'gdpr': {
            'consent_required': not request.session.get('gdpr_consent', False),
            'privacy_policy_url': '/privacy-policy/',
            'data_processing_url': '/data-processing/',
            'cookie_policy_url': '/cookie-policy/',
        }
    }
