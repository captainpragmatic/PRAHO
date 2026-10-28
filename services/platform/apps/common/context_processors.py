"""
Context processors for PRAHO Platform templates.
Common template variables.
"""

from typing import Any

from django.conf import settings
from django.http import HttpRequest


def _maintenance_mode_active() -> bool:
    """Deployment override wins when set; otherwise the runtime setting (cache-first)."""
    deployment_override = getattr(settings, "MAINTENANCE_MODE", None)
    if deployment_override is not None:
        return bool(deployment_override)
    from apps.settings.services import SettingsService  # noqa: PLC0415  # Function-level cross-app import (ADR-0007)

    return SettingsService.get_boolean_setting("system.maintenance_mode", False)


def feature_flags(request: HttpRequest) -> dict[str, Any]:
    """Feature flags for gradual rollout"""
    return {
        "features": {
            "billing_v2": getattr(settings, "FEATURE_BILLING_V2", False),
            "advanced_monitoring": getattr(settings, "FEATURE_MONITORING", True),
            "e_factura_integration": getattr(settings, "FEATURE_E_FACTURA", False),
            "multi_tenant": getattr(settings, "FEATURE_MULTI_TENANT", True),
            "api_v2": getattr(settings, "FEATURE_API_V2", False),
        }
    }


def user_permissions(request: HttpRequest) -> dict[str, Any]:
    """User permissions and role information"""
    if not request.user.is_authenticated:
        return {
            "user_permissions": {},
            "user_role": "anonymous",
            "can_access_admin": False,
        }

    return {
        "user_permissions": {
            "can_view_billing": request.user.has_perm("billing.view_invoice"),
            "can_manage_tickets": request.user.has_perm("tickets.change_ticket"),
            "can_manage_customers": request.user.has_perm("customers.change_customer"),
            "can_provision_services": request.user.has_perm("provisioning.add_service"),
            "can_view_audit": request.user.has_perm("audit.view_auditlog"),
        },
        "user_role": getattr(request.user, "role", "user"),
        "can_access_admin": getattr(request.user, "is_staff_user", False),
    }


def navigation_context(request: HttpRequest) -> dict[str, Any]:
    """Navigation context for templates"""
    nav_items = [
        {
            "name": "Dashboard",
            "url": "/",
            "icon": "dashboard",
            "active": request.path == "/",
        },
        {
            "name": "Clienți",
            "url": "/customers/",
            "icon": "users",
            "active": request.path.startswith("/customers/"),
            "permission": "customers.view_customer",
        },
        {
            "name": "Facturare",
            "url": "/billing/",
            "icon": "credit-card",
            "active": request.path.startswith("/billing/"),
            "permission": "billing.view_invoice",
        },
        {
            "name": "Tickete",
            "url": "/tickets/",
            "icon": "message-circle",
            "active": request.path.startswith("/tickets/"),
            "permission": "tickets.view_ticket",
        },
        {
            "name": "Servicii",
            "url": "/provisioning/",
            "icon": "server",
            "active": request.path.startswith("/provisioning/"),
            "permission": "provisioning.view_service",
        },
    ]

    # Filter navigation by permissions
    if request.user.is_authenticated:
        # ⚡ PERFORMANCE: Use list comprehension for better performance
        nav_items = [
            item
            for item in nav_items
            if "permission" not in item
            or (isinstance(item["permission"], str) and request.user.has_perm(item["permission"]))
        ]
    else:
        # Anonymous users see limited navigation
        nav_items = [item for item in nav_items if "permission" not in item]

    return {
        "nav_items": nav_items,
        "current_path": request.path,
    }


def system_status(request: HttpRequest) -> dict[str, Any]:
    """System status information.

    maintenance_mode is exposed TOP-LEVEL on purpose: the dashboard view passes
    its own "system_status" widget list, which shadows this processor's dict on
    that page (view context beats processors), silently hiding the staff banner.
    """
    return {
        **setup_attention(request),
        "maintenance_mode": _maintenance_mode_active(),
        "system_status": {
            "maintenance_mode": _maintenance_mode_active(),
            "read_only_mode": getattr(settings, "READ_ONLY_MODE", False),
            "debug_mode": settings.DEBUG,
            "environment": getattr(settings, "ENVIRONMENT", "development"),
        },
    }


def setup_attention(request: HttpRequest) -> dict[str, object]:
    """Read local evidence only; rendering a page never starts checks or writes progress."""
    user = getattr(request, "user", None)
    if "admin" in getattr(getattr(request, "resolver_match", None), "namespaces", ()):
        return {}  # Django admin has its own layout and can be mounted without staff-app routes.
    if (
        not user
        or not user.is_authenticated
        or not (getattr(user, "is_superuser", False) or getattr(user, "staff_role", "") == "admin")
    ):
        return {}
    from django.db import DatabaseError, InterfaceError, transaction  # noqa: PLC0415

    from apps.common.status_models import INTERNAL_CHECK_KEYS, SystemCheckState  # noqa: PLC0415
    from apps.common.status_observations import display_level  # noqa: PLC0415
    from apps.common.system_status import node_input_identities, runtime_input_identity  # noqa: PLC0415
    from apps.settings.setup_checklist import get_setup_report  # noqa: PLC0415

    try:
        with transaction.atomic():
            report = get_setup_report()
            rows = list(SystemCheckState.objects.exclude(check_key__in=INTERNAL_CHECK_KEYS).select_related("node"))
            identities = node_input_identities(row.node for row in rows if row.node is not None)
            global_identity = runtime_input_identity()
            issues = sum(
                display_level(row, current_identity=identities[row.node_id] if row.node_id else global_identity)
                in {"red", "amber", "unknown"}
                for row in rows
            )
            return {"setup_remaining": report.remaining, "health_attention_count": issues}
    except (DatabaseError, InterfaceError):
        # Bootstrap can render before additive migrations; absence is never reported as complete.
        return {"setup_status_unavailable": True}


def current_customer(request: HttpRequest) -> dict[str, Any]:
    """
    Provide the current customer context for templates.
    Updated for new CustomerMembership model with hybrid approach.
    """
    if not getattr(request, "user", None) or not request.user.is_authenticated:
        return {"current_customer": None}

    # For staff users (staff_role is set), they don't have a "current customer" by default
    staff_role = getattr(request.user, "staff_role", None)
    if staff_role:
        # Staff can switch customer context via session (check if session exists)
        if hasattr(request, "session") and request.session:
            customer_id = request.session.get("staff_customer_context")
            if customer_id:
                from apps.customers.models import (  # Cross-app import to avoid circular dependencies  # Circular: cross-app  # noqa: PLC0415  # Deferred: avoids circular import
                    Customer,
                )

                try:
                    customer = Customer.objects.get(id=customer_id)
                    return {"current_customer": customer}
                except Customer.DoesNotExist:
                    pass
        return {"current_customer": None}

    # For customer users, get their primary customer
    primary_customer = getattr(request.user, "primary_customer", None)
    return {"current_customer": primary_customer}


def navigation_dropdowns(request: HttpRequest) -> dict[str, Any]:
    """Navigation dropdown items for the header"""
    if not request.user.is_authenticated:
        return {}

    # Staff/Admin Navigation Items
    if request.user.is_staff_user:
        business_items = [
            {"text": "Customers", "url": "/customers/", "icon": "users"},
            {"text": "Products", "url": "/products/", "icon": "orders"},
            {"text": "Orders", "url": "/orders/", "icon": "clipboard"},
            {"text": "Promotions", "url": "/promotions/admin/", "icon": "gift"},
            {"divider": True},
            {"text": "Invoices", "url": "/billing/invoices/", "icon": "receipt"},
            {"text": "Services", "url": "/provisioning/services/", "icon": "services"},
            {"text": "Domains", "url": "/domains/", "icon": "globe"},
            {"divider": True},
            {"text": "Virtualmin Servers", "url": "/provisioning/virtualmin/servers/", "icon": "server"},
            {"text": "Hosting Accounts", "url": "/provisioning/virtualmin/accounts/", "icon": "building"},
            {"divider": True},
            {"text": "Registrars", "url": "/domains/admin/registrars/", "icon": "building"},
            {"text": "TLD Management", "url": "/domains/admin/tlds/", "icon": "globe"},
            {"divider": True},
            {"text": "Infrastructure", "url": "/infrastructure/", "icon": "server"},
        ]

        support_items = [
            {"text": "All Tickets", "url": "/tickets/", "icon": "chat"},
            {"text": "Create Ticket", "url": "/tickets/create/", "icon": "plus"},
            {"divider": True},
            {"text": "System Settings", "url": "/settings/", "icon": "settings"},
            {"text": "GDPR Management", "url": "/audit/gdpr_management/", "icon": "lock"},
            {"text": "Audit Management", "url": "/audit/management/", "icon": "chart"},
            {"text": "Audit Logs", "url": "/audit/logs/", "icon": "chart"},
        ]

        return {
            "business_items": business_items,
            "support_items": support_items,
        }

    # Customer User Navigation Items
    elif getattr(request.user, "is_customer_user", False):
        customer_items = [
            {"text": "My Orders", "url": "/orders/", "icon": "clipboard"},
            {"text": "My Invoices", "url": "/billing/invoices/", "icon": "receipt"},
            {"divider": True},
            {"text": "My Services", "url": "/provisioning/services/", "icon": "services"},
            {"text": "My Domains", "url": "/domains/", "icon": "globe"},
        ]

        customer_support_items = [
            {"text": "My Tickets", "url": "/tickets/", "icon": "chat"},
            {"text": "New Ticket", "url": "/tickets/create/", "icon": "plus"},
            {"divider": True},
            {"text": "Knowledge Base", "url": "/help/", "icon": "document"},
        ]

        return {
            "customer_items": customer_items,
            "customer_support_items": customer_support_items,
        }

    return {}


def csp_nonce(request: HttpRequest) -> dict[str, str]:
    """CSP nonce for inline scripts/styles.

    Usage in templates: <script nonce="{{ csp_nonce }}">...</script>
    Requires CSPNonceMiddleware to be active.
    """
    return {"csp_nonce": getattr(request, "csp_nonce", "")}


def default_currency(request: HttpRequest) -> dict[str, str]:
    """The default selling currency, which legacy single-currency prices on staff pages are in."""
    from apps.billing.currency_service import default_selling_currency  # noqa: PLC0415  # ADR-0007

    return {"default_currency": default_selling_currency()}


def gdpr_compliance(request: HttpRequest) -> dict[str, Any]:
    """GDPR compliance context"""
    # Check if session exists (for test environments)
    consent_required = True  # Default to requiring consent
    if hasattr(request, "session") and request.session:
        consent_required = not request.session.get("gdpr_consent", False)

    return {
        "gdpr": {
            "consent_required": consent_required,
            "privacy_policy_url": "/privacy-policy/",
            "data_processing_url": "/data-processing/",
            "cookie_policy_url": "/cookie-policy/",
        }
    }
