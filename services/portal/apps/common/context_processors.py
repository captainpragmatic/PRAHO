"""
Context processors for PRAHO Portal Service
"""

import logging

from django.http import HttpRequest
from django.utils.translation import gettext as _

from apps.common.account_health import get_account_health
from apps.common.decorators import BILLING_ROLES, _get_selected_customer_id
from apps.common.localisation_services import get_company_identity

logger = logging.getLogger(__name__)


def csp_nonce(request: HttpRequest) -> dict[str, str]:
    """CSP nonce for inline scripts/styles.

    Usage in templates: <script nonce="{{ csp_nonce }}">...</script>
    Requires CSPNonceMiddleware to be active.
    """
    return {"csp_nonce": getattr(request, "csp_nonce", "")}


def company_identity(request: HttpRequest) -> dict[str, object]:
    """Supply the validated public identity, including during Platform outages."""
    return {"company": get_company_identity()}


def _billing_nav_locked(request: HttpRequest) -> str:
    """Why the Billing menu is unavailable, or "" when it isn't (or the role isn't known yet).

    Reads the role from the session's cached memberships, never the API: this runs on every page. An unknown role
    leaves the link alone; the billing views still check it (require_billing_access).
    """
    customer_id = str(_get_selected_customer_id(request))  # the company the billing views check
    for membership in request.session.get("user_memberships", []) or []:
        if str(membership.get("customer_id")) == customer_id:
            if membership.get("role") not in BILLING_ROLES:
                return _("Only owners and billing members can open billing.")
            return ""
    return ""


def portal_context(request: HttpRequest) -> dict[str, object]:
    """Add portal-specific context and authenticated account navigation to templates."""
    context: dict[str, object] = {
        "portal_version": "1.0.0",
        "is_portal": True,
    }

    # Account health banner — only for authenticated users with a session
    if request.session.get("customer_id") and request.session.get("user_id"):
        context["account_status_authenticated"] = bool(getattr(request, "customer_id", None))
        try:
            context["account_banner"] = get_account_health(request)
            context["maintenance_unavailable"] = getattr(request, "maintenance_unavailable", False)
        except Exception as e:
            logger.warning("⚠️ [ContextProcessor] Account health check failed: %s", e)

        context["billing_nav_locked"] = _billing_nav_locked(request)

        # "My Account" nav dropdown items — available on every authenticated page
        context["account_menu_items"] = [
            {"url": "/profile/", "text": _("Account Settings"), "icon": "settings"},
            {"url": "/mfa/", "text": _("Security"), "icon": "lock"},
            {"divider": True},
            {"url": "/company/", "text": _("Company Profile"), "icon": "building"},
            {"url": "/company/team/", "text": _("Team Members"), "icon": "users"},
            {"url": "/company/addresses/", "text": _("Addresses"), "icon": "map-pin"},
            {"divider": True},
            {"url": "/privacy/", "text": _("Privacy"), "icon": "lock"},
        ]

    return context
