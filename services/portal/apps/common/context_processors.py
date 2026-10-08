"""
Context processors for PRAHO Portal Service
"""

import logging

from django.http import HttpRequest
from django.utils.translation import gettext as _

from apps.common.account_health import get_account_health
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


def portal_context(request: HttpRequest) -> dict[str, object]:
    """Add portal-specific context and authenticated account navigation to templates."""
    context: dict[str, object] = {
        "portal_version": "1.0.0",
        "is_portal": True,
    }

    # Account health banner — only for authenticated users with a session
    if request.session.get("customer_id") and request.session.get("user_id"):
        try:
            context["account_banner"] = get_account_health(request)
        except Exception as e:
            logger.warning("⚠️ [ContextProcessor] Account health check failed: %s", e)

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
