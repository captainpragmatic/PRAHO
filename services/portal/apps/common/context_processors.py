"""
Context processors for PRAHO Portal Service
"""

import logging
from typing import Any

from django.http import HttpRequest

from apps.common.account_health import get_account_health

logger = logging.getLogger(__name__)


def csp_nonce(request: HttpRequest) -> dict[str, str]:
    """CSP nonce for inline scripts/styles.

    Usage in templates: <script nonce="{{ csp_nonce }}">...</script>
    Requires CSPNonceMiddleware to be active.
    """
    return {"csp_nonce": getattr(request, "csp_nonce", "")}


def portal_context(request: HttpRequest) -> dict[str, Any]:
    """
    Add portal-specific context to templates.
    Stateless portal - no request.user available.
    """
    context: dict[str, Any] = {
        "portal_version": "1.0.0",
        "is_portal": True,
    }

    # Check if user is authenticated via JWT cookie
    portal_token = request.COOKIES.get("portal_token")
    if portal_token:
        context.update(
            {
                "user_is_authenticated": True,
                "user_full_name": "Customer",  # Could get from token if needed
            }
        )
    else:
        context.update(
            {
                "user_is_authenticated": False,
            }
        )

    # Account health banner — only for authenticated users with a session
    if request.session.get("customer_id") and request.session.get("user_id"):
        try:
            context["account_banner"] = get_account_health(request)
        except Exception as e:
            logger.warning("⚠️ [ContextProcessor] Account health check failed: %s", e)

    return context
