"""
Context processors for PRAHO Portal Service
"""

from typing import Any

from django.http import HttpRequest


def portal_context(request: HttpRequest) -> dict[str, Any]:
    """
    Add portal-specific context to templates.
    Stateless portal - no request.user available.
    """
    context = {
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

    return context
