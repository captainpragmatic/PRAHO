"""
Rate limiting key functions for user authentication endpoints.

Provides intelligent rate limiting that tracks authenticated users
by user ID and anonymous users by IP address.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from apps.common.request_ip import get_safe_client_ip

if TYPE_CHECKING:
    from django.http import HttpRequest


def user_or_ip(group: str, request: HttpRequest) -> str:
    """
    Rate limiting key that uses user ID for authenticated users
    and secure IP address for anonymous users.

    This prevents authenticated users from being rate limited
    by sharing IP addresses (e.g., office networks) while
    still providing protection against anonymous abuse.
    """
    if request.user.is_authenticated:
        return f"user:{request.user.pk}"
    return f"ip:{get_safe_client_ip(request)}"
