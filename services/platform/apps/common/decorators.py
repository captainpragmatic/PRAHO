"""
Security decorators for PRAHO Platform
Provides role-based access control decorators for views.
"""

import logging
from collections.abc import Callable
from functools import wraps
from typing import Any

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse, HttpResponseForbidden, HttpResponseRedirect
from django.shortcuts import redirect
from django.utils.translation import gettext_lazy as _

from apps.users.models import User

logger = logging.getLogger(__name__)


def _build_login_url(request: HttpRequest) -> str:
    """Build login URL with optional return path."""
    login_url = "/users/login/"
    full_path_getter = getattr(request, "get_full_path", None)
    if callable(full_path_getter):
        try:
            login_url += f"?next={full_path_getter()}"
        except (TypeError, ValueError):
            logger.debug("Could not append next parameter to login URL")
    return login_url


def staff_required(view_func: Callable[..., HttpResponse]) -> Callable[..., HttpResponse]:
    """
    Decorator that requires user to be staff (is_staff=True or staff_role is not None)
    This is the primary security check for staff-only functionality.
    """

    @wraps(view_func)
    def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        # Unauthenticated -> login redirect
        if not request.user.is_authenticated:
            return HttpResponseRedirect(_build_login_url(request))

        user = request.user
        # Authenticated but non-staff -> redirect to dashboard with message (orders tests)
        if not (user.is_staff or bool(getattr(user, "staff_role", "")) or getattr(user, "is_superuser", False)):
            messages.error(request, _("❌ Access denied. Staff privileges required."))
            return redirect("dashboard")

        return view_func(request, *args, **kwargs)

    return wrapper


def admin_required(view_func: Callable[..., HttpResponse]) -> Callable[..., HttpResponse]:
    """
    Decorator that requires user to be admin (staff_role='admin' or is_superuser)
    For the highest level administrative functions.
    """

    @wraps(view_func)
    def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        if not request.user.is_authenticated:
            return HttpResponseRedirect(_build_login_url(request))

        user = request.user
        # Check if user is admin
        if not (user.is_superuser or getattr(user, "staff_role", "") == "admin"):
            return HttpResponseForbidden("Administrator privileges required")

        return view_func(request, *args, **kwargs)

    return wrapper


def staff_required_strict(view_func: Callable[..., HttpResponse]) -> Callable[..., HttpResponse]:
    """Strict staff-only: unauthenticated -> login; non-staff -> 403."""

    @wraps(view_func)
    def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        if not request.user.is_authenticated:
            return HttpResponseRedirect(_build_login_url(request))

        user = request.user
        if not (user.is_staff or bool(getattr(user, "staff_role", "")) or getattr(user, "is_superuser", False)):
            return HttpResponseForbidden("Staff privileges required")

        return view_func(request, *args, **kwargs)

    return wrapper


def billing_staff_required(view_func: Callable[..., HttpResponse]) -> Callable[..., HttpResponse]:
    """
    Decorator that requires user to be billing staff or admin
    For financial operations and billing management.
    """

    @wraps(view_func)
    @login_required
    def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        user = request.user

        # Check if user has billing privileges
        allowed_roles = ["admin", "billing", "manager"]
        if not (user.is_superuser or getattr(user, "staff_role", "") in allowed_roles):
            messages.error(request, _("❌ Access denied. Billing staff privileges required."))
            return redirect("dashboard")

        return view_func(request, *args, **kwargs)

    return wrapper


def support_staff_required(view_func: Callable[..., HttpResponse]) -> Callable[..., HttpResponse]:
    """
    Decorator that requires user to be support staff or admin
    For customer support and ticket management.
    """

    @wraps(view_func)
    @login_required
    def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        user = request.user

        # Check if user has support privileges
        allowed_roles = ["admin", "support", "manager"]
        if not (user.is_superuser or getattr(user, "staff_role", "") in allowed_roles):
            messages.error(request, _("❌ Access denied. Support staff privileges required."))
            return redirect("dashboard")

        return view_func(request, *args, **kwargs)

    return wrapper


def customer_or_staff_required(view_func: Callable[..., HttpResponse]) -> Callable[..., HttpResponse]:
    """
    Decorator that allows both customers and staff access
    Used for views that can be accessed by both user types but with different permissions.
    The view itself should handle the different permission levels.
    """

    @wraps(view_func)
    @login_required
    def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        user = request.user

        # Allow access if user is either staff or has customer memberships
        # Check if user is authenticated and has the required attributes
        # Type guard: AnonymousUser doesn't have is_customer_user attribute
        if (
            (hasattr(user, "is_staff") and user.is_staff)
            or bool(getattr(user, "staff_role", ""))
            or (user.is_authenticated and hasattr(user, "is_customer_user") and user.is_customer_user)
        ):
            return view_func(request, *args, **kwargs)

        messages.error(request, _("❌ Access denied. Please contact support for account access."))
        return redirect("dashboard")

    return wrapper


def can_edit_proforma(user: User, proforma: Any) -> bool:
    """
    Business logic check for proforma editing permissions.
    Only staff can edit proformas - customers can only view them.
    """
    # Only staff can edit proformas
    if not (user.is_staff or bool(getattr(user, "staff_role", ""))):
        return False

    # Staff can edit non-expired proformas
    return not proforma.is_expired


def can_create_internal_notes(user: User) -> bool:
    """
    Business logic check for creating internal notes in tickets.
    Only staff can create internal notes.
    """
    return user.is_staff or bool(getattr(user, "staff_role", ""))


def can_view_internal_notes(user: User) -> bool:
    """
    Business logic check for viewing internal notes in tickets.
    Only staff can view internal notes.
    """
    return user.is_staff or bool(getattr(user, "staff_role", ""))


def can_manage_financial_data(user: User) -> bool:
    """
    Business logic check for managing financial data (payments, pricing, etc.).
    Only billing staff and admins can manage financial data.
    Must be staff AND have appropriate role (or be superuser).
    """
    if user.is_superuser:
        return True

    if not user.is_staff:
        return False

    allowed_roles = ["admin", "billing", "manager"]
    return getattr(user, "staff_role", "") in allowed_roles


def can_access_admin_functions(user: User) -> bool:
    """
    Business logic check for accessing administrative functions.
    Only admins and managers can access admin functions.
    """
    allowed_roles = ["admin", "manager"]
    return user.is_superuser or getattr(user, "staff_role", "") in allowed_roles


def rate_limit(
    requests_per_minute: int = 10, per_user: bool = True, block_anonymous: bool = True
) -> Callable[[Callable[..., HttpResponse]], Callable[..., HttpResponse]]:
    """
    🔒 Rate limiting decorator to prevent abuse of sensitive operations

    Protects against:
    - DoS attacks through rapid requests
    - Brute force attempts on form submissions
    - Resource exhaustion from file uploads

    Args:
        requests_per_minute: Maximum requests allowed per minute (default: 10)
        per_user: If True, limits per authenticated user; if False, limits per IP
        block_anonymous: If True, blocks all anonymous users (default: True)

    Usage:
        @rate_limit(5, per_user=True)  # 5 requests/minute per user
        @rate_limit(20, per_user=False)  # 20 requests/minute per IP
    """

    def decorator(view_func: Callable[..., HttpResponse]) -> Callable[..., HttpResponse]:
        @wraps(view_func)
        def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
            # Block anonymous users if required
            if block_anonymous and not request.user.is_authenticated:
                logger.warning(f"🚨 [Rate Limit] Anonymous user blocked from {request.path}")
                response = HttpResponse("Authentication required", status=429)
                response["Retry-After"] = "60"
                return response

            # Determine rate limit key
            if per_user and request.user.is_authenticated:
                # Rate limit per authenticated user
                rate_key = f"rate_limit_user_{request.user.id}_{view_func.__name__}"
                identifier = f"user {request.user.email}"
            else:
                # Rate limit per IP address
                client_ip = request.META.get("HTTP_X_FORWARDED_FOR", "").split(",")[0].strip()
                if not client_ip:
                    client_ip = request.META.get("REMOTE_ADDR", "unknown")
                rate_key = f"rate_limit_ip_{client_ip}_{view_func.__name__}"
                identifier = f"IP {client_ip}"

            # Get current request count
            current_requests = cache.get(rate_key, 0)

            # Check if rate limit exceeded
            if current_requests >= requests_per_minute:
                logger.warning(
                    f"🚨 [Rate Limit] {identifier} exceeded limit "
                    f"({current_requests}/{requests_per_minute} req/min) for {view_func.__name__}"
                )

                # Return rate limit response
                response = HttpResponse(
                    f"Rate limit exceeded. Maximum {requests_per_minute} requests per minute allowed.", status=429
                )
                response["Retry-After"] = "60"  # Suggest retry after 60 seconds
                return response

            # Increment request count (expire after 60 seconds)
            cache.set(rate_key, current_requests + 1, 60)

            # Log rate limit usage for monitoring
            if current_requests + 1 >= requests_per_minute * 0.8:  # Warn at 80% threshold
                logger.info(
                    f"⚠️ [Rate Limit] {identifier} approaching limit "
                    f"({current_requests + 1}/{requests_per_minute}) for {view_func.__name__}"
                )

            return view_func(request, *args, **kwargs)

        return wrapper

    return decorator
