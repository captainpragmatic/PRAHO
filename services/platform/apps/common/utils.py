"""
Common utilities for PRAHO Platform
Shared helper functions and decorators.
"""

from __future__ import annotations

import hmac
import secrets
from collections.abc import Callable
from datetime import date, datetime, timedelta
from functools import wraps
from typing import Any, TypeVar

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest, JsonResponse
from django.utils import timezone

# Type variable for function decorators
F = TypeVar("F", bound=Callable[..., Any])

# ===============================================================================
# SECURITY UTILITIES
# ===============================================================================


def generate_secure_token(length: int = 32) -> str:
    """Generate cryptographically secure token"""
    return secrets.token_urlsafe(length)


def hash_sensitive_data(data: str) -> str:
    """Hash sensitive data for logging/storage using HMAC-SHA256."""
    from apps.common.key_derivation import get_key_hex  # noqa: PLC0415

    key = get_key_hex("sensitive-data-hash")
    return hmac.new(key.encode(), data.encode(), "sha256").hexdigest()


def mask_sensitive_data(data: str, show_last: int = 4) -> str:
    """Mask sensitive data for display"""
    if len(data) <= show_last:
        return "*" * len(data)

    return "*" * (len(data) - show_last) + data[-show_last:]


# ===============================================================================
# DECORATORS
# ===============================================================================


def require_permission(permission: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator to require specific permission"""

    def decorator(view_func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(view_func)
        @login_required
        def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
            if not request.user.has_perm(permission):
                raise PermissionDenied(f"Permission required: {permission}")
            return view_func(request, *args, **kwargs)

        return wrapper

    return decorator


def require_role(role: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator to require specific user role"""

    def decorator(view_func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(view_func)
        @login_required
        def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
            user_role = getattr(request.user, "role", "user")
            if user_role != role and not request.user.is_superuser:
                raise PermissionDenied(f"Role required: {role}")
            return view_func(request, *args, **kwargs)

        return wrapper

    return decorator


def api_require_permission(permission: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """API decorator to require permission and return JSON error"""

    def decorator(view_func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(view_func)
        @login_required
        def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
            if not request.user.has_perm(permission):
                return JsonResponse(
                    {"error": True, "message": f"Permission required: {permission}", "code": "PERMISSION_DENIED"},
                    status=403,
                )
            return view_func(request, *args, **kwargs)

        return wrapper

    return decorator


# ===============================================================================
# DATE/TIME UTILITIES
# ===============================================================================


def operator_local_date(dt: datetime) -> date:
    """The operator's calendar day for an aware instant, in TIME_ZONE whatever zone is active.

    With USE_TZ=True the ORM hands back aware datetimes in UTC, so `.date()` is the UTC day, the
    PREVIOUS day for anything just after the operator's midnight. Billing periods and document
    dates are the operator's day (#220, #286). A Romanian operator runs on Bucharest time
    (prod.py), so this is also the day the e-Factura XML carries. It reads the configured zone,
    not the active one, so a user's activated timezone never moves a document's date.
    """
    return timezone.localdate(dt, timezone.get_default_timezone())


def format_document_date(dt: datetime) -> str:
    """A document date as the operator's calendar day, DD.MM.YYYY (invoice PDFs, emails).

    A naive datetime carries no zone to convert from, so it is formatted as given rather than
    assumed to be UTC: callers holding an already-local wall clock keep working.
    """
    return (operator_local_date(dt) if timezone.is_aware(dt) else dt).strftime("%d.%m.%Y")


# ===============================================================================
# BUSINESS LOGIC HELPERS
# ===============================================================================


def calculate_due_date(invoice_date: datetime, payment_terms: int = 30) -> datetime:
    """Calculate invoice due date"""
    return invoice_date + timedelta(days=payment_terms)


# ===============================================================================
# RESPONSE HELPERS
# ===============================================================================


def json_success(data: Any | None = None, message: str = "Success") -> JsonResponse:
    """Standard JSON success response"""
    response_data = {
        "success": True,
        "message": message,
    }

    if data is not None:
        response_data["data"] = data

    return JsonResponse(response_data)


def json_error(message: str, code: str = "ERROR", status: int = 400) -> JsonResponse:
    """Standard JSON error response"""
    return JsonResponse(
        {
            "success": False,
            "error": True,
            "message": message,
            "code": code,
        },
        status=status,
    )
