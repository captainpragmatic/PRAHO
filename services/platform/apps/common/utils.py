"""
Common utilities for PRAHO Platform
Shared helper functions and decorators.
"""

from __future__ import annotations

import hmac
import secrets
from collections.abc import Callable
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, TypeVar
from zoneinfo import ZoneInfo

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


def get_romanian_now() -> datetime:
    """Get current time in Romanian timezone"""
    return datetime.now(ZoneInfo("Europe/Bucharest"))


def _to_romanian_local(dt: datetime) -> datetime:
    """Convert an aware datetime to the Romanian wall clock; pass naive datetimes through.

    With USE_TZ=True the ORM hands back aware datetimes in UTC, so formatting one directly
    renders the UTC wall clock — the PREVIOUS day for anything between 00:00 and 02:00/03:00
    Romanian time. Customer-facing dates (invoice PDFs, notification emails) must show the
    Romanian day, matching the date filed with ANAF (see #286, #220).

    The target zone is pinned to Europe/Bucharest rather than Django's active timezone:
    these helpers promise the ROMANIAN wall clock, and a future timezone.activate() with a
    user timezone must not make the PDF disagree with the e-Factura XML, whose conversion
    (apps.billing.efactura.settings.ro_local_date) is likewise pinned.

    Naive datetimes carry no timezone to convert from, so they are returned unchanged rather
    than assumed to be UTC: callers holding an already-local wall clock keep working. This is
    deliberately laxer than ro_local_date(), which raises on naive input — that helper feeds
    mandatory legal XML fields where every caller is a guaranteed-aware ORM datetime, while
    these are generic formatters with pre-existing naive-input callers in tests.
    """
    if timezone.is_aware(dt):
        return timezone.localtime(dt, ZoneInfo("Europe/Bucharest"))
    return dt


def format_romanian_date(dt: datetime) -> str:
    """Format date in Romanian style: DD.MM.YYYY"""
    return _to_romanian_local(dt).strftime("%d.%m.%Y")


def format_romanian_datetime(dt: datetime) -> str:
    """Format datetime in Romanian style: DD.MM.YYYY HH:MM"""
    return _to_romanian_local(dt).strftime("%d.%m.%Y %H:%M")


# ===============================================================================
# BUSINESS LOGIC HELPERS
# ===============================================================================


def generate_invoice_number(year: int | None = None) -> str:
    """Generate Romanian invoice number format"""
    if year is None:
        year = get_romanian_now().year

    # Format: YYYY-000001 (sequential per year)
    from apps.billing.models import (  # noqa: PLC0415  # Deferred: avoids circular import
        Invoice,  # Cross-app import to avoid circular dependencies  # Circular: cross-app
    )

    # Get next invoice number for this year
    last_invoice = Invoice.objects.filter(number__startswith=f"{year}-").order_by("number").last()

    if last_invoice:
        last_num = int(last_invoice.number.split("-")[1])
        next_num = last_num + 1
    else:
        next_num = 1

    return f"{year}-{next_num:06d}"


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
