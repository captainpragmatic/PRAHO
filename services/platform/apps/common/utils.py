"""
Common utilities for PRAHO Platform
Shared helper functions and decorators.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Callable
from datetime import datetime, timedelta
from decimal import Decimal
from functools import wraps
from typing import Any, TypedDict, TypeVar
from zoneinfo import ZoneInfo

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.translation import gettext_lazy as _

# Type variable for function decorators
F = TypeVar("F", bound=Callable[..., Any])

# Import for VAT calculation - handle potential circular import gracefully
new_calculator: Callable[[int, bool], dict[str, float]] | None
try:
    from apps.common.types import calculate_romanian_vat as new_calculator
except ImportError:
    new_calculator = None

# ===============================================================================
# ROMANIAN VALIDATION UTILITIES
# ===============================================================================


class VATCalculation(TypedDict):
    """Type definition for VAT calculation results"""

    amount_without_vat: Decimal
    vat_amount: Decimal
    amount_with_vat: Decimal
    vat_rate: int


def calculate_romanian_vat(amount: Decimal, vat_rate: int = 19) -> VATCalculation:
    """Calculate Romanian VAT breakdown (deprecated - use apps.common.types.calculate_romanian_vat)"""
    if new_calculator is None:
        # Fallback implementation in case of circular import
        vat_amount = amount * Decimal(vat_rate) / Decimal("119")  # 19% VAT included
        amount_without_vat = amount - vat_amount
        return VATCalculation(
            amount_without_vat=amount_without_vat,
            vat_amount=vat_amount,
            amount_with_vat=amount,
            vat_rate=vat_rate,
        )

    # Convert to cents-based calculation for precision
    amount_cents = int(amount * 100)
    result = new_calculator(amount_cents, include_vat=True)  # type: ignore[call-arg]

    return VATCalculation(
        amount_without_vat=Decimal(result["base_amount"]) / 100,
        vat_amount=Decimal(result["vat_amount"]) / 100,
        amount_with_vat=Decimal(result["total_amount"]) / 100,
        vat_rate=vat_rate,
    )


# ===============================================================================
# SECURITY UTILITIES
# ===============================================================================


def generate_secure_token(length: int = 32) -> str:
    """Generate cryptographically secure token"""
    return secrets.token_urlsafe(length)


def hash_sensitive_data(data: str) -> str:
    """Hash sensitive data for logging/storage"""
    salt = getattr(settings, "SECRET_KEY", "default-salt")
    return hashlib.sha256(f"{data}{salt}".encode()).hexdigest()


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


def format_romanian_date(dt: datetime) -> str:
    """Format date in Romanian style: DD.MM.YYYY"""
    return dt.strftime("%d.%m.%Y")


def format_romanian_datetime(dt: datetime) -> str:
    """Format datetime in Romanian style: DD.MM.YYYY HH:MM"""
    return dt.strftime("%d.%m.%Y %H:%M")


# ===============================================================================
# BUSINESS LOGIC HELPERS
# ===============================================================================


def generate_invoice_number(year: int | None = None) -> str:
    """Generate Romanian invoice number format"""
    if year is None:
        year = get_romanian_now().year

    # Format: YYYY-000001 (sequential per year)
    from apps.billing.models import Invoice  # Cross-app import to avoid circular dependencies  # noqa: PLC0415

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


# ===============================================================================
# MAINTENANCE MODE
# ===============================================================================


def maintenance_mode_check(view_func: Callable[..., Any]) -> Callable[..., Any]:
    """Check if system is in maintenance mode"""

    @wraps(view_func)
    def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
        if getattr(settings, "MAINTENANCE_MODE", False) and not request.user.is_staff:
            return HttpResponse(_("System is under maintenance. Please try again later."), status=503)
        return view_func(request, *args, **kwargs)

    return wrapper
