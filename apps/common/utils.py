"""
Common utilities for PRAHO Platform
Shared helper functions and decorators.
"""

import hashlib
import re
import secrets
from collections.abc import Callable
from datetime import datetime
from decimal import Decimal
from functools import wraps
from typing import Any

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse, JsonResponse
from django.utils.translation import gettext_lazy as _

# ===============================================================================
# ROMANIAN VALIDATION UTILITIES
# ===============================================================================

def validate_romanian_phone(phone: str) -> bool:
    """Validate Romanian phone number format (deprecated - use apps.common.types.validate_romanian_phone)"""
    from apps.common.types import validate_romanian_phone as new_validator
    result = new_validator(phone)
    return result.is_ok()


def format_romanian_phone(phone: str) -> str:
    """Format phone number to Romanian standard"""
    # Remove all non-digits
    digits = re.sub(r'\D', '', phone)

    # Handle different input formats
    if digits.startswith('40') and len(digits) == 11:
        # +40XXXXXXXXX -> +40.XX.XXX.XXXX
        return f"+40.{digits[2:4]}.{digits[4:7]}.{digits[7:]}"
    elif digits.startswith('07') and len(digits) == 10:
        # 07XXXXXXXX -> +40.7X.XXX.XXXX
        return f"+40.{digits[1:3]}.{digits[3:6]}.{digits[6:]}"

    return phone  # Return original if can't format


def calculate_romanian_vat(amount: Decimal, vat_rate: int = 19) -> dict[str, Decimal]:
    """Calculate Romanian VAT breakdown"""
    vat_multiplier = Decimal(vat_rate) / Decimal(100)

    # Amount includes VAT
    amount_without_vat = amount / (Decimal(1) + vat_multiplier)
    vat_amount = amount - amount_without_vat

    return {
        'amount_without_vat': amount_without_vat.quantize(Decimal('0.01')),
        'vat_amount': vat_amount.quantize(Decimal('0.01')),
        'amount_with_vat': amount,
        'vat_rate': vat_rate,
    }


# ===============================================================================
# SECURITY UTILITIES
# ===============================================================================

def generate_secure_token(length: int = 32) -> str:
    """Generate cryptographically secure token"""
    return secrets.token_urlsafe(length)


def hash_sensitive_data(data: str) -> str:
    """Hash sensitive data for logging/storage"""
    salt = getattr(settings, 'SECRET_KEY', 'default-salt')
    return hashlib.sha256(f"{data}{salt}".encode()).hexdigest()


def mask_sensitive_data(data: str, show_last: int = 4) -> str:
    """Mask sensitive data for display"""
    if len(data) <= show_last:
        return '*' * len(data)

    return '*' * (len(data) - show_last) + data[-show_last:]


# ===============================================================================
# DECORATORS
# ===============================================================================

def require_permission(permission: str):
    """Decorator to require specific permission"""
    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        @login_required
        def wrapper(request, *args, **kwargs):
            if not request.user.has_perm(permission):
                raise PermissionDenied(f"Permission required: {permission}")
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def require_role(role: str):
    """Decorator to require specific user role"""
    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        @login_required
        def wrapper(request, *args, **kwargs):
            user_role = getattr(request.user, 'role', 'user')
            if user_role != role and not request.user.is_superuser:
                raise PermissionDenied(f"Role required: {role}")
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def api_require_permission(permission: str):
    """API decorator to require permission and return JSON error"""
    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        @login_required
        def wrapper(request, *args, **kwargs):
            if not request.user.has_perm(permission):
                return JsonResponse({
                    'error': True,
                    'message': f'Permission required: {permission}',
                    'code': 'PERMISSION_DENIED'
                }, status=403)
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


# ===============================================================================
# DATE/TIME UTILITIES
# ===============================================================================

def get_romanian_now() -> datetime:
    """Get current time in Romanian timezone"""
    from zoneinfo import ZoneInfo
    return datetime.now(ZoneInfo('Europe/Bucharest'))


def format_romanian_date(dt: datetime) -> str:
    """Format date in Romanian style: DD.MM.YYYY"""
    return dt.strftime('%d.%m.%Y')


def format_romanian_datetime(dt: datetime) -> str:
    """Format datetime in Romanian style: DD.MM.YYYY HH:MM"""
    return dt.strftime('%d.%m.%Y %H:%M')


# ===============================================================================
# BUSINESS LOGIC HELPERS
# ===============================================================================

def generate_invoice_number(year: int | None = None) -> str:
    """Generate Romanian invoice number format"""
    if year is None:
        year = get_romanian_now().year

    # Format: YYYY-000001 (sequential per year)
    from apps.billing.models import Invoice

    # Get next invoice number for this year
    last_invoice = Invoice.objects.filter(
        invoice_number__startswith=f"{year}-"
    ).order_by('invoice_number').last()

    if last_invoice:
        last_num = int(last_invoice.invoice_number.split('-')[1])
        next_num = last_num + 1
    else:
        next_num = 1

    return f"{year}-{next_num:06d}"


def calculate_due_date(invoice_date: datetime, payment_terms: int = 30) -> datetime:
    """Calculate invoice due date"""
    from datetime import timedelta
    return invoice_date + timedelta(days=payment_terms)


# ===============================================================================
# RESPONSE HELPERS
# ===============================================================================

def json_success(data: Any = None, message: str = "Success") -> JsonResponse:
    """Standard JSON success response"""
    response_data = {
        'success': True,
        'message': message,
    }

    if data is not None:
        response_data['data'] = data

    return JsonResponse(response_data)


def json_error(message: str, code: str = "ERROR", status: int = 400) -> JsonResponse:
    """Standard JSON error response"""
    return JsonResponse({
        'success': False,
        'error': True,
        'message': message,
        'code': code,
    }, status=status)


# ===============================================================================
# MAINTENANCE MODE
# ===============================================================================

def maintenance_mode_check(view_func: Callable) -> Callable:
    """Check if system is in maintenance mode"""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if getattr(settings, 'MAINTENANCE_MODE', False) and not request.user.is_staff:
            return HttpResponse(
                _("System is under maintenance. Please try again later."),
                status=503
            )
        return view_func(request, *args, **kwargs)
    return wrapper
