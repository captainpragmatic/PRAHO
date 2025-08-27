"""
Security decorators for PRAHO Platform
Provides role-based access control decorators for views.
"""

from collections.abc import Callable
from functools import wraps
from typing import Any

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.utils.translation import gettext_lazy as _

from apps.users.models import User


def staff_required(view_func: Callable[..., HttpResponse]) -> Callable[..., HttpResponse]:
    """
    Decorator that requires user to be staff (is_staff=True or staff_role is not None)
    This is the primary security check for staff-only functionality.
    """
    @wraps(view_func)
    @login_required  # Ensure user is logged in first
    def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        user = request.user
        
        # Check if user is staff (either Django is_staff or has staff_role)
        if not (user.is_staff or bool(getattr(user, 'staff_role', ''))):
            messages.error(request, _("❌ Access denied. Staff privileges required."))
            return redirect('dashboard')
        
        return view_func(request, *args, **kwargs)
    
    return wrapper


def admin_required(view_func: Callable[..., HttpResponse]) -> Callable[..., HttpResponse]:
    """
    Decorator that requires user to be admin (staff_role='admin' or is_superuser)
    For the highest level administrative functions.
    """
    @wraps(view_func)
    @login_required
    def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        user = request.user
        
        # Check if user is admin
        if not (user.is_superuser or getattr(user, 'staff_role', '') == 'admin'):
            messages.error(request, _("❌ Access denied. Administrator privileges required."))
            return redirect('dashboard')
        
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
        allowed_roles = ['admin', 'billing', 'manager']
        if not (user.is_superuser or getattr(user, 'staff_role', '') in allowed_roles):
            messages.error(request, _("❌ Access denied. Billing staff privileges required."))
            return redirect('dashboard')
        
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
        allowed_roles = ['admin', 'support', 'manager']
        if not (user.is_superuser or getattr(user, 'staff_role', '') in allowed_roles):
            messages.error(request, _("❌ Access denied. Support staff privileges required."))
            return redirect('dashboard')
        
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
        if (hasattr(user, 'is_staff') and user.is_staff) or \
           bool(getattr(user, 'staff_role', '')) or \
           (user.is_authenticated and hasattr(user, 'is_customer_user') and user.is_customer_user):
            return view_func(request, *args, **kwargs)
        
        messages.error(request, _("❌ Access denied. Please contact support for account access."))
        return redirect('dashboard')
    
    return wrapper


def can_edit_proforma(user: User, proforma: Any) -> bool:
    """
    Business logic check for proforma editing permissions.
    Only staff can edit proformas - customers can only view them.
    """
    # Only staff can edit proformas
    if not (user.is_staff or bool(getattr(user, 'staff_role', ''))):
        return False
    
    # Staff can edit non-expired proformas
    return not proforma.is_expired


def can_create_internal_notes(user: User) -> bool:
    """
    Business logic check for creating internal notes in tickets.
    Only staff can create internal notes.
    """
    return user.is_staff or bool(getattr(user, 'staff_role', ''))


def can_view_internal_notes(user: User) -> bool:
    """
    Business logic check for viewing internal notes in tickets.
    Only staff can view internal notes.
    """
    return user.is_staff or bool(getattr(user, 'staff_role', ''))


def can_manage_financial_data(user: User) -> bool:
    """
    Business logic check for managing financial data (payments, pricing, etc.).
    Only billing staff and admins can manage financial data.
    """
    allowed_roles = ['admin', 'billing', 'manager']
    return user.is_superuser or getattr(user, 'staff_role', '') in allowed_roles


def can_access_admin_functions(user: User) -> bool:
    """
    Business logic check for accessing administrative functions.
    Only admins and managers can access admin functions.
    """
    allowed_roles = ['admin', 'manager']
    return user.is_superuser or getattr(user, 'staff_role', '') in allowed_roles
