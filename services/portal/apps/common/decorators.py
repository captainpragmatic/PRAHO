"""
Access Control Decorators for PRAHO Portal
Comprehensive role-based access control and authentication verification.
"""

import logging
from collections.abc import Callable
from functools import wraps
from typing import Any

from django.http import HttpRequest, HttpResponse, HttpResponseForbidden, JsonResponse
from django.shortcuts import redirect
from django.utils import timezone
from django.utils.translation import gettext as _

from apps.api_client.services import PlatformAPIError, api_client

logger = logging.getLogger(__name__)


def _get_selected_customer_id(request: HttpRequest) -> str | None:
    """Get the currently selected customer ID, fallback to session customer_id"""
    selected_customer_id = request.session.get('selected_customer_id')
    if selected_customer_id:
        return selected_customer_id

    # Fallback to login customer_id for backward compatibility
    return request.session.get('customer_id')


def _get_user_role_for_customer(request: HttpRequest, customer_id: str) -> str | None:
    """Get user's role for specific customer from cached memberships"""
    memberships = request.session.get('user_memberships', [])
    for membership in memberships:
        if str(membership.get('customer_id')) == str(customer_id):
            return membership.get('role')
    return None


def _verify_customer_access_realtime(request: HttpRequest, customer_id: str) -> dict | None:
    """🔒 Real-time verification of user access to customer via Platform API"""
    user_id = request.session.get('user_id')
    if not user_id:
        return None

    try:
        response = api_client.post('users/verify-customer-access/', {
            'user_id': user_id,
            'customer_id': customer_id,
            'timestamp': int(timezone.now().timestamp())
        }, user_id=user_id)

        if response and response.get('success'):
            return {
                'has_access': response.get('has_access', False),
                'role': response.get('role', 'viewer'),
                'permissions': response.get('permissions', [])
            }
        return None

    except PlatformAPIError as e:
        logger.error(f"🔥 [Security] Failed to verify customer access: {e}")
        return None


def require_authentication(view_func: Callable) -> Callable:
    """🔒 Require user to be authenticated via Portal session"""
    @wraps(view_func)
    def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        if not request.session.get('customer_id') or not request.session.get('user_id'):
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'error': _('Autentificare necesară')}, status=401)
            return redirect('/login/')

        return view_func(request, *args, **kwargs)
    return wrapper


def require_customer_role(required_roles: list[str] | None = None, realtime_verification: bool = False) -> Callable:
    """
    🔒 Require specific customer role(s) for access

    Args:
        required_roles: List of allowed roles ['admin', 'billing', 'technical', 'viewer']
        realtime_verification: Whether to verify access with Platform API in real-time
    """
    if required_roles is None:
        required_roles = ['viewer']  # Default minimum role

    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
            # Check basic authentication first
            if not request.session.get('customer_id') or not request.session.get('user_id'):
                if request.headers.get('Accept') == 'application/json':
                    return JsonResponse({'error': _('Autentificare necesară')}, status=401)
                return redirect('/login/')

            customer_id = _get_selected_customer_id(request)
            if not customer_id:
                logger.warning(f"🚨 [Security] No customer selected for user {request.session.get('user_id')}")
                if request.headers.get('Accept') == 'application/json':
                    return JsonResponse({'error': _('Niciun client selectat')}, status=403)
                return HttpResponseForbidden(_('Niciun client selectat'))

            # Real-time verification if requested
            if realtime_verification:
                verification = _verify_customer_access_realtime(request, customer_id)
                if not verification or not verification.get('has_access'):
                    logger.warning(
                        f"🚨 [Security] Real-time access verification failed: "
                        f"user {request.session.get('user_id')} -> customer {customer_id}"
                    )
                    if request.headers.get('Accept') == 'application/json':
                        return JsonResponse({'error': _('Acces interzis')}, status=403)
                    return HttpResponseForbidden(_('Acces interzis'))

                user_role = verification.get('role', 'viewer')
            else:
                # Use cached role from session
                user_role = _get_user_role_for_customer(request, customer_id)

            if not user_role:
                logger.warning(
                    f"🚨 [Security] No role found for user {request.session.get('user_id')} "
                    f"in customer {customer_id}"
                )
                if request.headers.get('Accept') == 'application/json':
                    return JsonResponse({'error': _('Rol inexistent')}, status=403)
                return HttpResponseForbidden(_('Rol inexistent'))

            # Check role permissions
            if user_role not in required_roles:
                logger.warning(
                    f"🚨 [Security] Insufficient permissions: user {request.session.get('user_id')} "
                    f"has role '{user_role}' but requires one of {required_roles}"
                )
                if request.headers.get('Accept') == 'application/json':
                    return JsonResponse({'error': _('Permisiuni insuficiente')}, status=403)
                return HttpResponseForbidden(_('Permisiuni insuficiente'))

            # Store current role in request for use in view
            request.user_role = user_role
            request.current_customer_id = customer_id

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def require_admin_role(realtime_verification: bool = False) -> Callable:
    """🔒 Require admin role - shortcut for admin-only views"""
    return require_customer_role(['admin'], realtime_verification)


def require_billing_access(realtime_verification: bool = False) -> Callable:
    """🔒 Require billing access - admin or billing role"""
    return require_customer_role(['admin', 'billing'], realtime_verification)


def require_technical_access(realtime_verification: bool = False) -> Callable:
    """🔒 Require technical access - admin or technical role"""
    return require_customer_role(['admin', 'technical'], realtime_verification)


def require_any_role(realtime_verification: bool = False) -> Callable:
    """🔒 Require any valid role - equivalent to authenticated user with customer access"""
    return require_customer_role(['admin', 'billing', 'technical', 'viewer'], realtime_verification)


def api_key_required(view_func: Callable) -> Callable:
    """🔒 Require valid API key for API endpoints (if implemented)"""
    @wraps(view_func)
    def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        # Future implementation for API key authentication
        # For now, require session authentication
        return require_authentication(view_func)(request, *args, **kwargs)
    return wrapper


def log_access_attempt(view_func: Callable) -> Callable:
    """🔒 Log access attempts for security monitoring"""
    @wraps(view_func)
    def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        user_id = request.session.get('user_id', 'anonymous')
        customer_id = _get_selected_customer_id(request)

        logger.info(
            f"🔍 [Access] {request.method} {request.path} - "
            f"user: {user_id}, customer: {customer_id}, "
            f"IP: {request.META.get('REMOTE_ADDR', 'unknown')}"
        )

        response = view_func(request, *args, **kwargs)

        # Log access result
        ACCESS_DENIED_STATUS_CODE = 400
        if response.status_code >= ACCESS_DENIED_STATUS_CODE:
            logger.warning(
                f"🚨 [Access] Access denied {response.status_code} - "
                f"user: {user_id}, customer: {customer_id}, path: {request.path}"
            )

        return response
    return wrapper
