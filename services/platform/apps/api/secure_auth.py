# ===============================================================================
# UNIFIED SECURE API AUTHENTICATION - ANTI-ENUMERATION 🔐
# ===============================================================================

import json
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from django.http import HttpRequest, JsonResponse
from rest_framework.response import Response

from apps.customers.models import Customer
from apps.users.models import CustomerMembership, User

# Security configuration constants
HMAC_TIMESTAMP_WINDOW_SECONDS = 300  # 5 minutes

logger = logging.getLogger(__name__)


def _uniform_error_response(message: str = "Access denied", status_code: int = 403, extra_headers: dict[str, Any] | None = None) -> Response:
    """
    🔒 Uniform error response to prevent information leakage.
    
    Security headers prevent caching of error responses.
    Generic messages prevent enumeration attacks.
    """
    headers = {
        'Cache-Control': 'no-store',
        'Pragma': 'no-cache',
        'X-Content-Type-Options': 'nosniff',
    }
    if extra_headers:
        headers.update(extra_headers)
        
    return Response({
        'success': False,
        'error': message
    }, status=status_code, headers=headers)


def validate_hmac_authenticated_request(request: HttpRequest) -> tuple[dict[str, Any] | None, Response | None]:
    """
    🔒 Core HMAC authentication validation.
    
    Validates:
    1. HMAC middleware has authenticated the request
    2. Request body contains required context
    3. Timestamp freshness (5 minute window)
    
    Returns:
        (request_data_dict, error_response)
        - Success: ({"customer_id": 123, ...}, None)
        - Failure: (None, error_response)
    """
    
    # Check HMAC middleware authentication
    if not hasattr(request, '_portal_authenticated'):
        logger.warning("🔥 [API Security] Request not HMAC authenticated")
        return None, _uniform_error_response("Authentication required", 401)
    
    # Extract portal context for logging (no PII)
    portal_id = request.headers.get('X-Portal-Id', 'unknown')
    jti = request.headers.get('X-Nonce', 'unknown')[:8]  # First 8 chars only
    
    # Parse HMAC-signed request body
    try:
        request_data = request.data if hasattr(request, 'data') else json.loads(request.body)
        
        # Validate required fields
        request_timestamp = request_data.get('timestamp')
        user_id = request_data.get('user_id')
        
        # Temporary debug logging to inspect parsed body keys for troubleshooting
        # Debug noise removed after stabilization

        if not request_timestamp:
            logger.warning(f"🚨 [API Security] Portal {portal_id} missing timestamp in HMAC context")
            return None, _uniform_error_response("Invalid request format", 400)

        # Phase 1: require user_id in signed body to bind identity
        if user_id is None:
            logger.warning(f"🚨 [API Security] Portal {portal_id} missing user_id in HMAC context body")
            return None, _uniform_error_response("Invalid request format", 400)
            
        # Timestamp freshness check (within 5 minutes)
        current_time = datetime.now(UTC).timestamp()
        if abs(current_time - request_timestamp) > HMAC_TIMESTAMP_WINDOW_SECONDS:
            logger.warning(f"🚨 [API Security] Portal {portal_id} stale timestamp in HMAC context")
            return None, _uniform_error_response("Invalid request format", 400)
            
    except (json.JSONDecodeError, TypeError, AttributeError, ValueError):
        logger.warning(f"🚨 [API Security] Portal {portal_id} invalid HMAC request body format")
        return None, _uniform_error_response("Invalid request format", 400)
    
    logger.debug(f"✅ [API Security] Portal {portal_id} HMAC request validated (jti: {jti})")
    return request_data, None


def _validate_customer_exists(customer_id: str | int) -> tuple[Customer | None, Response | None]:
    """Validate that customer exists and is active"""
    try:
        customer_id = int(customer_id)
        customer = Customer.objects.get(id=customer_id, status="active")
        return customer, None
        
    except (ValueError, TypeError):
        logger.warning(f"🚨 [API Security] Invalid customer_id format in HMAC context: {customer_id}")
        return None, _uniform_error_response()
        
    except Customer.DoesNotExist:
        logger.warning(f"🚨 [API Security] Customer not found or inactive: {customer_id}")
        return None, _uniform_error_response()


def _validate_user_membership(body_user_id: str | int, customer: Customer, action: str, customer_id: int) -> tuple[bool, Response | None]:
    """Validate user membership to customer"""
    # Resolve user identity from signed body only (no header reliance)
    logger.debug(f"🔍 [API Security] Validating membership - body_user_id: {body_user_id}, customer_id: {customer_id}")
    
    try:
        resolved_user_id = int(body_user_id)
        logger.debug(f"🔍 [API Security] Resolved user_id: {resolved_user_id}")
    except (TypeError, ValueError):
        logger.warning(f"🚨 [API Security] Invalid user_id format in HMAC context: {body_user_id}")
        return False, _uniform_error_response("Authentication required", 401)

    try:
        user = User.objects.get(id=resolved_user_id, is_active=True)
        logger.debug(f"🔍 [API Security] Found user: {user.email}, is_active: {user.is_active}")
    except User.DoesNotExist:
        logger.warning(f"🚨 [API Security] User not found or inactive: {resolved_user_id}")
        return False, _uniform_error_response("Authentication required", 401)
    
    membership = CustomerMembership.objects.filter(
        user=user,
        customer=customer
    ).first()
    
    logger.debug(f"🔍 [API Security] Membership query result: {membership}")
    if membership:
        logger.debug(f"🔍 [API Security] Membership details - user: {membership.user.email}, customer: {membership.customer.company_name}")
    
    if not membership:
        logger.warning(f"🚨 [API Security] User {user.email} attempted {action} for customer {customer_id} without membership")
        return False, _uniform_error_response()  # Generic "access denied"
    
    logger.debug(f"✅ [API Security] Membership validation successful for user {user.email} -> customer {customer.company_name}")
    return True, None


def get_authenticated_customer(request: HttpRequest) -> tuple[Customer | None, Response | None]:
    """
    🔒 Get customer from HMAC-authenticated request with membership validation.
    
    This is the SINGLE authentication function for all customer APIs:
    - billing, tickets, services, users
    
    Security Features:
    - HMAC authentication required
    - Customer ID from signed request body (no URL enumeration)
    - Customer membership validation
    - Uniform error responses
    - Comprehensive audit logging
    
    Request Body Format:
    {
        "customer_id": 123,
        "action": "get_invoices",  # Optional action for logging
        "timestamp": 1699999999
    }
    
    Returns:
        (Customer object, error_response)
        - Success: (Customer, None)
        - Failure: (None, error_response)
    """
    
    # Step 1: Validate HMAC authentication
    request_data, error_response = validate_hmac_authenticated_request(request)
    if error_response or request_data is None:
        return None, error_response or _uniform_error_response()
    
    customer_id = request_data['customer_id']
    action = request_data.get('action', 'api_access')
    body_user_id = request_data.get('user_id')
    
    # Step 2: Validate customer exists
    customer, customer_error = _validate_customer_exists(customer_id)
    if customer_error or customer is None:
        return None, customer_error or _uniform_error_response()
    
    # Step 3: Validate user has membership to this customer
    # Note: For session validation, we skip this check since we're validating the user themselves
    if not request.path.endswith('/session/validate/'):
        if body_user_id is None:
            logger.warning("🔥 [API Security] Missing user_id in request body")
            return None, _uniform_error_response()
        has_membership, membership_error = _validate_user_membership(body_user_id, customer, action, customer_id)
        if not has_membership:
            return None, membership_error
    
    # Success!
    logger.debug(f"✅ [API Security] Customer {customer.company_name} authenticated for {action}")
    return customer, None


def get_authenticated_user(request: HttpRequest) -> tuple[User | None, Response | None]:
    """
    🔒 Get user from HMAC-authenticated request for session validation.
    
    Used specifically for /api/users/session/validate/ endpoint.
    Different from customer APIs - validates user directly, not customer membership.
    
    Returns:
        (User object, error_response)
        - Success: (User, None)
        - Failure: (None, error_response)
    """
    
    # Step 1: Validate HMAC authentication
    request_data, error_response = validate_hmac_authenticated_request(request)
    if error_response or request_data is None:
        return None, error_response or _uniform_error_response()
    
    # Read user identity from 'user_id' field (no legacy overloading)
    user_id_field = request_data.get('user_id')
    # Debug noise removed after stabilization
    
    # Step 2: Validate user exists and is active
    try:
        if user_id_field is None:
            logger.warning("🚨 [API Security] Missing user_id in request")
            return None, JsonResponse({"error": "Missing user_id"}, status=400)
            
        user_id = int(user_id_field)
        user = User.objects.get(id=user_id, is_active=True)
        
        logger.debug(f"✅ [API Security] User {user.email} authenticated for session validation")
        return user, None
        
    except (ValueError, TypeError):
        logger.warning(f"🚨 [API Security] Invalid user_id format in session validation: {user_id_field}")
        return None, _uniform_error_response()
        
    except User.DoesNotExist:
        logger.warning(f"🚨 [API Security] User not found or inactive: {user_id_field}")
        return None, _uniform_error_response()


# ===============================================================================
# CONVENIENCE DECORATORS FOR API VIEWS
# ===============================================================================

def require_customer_authentication(view_func: Callable[..., Any]) -> Callable[..., Any]:
    """
    🔒 Decorator for API views requiring customer authentication.
    
    Usage:
        @require_customer_authentication
        def my_api_view(request, customer):
            # customer is guaranteed to be authenticated Customer object
            return Response({"data": "success"})
    """
    def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Response:
        logger.info(f"🔧 [Auth Decorator] require_customer_authentication called for {request.path}")
        customer, error_response = get_authenticated_customer(request)
        if error_response:
            logger.warning(f"🔧 [Auth Decorator] Authentication failed for {request.path}")
            return error_response
        logger.info(f"🔧 [Auth Decorator] Authentication successful for {request.path} - Customer: {customer.company_name if customer else 'None'}")
        return view_func(request, customer, *args, **kwargs)
    return wrapper


def require_user_authentication(view_func: Callable[..., Any]) -> Callable[..., Any]:
    """
    🔒 Decorator for API views requiring user authentication (session validation).

    Usage:
        @require_user_authentication
        def session_validate_view(request, user):
            # user is guaranteed to be authenticated User object
            return Response({"active": True})
    """
    def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Response:
        user, error_response = get_authenticated_user(request)
        if error_response:
            return error_response
        return view_func(request, user, *args, **kwargs)
    return wrapper


def validate_portal_service_request(request: HttpRequest) -> tuple[dict[str, Any] | None, Response | None]:
    """
    🔒 Lighter HMAC validation for Portal-to-Platform service calls.

    KEY DIFFERENCE from validate_hmac_authenticated_request():
    This does NOT require user_id in the signed body.  This is intentional —
    GDPR cookie consent must be recordable by anonymous visitors who have
    no user account yet.  The HMAC still proves the request came from Portal
    (service-to-service auth), just without binding to a specific user.

    Validates:
    1. HMAC middleware has authenticated the request (_portal_authenticated)
    2. Request body is valid JSON with a fresh timestamp (5-min window)

    Returns:
        (request_data_dict, error_response)
    """
    if not hasattr(request, '_portal_authenticated'):
        logger.warning("🔥 [API Security] Request not HMAC authenticated (service-level)")
        return None, _uniform_error_response("Authentication required", 401)

    portal_id = request.headers.get('X-Portal-Id', 'unknown')

    try:
        request_data = request.data if hasattr(request, 'data') else json.loads(request.body)

        request_timestamp = request_data.get('timestamp')
        if not request_timestamp:
            logger.warning(f"🚨 [API Security] Portal {portal_id} missing timestamp in service request")
            return None, _uniform_error_response("Invalid request format", 400)

        current_time = datetime.now(UTC).timestamp()
        if abs(current_time - request_timestamp) > HMAC_TIMESTAMP_WINDOW_SECONDS:
            logger.warning(f"🚨 [API Security] Portal {portal_id} stale timestamp in service request")
            return None, _uniform_error_response("Invalid request format", 400)

    except (json.JSONDecodeError, TypeError, AttributeError, ValueError):
        logger.warning(f"🚨 [API Security] Portal {portal_id} invalid service request body format")
        return None, _uniform_error_response("Invalid request format", 400)

    logger.debug(f"✅ [API Security] Portal {portal_id} service request validated")
    return request_data, None


def require_portal_service_authentication(view_func: Callable[..., Any]) -> Callable[..., Any]:
    """
    🔒 Decorator for Portal-to-Platform service endpoints (user_id optional).

    Validates HMAC service authentication but does NOT require user_id.
    Passes request_data dict as second argument to the view.

    Usage:
        @require_portal_service_authentication
        def my_api_view(request, request_data):
            user_id = request_data.get('user_id')  # May be None
            return Response({"success": True})
    """
    def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Response:
        request_data, error_response = validate_portal_service_request(request)
        if error_response:
            return error_response
        return view_func(request, request_data, *args, **kwargs)
    return wrapper
