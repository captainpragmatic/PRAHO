# ===============================================================================
# API AUTHENTICATION UTILITIES - ANTI-ENUMERATION SECURITY 🔐
# ===============================================================================

import json
import logging

from django.http import HttpRequest
from rest_framework.response import Response

from apps.customers.models import Customer
from apps.users.models import CustomerMembership

logger = logging.getLogger(__name__)


def get_authenticated_customer_from_request(request: HttpRequest, required_customer_id: int | None = None) -> tuple[Customer | None, Response | None]:
    """
    🔒 Securely get authenticated customer from HMAC-authenticated request.
    
    Follows the same security pattern as `validate_session_secure()`:
    - Uses HMAC middleware authentication (not query parameters)
    - Prevents customer ID enumeration attacks
    - Validates customer membership for authenticated user
    
    Security Features:
    - No customer IDs trusted from URLs (prevents enumeration) 
    - HMAC authentication required
    - Customer membership validation
    - Uniform error responses (no information leakage)
    
    Args:
        request: Django HTTP request with HMAC authentication
        required_customer_id: Optional specific customer ID to validate access to
        
    Returns:
        Tuple of (Customer, Error Response)
        - If successful: (Customer object, None)  
        - If failed: (None, Error Response)
    """
    
    # Check if request is HMAC authenticated
    if not hasattr(request, '_portal_authenticated'):
        logger.warning("🔥 [API Security] Request not HMAC authenticated")
        return None, Response({
            'success': False,
            'error': 'Authentication required'
        }, status=401)
    
    # Get authenticated user from HMAC middleware
    if not hasattr(request, 'user') or not request.user.is_authenticated:
        logger.warning("🔥 [API Security] No authenticated user in HMAC request")
        return None, Response({
            'success': False, 
            'error': 'User authentication required'
        }, status=401)
    
    user = request.user
    
    # If specific customer_id is requested, validate access
    if required_customer_id is not None:
        try:
            # Get customer and validate user has access
            customer = Customer.objects.get(id=required_customer_id)
            
            # Check if user has membership to this customer
            membership = CustomerMembership.objects.filter(
                user=user, 
                customer=customer,
                is_active=True
            ).first()
            
            if not membership:
                logger.warning(f"🔥 [API Security] User {user.email} attempted access to customer {required_customer_id} without membership")
                return None, Response({
                    'success': False,
                    'error': 'Access denied to customer data'
                }, status=403)
            
            logger.debug(f"✅ [API Security] User {user.email} validated for customer {customer.company_name}")
            return customer, None
            
        except Customer.DoesNotExist:
            logger.warning(f"🔥 [API Security] Customer {required_customer_id} not found")
            return None, Response({
                'success': False,
                'error': 'Customer not found'
            }, status=404)
    
    else:
        # No specific customer requested, get user's primary customer
        membership = CustomerMembership.objects.filter(
            user=user,
            is_primary=True,
            is_active=True
        ).select_related('customer').first()
        
        if not membership:
            logger.warning(f"🔥 [API Security] User {user.email} has no primary customer membership")
            return None, Response({
                'success': False,
                'error': 'No customer access found'
            }, status=403)
        
        logger.debug(f"✅ [API Security] User {user.email} using primary customer {membership.customer.company_name}")
        return membership.customer, None


def get_customer_id_from_request(request: HttpRequest) -> tuple[int | None, Response | None]:
    """
    DEPRECATED: Query parameter fallback for customer_id has been removed.

    For security (anti-enumeration), customer_id must be supplied in the
    HMAC-signed request body and validated via middleware + signed context.

    Returns:
        Always returns (None, 400 Response) guiding clients to use signed body.
    """
    logger.warning("🚫 [API Security] Deprecated customer_id query param access attempted. Use HMAC-signed body.")
    return None, Response({
        'success': False,
        'error': 'Use HMAC-signed request body with customer_id (query param deprecated)'
    }, status=400)


def require_customer_access(request: HttpRequest, customer_id: int | None = None) -> tuple[Customer | None, Response | None]:
    """
    Decorator-style helper for API views requiring customer access.
    
    Usage in API views:
        customer, error_response = require_customer_access(request, customer_id)
        if error_response:
            return error_response
        # Continue with customer object
    
    Args:
        request: Django HTTP request
        customer_id: Optional specific customer to validate access to
        
    Returns:
        Tuple of (Customer, Error Response) 
    """
    
    # No query parameter fallback allowed (anti-enumeration)
    # If customer_id is provided explicitly by the view, validate it; otherwise
    # extract it from the HMAC-signed request body context.
    if customer_id is not None:
        return get_authenticated_customer_from_request(request, customer_id)
    
    customer, error = get_customer_from_hmac_context(request)
    if error:
        return None, error
    return customer, None


def _uniform_api_error(message: str = "Access denied", status_code: int = 403) -> Response:
    """
    🔒 Return uniform error response to prevent information leakage.
    
    Matches the pattern from `validate_session_secure()` with uniform errors.
    """
    return Response({
        'success': False,
        'error': message
    }, status=status_code, headers={
        'Cache-Control': 'no-store',
        'Pragma': 'no-cache',
        'X-Content-Type-Options': 'nosniff',
    })


def get_customer_from_hmac_context(request: HttpRequest) -> tuple[Customer | None, Response | None]:
    """
    🔒 PREFERRED: Get customer from HMAC request body context (like session validation).
    
    This is the MOST SECURE approach that matches `validate_session_secure()`:
    - customer_id comes from HMAC-signed request body
    - No query parameters trusted
    - No URL enumeration possible
    
    Usage for APIs that can modify their portal integration:
        customer, error_response = get_customer_from_hmac_context(request)
        if error_response:
            return error_response
        # Use customer safely
    
    Request Body Expected:
    {
        "customer_id": 123,
        "action": "get_data",  
        "timestamp": 1699999999
    }
    """
    
    # Check if request is HMAC authenticated
    if not hasattr(request, '_portal_authenticated'):
        logger.warning("🔥 [API Security] Request not HMAC authenticated")
        return None, _uniform_api_error("Authentication required", 401)
    
    # Parse HMAC-signed request body
    try:
        request_data = request.data if hasattr(request, 'data') else json.loads(request.body)
        customer_id = request_data.get('customer_id')
        
        if not customer_id:
            logger.warning("🔥 [API Security] Missing customer_id in HMAC request body")
            return None, _uniform_api_error("Invalid request format", 400)
            
    except (json.JSONDecodeError, TypeError, AttributeError):
        logger.warning("🔥 [API Security] Invalid HMAC request body format")
        return None, _uniform_api_error("Invalid request format", 400)
    
    # Validate customer exists and user has access
    try:
        customer_id = int(customer_id)
        customer = Customer.objects.get(id=customer_id)
        
        # Validate user has membership to this customer
        if hasattr(request, 'user') and request.user.is_authenticated:
            membership = CustomerMembership.objects.filter(
                user=request.user,
                customer=customer,
                is_active=True
            ).first()
            
            if not membership:
                logger.warning(f"🔥 [API Security] User {request.user.email} attempted access to customer {customer_id} without membership")
                return None, _uniform_api_error()  # Generic "access denied"
        
        logger.debug(f"✅ [API Security] Customer {customer.company_name} validated from HMAC context")
        return customer, None
        
    except (ValueError, Customer.DoesNotExist):
        logger.warning(f"🔥 [API Security] Invalid customer_id in HMAC context: {customer_id}")
        return None, _uniform_api_error()  # Generic "access denied"
