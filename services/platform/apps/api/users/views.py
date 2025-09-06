# ===============================================================================
# AUTHENTICATION API VIEWS - PORTAL SERVICE INTEGRATION 🔐
# ===============================================================================

import logging
from typing import cast
from django.contrib.auth import authenticate
from django.http import HttpRequest, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils.decorators import method_decorator
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.throttling import AnonRateThrottle
import json

from apps.users.models import User
import base64
from datetime import datetime, timedelta, timezone
from django.views.decorators.cache import never_cache
from rest_framework.throttling import BaseThrottle
from django.core.cache import cache

logger = logging.getLogger(__name__)


@csrf_exempt
@require_http_methods(["POST"])
def portal_login_api(request: HttpRequest) -> JsonResponse:
    """
    Authentication endpoint for portal service.
    Validates user credentials and returns user data for session creation.
    """
    try:
        # Parse request body
        data = json.loads(request.body)
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')
        
        if not email or not password:
            return JsonResponse({
                'success': False,
                'error': 'Email and password are required'
            }, status=400)
        
        # Authenticate user
        user = authenticate(request, username=email, password=password)
        
        if user and user.is_active:
            # Successful authentication
            logger.info(f"✅ [Portal API Auth] User {email} authenticated successfully")
            
            # Return user data for portal service
            user_data = {
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'is_staff': user.is_staff,
                'is_active': user.is_active,
            }
            
            return JsonResponse({
                'success': True,
                'user': user_data,
                'message': 'Authentication successful'
            })
        else:
            # Failed authentication
            logger.warning(f"🔥 [Portal API Auth] Authentication failed for {email}")
            return JsonResponse({
                'success': False,
                'error': 'Invalid email or password'
            }, status=401)
            
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON in request body'
        }, status=400)
    except Exception as e:
        logger.error(f"🔥 [Portal API Auth] Unexpected error: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Authentication service error'
        }, status=500)


@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request: HttpRequest) -> Response:
    """
    Simple health check endpoint for API monitoring.
    """
    return Response({
        'status': 'healthy',
        'service': 'platform-api',
        'version': '1.0.0'
    })


@api_view(['GET'])
def user_info_api(request: HttpRequest) -> Response:
    """
    Get current user information.
    Requires portal service authentication.
    """
    user = cast(User, request.user)
    
    if not user.is_authenticated:
        return Response({
            'error': 'Authentication required'
        }, status=401)
    
    user_data = {
        'id': user.id,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'full_name': user.get_full_name(),
        'is_staff': user.is_staff,
        'is_active': user.is_active,
    }
    
    return Response({
        'success': True,
        'user': user_data
    })



# ===============================================================================
# TOKEN AUTHENTICATION ENDPOINTS 🎫
# ===============================================================================

class AuthThrottle(AnonRateThrottle):
    """Custom throttle for auth endpoints - more restrictive"""
    rate = '5/min'


@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([AuthThrottle])
def obtain_token(request):
    """
    🔐 Obtain authentication token for API access
    
    Used by portal service to authenticate with platform API.
    
    POST /api/users/token/
    {
        "email": "user@example.com", 
        "password": "password"
    }
    
    Response:
    {
        "token": "9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b",
        "user_id": 123,
        "email": "user@example.com"
    }
    """
    email = request.data.get('email')
    password = request.data.get('password')
    
    if not email or not password:
        logger.warning("🚨 [Auth] Token request missing email or password")
        return Response({
            'error': 'Email and password are required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Authenticate user
    user = authenticate(request, username=email, password=password)
    
    if user is None:
        logger.warning(f"🚨 [Auth] Failed token request for email: {email}")
        return Response({
            'error': 'Invalid credentials'
        }, status=status.HTTP_401_UNAUTHORIZED)
    
    if not user.is_active:
        logger.warning(f"🚨 [Auth] Token request for inactive user: {email}")
        return Response({
            'error': 'User account is disabled'
        }, status=status.HTTP_401_UNAUTHORIZED)
    
    # Get or create token
    token, created = Token.objects.get_or_create(user=user)
    
    if created:
        logger.info(f"✅ [Auth] New token created for user: {user.email}")
    else:
        logger.info(f"🔄 [Auth] Existing token returned for user: {user.email}")
    
    return Response({
        'token': token.key,
        'user_id': user.id,
        'email': user.email,
        'is_staff': user.is_staff,
    })


@api_view(['POST'])  
@permission_classes([AllowAny])
@throttle_classes([AuthThrottle])
def revoke_token(request):
    """
    🗑️ Revoke authentication token
    
    POST /api/users/token/revoke/
    {
        "token": "9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b"
    }
    """
    token_key = request.data.get('token')
    
    if not token_key:
        return Response({
            'error': 'Token is required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        token = Token.objects.get(key=token_key)
        user_email = token.user.email
        token.delete()
        
        logger.info(f"🗑️ [Auth] Token revoked for user: {user_email}")
        return Response({'message': 'Token revoked successfully'})
        
    except Token.DoesNotExist:
        return Response({
            'error': 'Invalid token'
        }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def verify_token(request):
    """
    ✅ Verify token is valid and get user info
    
    GET /api/users/token/verify/
    Headers: Authorization: Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b
    
    Response:
    {
        "user_id": 123,
        "email": "user@example.com", 
        "is_staff": false,
        "accessible_customers": [1, 2, 3]
    }
    """
    user = cast(User, request.user)  # Safe due to IsAuthenticated
    
    # Get accessible customers for this user
    accessible_customers = user.get_accessible_customers()
    customer_ids = []
    
    if hasattr(accessible_customers, 'values_list'):  # QuerySet
        customer_ids = list(accessible_customers.values_list('id', flat=True))
    elif accessible_customers:  # List
        customer_ids = [c.id for c in accessible_customers]
    
    logger.info(f"✅ [Auth] Token verified for user: {user.email}")
    
    return Response({
        'user_id': user.id,
        'email': user.email,
        'is_staff': user.is_staff,
        'accessible_customers': customer_ids,
        'full_name': f"{user.first_name} {user.last_name}".strip() or user.email,
    })


# ===============================================================================
# SECURE SESSION VALIDATION - HMAC-SIGNED CONTEXT (NO JWT) 🔒
# ===============================================================================

class SessionValidationThrottle(BaseThrottle):
    """Custom throttle for session validation - prevent brute force (60/min per portal)"""
    
    def allow_request(self, request, view):
        portal_id = request.headers.get('X-Portal-Id', 'unknown')
        cache_key = f"session_validation_throttle:{portal_id}"
        
        current_count = cache.get(cache_key, 0)
        if current_count >= 60:  # 60 requests per minute
            logger.warning(f"🚨 [Security] Portal {portal_id} rate limited for session validation")
            return False
        
        cache.set(cache_key, current_count + 1, 60)
        return True


@never_cache
@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])  # HMAC authentication required
@throttle_classes([SessionValidationThrottle])
def validate_session_secure(request: HttpRequest) -> Response:
    """
    🔒 SECURE Session Validation - HMAC-Signed Context (No JWT)
    
    Endpoint: POST /api/users/session/validate/
    Auth: HMAC headers with user context in request body
    
    Request Body:
    {
        "customer_id": "2",
        "state_version": 42,
        "timestamp": 1694022337
    }
    
    Headers:
        X-Portal-Id: portal-001
        X-Nonce: <unique nonce>
        X-Timestamp: <unix timestamp>
        X-Signature: <HMAC signature covering body + headers>
        
    Response: {"active": true, "state_version": 43, "revoke_before": "..."}
    
    Security Features:
    - No customer IDs in URL (prevents enumeration)
    - HMAC-signed request body (simpler than JWT)
    - Rate limiting (60/min per portal)
    - Uniform error responses
    - No PII in logs
    """
    
    # Security headers
    security_headers = {
        'Cache-Control': 'no-store',
        'Pragma': 'no-cache',
        'X-Content-Type-Options': 'nosniff',
    }
    
    try:
        # Extract portal ID for logging (no PII)
        portal_id = request.headers.get('X-Portal-Id', 'unknown')
        jti = request.headers.get('X-Nonce', 'unknown')[:8]  # First 8 chars only
        
        # NOTE: HMAC validation happens in middleware - if we reach here, request is authenticated
        
        # Parse request body for user context
        try:
            request_data = request.data if hasattr(request, 'data') else json.loads(request.body)
            customer_id = request_data.get('customer_id')
            state_version = request_data.get('state_version', 1)
            request_timestamp = request_data.get('timestamp')
            
            if not customer_id:
                logger.warning(f"🚨 [Security] Portal {portal_id} missing customer_id in context")
                return _uniform_session_error(security_headers)
                
            # Basic timestamp freshness check (within 5 minutes)
            current_time = datetime.now(timezone.utc).timestamp()
            if abs(current_time - request_timestamp) > 300:  # 5 minutes
                logger.warning(f"🚨 [Security] Portal {portal_id} stale timestamp in context")
                return _uniform_session_error(security_headers)
                
        except (json.JSONDecodeError, TypeError, AttributeError) as e:
            logger.warning(f"🚨 [Security] Portal {portal_id} invalid request body format")
            return _uniform_session_error(security_headers)
        
        # Validate customer exists and is active
        try:
            user = User.objects.get(id=customer_id, is_active=True)
            
            # Success - calculate next validation time
            next_validation = datetime.now(timezone.utc) + timedelta(minutes=10)
            
            logger.info(f"✅ [Security] Portal {portal_id} session validated (jti: {jti})")
            
            response_data = {
                'active': True,
                'state_version': state_version + 1,
                'revoke_before': next_validation.isoformat()
            }
            
            response = Response(response_data, status=status.HTTP_200_OK)
            for key, value in security_headers.items():
                response[key] = value
            return response
            
        except User.DoesNotExist:
            logger.warning(f"🚨 [Security] Portal {portal_id} session validation failed (jti: {jti})")
            return _uniform_session_error(security_headers)
        
    except Exception as e:
        logger.error(f"🔥 [Security] Session validation error: {type(e).__name__}")
        return _uniform_session_error(security_headers)


def _uniform_session_error(headers: dict) -> Response:
    """Uniform 401 response to prevent information leakage"""
    response_data = {
        'active': False,
        'error': 'Session validation failed'
    }
    
    response = Response(response_data, status=status.HTTP_401_UNAUTHORIZED)
    for key, value in headers.items():
        response[key] = value
    return response