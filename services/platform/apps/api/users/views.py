# ===============================================================================
# AUTHENTICATION API VIEWS - PORTAL SERVICE INTEGRATION 🔐
# ===============================================================================

import json
import logging
from datetime import UTC, datetime, timedelta
from typing import cast

from django.contrib.auth import authenticate
from django.core.cache import cache
from django.http import HttpRequest, JsonResponse
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, authentication_classes, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle, BaseThrottle

from apps.users.models import User

from ..secure_auth import require_customer_authentication, require_user_authentication

# Rate limiting and security constants
SESSION_VALIDATION_RATE_LIMIT = 60  # requests per minute
HMAC_TIMESTAMP_WINDOW_SECONDS = 300  # 5 minutes

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
                'customer_id': user.primary_customer.id if user.primary_customer else None,
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
        if current_count >= SESSION_VALIDATION_RATE_LIMIT:
            logger.warning(f"🚨 [Security] Portal {portal_id} rate limited for session validation")
            return False
        
        cache.set(cache_key, current_count + 1, 60)
        return True


@never_cache
@csrf_exempt
@api_view(['POST'])
@authentication_classes([])  # No DRF authentication - HMAC handled by middleware
@permission_classes([AllowAny])  # HMAC authentication required
@throttle_classes([SessionValidationThrottle])
def validate_session_secure(request: HttpRequest) -> Response:
    """
    🔒 SECURE Session Validation - HMAC-Signed Context (No JWT)
    
    Endpoint: POST /api/users/session/validate/
    Auth: HMAC headers with user context in request body
    
    Request Body:
    {
        "user_id": "2",
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
    - No user IDs in URL (prevents enumeration)
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
            user_id = request_data.get('user_id')
            state_version = request_data.get('state_version', 1)
            request_timestamp = request_data.get('timestamp')
            
            if not user_id:
                logger.warning(f"🚨 [Security] Portal {portal_id} missing user_id in context")
                return _uniform_session_error(security_headers)
                
            # Basic timestamp freshness check (within 5 minutes)
            current_time = datetime.now(UTC).timestamp()
            if abs(current_time - request_timestamp) > HMAC_TIMESTAMP_WINDOW_SECONDS:
                logger.warning(f"🚨 [Security] Portal {portal_id} stale timestamp in context")
                return _uniform_session_error(security_headers)
                
        except (json.JSONDecodeError, TypeError, AttributeError):
            logger.warning(f"🚨 [Security] Portal {portal_id} invalid request body format")
            return _uniform_session_error(security_headers)
        
        # Validate user exists and is active
        try:
            User.objects.get(id=user_id, is_active=True)
            
            # Success - calculate next validation time
            next_validation = datetime.now(UTC) + timedelta(minutes=10)
            
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


# ===============================================================================
# MULTI-FACTOR AUTHENTICATION ENDPOINTS 📱
# ===============================================================================

@api_view(['POST'])
@permission_classes([AllowAny])  # HMAC auth handled by secure_auth
@require_customer_authentication
def mfa_setup_api(request: HttpRequest, customer) -> Response:
    """
    📱 Initialize MFA Setup
    
    POST /api/users/mfa/setup/
    
    Generates QR code and secret for authenticator app setup.
    User must verify with a token to complete setup.
    
    Response:
    {
        "secret": "JBSWY3DPEHPK3PXP",
        "qr_code_svg": "<svg>...</svg>",
        "provisioning_uri": "otpauth://totp/PRAHO...",
        "manual_entry_key": "JBSWY3DPEHPK3PXP"
    }
    """
    from apps.users.models import CustomerMembership

    from .serializers import MFASetupSerializer
    
    # Get the user from the customer context (since this is a customer-authenticated endpoint)
    # The customer parameter comes from @require_customer_authentication
    # We need to get the associated user from the customer membership
    membership = CustomerMembership.objects.filter(customer=customer).first()
    if not membership:
        return Response({
            'success': False,
            'error': 'No user associated with this customer'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    user = membership.user
    
    if user.mfa_enabled:
        return Response({
            'success': False,
            'error': 'MFA is already enabled for this account'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    serializer = MFASetupSerializer(context={'request': request})
    
    try:
        result = serializer.save()
        
        return Response({
            'success': True,
            'message': 'Scan the QR code with your authenticator app',
            'setup_data': {
                'qr_code_svg': result['qr_code_svg'],
                'manual_entry_key': result['manual_entry_key'],
                'provisioning_uri': result['provisioning_uri']
            }
        })
        
    except Exception as e:
        logger.error(f"🔥 [MFA Setup] Setup failed for user {user.email}: {e}")
        return Response({
            'success': False,
            'error': 'MFA setup failed. Please try again.'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])  # HMAC auth handled by secure_auth
@require_user_authentication
def mfa_verify_api(request: HttpRequest, user) -> Response:
    """
    🔐 Verify MFA Token and Enable
    
    POST /api/users/mfa/verify/
    {
        "token": "123456"
    }
    
    Verifies the token from authenticator app and enables MFA.
    Returns backup codes on successful verification.
    
    Response:
    {
        "success": true,
        "message": "MFA enabled successfully",
        "backup_codes": ["12345678", "87654321", ...]
    }
    """
    from .serializers import MFAVerifySerializer
    
    if user.mfa_enabled:
        return Response({
            'success': False,
            'error': 'MFA is already enabled for this account'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    serializer = MFAVerifySerializer(
        data=request.data,
        context={'request': request}
    )
    
    if serializer.is_valid():
        try:
            result = serializer.save()
            
            # Rotate session for security after enabling MFA
            from apps.users.services import SessionSecurityService
            SessionSecurityService.rotate_session_on_mfa_change(request)
            
            return Response(result)
            
        except Exception as e:
            logger.error(f"🔥 [MFA Verify] Verification failed for user {user.email}: {e}")
            return Response({
                'success': False,
                'error': 'MFA verification failed. Please try again.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        return Response({
            'success': False,
            'error': 'Validation failed',
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@throttle_classes([AuthThrottle])
def mfa_disable_api(request: HttpRequest) -> Response:
    """
    🚫 Disable MFA
    
    POST /api/users/mfa/disable/
    {
        "token": "123456",
        "password": "current_password"
    }
    
    Disables MFA after verifying current password and MFA token.
    """
    from .serializers import MFADisableSerializer
    
    user = cast(User, request.user)
    
    if not user.mfa_enabled:
        return Response({
            'success': False,
            'error': 'MFA is not enabled for this account'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    serializer = MFADisableSerializer(
        data=request.data,
        context={'request': request}
    )
    
    if serializer.is_valid():
        try:
            result = serializer.save()
            
            # Rotate session for security after disabling MFA
            from apps.users.services import SessionSecurityService
            SessionSecurityService.rotate_session_on_mfa_change(request)
            
            return Response(result)
            
        except Exception as e:
            logger.error(f"🔥 [MFA Disable] Disable failed for user {user.email}: {e}")
            return Response({
                'success': False,
                'error': 'MFA disable failed. Please try again.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        return Response({
            'success': False,
            'error': 'Validation failed',
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def mfa_status_api(request: HttpRequest) -> Response:
    """
    📊 Get MFA Status
    
    GET /api/users/mfa/status/
    
    Returns current MFA status and backup codes count.
    
    Response:
    {
        "enabled": true,
        "backup_codes_remaining": 5
    }
    """
    user = cast(User, request.user)
    
    return Response({
        'enabled': user.mfa_enabled,
        'backup_codes_remaining': len(user.backup_tokens) if user.mfa_enabled else 0,
        'has_backup_codes': user.has_backup_codes() if user.mfa_enabled else False
    })


# ===============================================================================
# PASSWORD RESET ENDPOINTS 🔑
# ===============================================================================

@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([AuthThrottle])
def password_reset_request_api(request: HttpRequest) -> Response:
    """
    🔑 Request Password Reset
    
    POST /api/users/password/reset/
    {
        "email": "user@example.com"
    }
    
    Sends password reset email if account exists.
    Always returns success to prevent email enumeration.
    
    Response:
    {
        "success": true,
        "message": "If the email exists, a reset link has been sent."
    }
    """
    from .serializers import PasswordResetRequestSerializer
    
    serializer = PasswordResetRequestSerializer(data=request.data)
    
    if serializer.is_valid():
        try:
            result = serializer.save()
            return Response(result)
            
        except Exception as e:
            logger.error(f"🔥 [Password Reset] Request failed: {e}")
            return Response({
                'success': False,
                'error': 'Password reset service temporarily unavailable.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        return Response({
            'success': False,
            'error': 'Invalid email address',
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([AuthThrottle])
def password_reset_confirm_api(request: HttpRequest) -> Response:
    """
    🔐 Confirm Password Reset
    
    POST /api/users/password/reset/confirm/
    {
        "token": "abc123-def456-ghi789",
        "uid": "MjM",
        "new_password": "new_secure_password",
        "new_password_confirm": "new_secure_password"
    }
    
    Resets password with valid reset token.
    
    Response:
    {
        "success": true,
        "message": "Password reset successfully."
    }
    """
    from .serializers import PasswordResetConfirmSerializer
    
    serializer = PasswordResetConfirmSerializer(data=request.data)
    
    if serializer.is_valid():
        try:
            result = serializer.save()
            
            # Log successful password reset
            user = serializer.validated_data['uid']
            logger.info(f"✅ [Password Reset] Password reset completed for user: {user.email}")
            
            return Response(result)
            
        except Exception as e:
            logger.error(f"🔥 [Password Reset] Confirm failed: {e}")
            return Response({
                'success': False,
                'error': 'Password reset failed. Please try again.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        return Response({
            'success': False,
            'error': 'Validation failed',
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


# ===============================================================================
# CUSTOMER REGISTRATION API
# ===============================================================================

@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([AnonRateThrottle])
def customer_registration_api(request: HttpRequest) -> Response:
    """
    Customer registration API endpoint for Portal service.
    Creates new customer account with business information via Platform API.
    """
    try:
        # Use existing UserRegistrationService for consistency
        from apps.users.forms import UserRegistrationForm
        
        # Create form from API data
        form_data = {
            'email': request.data.get('email', '').lower().strip(),
            'first_name': request.data.get('first_name', ''),
            'last_name': request.data.get('last_name', ''),
            'phone': request.data.get('phone', ''),
            'password1': request.data.get('password1', ''),
            'password2': request.data.get('password2', ''),
            'gdpr_consent': request.data.get('gdpr_consent', False),
            'accepts_marketing': request.data.get('accepts_marketing', False),
        }
        
        form = UserRegistrationForm(data=form_data)
        
        if form.is_valid():
            try:
                # Create user using existing service
                user = form.save()
                
                logger.info(f"✅ [Registration API] Customer account created: {user.email}")
                
                return Response({
                    'success': True,
                    'message': 'Registration successful',
                    'customer_id': user.id,
                    'email': user.email,
                    'requires_verification': False  # Email verification can be added later
                }, status=status.HTTP_201_CREATED)
                
            except Exception as e:
                logger.error(f"🔥 [Registration API] Registration failed: {e}")
                return Response({
                    'success': False,
                    'error': 'Registration failed. Please try again.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response({
                'success': False,
                'error': 'Validation failed',
                'errors': form.errors
            }, status=status.HTTP_400_BAD_REQUEST)
            
    except Exception as e:
        logger.error(f"🔥 [Registration API] Unexpected error: {e}")
        return Response({
            'success': False,
            'error': 'Registration service unavailable'
        }, status=status.HTTP_503_SERVICE_UNAVAILABLE)


# ===============================================================================  
# PROFILE UPDATE API
# ===============================================================================

@api_view(['POST', 'PUT'])
@authentication_classes([])  # No DRF authentication - HMAC handled by middleware + secure_auth
@permission_classes([AllowAny])  # HMAC auth handled by secure_auth
@require_user_authentication
def customer_profile_api(request: HttpRequest, user) -> Response:
    """
    Customer profile management API endpoint for Portal service.
    Allows customers to view and update their profile via Platform API.
    
    POST /api/users/profile/ (to get profile)
    PUT /api/users/profile/ (to update profile)
    
    Request Body (HMAC-signed):
    {
        "customer_id": 123,
        "action": "get_profile" | "update_profile",
        "timestamp": 1699999999,
        // For updates:
        "first_name": "John",
        "last_name": "Doe",
        "phone": "+40123456789",
        "preferred_language": "en",
        "timezone": "Europe/Bucharest",
        "email_notifications": true,
        "sms_notifications": false
    }
    
    Security Features:
    - HMAC authentication required (user passed by decorator)
    - User validated by secure authentication system
    """
    try:
        
        if request.method == 'POST':  # Changed from GET to POST for security
            # Return profile data
            profile_data = {
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'phone': user.phone or '',
                'mfa_enabled': user.mfa_enabled,
            }
            
            # Add profile data (create default if doesn't exist)
            from apps.users.models import UserProfile
            profile, created = UserProfile.objects.get_or_create(user=user)
            
            if created:
                logger.info(f"✅ [Profile API] Created default profile for customer: {user.email}")
            
            profile_data['profile'] = {
                'preferred_language': profile.preferred_language,
                'timezone': profile.timezone,
                'email_notifications': profile.email_notifications,
                'sms_notifications': profile.sms_notifications,
            }
            
            return Response({
                'success': True,
                'profile': profile_data
            })
            
        elif request.method == 'PUT':
            # Get profile data from HMAC-signed request body
            request_data = request.data if hasattr(request, 'data') else {}
            
            # Update basic user fields
            user.first_name = request_data.get('first_name', user.first_name)
            user.last_name = request_data.get('last_name', user.last_name)
            user.phone = request_data.get('phone', user.phone)
            user.save()
            
            # Update or create profile
            from apps.users.models import UserProfile
            profile, created = UserProfile.objects.get_or_create(user=user)
            
            # Update profile fields if provided in request body
            if 'preferred_language' in request_data:
                profile.preferred_language = request_data.get('preferred_language')
            if 'timezone' in request_data:
                profile.timezone = request_data.get('timezone')
            if 'email_notifications' in request_data:
                profile.email_notifications = request_data.get('email_notifications')
            if 'sms_notifications' in request_data:
                profile.sms_notifications = request_data.get('sms_notifications')
            
            profile.save()
            
            if created:
                logger.info(f"✅ [Profile API] Created new profile for customer: {user.email}")
            else:
                logger.info(f"✅ [Profile API] Updated existing profile for customer: {user.email}")
            
            return Response({
                'success': True,
                'message': 'Profile updated successfully'
            })
                
    except Exception as e:
        logger.error(f"🔥 [Profile API] Unexpected error: {e}")
        return Response({
            'success': False,
            'error': 'Profile service unavailable'
        }, status=status.HTTP_503_SERVICE_UNAVAILABLE)


# ===============================================================================
# ACCESSIBLE CUSTOMERS FOR USER (HMAC-SIGNED) 👥
# ===============================================================================

@api_view(['POST'])
@authentication_classes([])  # HMAC handled by middleware + secure_auth
@permission_classes([AllowAny])
@require_user_authentication
def user_customers_api(request: HttpRequest, user: User) -> Response:
    """
    Return customers accessible to the authenticated user.

    POST /api/users/customers/

    Request Body (HMAC-signed):
    {
        "customer_id": <user_id>,
        "action": "get_user_customers",
        "timestamp": 1699999999
    }
    """
    try:
        customers = user.get_accessible_customers()
        results = []
        # Handle both QuerySet and list
        if hasattr(customers, 'all'):
            iterable = customers.all()
        else:
            iterable = customers or []
        for c in iterable:
            results.append({
                'id': c.id,
                'company_name': getattr(c, 'company_name', ''),
                'name': getattr(c, 'name', ''),
            })
        return Response({'success': True, 'results': results})
    except Exception as e:
        logger.error(f"🔥 [User Customers API] Error fetching customers for {getattr(user, 'email', 'unknown')}: {e}")
        return Response({'success': False, 'error': 'Unable to fetch customers'}, status=500)
