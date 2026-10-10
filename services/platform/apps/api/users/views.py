# ===============================================================================
# AUTHENTICATION API VIEWS - PORTAL SERVICE INTEGRATION 🔐
# ===============================================================================

import contextlib
import hashlib
import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import Error as DatabaseFailure
from django.db import transaction
from django.http import HttpRequest, JsonResponse
from django.utils.crypto import constant_time_compare
from django.utils.translation import gettext as _
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes, throttle_classes
from rest_framework.exceptions import ValidationError as APIValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from apps.api.core.throttling import AuthThrottle, BurstAPIThrottle, StandardAPIThrottle, TokenRequestAccountThrottle
from apps.api.secure_auth import (
    public_api_endpoint,
    require_customer_authentication,
    require_portal_authentication,
    require_user_authentication,
)
from apps.api.users.authentication import HashedTokenAuthentication
from apps.common.constants import HMAC_NTP_SKEW_SECONDS, HMAC_TIMESTAMP_WINDOW_SECONDS
from apps.common.localisation import resolve_display
from apps.common.localisation_services import get_localisation_defaults, user_localisation_preferences
from apps.common.performance.rate_limiting import (
    BurstRateThrottle,
    CustomerRateThrottle,
    EndpointRateThrottle,
    PortalHMACBurstThrottle,
    PortalHMACRateThrottle,
    RegistrationConfirmClientIPThrottle,
    ResetClientIPThrottle,
    fixed_window_limited,
    forwarded_client_ip,
)
from apps.common.request_ip import get_safe_client_ip
from apps.common.validators import log_security_event
from apps.customers.models import Customer
from apps.users.mfa import MFAService, verify_login_second_factor
from apps.users.models import APIToken, CustomerMembership, User, UserProfile
from apps.users.services import APITokenService, SessionSecurityService

from .serializers import (
    InvalidPasswordResetLink,
    MFADisableSerializer,
    MFASetupSerializer,
    MFAVerifySerializer,
    PasswordResetConfirmSerializer,
    PasswordResetRequestSerializer,
    ProfileUpdateSerializer,
    RegistrationConfirmSerializer,
    TokenObtainRequestSerializer,
)

logger = logging.getLogger(__name__)


_EMAIL_MASK_LOCAL_VISIBLE_CHARS: int = 2


def _mask_email(email: str) -> str:
    """Return a privacy-safe email string for logging. Sanitizes log injection chars."""
    email = email.replace("\n", "").replace("\r", "").replace("\t", "").replace("\0", "")[:254]
    if "@" not in email:
        return "[invalid-email]"
    local, domain = email.split("@", 1)
    # Domain is already sanitized — \n/\r stripped from full email above
    masked_local = (
        local[:_EMAIL_MASK_LOCAL_VISIBLE_CHARS] + "***" if len(local) > _EMAIL_MASK_LOCAL_VISIBLE_CHARS else "***"
    )
    return f"{masked_local}@{domain}"


def _record_failed_attempt(email: str) -> None:
    """Count a failed portal login against the account, if there is one.

    Silent for an unknown email. Best-effort: the write runs only for a real account, so letting
    its failure surface as a 500 would tell an attacker the email exists. A locked account's lock
    is not extended by more attempts, as on the staff login: otherwise anyone who knows an
    address could keep that account locked out.
    """
    with contextlib.suppress(User.DoesNotExist):
        failed_user = User.objects.get(email=email)
        if failed_user.is_account_locked():
            return
        try:
            failed_user.increment_failed_login_attempts()
        except DatabaseFailure:
            logger.exception("🔥 [Portal API Auth] Could not record a failed login attempt")


def _charge_login_failure(forwarded_ip: str | None) -> None:
    """Charge the per-client login failure budget; successful logins never count."""
    if forwarded_ip is not None:
        fixed_window_limited(f"login_ip:{forwarded_ip}", settings.THROTTLE_RATES["auth_login_ip"])


@csrf_exempt  # nosemgrep: no-csrf-exempt — HMAC-authenticated inter-service endpoint
@require_http_methods(["POST"])
@require_portal_authentication
def portal_login_api(request: HttpRequest) -> JsonResponse:  # noqa: PLR0911 -- distinct authentication failures
    """
    Authentication endpoint for portal service.
    Validates user credentials and returns user data for session creation.

    Rate limiting: PortalServiceHMACMiddleware applies the per-portal auth
    bucket before this view. A per-forwarded-IP limit runs before credential
    checks, followed by per-account lockout at ACCOUNT_LOCKOUT_THRESHOLD.

    """
    try:
        # Parse request body
        data = json.loads(request.body)
        email = data.get("email", "").lower().strip()
        password = data.get("password", "")

        if not email or not password:
            return JsonResponse({"success": False, "error": "Email and password are required"}, status=400)

        client_ip = get_safe_client_ip(request)
        forwarded_ip = forwarded_client_ip(request)
        if forwarded_ip is not None:
            limited, retry_after = fixed_window_limited(
                f"login_ip:{forwarded_ip}", settings.THROTTLE_RATES["auth_login_ip"], charge=False
            )
            if limited:
                response = JsonResponse(
                    {"success": False, "error": _("Too many login attempts"), "retry_after": retry_after},
                    status=429,
                )
                response["Retry-After"] = str(retry_after)
                return response

        # Apply the forwarded-IP limit before expensive credential checks.
        user = authenticate(request, username=email, password=password)

        if user is None:
            _record_failed_attempt(email)
            logger.warning("⚠️ [Portal API Auth] Failed login — ip=%s", forwarded_ip or client_ip)
            _charge_login_failure(forwarded_ip)
            return JsonResponse({"success": False, "error": "Invalid email or password"}, status=401)

        # Every decision is re-read on the locked row, so a password change, lockout,
        # deactivation or 2FA enrolment that lands after authenticate() cannot be skipped,
        # and the success reset cannot erase a failure recorded in between.
        authenticated = user
        refusal: str | None = None
        with transaction.atomic():
            user = User.objects.select_for_update().get(pk=authenticated.pk)
            if user.password != authenticated.password or user.is_account_locked() or not user.is_active:
                # Same generic error for locked/inactive — attacker cannot distinguish
                refusal = "credentials"
            # A password alone must never establish a session for an enrolled user.
            elif (
                user.two_factor_enabled
                and not verify_login_second_factor(user, str(data.get("mfa_token", "")), request).accepted
            ):
                refusal = "second_factor"  # the transaction commits, so the failed attempt counts
            else:
                user.failed_login_attempts = 0
                user.account_locked_until = None
                user.save(update_fields=["failed_login_attempts", "account_locked_until"])
                session_auth_hash = user.get_session_auth_hash()

        if refusal == "credentials":
            reason = "locked" if user.is_account_locked() else "inactive or changed"
            logger.warning("⚠️ [Portal API Auth] Login rejected (%s) — ip=%s", reason, forwarded_ip or client_ip)
            _charge_login_failure(forwarded_ip)
            return JsonResponse({"success": False, "error": "Invalid email or password"}, status=401)
        if refusal == "second_factor":
            _charge_login_failure(forwarded_ip)
            return JsonResponse({"success": False, "error": "Invalid authentication code"}, status=401)

        logger.info("✅ [Portal API Auth] User authenticated successfully — ip=%s", forwarded_ip or client_ip)

        # Return user data for portal service

        user_data = {
            "id": user.id,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "is_staff": user.is_staff,
            "is_active": user.is_active,
            "customer_id": user.primary_customer.id if user.primary_customer else None,
            "localisation_preferences": user_localisation_preferences(user),
        }

        return JsonResponse(
            {
                "success": True,
                "user": user_data,
                "session_auth_hash": session_auth_hash,
                "message": "Authentication successful",
            }
        )

    except json.JSONDecodeError:
        return JsonResponse({"success": False, "error": "Invalid JSON in request body"}, status=400)
    except Exception as e:
        logger.error(f"🔥 [Portal API Auth] Unexpected error: {e}")
        return JsonResponse({"success": False, "error": "Authentication service error"}, status=500)


@public_api_endpoint
@api_view(["GET"])
@authentication_classes([])  # No DRF authentication - public endpoint
@permission_classes([AllowAny])
def health_check(request: HttpRequest) -> Response:
    """Health check for load balancer probes -- intentionally public."""
    return Response({"status": "healthy", "service": "platform-api", "version": "1.0.0"})


@api_view(["GET"])
@authentication_classes([])  # No DRF authentication - HMAC handled by middleware + secure_auth
@permission_classes([AllowAny])  # HMAC auth handled by secure_auth
@require_customer_authentication
def user_info_api(request: HttpRequest, customer: Customer) -> Response:
    """
    Get current user information.
    Requires customer authentication via HMAC.
    """
    user = getattr(request, "_customer_user", None)
    if user is None:
        return Response(
            {"success": False, "error": "No user associated with this customer"}, status=status.HTTP_400_BAD_REQUEST
        )

    user_data = {
        "id": user.id,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "full_name": user.get_full_name(),
        "is_staff": user.is_staff,
        "is_active": user.is_active,
    }

    return Response({"success": True, "user": user_data})


def _authenticate_token_request(request: HttpRequest) -> User | Response:
    """Check the email and password for obtain_token.

    Returns the authenticated user, or the error Response the view should return
    verbatim. The second factor and the lockout reset are checked afterwards by
    _issue_token_under_lock, on a locked and freshly read row.
    """
    email = request.data.get("email")
    password = request.data.get("password")

    if not email or not password:
        logger.warning("🚨 [Auth] Token request missing email or password")
        return Response({"error": "Email and password are required"}, status=status.HTTP_400_BAD_REQUEST)

    client_ip = get_safe_client_ip(request)

    # Timing is NOT uniform past this point. With the correct password, an account with
    # 2FA goes on to verify the code, and an 8-digit code is checked against every stored
    # backup-code hash, so a slow refusal can confirm the password even though the body
    # is the same. That is narrower than before #565, when the correct password simply
    # returned a token, and TokenRequestAccountThrottle caps sampling at 5/min per
    # address. ADR-0031 "What a bare token can reach" records it.
    user = authenticate(request, username=email, password=password)

    if user is None:
        # Deliberately does NOT drive the account lockout. This endpoint is public, so
        # anyone could otherwise lock any account they knew the address of: five wrong
        # passwords applied a progressive lock escalating to four hours, across every
        # login path, with no credentials and nothing to attribute the attempt to. Every
        # other caller of that counter sits behind a working per-account rate limit; this
        # one inherited the lockout without the protection. TokenRequestAccountThrottle
        # now provides the per-account budget, keyed on the submitted address so it binds
        # even though the client-keyed throttles can be rotated away.
        logger.warning(  # nosemgrep: python-logger-credential-disclosure — literal log message, no secrets
            "[Auth] Failed token request — ip=%s", client_ip
        )
        return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

    # Same generic error for locked/inactive — attacker cannot distinguish
    if user.is_account_locked():
        logger.warning(  # nosemgrep: python-logger-credential-disclosure — literal log message, no secrets
            "[Auth] Token request for locked account — ip=%s", client_ip
        )
        return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

    if not user.is_active:
        logger.warning(  # nosemgrep: python-logger-credential-disclosure — literal log message, no secrets
            "[Auth] Token request for inactive account — ip=%s", client_ip
        )
        return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

    return user


def _issue_token_under_lock(
    request: HttpRequest, authenticated: User, params: TokenObtainRequestSerializer
) -> Response:
    """Check the second factor and issue the token in one transaction on the locked user row.

    Everything that decides whether a token may be issued is re-read under the lock, so a
    password change, a lockout or a 2FA enrolment that lands after authenticate() cannot
    be skipped. Refusals use the wrong-password body: anything more specific would confirm
    the password to anyone who can reach this public endpoint.
    """
    client_ip = get_safe_client_ip(request)
    refused = Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
    with transaction.atomic():
        user = User.objects.select_for_update().get(pk=authenticated.pk)
        if user.password != authenticated.password or user.is_account_locked() or not user.is_active:
            logger.warning(  # nosemgrep: python-logger-credential-disclosure — literal log message, no secrets
                "[Auth] Token request refused, account changed during the request — ip=%s", client_ip
            )
            return refused
        # A password alone must never yield a token for an enrolled account (#565).
        if (
            user.two_factor_enabled
            and not verify_login_second_factor(user, str(request.data.get("mfa_token", "")), request).accepted
        ):
            logger.warning(  # nosemgrep: python-logger-credential-disclosure — literal log message, no secrets
                "[Auth] Token request failed the second factor — ip=%s", client_ip
            )
            return refused  # the transaction commits, so the failed attempt counts

        user.failed_login_attempts = 0
        user.account_locked_until = None
        user.save(update_fields=["failed_login_attempts", "account_locked_until"])

        result = APITokenService.issue_token(
            user=user,
            name=params.validated_data["name"],
            description=params.validated_data["description"],
            ttl_days=params.validated_data.get("ttl_days"),
        )
        if result.is_err():
            # Nothing was issued, so nothing this request did may stick: a spent backup code
            # comes back and the counter reset is undone. Under the configured DatabaseCache the
            # TOTP replay marker is written on this same connection, so it rolls back too and the
            # code stays usable once; only a cache on a separate store would keep it spent.
            transaction.set_rollback(True)
            return Response({"error": result.unwrap_err()}, status=status.HTTP_400_BAD_REQUEST)
    issued = result.unwrap()
    token = issued.token

    return Response(
        {
            "token": issued.raw_key,
            "user_id": user.id,
            "email": user.email,
            "key_prefix": token.key_prefix,
            "name": token.name,
            "description": token.description,
            "expires_at": token.expires_at.isoformat() if token.expires_at else None,
        }
    )


@public_api_endpoint
@api_view(["POST"])
@authentication_classes([])  # No DRF authentication - credential auth performed in the view
@permission_classes([AllowAny])
@throttle_classes([AuthThrottle, TokenRequestAccountThrottle])
def obtain_token(request: HttpRequest) -> Response:
    """
    🔐 Obtain authentication token for API access -- intentionally public.

    Token auth requires email/password credentials, no HMAC needed. For CLI tools and
    scripts; the Portal never calls it (it signs every request with HMAC instead).

    POST /api/users/token/
    {
        "email": "user@example.com",
        "password": "password",
        "mfa_token": "123456",   # required when the account has 2FA: TOTP or backup code
        "name": "ci-pipeline",   # optional label
        "description": "Production deploys",  # optional purpose
        "ttl_days": 30           # optional, clamped to [1, API_TOKEN_MAX_TTL_DAYS]
    }

    Response (raw token shown once, never retrievable again):
    {
        "token": "<40-char-hex-key>",
        "user_id": 123,
        "email": "user@example.com",
        "key_prefix": "<first-8-chars>",
        "name": "ci-pipeline",
        "description": "Production deploys",
        "expires_at": "<iso-8601 or null>"
    }
    """
    # Parameters first, before any credential work: a parameter error that only answered
    # after a correct password would confirm the password, and one found after the second
    # factor would waste a spent backup code.
    params = TokenObtainRequestSerializer(data=request.data)
    if not params.is_valid():
        return Response(
            {"error": "Invalid token parameters.", "details": params.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )

    user_or_error = _authenticate_token_request(request)
    if isinstance(user_or_error, Response):
        return user_or_error
    return _issue_token_under_lock(request, user_or_error, params)


@public_api_endpoint
@api_view(["DELETE"])
@authentication_classes([HashedTokenAuthentication])
@permission_classes([IsAuthenticated])
@throttle_classes([BurstAPIThrottle, StandardAPIThrottle])
def revoke_token(request: HttpRequest) -> Response:
    """🗑️ Revoke the caller's own authentication token -- public to a bare token (#569).

    Exempt from the HMAC gate so a token holder can revoke the key it holds. It reaches
    only ``request.auth``, the token that authenticated this request. The deletion is
    audited by the APIToken ``pre_delete`` signal (ADR-0031, "What a bare token can reach").
    """
    token = request.auth  # Set by HashedTokenAuthentication — no extra DB query needed
    user_email = _mask_email(token.user.email)
    token_label = f"'{token.name}' ({token.key_prefix}\u2026)"
    token.delete()
    logger.info(  # nosemgrep: python-logger-credential-disclosure
        "[Auth] Token %s revoked for: %s", token_label, user_email
    )
    return Response({"message": "Token revoked successfully"})


@public_api_endpoint
@api_view(["GET"])
@authentication_classes([HashedTokenAuthentication])
@permission_classes([IsAuthenticated])
@throttle_classes([BurstAPIThrottle, StandardAPIThrottle])
def token_info(request: HttpRequest) -> Response:
    """
    Return identity of the authenticated token caller -- public to a bare token (#569).

    GET /api/users/token/me/
    Authorization: Bearer <key>   (or Token <key>)

    Designed for CLI tools and scripts to confirm their token is valid and see which
    user it belongs to. Exempt from the HMAC gate, and it reads only the caller's own
    token. Business routes still require the Portal's signature (ADR-0031, "What a bare
    token can reach").
    """
    user = cast(User, request.user)
    token: APIToken = request.auth
    return Response(
        {
            "user_id": user.id,
            "email": user.email,
            "staff_role": user.staff_role,
            "is_active": user.is_active,
            "token_name": token.name,
            "token_description": token.description,
            "key_prefix": token.key_prefix,
            "created_at": token.created_at.isoformat(),
            "expires_at": token.expires_at.isoformat() if token.expires_at else None,
            "last_used_at": token.last_used_at.isoformat() if token.last_used_at else None,
        }
    )


@api_view(["GET"])
@authentication_classes([])  # No DRF authentication - HMAC handled by middleware + secure_auth
@permission_classes([AllowAny])  # HMAC auth handled by secure_auth
@require_customer_authentication
def verify_token(request: HttpRequest, customer: Customer) -> Response:
    """
    ✅ Verify token is valid and get user info

    GET /api/users/token/verify/
    Requires customer authentication via HMAC.

    Response:
    {
        "user_id": 123,
        "email": "user@example.com",
        "is_staff": false,
        "accessible_customers": [1, 2, 3]
    }
    """
    # Get the user from the customer context (since this is a customer-authenticated endpoint)
    membership = CustomerMembership.objects.filter(customer=customer).first()
    if not membership:
        return Response(
            {"success": False, "error": "No user associated with this customer"}, status=status.HTTP_400_BAD_REQUEST
        )

    user = membership.user

    # Get accessible customers for this user
    accessible_customers = user.get_accessible_customers()
    customer_ids = []

    if hasattr(accessible_customers, "values_list"):  # QuerySet
        customer_ids = list(accessible_customers.values_list("id", flat=True))
    elif accessible_customers:  # List
        customer_ids = [c.id for c in accessible_customers]

    logger.info(f"✅ [Auth] Token verified for user: {user.email}")

    return Response(
        {
            "user_id": user.id,
            "email": user.email,
            "is_staff": user.is_staff,
            "accessible_customers": customer_ids,
            "full_name": f"{user.first_name} {user.last_name}".strip() or user.email,
        }
    )


# ===============================================================================
# SECURE SESSION VALIDATION - HMAC-SIGNED CONTEXT (NO JWT) 🔒
# ===============================================================================


class SessionValidationThrottle(EndpointRateThrottle):
    """Per-portal endpoint throttle for session validation."""

    scope = "session_validation"


@never_cache  # nosemgrep: no-csrf-exempt — HMAC-authenticated inter-service endpoint
@csrf_exempt
@api_view(["POST"])
@authentication_classes([])  # No DRF authentication - HMAC handled by middleware
@permission_classes([AllowAny])  # HMAC authentication via @require_portal_authentication below
@throttle_classes([PortalHMACRateThrottle, PortalHMACBurstThrottle, SessionValidationThrottle])
@require_portal_authentication
def validate_session_secure(request: HttpRequest) -> Response:  # noqa: PLR0911 -- distinct session rejection paths
    """

    🔒 SECURE Session Validation - HMAC-Signed Context (No JWT)

    Endpoint: POST /api/users/session/validate/
    Auth: HMAC headers with user context in request body

    Request Body:
    {
        "user_id": "2",
        "session_auth_hash": "<session auth hash returned by login>",
        "timestamp": 1694022337

    }

    Headers:
        X-Portal-Id: portal-001
        X-Nonce: <unique nonce>
        X-Timestamp: <unix timestamp>
        X-Signature: <HMAC signature covering body + headers>

    Response: {
        "active": true,
        "membership_hash": "a1b2c3...",
        "session_auth_hash": "<current session auth hash>",
        "revoke_before": "..."
    }

    Security Features:

    - No user IDs in URL (prevents enumeration)
    - HMAC-signed request body (simpler than JWT)
    - Rate limiting (60/min per portal)
    - Uniform error responses
    - No PII in logs
    """

    # Security headers
    security_headers = {
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
        "X-Content-Type-Options": "nosniff",
    }

    try:
        # Extract portal ID for logging (no PII)
        portal_id = request.headers.get("X-Portal-Id", "unknown")
        jti = request.headers.get("X-Nonce", "unknown")[:8]  # First 8 chars only

        # NOTE: HMAC validation happens in middleware - if we reach here, request is authenticated

        # Parse request body for user context
        try:
            request_data = request.data if hasattr(request, "data") else json.loads(request.body)
            user_id = request_data.get("user_id")
            session_auth_hash = request_data.get("session_auth_hash")
            request_timestamp = request_data.get("timestamp")

            if not user_id:
                logger.warning(f"🚨 [Security] Portal {portal_id} missing user_id in context")
                return _uniform_session_error(security_headers)

            # Basic timestamp freshness check (within 5 minutes)
            current_time = int(datetime.now(UTC).timestamp())
            # Allow 2s forward skew for NTP jitter between portal and platform clocks.
            if not (-HMAC_NTP_SKEW_SECONDS <= (current_time - request_timestamp) <= HMAC_TIMESTAMP_WINDOW_SECONDS):
                logger.warning(f"🚨 [Security] Portal {portal_id} stale timestamp in context")
                return _uniform_session_error(security_headers)

        except (json.JSONDecodeError, TypeError, AttributeError):
            logger.warning(f"🚨 [Security] Portal {portal_id} invalid request body format")
            return _uniform_session_error(security_headers)

        # Validate user exists and is active
        try:
            # Joined: the hash below reads credential_version on every Portal request (#553).
            user = User.objects.select_related("credential_version").get(id=user_id, is_active=True)
            current_auth_hash = user.get_session_auth_hash()
            if not isinstance(session_auth_hash, str) or not (
                constant_time_compare(session_auth_hash, current_auth_hash)
                or any(
                    constant_time_compare(session_auth_hash, fallback_hash)
                    for fallback_hash in user.get_session_auth_fallback_hash()
                )
            ):
                logger.warning("🚨 [Security] Portal %s session credential rejected (jti: %s)", portal_id, jti)
                return _uniform_session_error(security_headers)

            # Compute a stable hash of the user's active memberships so Portal

            # can detect changes (role grant/revoke) without polling.
            # Truncated to 64 bits — sufficient for change detection (not a security boundary).
            memberships = (
                CustomerMembership.objects.filter(user=user, is_active=True)
                .order_by("customer_id")
                .values_list("customer_id", "role")
            )
            hash_input = ",".join(f"{cid}:{role}" for cid, role in memberships)
            membership_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:16]

            # Success - calculate next validation time
            next_validation = datetime.now(UTC) + timedelta(minutes=10)

            logger.info(f"✅ [Security] Portal {portal_id} session validated (jti: {jti})")

            response_data = {
                "active": True,
                "session_auth_hash": current_auth_hash,
                "membership_hash": membership_hash,
                "localisation_preferences": user_localisation_preferences(user),
                "revoke_before": next_validation.isoformat(),
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


def _uniform_session_error(headers: dict[str, Any]) -> Response:
    """Uniform 401 response to prevent information leakage"""
    response_data = {"active": False, "error": "Session validation failed"}

    response = Response(response_data, status=status.HTTP_401_UNAUTHORIZED)
    for key, value in headers.items():
        response[key] = value
    return response


# ===============================================================================
# MULTI-FACTOR AUTHENTICATION ENDPOINTS 📱
# ===============================================================================


@api_view(["POST"])
@authentication_classes([])  # No DRF authentication - HMAC handled by middleware + secure_auth
@permission_classes([AllowAny])  # HMAC auth handled by secure_auth
@require_user_authentication
def mfa_setup_api(request: HttpRequest, user: User) -> Response:
    """Initialize only the signed user's TOTP secret; enrollment requires verification."""
    with transaction.atomic():
        user = User.objects.select_for_update().get(pk=user.pk)
        if user.mfa_enabled:
            return Response({"success": False, "error": "MFA is already enabled"}, status=400)
        serializer = MFASetupSerializer(data={}, context={"request": request, "user": user})
        serializer.is_valid(raise_exception=True)
        result = serializer.save()
    return Response({"success": True, "setup_data": result})


@api_view(["POST"])
@authentication_classes([])  # No DRF authentication - HMAC handled by middleware + secure_auth
@permission_classes([AllowAny])  # HMAC auth handled by secure_auth
@require_user_authentication
def mfa_verify_api(request: HttpRequest, user: User) -> Response:
    """Complete enrollment and return plaintext recovery codes exactly once."""
    with transaction.atomic():
        user = User.objects.select_for_update().get(pk=user.pk)
        if user.mfa_enabled:
            return Response({"success": False, "error": "MFA is already enabled"}, status=400)
        serializer = MFAVerifySerializer(data=request.data, context={"request": request, "user": user})
        serializer.is_valid(raise_exception=True)
        result = serializer.save()
        result["session_auth_hash"] = user.get_session_auth_hash()
    return Response(result)


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_user_authentication
def mfa_disable_api(request: HttpRequest, user: User) -> Response:
    """Require current password and a second factor before removing MFA."""
    with transaction.atomic():
        user = User.objects.select_for_update().get(pk=user.pk)
        serializer = MFADisableSerializer(data=request.data, context={"request": request, "user": user})
        serializer.is_valid(raise_exception=True)
        result = serializer.save()
        result["session_auth_hash"] = user.get_session_auth_hash()
        return Response(result)


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_user_authentication
def mfa_status_api(request: HttpRequest, user: User) -> Response:
    """Return status for the signed user without exposing recovery secrets."""
    return Response(
        {
            "success": True,
            "enabled": user.mfa_enabled,
            "backup_codes_remaining": len(user.backup_tokens) if user.mfa_enabled else 0,
        }
    )


# ===============================================================================
# PASSWORD RESET ENDPOINTS 🔑
# ===============================================================================


@api_view(["POST"])
@authentication_classes([])  # HMAC authentication is handled by middleware and the decorator.
@permission_classes([AllowAny])
@throttle_classes(
    [PortalHMACRateThrottle, PortalHMACBurstThrottle, ResetClientIPThrottle, CustomerRateThrottle, BurstRateThrottle]
)
@require_portal_authentication
def password_reset_request_api(request: HttpRequest) -> Response:
    """
    Request a customer password reset through an HMAC-signed Portal call.

    Email links use the configured public Portal URL. Accepted requests
    keep a neutral response whether or not the account exists or email is delivered.

    POST /api/users/password/reset/
    {
        "email": "user@example.com"
    }

    Queues the reset mail for every address; a worker sends it if the account is active.
    Responses and the request's work do not disclose account or delivery status. Delivery
    and configuration failures remain in private error logs.

    Response:
    {
        "success": true,
        "message": "If an eligible account exists and email delivery is available, ..."
    }
    """

    serializer = PasswordResetRequestSerializer(data=request.data)

    if serializer.is_valid():
        try:
            result = serializer.save()
            return Response(result)

        except Exception as e:
            logger.error("🔥 [Password Reset] Request failed (%s): %s", type(e).__name__, e)
            # A configuration or queue failure gets the same answer as everything else.
            return Response(PasswordResetRequestSerializer.accepted_response())
    else:
        return Response(
            {"success": False, "error": "Invalid email address", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )


@api_view(["POST"])
@authentication_classes([])  # HMAC authentication is handled by middleware and the decorator.
@permission_classes([AllowAny])
@throttle_classes(
    [
        PortalHMACRateThrottle,
        PortalHMACBurstThrottle,
        RegistrationConfirmClientIPThrottle,
        CustomerRateThrottle,
        BurstRateThrottle,
    ]
)
@require_portal_authentication
def registration_confirm_api(request: HttpRequest) -> Response:
    """
    Finish a pending registration through an HMAC-signed Portal call.

    The link's token proves the caller holds the mailbox; the password is chosen here.

    POST /api/users/register/confirm/
    {
        "registration_id": "<uuid>",
        "token": "<hex>",
        "password": "...",
        "password_confirm": "...",
        "data_processing_consent": true,
        "marketing_consent": false
    }

    201 on success. 400 `invalid_link` for a link that is wrong, used or expired; 400
    `validation_failed` for the form or a rejected password; 409 `details_unavailable` when the
    email or company was taken meanwhile; 503 when the account could not be created now.
    """
    from apps.users import registration_confirmation  # noqa: PLC0415  # Deferred: users services import cycle

    serializer = RegistrationConfirmSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(
            {"success": False, "code": "validation_failed", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )
    data = serializer.validated_data
    try:
        result = registration_confirmation.confirm(
            str(data["registration_id"]),
            data["token"],
            data["password"],
            accepts_marketing=data["marketing_consent"],
            data_processing_consent=data["data_processing_consent"],
            request_ip=forwarded_client_ip(request),
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
        )
    except Exception:
        logger.exception("🔥 [Registration] Confirmation unavailable")
        result = None

    if result is not None and result.is_ok():
        user, _customer = result.unwrap()
        logger.info("✅ [Registration] Pending registration confirmed for user %s", user.pk)
        return Response({"success": True, "email": user.email}, status=status.HTTP_201_CREATED)

    refusal = None if result is None else result.unwrap_err()
    code = "unavailable" if refusal is None else refusal.code
    answers: dict[str, tuple[int, dict[str, Any]]] = {
        "invalid_link": (
            status.HTTP_400_BAD_REQUEST,
            {"code": "invalid_link", "error": _("This link has expired or was already used.")},
        ),
        "consent_required": (
            status.HTTP_400_BAD_REQUEST,
            {
                "code": "validation_failed",
                "errors": {"data_processing_consent": [_("Data processing consent is required.")]},
            },
        ),
        "password_rejected": (
            status.HTTP_400_BAD_REQUEST,
            {"code": "validation_failed", "errors": {"password": [] if refusal is None else refusal.messages}},
        ),
        "details_unavailable": (
            status.HTTP_409_CONFLICT,
            {
                "code": "details_unavailable",
                "error": _("These details are no longer available. Please register again."),
            },
        ),
        "unavailable": (
            status.HTTP_503_SERVICE_UNAVAILABLE,
            {"code": "unavailable", "error": _("Your account could not be created right now. Please try again.")},
        ),
    }
    answer_status, payload = answers[code]
    return Response({"success": False, **payload}, status=answer_status)


@api_view(["POST"])
@authentication_classes([])  # HMAC authentication is handled by middleware and the decorator.
@permission_classes([AllowAny])
@throttle_classes(
    [PortalHMACRateThrottle, PortalHMACBurstThrottle, ResetClientIPThrottle, CustomerRateThrottle, BurstRateThrottle]
)
@require_portal_authentication
def password_reset_confirm_api(request: HttpRequest) -> Response:
    """
    Confirm a customer password reset through an HMAC-signed Portal call.

    The reset token proves possession of the email account. Invalid tokens
    and rejected passwords return validation errors before any mutation.

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

    serializer = PasswordResetConfirmSerializer(data=request.data, context={"request": request})

    if serializer.is_valid():
        try:
            result = serializer.save()

            # Log successful password reset
            user = serializer.validated_data["uid"]
            logger.info(f"✅ [Password Reset] Password reset completed for user: {user.email}")

            return Response(result)

        except InvalidPasswordResetLink:
            return Response(
                {"success": False, "code": "invalid_reset_link", "error": "Invalid or expired reset link."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except APIValidationError as exc:
            return Response(
                {"success": False, "code": "validation_failed", "errors": exc.detail},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception:
            logger.exception("🔥 [Password Reset] Confirmation unavailable")
            return Response(
                {"success": False, "error": "Password reset failed. Please try again."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
    else:
        code = (
            "invalid_reset_link" if "uid" in serializer.errors or "token" in serializer.errors else "validation_failed"
        )
        return Response(
            {"success": False, "code": code, "error": "Validation failed", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )


# ===============================================================================
# PROFILE UPDATE API
# ===============================================================================


@api_view(["POST", "PUT"])
@authentication_classes([])  # No DRF authentication - HMAC handled by middleware + secure_auth
@permission_classes([AllowAny])  # HMAC auth handled by secure_auth
@require_user_authentication
def customer_profile_api(request: HttpRequest, user: User) -> Response:
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
        if request.method == "POST":  # Changed from GET to POST for security
            # Return profile data
            profile_data = {
                "id": user.id,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "phone": user.phone or "",
                "mfa_enabled": user.mfa_enabled,
                "backup_codes_count": len(user.backup_tokens),
                "date_joined": user.date_joined.isoformat() if user.date_joined else None,
            }

            # Add profile data (create default if doesn't exist)
            profile, created = UserProfile.objects.get_or_create(user=user)

            if created:
                logger.info(f"✅ [Profile API] Created default profile for customer: {user.email}")

            preferences = user_localisation_preferences(user)
            display = resolve_display(get_localisation_defaults(), preferences)
            profile_data["profile"] = {
                "preferred_language": display.language,
                "timezone": display.timezone,
                "date_format": display.date_format,
                "localisation_preferences": preferences,
                "email_notifications": profile.email_notifications,
                "sms_notifications": profile.sms_notifications,
                "marketing_emails": profile.marketing_emails,
            }

            return Response({"success": True, "profile": profile_data})

        elif request.method == "PUT":
            # Get profile data from HMAC-signed request body
            request_data = request.data if hasattr(request, "data") else {}

            serializer = ProfileUpdateSerializer(data=request_data)
            if not serializer.is_valid():
                return Response({"success": False, "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
            serializer.update(user, serializer.validated_data)
            logger.info(f"✅ [Profile API] Updated profile for customer: {user.email}")

            return Response({"success": True, "message": "Profile updated successfully"})

    except Exception as e:
        logger.error(f"🔥 [Profile API] Unexpected error: {e}")
        return Response(
            {"success": False, "error": "Profile service unavailable"}, status=status.HTTP_503_SERVICE_UNAVAILABLE
        )


# ===============================================================================
# ACCESSIBLE CUSTOMERS FOR USER (HMAC-SIGNED) 👥
# ===============================================================================


@api_view(["POST"])
@authentication_classes([])  # HMAC handled by middleware + secure_auth
@permission_classes([AllowAny])
# #277 follow-up: the PortalHMAC* throttles return None for non-portal traffic, so an
# unsigned caller reaches this endpoint's HMAC-rejection path unthrottled (DRF runs
# throttles before @require_user_authentication). CustomerRateThrottle/BurstRateThrottle
# key anonymous traffic by client IP while deferring to the portal limits for signed
# traffic, restoring the DEFAULT_THROTTLE_CLASSES anonymous fallback.
@throttle_classes([PortalHMACRateThrottle, PortalHMACBurstThrottle, CustomerRateThrottle, BurstRateThrottle])
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
        # Get customer memberships with role information
        memberships = CustomerMembership.objects.filter(user=user).select_related("customer")

        results = []
        for membership in memberships:
            customer = membership.customer
            results.append(
                {
                    "id": customer.id,
                    "company_name": getattr(customer, "company_name", ""),
                    "name": getattr(customer, "name", ""),
                    "role": membership.role,  # Include the actual role
                    "is_primary": membership.is_primary,
                }
            )

        return Response({"success": True, "results": results})
    except Exception as e:
        logger.error(f"🔥 [User Customers API] Error fetching customers for {getattr(user, 'email', 'unknown')}: {e}")
        return Response({"success": False, "error": "Unable to fetch customers"}, status=500)


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_user_authentication
def verify_customer_access_api(request: HttpRequest, user: User) -> Response:
    """Verify current membership before the Portal changes its selected customer."""
    try:
        customer_id = int(request.data.get("customer_id", ""))
    except (TypeError, ValueError):
        return Response({"success": False, "error": "Invalid customer ID"}, status=400)
    membership = (
        CustomerMembership.objects.filter(user=user, customer_id=customer_id, is_active=True, customer__status="active")
        .select_related("customer")
        .first()
    )
    data: dict[str, Any] = {"has_access": False}
    if membership:
        data = {"has_access": True, "customer_name": membership.customer.name, "role": membership.role}
    return Response({"success": True, "data": data})


@api_view(["PUT"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_user_authentication
def password_change_api(request: HttpRequest, user: User) -> Response:
    """Change the signed user's password after reauthentication on the Platform."""
    current = request.data.get("current_password")
    new_password = request.data.get("new_password")
    if not isinstance(current, str) or not isinstance(new_password, str):
        return Response({"success": False, "error": "Current and new passwords are required"}, status=400)
    with transaction.atomic():
        user = User.objects.select_for_update().get(pk=user.pk)
        if user.is_account_locked() or not user.check_password(current):
            user.increment_failed_login_attempts()
            return Response({"success": False, "error": "Current password is incorrect"}, status=400)
        try:
            validate_password(new_password, user=user)
        except DjangoValidationError as exc:
            return Response({"success": False, "errors": exc.messages}, status=400)
        if (
            user.mfa_enabled
            and not MFAService.verify_mfa_code(user, str(request.data.get("token", "")), request)["success"]
        ):
            return Response({"success": False, "error": "Invalid authentication code"}, status=400)
        user.set_password(new_password)
        user.save(update_fields=["password"])
        SessionSecurityService.invalidate_all_sessions_for_user(user.id)
        log_security_event("portal_password_changed", {"user_id": user.id}, get_safe_client_ip(request))
    return Response({"success": True, "session_auth_hash": user.get_session_auth_hash()})


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_user_authentication
def mfa_regenerate_backup_codes_api(request: HttpRequest, user: User) -> Response:
    """Replace recovery codes only after password and second-factor verification."""
    with transaction.atomic():
        user = User.objects.select_for_update().get(pk=user.pk)
        # Reuse the credential validation, without executing the disable operation.
        serializer = MFADisableSerializer(data=request.data, context={"request": request, "user": user})
        serializer.is_valid(raise_exception=True)
        codes = user.generate_backup_codes()
    return Response({"success": True, "backup_codes": codes})
