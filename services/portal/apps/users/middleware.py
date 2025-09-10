"""
Portal Authentication Middleware
Production-ready two-tier validation with jitter, single-flight locks, and stale-while-revalidate.
"""

import logging
import random
import time
from datetime import datetime, timedelta

from django.conf import settings
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.utils import timezone as django_timezone
from django.utils.http import urlencode

from apps.api_client.services import PlatformAPIError, api_client

logger = logging.getLogger(__name__)


class PortalAuthenticationMiddleware:
    """
    Production-ready authentication middleware with sophisticated caching patterns.
    
    Architecture:
    - Tier 1: Fast session check (zero latency)
    - Tier 2: Jittered periodic validation with single-flight locks
    - Stale-while-revalidate: Soft/hard TTL boundaries
    - Thundering herd protection: Single validation per customer at a time
    - Fail-open windows: Graceful degradation when Platform is unavailable
    """
    
    # Public URLs that don't require authentication
    PUBLIC_URLS = [
        '/login/',
        '/logout/', 
        '/register/',
        '/password-reset/',
        '/static/',
        '/media/',
        '/status/',
        '/favicon.ico',
    ]
    
    # Validation timing configuration
    REVALIDATE_EVERY = 600  # 10 minutes base interval
    JITTER_MAX = 120       # 0-2 minutes random jitter
    VALIDATION_TIMEOUT = 30  # Single-flight lock timeout
    SOFT_TTL_GRACE = 300   # 5 minutes soft grace period (stale-while-revalidate)
    HARD_TTL_GRACE = 21600   # 6 hours hard grace period (force logout after this)
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Skip authentication for public URLs
        if self.is_public_url(request.path):
            # Add an anonymous user for Django auth compatibility
            class AnonymousUser:
                id = None
                email = None
                is_authenticated = False
                is_active = False
                is_staff = False
                is_superuser = False
                
                def __str__(self):
                    return "AnonymousUser"
            
            request.user = AnonymousUser()
            return self.get_response(request)
        
        # Tier 1: Fast session check with age validation
        # Historically, 'customer_id' in session stored the platform user_id.
        # We normalize here: ensure we have a user_id and derive an active customer_id.
        session_user_id = request.session.get('user_id') or request.session.get('customer_id')
        if not session_user_id:
            logger.debug("🔒 [Auth] No customer_id in session, redirecting to login")
            return self.redirect_to_login(request)
            
        # Check if session has exceeded its intended lifetime
        if not self._is_session_age_valid(request):
            logger.warning(f"⏰ [Auth] Session for user {session_user_id} has exceeded lifetime, forcing logout")
            request.session.flush()
            return self.redirect_to_login(request)
        
        # Tier 2: Sophisticated validation with timing controls
        validation_result = self.validate_customer_with_timing(request, str(session_user_id))
        
        if not validation_result:
            logger.warning(f"⚠️ [Auth] User {session_user_id} validation failed, clearing session")
            request.session.flush()
            return self.redirect_to_login(request)
        
        # Attach customer data to request for views
        # Resolve active customer context for this user (first accessible if not set)
        active_customer_id = request.session.get('active_customer_id')
        try:
            user_id_int = int(session_user_id)
        except (TypeError, ValueError):
            user_id_int = None

        if user_id_int and not active_customer_id:
            try:
                customers = api_client.get_user_customers(user_id_int)
                if customers:
                    active_customer_id = customers[0].get('id')
                    request.session['active_customer_id'] = active_customer_id
                else:
                    # No accessible customers for this user; leave active_customer_id unset
                    active_customer_id = None
            except Exception as e:
                logger.error(f"🔥 [Auth] Failed to fetch accessible customers for user {session_user_id}: {e}")

        request.customer_id = active_customer_id or request.session.get('customer_id')
        request.user_id = session_user_id
        request.customer_email = request.session.get('email')
        request.is_authenticated = True
        
        # Create a simple user-like object for Django auth compatibility
        class PortalUser:
            def __init__(self, user_id: str, email: str):
                self.id = user_id
                self.email = email
                self.is_authenticated = True
                self.is_active = True
                self.is_staff = False
                self.is_superuser = False
            
            def __str__(self):
                return self.email or f"customer_{self.id}"
        
        request.user = PortalUser(str(session_user_id), request.session.get('email', ''))
        
        return self.get_response(request)
    
    def is_public_url(self, path: str) -> bool:
        """Check if path requires authentication."""
        return any(path.startswith(public_url) for public_url in self.PUBLIC_URLS)
    
    def redirect_to_login(self, request: HttpRequest) -> HttpResponse:
        """Redirect to login preserving the originally requested URL."""
        login_url = '/login/'
        if request.path and request.path != '/':
            # Add the current path as the next parameter
            params = urlencode({'next': request.get_full_path()})
            login_url = f'{login_url}?{params}'
        return redirect(login_url)
    
    def validate_customer_with_timing(self, request: HttpRequest, customer_id: str) -> bool:
        """
        Sophisticated validation with jitter, single-flight locks, and stale-while-revalidate.
        
        Session validation fields:
        - validated_at: Last successful validation timestamp
        - next_validate_at: When next validation should occur (with jitter)
        - state_version: Incrementing version for cache invalidation
        - session_created_at: When session was first created
        """
        now = django_timezone.now()
        
        # Get or initialize session validation metadata
        validated_at = self._get_session_datetime(request, 'validated_at')
        next_validate_at = self._get_session_datetime(request, 'next_validate_at')
        state_version = request.session.get('state_version', 1)
        session_created_at = self._get_session_datetime(request, 'session_created_at', now)
        
        # Initialize session metadata if missing
        if not validated_at or not next_validate_at:
            # Fresh session - validate immediately but set next validation with jitter
            request.session['session_created_at'] = session_created_at.isoformat()
            next_validate_at = self._calculate_next_validation_time(now)
            request.session['next_validate_at'] = next_validate_at.isoformat()
            return self._perform_validation(request, customer_id, now, state_version)
        
        # Check if we're within soft TTL (no validation needed)
        if now <= next_validate_at:
            logger.debug(f"✅ [Auth] Customer {customer_id} within soft TTL, skipping validation")
            return True
        
        # Check if we're within soft grace period (stale-while-revalidate)
        soft_deadline = next_validate_at + timedelta(seconds=self.SOFT_TTL_GRACE)
        if now <= soft_deadline:
            # Try to revalidate in background, but allow request through
            if self._should_revalidate_async(customer_id):
                self._perform_validation(request, customer_id, now, state_version)
            return True
        
        # Check if we're within hard grace period (force validation)
        hard_deadline = next_validate_at + timedelta(seconds=self.HARD_TTL_GRACE)
        if now <= hard_deadline:
            logger.info(f"⏰ [Auth] Customer {customer_id} past soft TTL, forcing validation")
            return self._perform_validation(request, customer_id, now, state_version)
        
        # Past hard deadline - force logout for security
        logger.warning(f"🚨 [Auth] Customer {customer_id} past hard TTL deadline, forcing logout")
        return False
    
    def _get_session_datetime(self, request: HttpRequest, key: str, default=None) -> datetime:
        """Get datetime from session, handling ISO format conversion."""
        value = request.session.get(key)
        if value:
            try:
                return datetime.fromisoformat(value.replace('Z', '+00:00'))
            except (ValueError, AttributeError):
                pass
        return default
    
    def _calculate_next_validation_time(self, now: datetime) -> datetime:
        """Calculate next validation time with jitter to prevent thundering herd."""
        jitter_seconds = random.randint(0, self.JITTER_MAX)
        return now + timedelta(seconds=self.REVALIDATE_EVERY + jitter_seconds)
    
    def _should_revalidate_async(self, customer_id: str) -> bool:
        """
        Check if we should perform async revalidation using single-flight lock.
        Prevents multiple concurrent validations for the same customer.
        """
        lock_key = f"validating:{customer_id}"
        validating_until = cache.get(lock_key)
        
        if validating_until and time.time() < validating_until:
            # Another request is already validating, skip
            logger.debug(f"🔄 [Auth] Customer {customer_id} validation already in progress, skipping")
            return False
        
        # Acquire single-flight lock
        cache.set(lock_key, time.time() + self.VALIDATION_TIMEOUT, timeout=self.VALIDATION_TIMEOUT)
        return True
    
    def _perform_validation(self, request: HttpRequest, customer_id: str, now: datetime, state_version: int) -> bool:
        """
        Perform actual Platform API validation and update session metadata.
        """
        try:
            # Call secure Platform API validation (HMAC-signed, no ID enumeration)
            validation_response = api_client.validate_session_secure(customer_id, state_version)
            is_valid = validation_response and validation_response.get('active', False)
            
            if is_valid:
                # Update session with successful validation
                request.session['validated_at'] = now.isoformat()
                request.session['next_validate_at'] = self._calculate_next_validation_time(now).isoformat()
                request.session['state_version'] = state_version + 1
                request.session.modified = True
                
                logger.debug(f"✅ [Auth] Customer {customer_id} validated successfully")
                return True
            else:
                logger.warning(f"❌ [Auth] Customer {customer_id} validation failed - account disabled/deleted")
                return False
                
        except PlatformAPIError as e:
            logger.error(f"🔥 [Auth] Platform API error during validation for {customer_id}: {e}")
            
            # Fail-open strategy: Allow access during API outages but don't update metadata
            # This provides availability during platform maintenance windows
            logger.info(f"🛡️ [Auth] Failing open for customer {customer_id} due to API unavailability")
            return True
        
        except Exception as e:
            logger.error(f"🔥 [Auth] Unexpected validation error for {customer_id}: {e}")
            # Fail-open for unexpected errors too
            return True
    
    def _is_session_age_valid(self, request: HttpRequest) -> bool:
        """
        Validate that the session hasn't exceeded its intended lifetime based on 'remember_me' setting.
        
        Returns:
            bool: True if session is within its intended lifetime, False if expired
        """
        authenticated_at_str = request.session.get('authenticated_at')
        remember_me = request.session.get('remember_me', False)
        
        if not authenticated_at_str:
            logger.warning("⚠️ [Auth] No authenticated_at timestamp in session")
            return False
            
        try:
            authenticated_at = datetime.fromisoformat(authenticated_at_str.replace('Z', '+00:00'))
        except (ValueError, AttributeError) as e:
            logger.error(f"🔥 [Auth] Invalid authenticated_at format in session: {e}")
            return False
        
        # Calculate intended session lifetime
        if remember_me:
            max_age_seconds = getattr(settings, 'SESSION_COOKIE_AGE_REMEMBER_ME', 30 * 24 * 60 * 60)  # 30 days
            session_type = "extended (30 days)"
        else:
            max_age_seconds = getattr(settings, 'SESSION_COOKIE_AGE_DEFAULT', 24 * 60 * 60)  # 24 hours
            session_type = "standard (24 hours)"
        
        # Check if session has exceeded its intended lifetime
        now = django_timezone.now()
        session_age = (now - authenticated_at).total_seconds()
        
        if session_age > max_age_seconds:
            customer_id = request.session.get('customer_id', 'unknown')
            logger.warning(f"⏰ [Auth] {session_type} session for customer {customer_id} has exceeded lifetime "
                         f"({session_age:.0f}s > {max_age_seconds:.0f}s)")
            return False
        
        logger.debug(f"✅ [Auth] {session_type} session is within valid lifetime "
                    f"({session_age:.0f}s / {max_age_seconds:.0f}s)")
        return True
