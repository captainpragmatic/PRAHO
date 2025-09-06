"""
Portal Authentication Middleware
Production-ready two-tier validation with jitter, single-flight locks, and stale-while-revalidate.
"""

import logging
import random
import time
from datetime import datetime, timedelta, timezone
from django.shortcuts import redirect
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse
from django.utils import timezone as django_timezone

from apps.api_client.services import api_client, PlatformAPIError

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
    HARD_TTL_GRACE = 900   # 15 minutes hard grace period (force logout after this)
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Skip authentication for public URLs
        if self.is_public_url(request.path):
            return self.get_response(request)
        
        # Tier 1: Fast session check
        customer_id = request.session.get('customer_id')
        if not customer_id:
            logger.debug("🔒 [Auth] No customer_id in session, redirecting to login")
            return redirect('/login/')
        
        # Tier 2: Sophisticated validation with timing controls
        validation_result = self.validate_customer_with_timing(request, customer_id)
        
        if not validation_result:
            logger.warning(f"⚠️ [Auth] Customer {customer_id} validation failed, clearing session")
            request.session.flush()
            return redirect('/login/')
        
        # Attach customer data to request for views
        request.customer_id = customer_id
        request.customer_email = request.session.get('email')
        request.is_authenticated = True
        
        return self.get_response(request)
    
    def is_public_url(self, path: str) -> bool:
        """Check if path requires authentication."""
        return any(path.startswith(public_url) for public_url in self.PUBLIC_URLS)
    
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