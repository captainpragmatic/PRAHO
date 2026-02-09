"""
Order-Specific Security Hardening for PRAHO Portal
DoS protection and uniform response timing for order endpoints.
"""

import logging
import random
import time

from django.core.cache import cache
from django.http import JsonResponse
from django.utils.translation import gettext as _

logger = logging.getLogger(__name__)


class OrderSecurityHardening:
    """🔒 DoS protection and timing attack prevention for order system"""
    
    # Response timing constants
    MIN_RESPONSE_TIME = 0.1  # 100ms minimum response time
    MAX_RESPONSE_TIME = 0.3  # 300ms maximum response time
    
    # Cache failure handling
    CACHE_FAILURE_BLOCK_TIME = 300  # 5 minutes when cache fails
    
    @staticmethod
    def uniform_response_delay() -> None:
        """
        🔒 SECURITY: Add uniform delay to prevent timing-based information disclosure.
        Reduces probing signal by making all responses take similar time.
        """
        delay = random.uniform(
            OrderSecurityHardening.MIN_RESPONSE_TIME,
            OrderSecurityHardening.MAX_RESPONSE_TIME
        )
        time.sleep(delay)
    
    @staticmethod  
    def fail_closed_on_cache_failure(cache_key: str, operation: str) -> JsonResponse | None:
        """
        🔒 SECURITY: Fail closed when cache is unavailable.
        Prevents unlimited traffic when rate limiting fails.
        
        Args:
            cache_key: Cache key being accessed
            operation: Description of operation for logging
            
        Returns:
            JsonResponse with 503 error if cache is down, None if cache is working
        """
        try:
            # Test cache availability with a simple operation
            cache.set(f'cache_test_{cache_key}', 1, timeout=1)
            cache.get(f'cache_test_{cache_key}')
            return None  # Cache is working
            
        except Exception as e:
            logger.error(f"🔥 [Security] Cache failure detected for {operation}: {e}")
            
            # Fail closed - block traffic rather than allow unlimited access
            OrderSecurityHardening.uniform_response_delay()  # Still apply delay
            
            return JsonResponse({
                'error': _('Serviciul este temporar indisponibil. Vă rugăm încercați din nou.'),
                'retry_after': OrderSecurityHardening.CACHE_FAILURE_BLOCK_TIME
            }, status=503)
    
    @staticmethod
    def validate_request_size(request, max_size_bytes: int = 10240) -> JsonResponse | None:
        """
        🔒 SECURITY: Validate request body size to prevent DoS via large payloads.
        
        Args:
            request: Django request object
            max_size_bytes: Maximum allowed request size (default 10KB)
            
        Returns:
            JsonResponse with 413 error if too large, None if size is acceptable
        """
        content_length = request.META.get('CONTENT_LENGTH')
        
        if content_length:
            try:
                size = int(content_length)
                if size > max_size_bytes:
                    logger.warning(f"🚨 [Security] Oversized request blocked: {size} bytes")
                    
                    OrderSecurityHardening.uniform_response_delay()
                    
                    return JsonResponse({
                        'error': _('Cererea este prea mare.'),
                    }, status=413)
                    
            except ValueError:
                # Invalid content-length header
                logger.warning(f"🚨 [Security] Invalid Content-Length header: {content_length}")
                return JsonResponse({
                    'error': _('Cererea este invalidă.'),
                }, status=400)
        
        return None
    
    @staticmethod
    def check_suspicious_patterns(request) -> JsonResponse | None:
        """
        🔒 SECURITY: Check for suspicious request patterns that might indicate attacks.
        
        Args:
            request: Django request object
            
        Returns:
            JsonResponse with 400 error if suspicious, None if clean
        """
        # Check for suspiciously large number of form fields
        if hasattr(request, 'POST') and len(request.POST) > 50:
            logger.warning(f"🚨 [Security] Suspicious number of POST fields: {len(request.POST)}")
            
            OrderSecurityHardening.uniform_response_delay()
            
            return JsonResponse({
                'error': _('Cererea conține prea multe câmpuri.'),
            }, status=400)
        
        # Check for suspiciously long individual field values
        if hasattr(request, 'POST'):
            for field_name, field_value in request.POST.items():
                if field_name == 'config':
                    # Large JSON config blobs are handled by total request-size validation (413).
                    continue
                if isinstance(field_value, str) and len(field_value) > 10000:  # 10KB per field
                    logger.warning(f"🚨 [Security] Oversized field blocked: {field_name} ({len(field_value)} chars)")
                    
                    OrderSecurityHardening.uniform_response_delay()
                    
                    return JsonResponse({
                        'error': _('Un câmp din cerere este prea lung.'),
                    }, status=400)
        
        return None
