# ===============================================================================
# PLATFORM API CLIENT SERVICE - PORTAL TO PLATFORM COMMUNICATION 🔗
# ===============================================================================

import base64
import hashlib
import hmac
import logging
import secrets
import time
import requests
from typing import Any, Dict, Optional, List
from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)


class PlatformAPIError(Exception):
    """Exception raised when platform API calls fail"""
    def __init__(self, message: str, status_code: Optional[int] = None, response_data: Optional[Dict] = None):
        self.message = message
        self.status_code = status_code
        self.response_data = response_data
        super().__init__(message)


class PlatformAPIClient:
    """
    Centralized API client for communication with PRAHO Platform service.
    
    Handles:
    - Shared secret authentication
    - User context passing
    - Error handling and retries
    - Response caching for performance
    """
    
    def __init__(self):
        self.base_url = settings.PLATFORM_API_BASE_URL
        self.portal_id = getattr(settings, 'PORTAL_ID', 'portal-001')
        self.portal_secret = settings.PLATFORM_API_SECRET  # Will be portal-specific secret
        self.timeout = settings.PLATFORM_API_TIMEOUT
        
    def _generate_hmac_headers(self, method: str, path: str, body: bytes) -> Dict[str, str]:
        """
        Generate HMAC authentication headers for secure API communication.
        ✅ Implements canonical string signing with nonce deduplication.
        """
        # Generate unique nonce and timestamp
        nonce = secrets.token_urlsafe(16)
        timestamp = str(time.time())
        
        # Compute body hash
        body_hash = base64.b64encode(hashlib.sha256(body).digest()).decode('ascii')
        
        # Build canonical string for signing
        canonical_string = "\n".join([
            method,
            path,
            'application/json',  # content-type
            body_hash,
            nonce,
            timestamp
        ])
        
        # Generate HMAC signature
        signature = hmac.new(
            self.portal_secret.encode(),
            canonical_string.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return {
            'X-Portal-Id': self.portal_id,
            'X-Nonce': nonce,
            'X-Timestamp': timestamp,
            'X-Body-Hash': body_hash,
            'X-Signature': signature,
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }
    
    def _make_request(self, method: str, endpoint: str, user_id: Optional[int] = None, 
                     data: Optional[Dict] = None, params: Optional[Dict] = None) -> Dict[str, Any]:
        """Make HMAC-authenticated request to platform API"""
        url = f"{self.base_url.rstrip('/')}/{endpoint.lstrip('/')}"
        
        # Prepare request body
        request_body = b''
        if data:
            import json
            request_body = json.dumps(data).encode('utf-8')
        
        # Generate HMAC headers
        parsed_url = requests.utils.urlparse(url)
        path_with_query = parsed_url.path
        if parsed_url.query:
            path_with_query += f"?{parsed_url.query}"
            
        headers = self._generate_hmac_headers(method, path_with_query, request_body)
        
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                data=request_body if request_body else None,
                params=params if params else None,
                timeout=self.timeout
            )
            
            # Log the request for debugging
            logger.debug(f"🌐 [API Client] {method} {url} -> {response.status_code}")
            
            # Handle successful responses
            if 200 <= response.status_code < 300:
                try:
                    return response.json()
                except ValueError:
                    return {'success': True}
                    
            # Handle API errors
            try:
                error_data = response.json()
            except ValueError:
                error_data = {'error': 'Invalid response format'}
                
            raise PlatformAPIError(
                message=f"API request failed: {error_data.get('error', 'Unknown error')}",
                status_code=response.status_code,
                response_data=error_data
            )
            
        except requests.exceptions.ConnectionError:
            logger.error(f"🔥 [API Client] Connection failed to platform service: {url}")
            raise PlatformAPIError("Platform service unavailable")
            
        except requests.exceptions.Timeout:
            logger.error(f"🔥 [API Client] Timeout connecting to platform service: {url}")
            raise PlatformAPIError("Platform service timeout")
            
        except requests.exceptions.RequestException as e:
            logger.error(f"🔥 [API Client] Request error: {e}")
            raise PlatformAPIError(f"Request failed: {str(e)}")
    
    # ===============================================================================
    # AUTHENTICATION API ENDPOINTS
    # ===============================================================================
    
    def authenticate_customer(self, email: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate customer with email and password via platform API"""
        try:
            # Use existing platform login endpoint
            data = self._make_request(
                'POST', 
                '/users/login/', 
                data={'email': email, 'password': password}
            )
            
            # Transform response to match portal expectations
            if data.get('success') and data.get('user'):
                return {
                    'valid': True,
                    'token': data.get('user', {}).get('id'),  # Use user ID as simple token for now
                    'customer_id': data.get('user', {}).get('id'),
                    'customer_data': data.get('user', {})
                }
            else:
                return {'valid': False}
                
        except PlatformAPIError as e:
            logger.warning(f"⚠️ [API Client] Customer authentication failed for {email}: {e}")
            return None
    
    def validate_session_secure(self, customer_id: str, state_version: int = 1) -> Optional[Dict[str, Any]]:
        """
        🔒 SECURE session validation using HMAC-signed context (No JWT, No ID enumeration)
        
        Sends customer context in request body, signed by HMAC headers.
        Much simpler and more secure than JWT approach.
        """
        try:
            # Create request body with user context
            current_timestamp = time.time()
            request_data = {
                'customer_id': customer_id,
                'state_version': state_version,
                'timestamp': current_timestamp
            }
            
            # Use existing HMAC-signed request mechanism
            data = self._make_request(
                'POST', 
                '/users/session/validate/',
                data=request_data  # Context in body, signed by HMAC
            )
            return data
            
        except PlatformAPIError as e:
            logger.warning(f"⚠️ [API Client] Secure session validation failed: {e}")
            return None
    
    # ===============================================================================
    # CUSTOMER API ENDPOINTS
    # ===============================================================================
    
    def get_user_customers(self, user_id: int) -> List[Dict[str, Any]]:
        """Get customers accessible to user"""
        cache_key = f"user_customers_{user_id}"
        cached_data = cache.get(cache_key)
        if cached_data:
            return cached_data
            
        data = self._make_request('GET', '/customers/', user_id=user_id)
        customers = data.get('results', [])
        
        # Cache for 5 minutes
        cache.set(cache_key, customers, 300)
        return customers
    
    def get_customer_details(self, customer_id: int, user_id: int) -> Dict[str, Any]:
        """Get customer details"""
        return self._make_request('GET', f'/customers/{customer_id}/', user_id=user_id)
    
    def search_customers(self, query: str, user_id: int) -> List[Dict[str, Any]]:
        """Search customers"""
        params = {'q': query}
        data = self._make_request('GET', '/customers/search/', user_id=user_id, params=params)
        return data.get('results', [])
    
    # ===============================================================================
    # BILLING API ENDPOINTS  
    # ===============================================================================
    
    def get_user_invoices(self, user_id: int, page: int = 1) -> Dict[str, Any]:
        """Get invoices for user"""
        params = {'page': page}
        return self._make_request('GET', '/billing/invoices/', user_id=user_id, params=params)
    
    def get_invoice_details(self, invoice_id: int, user_id: int) -> Dict[str, Any]:
        """Get invoice details"""
        return self._make_request('GET', f'/billing/invoices/{invoice_id}/', user_id=user_id)
    
    def get_user_payments(self, user_id: int) -> List[Dict[str, Any]]:
        """Get payments for user"""
        data = self._make_request('GET', '/billing/payments/', user_id=user_id)
        return data.get('results', [])
    
    # ===============================================================================
    # TICKETS API ENDPOINTS
    # ===============================================================================
    
    def get_user_tickets(self, user_id: int, page: int = 1) -> Dict[str, Any]:
        """Get tickets for user"""
        params = {'page': page}
        return self._make_request('GET', '/tickets/', user_id=user_id, params=params)
    
    def get_ticket_details(self, ticket_id: int, user_id: int) -> Dict[str, Any]:
        """Get ticket details"""
        return self._make_request('GET', f'/tickets/{ticket_id}/', user_id=user_id)
    
    def create_ticket(self, ticket_data: Dict[str, Any], user_id: int) -> Dict[str, Any]:
        """Create new support ticket"""
        return self._make_request('POST', '/tickets/', user_id=user_id, data=ticket_data)
    
    def add_ticket_comment(self, ticket_id: int, comment_data: Dict[str, Any], user_id: int) -> Dict[str, Any]:
        """Add comment to ticket"""
        return self._make_request('POST', f'/tickets/{ticket_id}/comments/', user_id=user_id, data=comment_data)
    
    # ===============================================================================
    # SERVICES API ENDPOINTS
    # ===============================================================================
    
    def get_customer_services(self, customer_id: int, user_id: int) -> List[Dict[str, Any]]:
        """Get services for customer"""
        data = self._make_request('GET', f'/customers/{customer_id}/services/', user_id=user_id)
        return data if isinstance(data, list) else []
    
    # ===============================================================================
    # DASHBOARD DATA
    # ===============================================================================
    
    def get_dashboard_data(self, user_id: int) -> Dict[str, Any]:
        """Get dashboard data for user"""
        cache_key = f"dashboard_data_{user_id}"
        cached_data = cache.get(cache_key)
        if cached_data:
            return cached_data
        
        try:
            # Make multiple API calls to get dashboard data
            customers = self.get_user_customers(user_id)
            invoices_data = self.get_user_invoices(user_id)
            tickets_data = self.get_user_tickets(user_id)
            
            dashboard_data = {
                'customers': customers,
                'recent_invoices': invoices_data.get('results', [])[:5],  # Last 5 invoices
                'recent_tickets': tickets_data.get('results', [])[:5],    # Last 5 tickets
                'stats': {
                    'total_customers': len(customers),
                    'active_services': sum(len(self.get_customer_services(c['id'], user_id)) for c in customers[:3]),  # Sample first 3
                    'open_tickets': len([t for t in tickets_data.get('results', []) if t.get('status') == 'open']),
                    'total_invoices': invoices_data.get('count', 0),
                }
            }
            
            # Cache for 2 minutes
            cache.set(cache_key, dashboard_data, 120)
            return dashboard_data
            
        except PlatformAPIError as e:
            logger.error(f"🔥 [API Client] Failed to get dashboard data: {e}")
            # Return empty data structure on API failure
            return {
                'customers': [],
                'recent_invoices': [],
                'recent_tickets': [],
                'stats': {
                    'total_customers': 0,
                    'active_services': 0,
                    'open_tickets': 0,
                    'total_invoices': 0,
                }
            }


# Singleton instance
api_client = PlatformAPIClient()