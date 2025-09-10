"""
Platform API Client (Portal → Platform)

Security guidelines for all requests:
- Customer/user-scoped endpoints MUST use POST with an HMAC-signed JSON body
  that includes identity fields: 'user_id' and, for customer-scoped calls,
  'customer_id'. Do not put identities in URL or query parameters
  (prevents ID enumeration).
- GET is allowed only for public/non-identity resources (e.g., service plans,
  currencies) where no customer/user context is required.
- The client automatically injects 'timestamp' (and 'user_id' when provided)
  into the signed body and ensures header/body timestamps match the signature.
"""

# ===============================================================================
# PLATFORM API CLIENT SERVICE - PORTAL TO PLATFORM COMMUNICATION 🔗
# ===============================================================================

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
import urllib.parse
from typing import Any

import requests
from django.conf import settings
from django.core.cache import cache

# HTTP status code constants
HTTP_OK = 200
HTTP_MULTIPLE_CHOICES = 300

logger = logging.getLogger(__name__)


class PlatformAPIError(Exception):
    """Exception raised when platform API calls fail"""
    def __init__(self, message: str, status_code: int | None = None, response_data: dict | None = None):
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
    
    def __init__(self) -> None:
        self.base_url = settings.PLATFORM_API_BASE_URL
        self.portal_id = getattr(settings, 'PORTAL_ID', 'portal-001')
        self.portal_secret = settings.PLATFORM_API_SECRET  # Will be portal-specific secret
        self.timeout = settings.PLATFORM_API_TIMEOUT
        
    def _generate_hmac_headers(self, method: str, path: str, body: bytes, fixed_timestamp: str | None = None) -> dict[str, str]:
        """
        Generate HMAC authentication headers for secure API communication.
        ✅ Implements canonical string signing with nonce deduplication.
        """
        # Generate unique nonce and timestamp
        nonce = secrets.token_urlsafe(16)
        timestamp = fixed_timestamp or str(time.time())
        
        # Compute body hash
        body_hash = base64.b64encode(hashlib.sha256(body).digest()).decode('ascii')
        
        # Normalize content type (lowercase, no parameters)
        content_type = 'application/json'
        
        # Normalize path+query to match platform canonicalization
        parsed = urllib.parse.urlsplit(path)
        query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        query_pairs.sort(key=lambda kv: (kv[0], kv[1]))
        normalized_query = urllib.parse.urlencode(query_pairs, doseq=True)
        normalized_path = parsed.path + ("?" + normalized_query if normalized_query else "")
        
        # Build canonical string for signing (Phase 2 strict)
        canonical_string = "\n".join([
            method,
            normalized_path,
            content_type,
            body_hash,
            self.portal_id,
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
            'Content-Type': content_type,
            'Accept': 'application/json',
        }
    
    # ---- Small helpers to reduce branching/complexity in _make_request ----
    def _build_url(self, endpoint: str) -> str:
        return f"{self.base_url.rstrip('/')}/{endpoint.lstrip('/')}"

    def _prepare_json_body(self, data: dict | None, user_id: int | None) -> tuple[bytes, dict]:
        payload: dict[str, Any] = {} if data is None else dict(data)
        if user_id is not None and 'user_id' not in payload:
            payload['user_id'] = user_id
        if 'timestamp' not in payload:
            payload['timestamp'] = time.time()
        return json.dumps(payload).encode('utf-8'), payload

    def _normalized_path_with_query(self, url: str, params: dict | None) -> str:
        parsed_url = urllib.parse.urlsplit(url)
        pairs = urllib.parse.parse_qsl(parsed_url.query, keep_blank_values=True)
        if params:
            for k, v in params.items():
                if isinstance(v, list | tuple):
                    for item in v:
                        pairs.append((str(k), str(item)))
                else:
                    pairs.append((str(k), str(v)))
        pairs.sort(key=lambda kv: (kv[0], kv[1]))
        normalized_query = urllib.parse.urlencode(pairs, doseq=True)
        return parsed_url.path + ("?" + normalized_query if normalized_query else "")

    def _prepare_request_headers(self, method: str, url: str, params: dict | None, body: bytes, body_ts: str | None) -> dict[str, str]:
        path_with_query = self._normalized_path_with_query(url, params)
        return self._generate_hmac_headers(method, path_with_query, body, fixed_timestamp=body_ts)

    def _handle_api_response(self, response: requests.Response, endpoint: str) -> dict[str, Any]:
        if HTTP_OK <= response.status_code < HTTP_MULTIPLE_CHOICES:
            try:
                return response.json()
            except ValueError:
                return {'success': True}

        try:
            error_data = response.json()
        except ValueError:
            error_data = {'error': 'Invalid response format'}

        raise PlatformAPIError(
            message=f"API request failed: {error_data.get('error', 'Unknown error')}",
            status_code=response.status_code,
            response_data=error_data,
        )

    def _make_request(self, method: str, endpoint: str, user_id: int | None = None,
                      data: dict | None = None, params: dict | None = None) -> dict[str, Any]:
        """Make HMAC-authenticated request to platform API"""
        url = self._build_url(endpoint)

        # Prepare JSON body and headers
        body_bytes, payload = self._prepare_json_body(data, user_id)
        body_ts = str(payload.get('timestamp')) if 'timestamp' in payload else None
        headers = self._prepare_request_headers(method, url, params, body_bytes, body_ts)

        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                data=body_bytes if body_bytes else None,
                params=params if params else None,
                timeout=self.timeout,
            )

            # Log the request for debugging
            logger.debug(f"🌐 [API Client] {method} {url} -> {response.status_code}")

            return self._handle_api_response(response, endpoint)

        except requests.exceptions.ConnectionError as e:
            logger.error(f"🔥 [API Client] Connection failed to platform service: {url}")
            raise PlatformAPIError("Platform service unavailable") from e
        except requests.exceptions.Timeout as e:
            logger.error(f"🔥 [API Client] Timeout connecting to platform service: {url}")
            raise PlatformAPIError("Platform service timeout") from e
        except requests.exceptions.RequestException as e:
            logger.error(f"🔥 [API Client] Request error: {e}")
            raise PlatformAPIError(f"Request failed: {e!s}") from e
    
    def _handle_binary_response(self, response: requests.Response, endpoint: str) -> bytes:
        if HTTP_OK <= response.status_code < HTTP_MULTIPLE_CHOICES:
            return response.content

        try:
            error_data = response.json()
        except ValueError:
            error_data = {'error': 'Invalid response format'}

        raise PlatformAPIError(
            message=f"Binary API request failed: {error_data.get('error', 'Unknown error')}",
            status_code=response.status_code,
            response_data=error_data,
        )

    def _make_binary_request(self, method: str, endpoint: str, params: dict | None = None, data: dict | None = None) -> bytes:
        """Make HMAC-authenticated request and return binary response (for PDFs). Supports signed JSON body."""
        url = self._build_url(endpoint)

        # Prepare body and headers using shared helpers
        body_bytes, payload = self._prepare_json_body(data, user_id=None)
        body_ts = str(payload.get('timestamp')) if 'timestamp' in payload else None
        headers = self._prepare_request_headers(method, url, params, body_bytes, body_ts)

        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                data=body_bytes if body_bytes else None,
                params=params if params else None,
                timeout=self.timeout
            )

            logger.debug(f"🌐 [API Client Binary] {method} {url} -> {response.status_code}")
            return self._handle_binary_response(response, endpoint)

        except requests.exceptions.ConnectionError as e:
            logger.error(f"🔥 [API Client Binary] Connection failed to platform service: {url}")
            raise PlatformAPIError("Platform service unavailable") from e
        except requests.exceptions.Timeout as e:
            logger.error(f"🔥 [API Client Binary] Timeout connecting to platform service: {url}")
            raise PlatformAPIError("Platform service timeout") from e
        except requests.exceptions.RequestException as e:
            logger.error(f"🔥 [API Client Binary] Request error: {e}")
            raise PlatformAPIError(f"Binary request failed: {e!s}") from e
    
    def _make_binary_request_with_headers(self, method: str, endpoint: str, params: dict | None = None, data: dict | None = None) -> tuple[bytes, dict]:
        """Make HMAC-authenticated request and return both binary content and headers."""
        url = self._build_url(endpoint)

        body_bytes, payload = self._prepare_json_body(data, user_id=None)
        body_ts = str(payload.get('timestamp')) if 'timestamp' in payload else None
        headers = self._prepare_request_headers(method, url, params, body_bytes, body_ts)

        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                data=body_bytes if body_bytes else None,
                params=params if params else None,
                timeout=self.timeout
            )

            logger.debug(f"🌐 [API Client Binary+Headers] {method} {url} -> {response.status_code}")
            content = self._handle_binary_response(response, endpoint)
            return content, dict(response.headers)

        except requests.exceptions.ConnectionError as e:
            logger.error(f"🔥 [API Client Binary+Headers] Connection failed to platform service: {url}")
            raise PlatformAPIError("Platform service unavailable") from e
        except requests.exceptions.Timeout as e:
            logger.error(f"🔥 [API Client Binary+Headers] Timeout connecting to platform service: {url}")
            raise PlatformAPIError("Platform service timeout") from e
        except requests.exceptions.RequestException as e:
            logger.error(f"🔥 [API Client Binary+Headers] Request error: {e}")
            raise PlatformAPIError(f"Binary request with headers failed: {e!s}") from e
    
    # ===============================================================================
    # AUTHENTICATION API ENDPOINTS
    # ===============================================================================
    
    def authenticate_customer(self, email: str, password: str) -> dict[str, Any] | None:
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
                user_data = data.get('user', {})
                return {
                    'valid': True,
                    'token': user_data.get('id'),  # Use user ID as simple token for now
                    # Backward-compatible: expose both user_id and customer_id (legacy name)
                    'user_id': user_data.get('id'),
                    'customer_id': user_data.get('customer_id') or user_data.get('id'),
                    'customer_data': data.get('user', {})
                }
            else:
                return {'valid': False}
                
        except PlatformAPIError as e:
            logger.warning(f"⚠️ [API Client] Customer authentication failed for {email}: {e}")
            return None
    
    def validate_session_secure(self, user_id: str, state_version: int = 1) -> dict[str, Any] | None:
        """
        🔒 SECURE session validation using HMAC-signed context (No JWT, No ID enumeration)
        
        Sends customer context in request body, signed by HMAC headers.
        Much simpler and more secure than JWT approach.
        """
        try:
            # Create request body with user context
            current_timestamp = time.time()
            request_data = {
                'user_id': user_id,
                'state_version': state_version,
                'timestamp': current_timestamp
            }
            
            # Use existing HMAC-signed request mechanism
            data = self._make_request(
                'POST', 
                '/users/session/validate/',
                user_id=user_id,
                data=request_data  # Context in body, signed by HMAC
            )
            return data
            
        except PlatformAPIError as e:
            logger.warning(f"⚠️ [API Client] Secure session validation failed: {e}")
            return None
    
    # ===============================================================================
    # CUSTOMER API ENDPOINTS
    # ===============================================================================
    
    def get_user_customers(self, user_id: int) -> list[dict[str, Any]]:
        """🔒 Get customers accessible to user - SECURE HMAC BODY"""
        cache_key = f"user_customers_{user_id}"
        cached_data = cache.get(cache_key)
        if cached_data:
            return cached_data

        request_data = {
            'action': 'get_user_customers',
            'user_id': user_id,
            'timestamp': time.time(),
        }
        # Pass user_id to _make_request so it auto-injects 'user_id' in the signed body (defensive)
        data = self._make_request('POST', '/users/customers/', user_id=user_id, data=request_data)
        customers = data.get('results', []) if data.get('success') else []
        cache.set(cache_key, customers, 300)
        return customers
    
    def get_customer_details(self, customer_id: int, user_id: int) -> dict[str, Any]:
        """Get customer details using secure HMAC authenticated endpoint"""
        return self._make_request(
            'POST', 
            '/customers/details/', 
            user_id=user_id,
            data={
                'customer_id': customer_id,
                'action': 'get_customer_details'
            }
        )
    
    def search_customers(self, query: str, user_id: int) -> list[dict[str, Any]]:
        """Search customers"""
        params = {'q': query}
        data = self._make_request('GET', '/customers/search/', user_id=user_id, params=params)
        return data.get('results', [])
    
    def get_customer_profile(self, user_id: int) -> dict[str, Any] | None:
        """Get user profile data (user-scoped, HMAC body with user_id)"""
        try:
            payload = {'user_id': user_id, 'timestamp': time.time()}
            data = self._make_request(
                'POST', 
                '/users/profile/',
                user_id=user_id,
                data=payload
            )
            
            if data.get('success'):
                return data.get('profile')
            return None
            
        except PlatformAPIError as e:
            logger.warning(f"⚠️ [API Client] Failed to get customer profile: {e}")
            return None
    
    def update_customer_profile(self, user_id: int, profile_data: dict[str, Any]) -> bool:
        """Update customer profile data (requires user_id in signed body for HMAC validation)."""
        try:
            # Ensure the signed body contains user identity for the HMAC validator
            update_data: dict[str, Any] = {**profile_data, 'user_id': user_id}

            data = self._make_request(
                'PUT',
                '/users/profile/',
                user_id=user_id,
                data=update_data,
            )

            return data.get('success', False)

        except PlatformAPIError as e:
            logger.warning(f"⚠️ [API Client] Failed to update customer profile: {e}")
            return False
    
    def update_customer_password(self, user_id: int, new_password: str) -> bool:
        """Update customer password (requires user_id in signed body for HMAC validation)."""
        try:
            data = self._make_request(
                'PUT',
                '/users/change-password/',
                user_id=user_id,
                data={
                    'user_id': user_id,
                    'new_password': new_password,
                },
            )

            return data.get('success', False)

        except PlatformAPIError as e:
            logger.warning(f"⚠️ [API Client] Failed to update customer password: {e}")
            return False
    
    # ===============================================================================
    # MULTI-FACTOR AUTHENTICATION API ENDPOINTS
    # ===============================================================================
    
    def get_mfa_status(self, customer_id: str) -> dict[str, Any] | None:
        """Get MFA status and methods for customer"""
        try:
            data = self._make_request(
                'GET',
                '/users/mfa/status/',
                data={'customer_id': customer_id}
            )
            return data if data.get('success') else None
        except PlatformAPIError as e:
            logger.warning(f"⚠️ [API Client] Failed to get MFA status: {e}")
            return None
    
    def setup_totp_mfa(self, customer_id: str) -> dict[str, Any] | None:
        """Initialize TOTP MFA setup - returns QR code and secret"""
        try:
            data = self._make_request(
                'POST',
                '/users/mfa/setup/',
                data={'customer_id': customer_id}
            )
            if data.get('success') and 'setup_data' in data:
                setup_data = data['setup_data']
                return {
                    'qr_code': setup_data.get('qr_code_svg'),
                    'secret': setup_data.get('manual_entry_key'),
                    'provisioning_uri': setup_data.get('provisioning_uri')
                }
            return None
        except PlatformAPIError as e:
            logger.warning(f"⚠️ [API Client] Failed to setup TOTP MFA: {e}")
            return None
    
    def verify_totp_mfa(self, customer_id: str, token: str) -> bool:
        """Verify TOTP token and enable MFA"""
        try:
            data = self._make_request(
                'POST',
                '/users/mfa/verify/',
                data={
                    'customer_id': customer_id,
                    'token': token
                }
            )
            return data.get('success', False)
        except PlatformAPIError as e:
            logger.warning(f"⚠️ [API Client] Failed to verify TOTP: {e}")
            return False
    
    def setup_webauthn_mfa(self, customer_id: str) -> dict[str, Any] | None:
        """Initialize WebAuthn/Passkey MFA setup"""
        try:
            data = self._make_request(
                'POST',
                '/users/mfa/setup/webauthn/',
                data={'customer_id': customer_id}
            )
            return data if data.get('success') else None
        except PlatformAPIError as e:
            logger.warning(f"⚠️ [API Client] Failed to setup WebAuthn MFA: {e}")
            return None
    
    def get_backup_codes(self, customer_id: str) -> list[str] | None:
        """Get backup codes for customer"""
        try:
            data = self._make_request(
                'GET',
                '/users/mfa/backup-codes/',
                data={'customer_id': customer_id}
            )
            return data.get('backup_codes') if data.get('success') else None
        except PlatformAPIError as e:
            logger.warning(f"⚠️ [API Client] Failed to get backup codes: {e}")
            return None
    
    def regenerate_backup_codes(self, customer_id: str) -> list[str] | None:
        """Regenerate backup codes for customer"""
        try:
            data = self._make_request(
                'POST',
                '/users/mfa/regenerate-backup-codes/',
                data={'customer_id': customer_id}
            )
            return data.get('backup_codes') if data.get('success') else None
        except PlatformAPIError as e:
            logger.warning(f"⚠️ [API Client] Failed to regenerate backup codes: {e}")
            return None
    
    def disable_mfa(self, customer_id: str, confirmation_token: str | None = None) -> bool:
        """Disable MFA for customer"""
        try:
            request_data = {'customer_id': customer_id}
            if confirmation_token:
                request_data['confirmation_token'] = confirmation_token
            
            data = self._make_request(
                'POST',
                '/users/mfa/disable/',
                data=request_data
            )
            return data.get('success', False)
        except PlatformAPIError as e:
            logger.warning(f"⚠️ [API Client] Failed to disable MFA: {e}")
            return False

    # ===============================================================================
    # GENERIC HTTP METHODS
    # ===============================================================================
    
    def get(self, endpoint: str, params: dict | None = None, user_id: int | None = None) -> dict[str, Any]:
        """Generic GET request"""
        return self._make_request('GET', endpoint, user_id=user_id, params=params)
    
    def post(self, endpoint: str, data: dict | None = None, user_id: int | None = None) -> dict[str, Any]:
        """Generic POST request"""
        return self._make_request('POST', endpoint, user_id=user_id, data=data)
    
    def put(self, endpoint: str, data: dict | None = None, user_id: int | None = None) -> dict[str, Any]:
        """Generic PUT request"""
        return self._make_request('PUT', endpoint, user_id=user_id, data=data)
    
    def delete(self, endpoint: str, user_id: int | None = None) -> dict[str, Any]:
        """Generic DELETE request"""
        return self._make_request('DELETE', endpoint, user_id=user_id)
    
    # ===============================================================================
    # BILLING API ENDPOINTS  
    # ===============================================================================
    
    def get_invoice_details(self, invoice_id: int, user_id: int) -> dict[str, Any]:
        """Get invoice details"""
        return self._make_request('GET', f'/billing/invoices/{invoice_id}/', user_id=user_id)
    
    # ===============================================================================
    # TICKETS API ENDPOINTS
    # ===============================================================================
    
    # (Legacy user-scoped GET ticket methods removed; use secure POST endpoints instead)
    
    def get_ticket_details(self, ticket_id: int, user_id: int) -> dict[str, Any]:
        """Get ticket details"""
        return self._make_request('GET', f'/tickets/{ticket_id}/', user_id=user_id)
    
    def create_ticket(self, ticket_data: dict[str, Any], user_id: int) -> dict[str, Any]:
        """Create new support ticket"""
        return self._make_request('POST', '/tickets/', user_id=user_id, data=ticket_data)
    
    def add_ticket_comment(self, ticket_id: int, comment_data: dict[str, Any], user_id: int) -> dict[str, Any]:
        """Add comment to ticket"""
        return self._make_request('POST', f'/tickets/{ticket_id}/comments/', user_id=user_id, data=comment_data)
    
    # ===============================================================================
    # SERVICES API ENDPOINTS
    # ===============================================================================
    
    def get_customer_services(self, customer_id: int, user_id: int) -> list[dict[str, Any]]:
        """Get services for customer"""
        data = self._make_request('GET', f'/customers/{customer_id}/services/', user_id=user_id)
        return data if isinstance(data, list) else []
    
    # ===============================================================================
    # DASHBOARD DATA
    # ===============================================================================
    
    # (Removed legacy get_dashboard_data; portal dashboard aggregates via InvoiceViewService)
    
    # ===============================================================================
    # SECURE BILLING API ENDPOINTS 💳
    # ===============================================================================
    
    def get_customer_invoices_secure(self, customer_id: int) -> dict[str, Any]:
        """🔒 Get customer invoices - SECURE HMAC BODY"""
        request_data = {
            'customer_id': customer_id,
            'action': 'get_invoices', 
            'timestamp': time.time()
        }
        return self._make_request('POST', '/api/billing/invoices/', data=request_data)
    
    def get_customer_proformas_secure(self, customer_id: int) -> dict[str, Any]:
        """🔒 Get customer proformas - SECURE HMAC BODY"""
        request_data = {
            'customer_id': customer_id,
            'action': 'get_proformas',
            'timestamp': time.time()
        }
        return self._make_request('POST', '/api/billing/proformas/', data=request_data)
    
    def get_billing_summary_secure(self, customer_id: int) -> dict[str, Any]:
        """🔒 Get billing summary - SECURE HMAC BODY"""
        request_data = {
            'customer_id': customer_id,
            'action': 'get_billing_summary',
            'timestamp': time.time()
        }
        return self._make_request('POST', '/api/billing/summary/', data=request_data)
    
    def get_invoice_detail_secure(self, customer_id: int, invoice_number: str) -> dict[str, Any]:
        """🔒 Get invoice detail - SECURE HMAC BODY"""
        request_data = {
            'customer_id': customer_id,
            'invoice_number': invoice_number,
            'action': 'get_invoice_detail',
            'timestamp': time.time()
        }
        return self._make_request('POST', f'/api/billing/invoices/{invoice_number}/', data=request_data)
    
    def get_proforma_detail_secure(self, customer_id: int, proforma_number: str) -> dict[str, Any]:
        """🔒 Get proforma detail - SECURE HMAC BODY"""
        request_data = {
            'customer_id': customer_id,
            'proforma_number': proforma_number,
            'action': 'get_proforma_detail',
            'timestamp': time.time()
        }
        return self._make_request('POST', f'/api/billing/proformas/{proforma_number}/', data=request_data)
    
    # ===============================================================================
    # SECURE TICKETS API ENDPOINTS 🎫
    # ===============================================================================
    
    def get_customer_tickets_secure(self, customer_id: int) -> dict[str, Any]:
        """🔒 Get customer tickets - SECURE HMAC BODY"""
        request_data = {
            'customer_id': customer_id,
            'action': 'get_tickets',
            'timestamp': time.time()
        }
        return self._make_request('POST', '/api/tickets/', data=request_data)
    
    def get_ticket_detail_secure(self, customer_id: int, ticket_number: str) -> dict[str, Any]:
        """🔒 Get ticket detail - SECURE HMAC BODY"""
        request_data = {
            'customer_id': customer_id,
            'ticket_number': ticket_number,
            'action': 'get_ticket_detail',
            'timestamp': time.time()
        }
        return self._make_request('POST', f'/api/tickets/{ticket_number}/', data=request_data)
    
    def create_ticket_secure(self, customer_id: int, ticket_data: dict[str, Any]) -> dict[str, Any]:
        """🔒 Create ticket - SECURE HMAC BODY"""
        request_data = {
            'customer_id': customer_id,
            'action': 'create_ticket',
            'timestamp': time.time(),
            **ticket_data
        }
        return self._make_request('POST', '/api/tickets/create/', data=request_data)
    
    def reply_to_ticket_secure(self, customer_id: int, ticket_number: str, reply_content: str) -> dict[str, Any]:
        """🔒 Reply to ticket - SECURE HMAC BODY"""
        request_data = {
            'customer_id': customer_id,
            'ticket_number': ticket_number,
            'content': reply_content,
            'action': 'reply_to_ticket',
            'timestamp': time.time()
        }
        return self._make_request('POST', f'/api/tickets/{ticket_number}/reply/', data=request_data)
    
    # ===============================================================================
    # SECURE SERVICES API ENDPOINTS 📦
    # ===============================================================================
    
    def get_customer_services_secure(self, customer_id: int) -> dict[str, Any]:
        """🔒 Get customer services - SECURE HMAC BODY"""
        request_data = {
            'customer_id': customer_id,
            'action': 'get_services',
            'timestamp': time.time()
        }
        return self._make_request('POST', '/api/services/', data=request_data)
    
    def get_service_detail_secure(self, customer_id: int, service_id: int) -> dict[str, Any]:
        """🔒 Get service detail - SECURE HMAC BODY"""
        request_data = {
            'customer_id': customer_id,
            'service_id': service_id,
            'action': 'get_service_detail',
            'timestamp': time.time()
        }
        return self._make_request('POST', f'/api/services/{service_id}/', data=request_data)
    
    def get_services_summary_secure(self, customer_id: int) -> dict[str, Any]:
        """🔒 Get services summary - SECURE HMAC BODY"""
        request_data = {
            'customer_id': customer_id,
            'action': 'get_services_summary',
            'timestamp': time.time()
        }
        return self._make_request('POST', '/api/services/summary/', data=request_data)
    
    def update_service_auto_renew_secure(self, customer_id: int, service_id: int, auto_renew: bool) -> dict[str, Any]:
        """🔒 Update service auto-renew - SECURE HMAC BODY"""
        request_data = {
            'customer_id': customer_id,
            'service_id': service_id,
            'auto_renew': auto_renew,
            'action': 'update_auto_renew',
            'timestamp': time.time()
        }
        return self._make_request('POST', f'/api/services/{service_id}/auto-renew/', data=request_data)
    
    def download_ticket_attachment(self, customer_id: int, user_id: int, ticket_id: int, attachment_id: int) -> dict[str, Any]:
        """🔒 Download ticket attachment - SECURE HMAC BODY"""
        request_data = {
            'customer_id': customer_id,
            'user_id': user_id,
            'ticket_id': ticket_id,
            'attachment_id': attachment_id,
            'action': 'download_attachment',
            'timestamp': time.time()
        }
        return self._make_request('POST', f'/tickets/{ticket_id}/attachments/{attachment_id}/download/', data=request_data)


# Singleton instance
api_client = PlatformAPIClient()

# Alias for convenience  
platform_api = api_client
