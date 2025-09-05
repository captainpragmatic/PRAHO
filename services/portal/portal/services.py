# ===============================================================================
# PLATFORM API CLIENT - SECURE COMMUNICATION 🌐
# ===============================================================================

"""
Portal-to-Platform API Client
Handles all communication between portal and platform services.
🚨 SECURITY: Portal has NO database access - all data via API.
"""

import logging
import requests
from typing import Any, Dict, Optional, List
from django.conf import settings

logger = logging.getLogger(__name__)


class PlatformAPIException(Exception):
    """Exception raised for Platform API communication errors."""
    pass


class PlatformAPIClient:
    """
    🔒 SECURE API CLIENT for Portal → Platform communication
    
    Features:
    - Token-based authentication
    - Request/response logging
    - Error handling with fallbacks  
    - Session management
    """
    
    def __init__(self):
        self.base_url = settings.PLATFORM_API_BASE_URL.rstrip('/')
        self.token = settings.PLATFORM_API_TOKEN
        self.session = requests.Session()
        
        # Set authentication header
        self.session.headers.update({
            'Authorization': f'Token {self.token}',
            'Content-Type': 'application/json',
            'User-Agent': 'PRAHO-Portal/1.0'
        })
        
        logger.info(f"🚀 [Portal API] Initialized client for {self.base_url}")
    
    def _make_request(
        self, 
        method: str, 
        endpoint: str, 
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Make authenticated request to platform API.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint (e.g., 'customers/123')
            data: Request body data
            params: URL parameters
            
        Returns:
            Parsed JSON response
            
        Raises:
            PlatformAPIException: On API communication errors
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        
        try:
            logger.debug(f"🌐 [Portal API] {method} {url}")
            
            response = self.session.request(
                method=method,
                url=url,
                json=data if data else None,
                params=params if params else None,
                timeout=30
            )
            
            # Log response
            logger.debug(
                f"✅ [Portal API] {method} {url} → {response.status_code}"
            )
            
            response.raise_for_status()
            return response.json()
            
        except requests.RequestException as e:
            logger.error(f"🔥 [Portal API] {method} {url} failed: {e}")
            raise PlatformAPIException(f"API request failed: {e}")
    
    # ===============================================================================
    # CUSTOMER OPERATIONS
    # ===============================================================================
    
    def get_customer(self, customer_id: str) -> Dict[str, Any]:
        """Get customer details by ID."""
        return self._make_request('GET', f'customers/{customer_id}')
    
    def get_customer_orders(self, customer_id: str) -> List[Dict[str, Any]]:
        """Get customer's orders."""
        response = self._make_request('GET', f'customers/{customer_id}/orders')
        return response.get('orders', [])
    
    def get_customer_invoices(self, customer_id: str) -> List[Dict[str, Any]]:
        """Get customer's invoices."""
        response = self._make_request('GET', f'customers/{customer_id}/invoices')
        return response.get('invoices', [])
    
    # ===============================================================================
    # SERVICE OPERATIONS  
    # ===============================================================================
    
    def get_customer_services(self, customer_id: str) -> List[Dict[str, Any]]:
        """Get customer's active services."""
        response = self._make_request('GET', f'customers/{customer_id}/services')
        return response.get('services', [])
    
    def get_service_details(self, service_id: str) -> Dict[str, Any]:
        """Get detailed service information."""
        return self._make_request('GET', f'services/{service_id}')
    
    # ===============================================================================
    # SUPPORT OPERATIONS
    # ===============================================================================
    
    def create_ticket(self, customer_id: str, ticket_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create support ticket."""
        return self._make_request('POST', f'customers/{customer_id}/tickets', data=ticket_data)
    
    def get_customer_tickets(self, customer_id: str) -> List[Dict[str, Any]]:
        """Get customer's support tickets."""
        response = self._make_request('GET', f'customers/{customer_id}/tickets')
        return response.get('tickets', [])
    
    # ===============================================================================
    # AUTHENTICATION
    # ===============================================================================
    
    def authenticate_customer(self, email: str, password: str) -> Optional[Dict[str, Any]]:
        """
        Authenticate customer credentials.
        
        Returns:
            Customer data if valid, None if invalid
        """
        try:
            return self._make_request('POST', 'auth/login', data={
                'email': email,
                'password': password
            })
        except PlatformAPIException:
            return None
    
    def refresh_customer_session(self, session_token: str) -> Optional[Dict[str, Any]]:
        """Refresh customer session."""
        try:
            return self._make_request('POST', 'auth/refresh', data={
                'session_token': session_token
            })
        except PlatformAPIException:
            return None


# ===============================================================================
# GLOBAL CLIENT INSTANCE
# ===============================================================================

# Singleton instance for use throughout portal
platform_api = PlatformAPIClient()
