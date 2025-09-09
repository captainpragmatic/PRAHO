"""
Services API Client (customer‑facing "My Services")

Security guidelines:
- All customer/user‑scoped calls MUST use POST with an HMAC‑signed JSON body
  that includes 'user_id' and 'customer_id'. Avoid putting identities in URL
  or query parameters to prevent ID enumeration.
- GET is reserved for public/non‑identity endpoints (e.g., /api/services/plans/),
  which accept optional filters but no customer/user identity.
"""

# ===============================================================================
# SERVICES API CLIENT SERVICE - CUSTOMER HOSTING MANAGEMENT 🔧
# ===============================================================================

import logging
from typing import Dict, List, Any
from apps.api_client.services import PlatformAPIClient, PlatformAPIError

logger = logging.getLogger(__name__)


class ServicesAPIClient(PlatformAPIClient):
    """
    Customer hosting services API client for portal service.
    
    Provides customer-only access to their hosting services:
    - List customer services
    - View service details
    - View service status and usage
    - Service management (limited customer actions)
    """
    
    def get_customer_services(self, customer_id: int, user_id: int, page: int = 1, status: str = '', service_type: str = '') -> Dict[str, Any]:
        """
        Get paginated list of hosting services for a specific customer.
        
        Args:
            customer_id: Customer ID for filtering services
            user_id: User ID for HMAC authentication
            page: Page number for pagination
            status: Filter by service status (active, suspended, pending, cancelled)
            service_type: Filter by service type (shared, vps, dedicated, etc.)
            
        Returns:
            Dict containing services list and pagination info
        """
        try:
            data = {
                'customer_id': customer_id,
                'user_id': user_id,
                'page': page,
                'page_size': 20,
            }
            
            if status:
                data['status'] = status
            if service_type:
                data['service_type'] = service_type
                
            response = self._make_request('POST', '/services/', user_id=user_id, data=data)
            
            # Transform platform API response format to expected portal format
            if response.get('success') and 'data' in response:
                platform_data = response['data']
                adapted_response = {
                    'results': platform_data.get('services', []),
                    'count': platform_data.get('pagination', {}).get('total', 0),
                    'stats': platform_data.get('stats', {})
                }
                logger.info(f"✅ [Services API] Retrieved services for customer {customer_id}: {adapted_response.get('count', 0)} total")
                return adapted_response
            else:
                logger.warning(f"⚠️ [Services API] Unexpected response format: {response}")
                return {'results': [], 'count': 0}
            
        except PlatformAPIError as e:
            logger.error(f"🔥 [Services API] Error retrieving services for customer {customer_id}: {e}")
            raise
    
    def get_service_detail(self, customer_id: int, user_id: int, service_id: int) -> Dict[str, Any]:
        """
        Get detailed service information for customer view.
        
        Args:
            customer_id: Customer ID for authorization
            user_id: User ID for HMAC authentication
            service_id: Service ID to retrieve
            
        Returns:
            Dict containing service details, plan info, and configuration
        """
        try:
            data = {'customer_id': customer_id, 'user_id': user_id}
            response = self._make_request('POST', f'/services/{service_id}/', user_id=user_id, data=data)
            
            logger.info(f"✅ [Services API] Retrieved service {service_id} details for customer {customer_id}")
            return response
            
        except PlatformAPIError as e:
            logger.error(f"🔥 [Services API] Error retrieving service {service_id} for customer {customer_id}: {e}")
            raise
    
    def get_service_usage(self, customer_id: int, service_id: int, period: str = '30d') -> Dict[str, Any]:
        """
        Get service usage statistics for customer view.
        
        Args:
            customer_id: Customer ID for authorization
            service_id: Service ID to get usage for
            period: Usage period (7d, 30d, 90d)
            
        Returns:
            Dict containing usage statistics (bandwidth, storage, etc.)
        """
        try:
            data = {
                'customer_id': customer_id,
                'period': period
            }
            response = self._make_request('POST', f'/services/{service_id}/usage/', data=data)
            
            logger.info(f"✅ [Services API] Retrieved usage for service {service_id} for customer {customer_id}")
            return response
            
        except PlatformAPIError as e:
            logger.error(f"🔥 [Services API] Error retrieving usage for service {service_id} for customer {customer_id}: {e}")
            # Return empty usage on error to avoid breaking UI
            return {
                'bandwidth_used': 0,
                'bandwidth_limit': 0,
                'storage_used': 0,
                'storage_limit': 0,
                'period': period
            }
    
    def get_services_summary(self, customer_id: int, user_id: int) -> Dict[str, Any]:
        """
        Get services summary statistics for customer dashboard.
        
        Args:
            customer_id: Customer ID for statistics
            user_id: User ID for HMAC authentication
            
        Returns:
            Dict containing service counts by status and type
        """
        try:
            data = {'customer_id': customer_id, 'user_id': user_id}
            response = self._make_request('POST', '/services/summary/', user_id=user_id, data=data)
            
            # Extract summary data from nested response structure
            if response.get('success') and 'data' in response and 'summary' in response['data']:
                summary_data = response['data']['summary']
                logger.info(f"✅ [Services API] Retrieved services summary for customer {customer_id}: {summary_data.get('active_services', 0)} active")
                return summary_data
            else:
                logger.warning(f"⚠️ [Services API] Unexpected summary response format: {response}")
                return {
                    'total_services': 0,
                    'active_services': 0,
                    'suspended_services': 0,
                    'pending_services': 0,
                }
            
        except PlatformAPIError as e:
            logger.error(f"🔥 [Services API] Error retrieving services summary for customer {customer_id}: {e}")
            # Return empty summary on error
            return {
                'total_services': 0,
                'active_services': 0,
                'suspended_services': 0,
                'pending_services': 0,
                'by_type': {}
            }
    
    def get_service_domains(self, customer_id: int, service_id: int) -> List[Dict[str, Any]]:
        """
        Get domains associated with a specific service.
        
        Args:
            customer_id: Customer ID for authorization
            service_id: Service ID to get domains for
            
        Returns:
            List of domain dictionaries
        """
        try:
            data = {'customer_id': customer_id}
            response = self._make_request('POST', f'/services/{service_id}/domains/', data=data)
            
            logger.info(f"✅ [Services API] Retrieved domains for service {service_id} for customer {customer_id}")
            return response.get('domains', [])
            
        except PlatformAPIError as e:
            logger.error(f"🔥 [Services API] Error retrieving domains for service {service_id} for customer {customer_id}: {e}")
            return []
    
    def request_service_action(self, customer_id: int, service_id: int, action: str, reason: str = '') -> Dict[str, Any]:
        """
        Request service action (customer-available actions only).
        Creates a service request that staff must approve.
        
        Args:
            customer_id: Customer ID for authorization
            service_id: Service ID to perform action on
            action: Action type (upgrade, downgrade, suspend_request, cancel_request)
            reason: Optional reason for the request
            
        Returns:
            Dict containing request information
        """
        try:
            # Only allow customer-safe actions
            allowed_actions = ['upgrade_request', 'downgrade_request', 'suspend_request', 'cancel_request']
            if action not in allowed_actions:
                raise PlatformAPIError(f"Action '{action}' not allowed for customer requests")
            
            data = {
                'customer_id': customer_id,
                'action': action,
                'reason': reason,
                'requested_by_customer': True
            }
            
            response = self._make_request('POST', f'/services/{service_id}/actions/', data=data)
            
            logger.info(f"✅ [Services API] Requested action '{action}' for service {service_id} by customer {customer_id}")
            return response
            
        except PlatformAPIError as e:
            logger.error(f"🔥 [Services API] Error requesting action '{action}' for service {service_id} by customer {customer_id}: {e}")
            raise
    
    def get_available_plans(self, customer_id: int, service_type: str = '') -> List[Dict[str, Any]]:
        """
        Get available hosting plans for customer (for upgrades/downgrades).
        
        Args:
            customer_id: Customer ID for authorization
            service_type: Optional filter by service type
            
        Returns:
            List of available plan dictionaries
        """
        try:
            # Platform expects GET /api/services/plans/ with optional plan_type filter
            params = {}
            if service_type:
                params['plan_type'] = service_type
            
            response = self._make_request('GET', '/services/plans/', params=params)
            
            logger.info(f"✅ [Services API] Retrieved available plans for customer {customer_id}")
            return response.get('plans', [])
            
        except PlatformAPIError as e:
            logger.error(f"🔥 [Services API] Error retrieving plans for customer {customer_id}: {e}")
            return []


# Global instance for easy importing
services_api = ServicesAPIClient()
