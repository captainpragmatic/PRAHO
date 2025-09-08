# ===============================================================================
# TICKETS API CLIENT SERVICE - CUSTOMER SUPPORT INTEGRATION 🎫
# ===============================================================================

import logging
from typing import Dict, List, Optional, Any
from apps.api_client.services import PlatformAPIClient, PlatformAPIError

logger = logging.getLogger(__name__)


class TicketAPIClient(PlatformAPIClient):
    """
    Customer support tickets API client for portal service.
    
    Provides customer-only access to their support tickets:
    - List customer tickets
    - View ticket details
    - Create new tickets
    - Reply to tickets
    - View ticket status
    """
    
    def get_customer_tickets(self, customer_id: int, user_id: int, page: int = 1, status: str = '', priority: str = '', search: str = '') -> Dict[str, Any]:
        """
        Get paginated list of tickets for a specific customer.
        
        Args:
            customer_id: Customer ID for filtering tickets
            page: Page number for pagination
            status: Filter by ticket status (new, open, pending, resolved, closed)
            priority: Filter by priority (critical, urgent, high, normal, low)
            search: Search in ticket title/description
            
        Returns:
            Dict containing tickets list and pagination info
        """
        try:
            request_data = {
                'customer_id': customer_id,
                'user_id': user_id,
                'page': page,
                'page_size': 20,  # Customer portal pagination
            }
            
            if status:
                request_data['status'] = status
            if priority:
                request_data['priority'] = priority  
            if search:
                request_data['search'] = search
                
            response = self._make_request('POST', '/tickets/', data=request_data)
            
            # Transform platform API response format to expected portal format
            if response.get('success') and 'data' in response:
                platform_data = response['data']
                adapted_response = {
                    'results': platform_data.get('tickets', []),
                    'count': platform_data.get('pagination', {}).get('total', 0),
                    'next': platform_data.get('pagination', {}).get('has_next'),
                    'previous': platform_data.get('pagination', {}).get('has_previous')
                }
                logger.info(f"✅ [Tickets API] Retrieved tickets for customer {customer_id}: {adapted_response.get('count', 0)} total")
                return adapted_response
            else:
                logger.warning(f"⚠️ [Tickets API] Unexpected response format: {response}")
                return {'results': [], 'count': 0}
            
        except PlatformAPIError as e:
            logger.error(f"🔥 [Tickets API] Error retrieving tickets for customer {customer_id}: {e}")
            raise
    
    def get_ticket_detail(self, customer_id: int, user_id: int, ticket_id: int) -> Dict[str, Any]:
        """
        Get detailed ticket information for customer view.
        
        Args:
            customer_id: Customer ID for authorization
            user_id: User ID for HMAC authentication
            ticket_id: Ticket ID to retrieve
            
        Returns:
            Dict containing ticket details and comments
        """
        try:
            data = {'customer_id': customer_id, 'user_id': user_id}
            response = self._make_request('POST', f'/tickets/{ticket_id}/', data=data)
            
            logger.info(f"✅ [Tickets API] Retrieved ticket {ticket_id} details for customer {customer_id}")
            return response
            
        except PlatformAPIError as e:
            logger.error(f"🔥 [Tickets API] Error retrieving ticket {ticket_id} for customer {customer_id}: {e}")
            raise
    
    def create_ticket(self, customer_id: int, user_id: int, title: str, description: str, 
                     priority: str = 'normal', category: str = '') -> Dict[str, Any]:
        """
        Create a new support ticket for customer.
        
        Args:
            customer_id: Customer ID creating the ticket
            user_id: User ID for HMAC authentication
            title: Ticket subject/title
            description: Detailed description of the issue
            priority: Priority level (critical, urgent, high, normal, low)
            category: Optional category for ticket classification
            
        Returns:
            Dict containing created ticket information
        """
        try:
            data = {
                'customer_id': customer_id,
                'user_id': user_id,
                'title': title,
                'description': description,
                'priority': priority,
                'status': 'new',  # Customer-created tickets start as 'new'
            }
            
            if category:
                data['category'] = category
                
            response = self._make_request('POST', '/tickets/', data=data)
            
            logger.info(f"✅ [Tickets API] Created ticket {response.get('id')} for customer {customer_id}")
            return response
            
        except PlatformAPIError as e:
            logger.error(f"🔥 [Tickets API] Error creating ticket for customer {customer_id}: {e}")
            raise
    
    def add_ticket_reply(self, customer_id: int, user_id: int, ticket_id: int, message: str, 
                        attachments: Optional[List] = None) -> Dict[str, Any]:
        """
        Add customer reply to existing ticket.
        
        Args:
            customer_id: Customer ID for authorization
            user_id: User ID for HMAC authentication
            ticket_id: Ticket ID to reply to
            message: Reply message content
            attachments: Optional list of file attachments
            
        Returns:
            Dict containing reply information
        """
        try:
            data = {
                'customer_id': customer_id,
                'user_id': user_id,
                'content': message,  # Platform API expects 'content' field
                'is_internal': False,  # Customer replies are always public
            }
            
            if attachments:
                data['attachments'] = attachments
                
            response = self._make_request('POST', f'/tickets/{ticket_id}/reply/', data=data)
            
            logger.info(f"✅ [Tickets API] Added reply to ticket {ticket_id} for customer {customer_id}")
            return response
            
        except PlatformAPIError as e:
            logger.error(f"🔥 [Tickets API] Error adding reply to ticket {ticket_id} for customer {customer_id}: {e}")
            raise
    
    def get_ticket_replies(self, customer_id: int, user_id: int, ticket_id: int) -> List[Dict[str, Any]]:
        """
        Get all replies for a ticket (customer view - excludes internal notes).
        
        Args:
            customer_id: Customer ID for authorization
            user_id: User ID for HMAC authentication
            ticket_id: Ticket ID to get replies for
            
        Returns:
            List of reply dictionaries
        """
        try:
            data = {'customer_id': customer_id, 'user_id': user_id}
            response = self._make_request('POST', f'/tickets/{ticket_id}/reply/', data=data)
            
            logger.info(f"✅ [Tickets API] Retrieved replies for ticket {ticket_id} for customer {customer_id}")
            return response.get('replies', [])
            
        except PlatformAPIError as e:
            logger.error(f"🔥 [Tickets API] Error retrieving replies for ticket {ticket_id} for customer {customer_id}: {e}")
            raise
    
    def get_tickets_summary(self, customer_id: int, user_id: int) -> Dict[str, Any]:
        """
        Get ticket summary statistics for customer dashboard.
        
        Args:
            customer_id: Customer ID for statistics
            
        Returns:
            Dict containing ticket counts by status
        """
        try:
            data = {'customer_id': customer_id, 'user_id': user_id}
            response = self._make_request('POST', '/tickets/summary/', data=data)
            
            logger.info(f"✅ [Tickets API] Retrieved ticket summary for customer {customer_id}")
            return response
            
        except PlatformAPIError as e:
            logger.error(f"🔥 [Tickets API] Error retrieving ticket summary for customer {customer_id}: {e}")
            # Return empty summary on error to avoid breaking dashboard
            return {
                'total_tickets': 0,
                'open_tickets': 0,
                'pending_tickets': 0,
                'resolved_tickets': 0,
                'by_priority': {'critical': 0, 'urgent': 0, 'high': 0, 'normal': 0, 'low': 0}
            }


# Global instance for easy importing
ticket_api = TicketAPIClient()