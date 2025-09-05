# ===============================================================================
# PORTAL API VIEWS - AJAX ENDPOINTS 🔌
# ===============================================================================

"""
Portal API views for AJAX calls from customer interface.
All endpoints proxy to Platform API service.
"""

import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.http import HttpRequest
from .services import platform_api, PlatformAPIException

logger = logging.getLogger(__name__)


class BaseAPIView(APIView):
    """Base API view with common functionality."""
    
    def get_customer_id(self, request: HttpRequest) -> str | None:
        """Get customer ID from session."""
        return request.session.get('customer_id')
    
    def require_authentication(self, request: HttpRequest) -> bool:
        """Check if customer is authenticated."""
        return self.get_customer_id(request) is not None


class ServicesAPIView(BaseAPIView):
    """AJAX endpoint for customer services."""
    
    def get(self, request: HttpRequest) -> Response:
        """Get customer services via Platform API."""
        if not self.require_authentication(request):
            return Response(
                {'error': 'Authentication required'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        customer_id = self.get_customer_id(request)
        
        try:
            services = platform_api.get_customer_services(customer_id)
            return Response({'services': services})
            
        except PlatformAPIException as e:
            logger.error(f"🔥 [Portal API Services] {e}")
            return Response(
                {'error': 'Unable to load services'}, 
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )


class ServiceDetailAPIView(BaseAPIView):
    """AJAX endpoint for service details."""
    
    def get(self, request: HttpRequest, service_id: str) -> Response:
        """Get service details via Platform API."""
        if not self.require_authentication(request):
            return Response(
                {'error': 'Authentication required'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        try:
            service = platform_api.get_service_details(service_id)
            return Response({'service': service})
            
        except PlatformAPIException as e:
            logger.error(f"🔥 [Portal API Service Detail] {e}")
            return Response(
                {'error': 'Service not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )


class TicketsAPIView(BaseAPIView):
    """AJAX endpoint for customer tickets."""
    
    def get(self, request: HttpRequest) -> Response:
        """Get customer tickets via Platform API."""
        if not self.require_authentication(request):
            return Response(
                {'error': 'Authentication required'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        customer_id = self.get_customer_id(request)
        
        try:
            tickets = platform_api.get_customer_tickets(customer_id)
            return Response({'tickets': tickets})
            
        except PlatformAPIException as e:
            logger.error(f"🔥 [Portal API Tickets] {e}")
            return Response(
                {'error': 'Unable to load tickets'}, 
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )
    
    def post(self, request: HttpRequest) -> Response:
        """Create new ticket via Platform API."""
        if not self.require_authentication(request):
            return Response(
                {'error': 'Authentication required'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        customer_id = self.get_customer_id(request)
        
        try:
            ticket_data = request.data
            ticket = platform_api.create_ticket(customer_id, ticket_data)
            return Response({'ticket': ticket}, status=status.HTTP_201_CREATED)
            
        except PlatformAPIException as e:
            logger.error(f"🔥 [Portal API Create Ticket] {e}")
            return Response(
                {'error': 'Unable to create ticket'}, 
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )


class TicketDetailAPIView(BaseAPIView):
    """AJAX endpoint for ticket details."""
    
    def get(self, request: HttpRequest, ticket_id: str) -> Response:
        """Get ticket details via Platform API."""
        if not self.require_authentication(request):
            return Response(
                {'error': 'Authentication required'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        try:
            # Note: In a real implementation, you'd want to verify
            # that this ticket belongs to the authenticated customer
            ticket = platform_api.get_ticket_details(ticket_id)
            return Response({'ticket': ticket})
            
        except PlatformAPIException as e:
            logger.error(f"🔥 [Portal API Ticket Detail] {e}")
            return Response(
                {'error': 'Ticket not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )


class InvoicesAPIView(BaseAPIView):
    """AJAX endpoint for customer invoices."""
    
    def get(self, request: HttpRequest) -> Response:
        """Get customer invoices via Platform API."""
        if not self.require_authentication(request):
            return Response(
                {'error': 'Authentication required'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        customer_id = self.get_customer_id(request)
        
        try:
            invoices = platform_api.get_customer_invoices(customer_id)
            return Response({'invoices': invoices})
            
        except PlatformAPIException as e:
            logger.error(f"🔥 [Portal API Invoices] {e}")
            return Response(
                {'error': 'Unable to load invoices'}, 
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )


class InvoiceDetailAPIView(BaseAPIView):
    """AJAX endpoint for invoice details."""
    
    def get(self, request: HttpRequest, invoice_id: str) -> Response:
        """Get invoice details via Platform API."""
        if not self.require_authentication(request):
            return Response(
                {'error': 'Authentication required'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        try:
            invoice = platform_api.get_invoice_details(invoice_id)
            return Response({'invoice': invoice})
            
        except PlatformAPIException as e:
            logger.error(f"🔥 [Portal API Invoice Detail] {e}")
            return Response(
                {'error': 'Invoice not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )
