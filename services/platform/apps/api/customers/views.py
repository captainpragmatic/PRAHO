# ===============================================================================
# CUSTOMER API VIEWS 🎯
# ===============================================================================

import logging
from typing import cast

from django.db.models import Q, QuerySet
from django.http import HttpRequest
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.response import Response

from apps.api.core import BaseAPIViewSet, ReadOnlyAPIViewSet
from apps.customers.models import Customer
from apps.users.models import User
from .serializers import CustomerSearchSerializer, CustomerServiceSerializer

logger = logging.getLogger(__name__)

# Constants
SEARCH_QUERY_MIN_LENGTH = 2


# ===============================================================================
# CUSTOMER SEARCH API 🔍
# ===============================================================================

class CustomerSearchViewSet(ReadOnlyAPIViewSet):
    """
    🔍 Customer search API for dropdowns and autocomplete.
    
    Migrated from apps.customers.customer_views.customer_search_api
    Now uses DRF with proper rate limiting and permissions.
    """
    
    serializer_class = CustomerSearchSerializer
    
    def get_queryset(self):
        """Filter customers based on user access and search query"""
        user = cast(User, self.request.user)
        customers = user.get_accessible_customers()
        
        # Handle both QuerySet and list return types
        if hasattr(customers, "filter"):  # QuerySet
            return customers
        elif customers:  # List
            customer_ids = [c.id for c in customers]
            return Customer.objects.filter(id__in=customer_ids)
        else:
            return Customer.objects.none()
    
    def list(self, request: HttpRequest, *args, **kwargs):
        """
        Search customers with query parameter.
        
        Query Parameters:
            q (str): Search query (min 2 characters)
            
        Returns:
            List of customers matching the search query
        """
        query = request.GET.get("q", "")
        
        if len(query) < SEARCH_QUERY_MIN_LENGTH:
            return Response({"results": []})
        
        queryset = self.get_queryset()
        
        # Apply search filter
        if hasattr(queryset, "filter"):  # QuerySet
            filtered_customers = queryset.filter(
                Q(name__icontains=query) | 
                Q(company_name__icontains=query) | 
                Q(primary_email__icontains=query)
            )[:10]
        else:  # List (fallback)
            filtered_customers = [
                c for c in queryset
                if query.lower() in c.name.lower()
                or query.lower() in c.company_name.lower() 
                or query.lower() in c.primary_email.lower()
            ][:10]
        
        serializer = self.get_serializer(filtered_customers, many=True)
        return Response({"results": serializer.data})


# ===============================================================================
# CUSTOMER SERVICES API 🔗
# ===============================================================================

class CustomerServicesViewSet(ReadOnlyAPIViewSet):
    """
    🔗 Customer services API for ticket forms and service management.
    
    Migrated from apps.customers.customer_views.customer_services_api
    Currently returns empty list - placeholder for future service management.
    """
    
    serializer_class = CustomerServiceSerializer
    
    def get_queryset(self):
        """Get customers the user has access to"""
        user = cast(User, self.request.user)
        accessible_customers = user.get_accessible_customers()
        
        if isinstance(accessible_customers, QuerySet):
            return accessible_customers
        elif accessible_customers:
            customer_ids = [c.id for c in accessible_customers]
            return Customer.objects.filter(id__in=customer_ids)
        else:
            return Customer.objects.none()
    
    @action(detail=True, methods=['get'], url_path='services')
    def services(self, request: HttpRequest, pk=None):
        """
        Get services for a specific customer.
        
        Path Parameters:
            pk (int): Customer ID
            
        Returns:
            List of services for the customer (empty for now)
        """
        try:
            customer_id = int(pk)
        except (ValueError, TypeError):
            return Response(
                {"error": "Invalid customer ID"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Verify user has access to this customer
        queryset = self.get_queryset()
        if not queryset.filter(id=customer_id).exists():
            return Response(
                {"error": "Access denied"}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        # TODO: Implement actual service management
        # For now, return empty services list
        logger.info(f"🔗 [API] Customer services requested for customer {customer_id}")
        return Response([])  # Empty list for now
