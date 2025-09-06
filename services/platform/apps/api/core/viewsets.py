# ===============================================================================
# API BASE VIEWSETS 🎯
# ===============================================================================

from rest_framework import viewsets
from .permissions import IsAuthenticatedAndAccessible
from .pagination import StandardResultsSetPagination
from .throttling import StandardAPIThrottle, BurstAPIThrottle


class BaseAPIViewSet(viewsets.ModelViewSet):
    """
    Base viewset that ALL PRAHO API endpoints should extend.
    
    Provides consistent:
    - Authentication & permissions
    - Pagination  
    - Rate limiting
    - Error handling
    - Logging patterns
    
    Usage:
        class CustomerViewSet(BaseAPIViewSet):
            queryset = Customer.objects.all()
            serializer_class = CustomerSerializer
    """
    
    permission_classes = [IsAuthenticatedAndAccessible]
    pagination_class = StandardResultsSetPagination
    throttle_classes = [StandardAPIThrottle]
    
    def get_queryset(self):
        """
        Override in subclasses to filter based on user access.
        Each domain handles its own access control logic.
        """
        # This method must be implemented by subclasses
        queryset = getattr(self, 'queryset', None)
        if queryset is None:
            raise NotImplementedError(
                f"{self.__class__.__name__} must define 'queryset' or override 'get_queryset()'"
            )
        return queryset
    
    def perform_create(self, serializer):
        """Override to use domain services for business logic"""
        # Default implementation - subclasses should override
        # to use their domain's service layer
        serializer.save()
    
    def perform_update(self, serializer):
        """Override to use domain services for business logic"""
        # Default implementation - subclasses should override
        serializer.save()


class ReadOnlyAPIViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Base viewset for read-only API endpoints.
    Used for reference data, search results, etc.
    """
    
    permission_classes = [IsAuthenticatedAndAccessible]  
    pagination_class = StandardResultsSetPagination
    throttle_classes = [BurstAPIThrottle]  # Higher rate limit for read-only
    
    def get_queryset(self):
        """Must be implemented by subclasses"""
        queryset = getattr(self, 'queryset', None)
        if queryset is None:
            raise NotImplementedError(
                f"{self.__class__.__name__} must define 'queryset' or override 'get_queryset()'"
            )
        return queryset
