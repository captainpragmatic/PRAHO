# ===============================================================================
# API BASE VIEWSETS 🎯
# ===============================================================================

from typing import ClassVar

from django.db.models import QuerySet
from rest_framework import viewsets
from rest_framework.serializers import BaseSerializer

from .pagination import StandardResultsSetPagination
from .permissions import IsAuthenticatedAndAccessible
from .throttling import BurstAPIThrottle, StandardAPIThrottle


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
    
    permission_classes: ClassVar = [IsAuthenticatedAndAccessible]
    pagination_class = StandardResultsSetPagination
    throttle_classes: ClassVar = [StandardAPIThrottle]
    
    def get_queryset(self) -> QuerySet:
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
    
    def perform_create(self, serializer: BaseSerializer) -> None:
        """Override to use domain services for business logic"""
        # Default implementation - subclasses should override
        # to use their domain's service layer
        serializer.save()
    
    def perform_update(self, serializer: BaseSerializer) -> None:
        """Override to use domain services for business logic"""
        # Default implementation - subclasses should override
        serializer.save()


class ReadOnlyAPIViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Base viewset for read-only API endpoints.
    Used for reference data, search results, etc.
    """
    
    permission_classes: ClassVar = [IsAuthenticatedAndAccessible]  
    pagination_class = StandardResultsSetPagination
    throttle_classes: ClassVar = [BurstAPIThrottle]  # Higher rate limit for read-only
    
    def get_queryset(self) -> QuerySet:
        """Must be implemented by subclasses"""
        queryset = getattr(self, 'queryset', None)
        if queryset is None:
            raise NotImplementedError(
                f"{self.__class__.__name__} must define 'queryset' or override 'get_queryset()'"
            )
        return queryset
