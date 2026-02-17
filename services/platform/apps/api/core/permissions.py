# ===============================================================================
# API PERMISSIONS CLASSES 🔐
# ===============================================================================

from typing import Any

from django.http import HttpRequest
from rest_framework import permissions


class IsAuthenticatedAndAccessible(permissions.BasePermission):
    """
    Custom permission that ensures user is authenticated AND
    has access to the requested resource based on PRAHO's
    customer membership system.
    """

    def has_permission(self, request: HttpRequest, view: Any) -> bool:
        """Check if user is authenticated"""
        return bool(request.user and request.user.is_authenticated)

    def has_object_permission(self, request: HttpRequest, view: Any, obj: Any) -> bool:
        """
        Check object-level permissions using PRAHO's customer access system.
        This will be customized per domain (customer, billing, tickets).
        """
        # Default implementation - can be overridden by specific viewsets
        return True
