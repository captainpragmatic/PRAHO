"""
Infrastructure Permissions

Role-based access control for infrastructure management operations.
"""

from __future__ import annotations

import logging
from functools import wraps
from typing import TYPE_CHECKING, Callable

from django.contrib.auth.decorators import user_passes_test
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest, HttpResponse

if TYPE_CHECKING:
    from apps.users.models import User

logger = logging.getLogger(__name__)


# ===============================================================================
# PERMISSION CONSTANTS
# ===============================================================================

# Infrastructure permission codes
PERM_VIEW_INFRASTRUCTURE = "infrastructure.view_infrastructure"
PERM_MANAGE_DEPLOYMENTS = "infrastructure.manage_deployments"
PERM_DEPLOY_NODES = "infrastructure.deploy_nodes"
PERM_DESTROY_NODES = "infrastructure.destroy_nodes"
PERM_MANAGE_PROVIDERS = "infrastructure.manage_providers"
PERM_MANAGE_SIZES = "infrastructure.manage_sizes"
PERM_MANAGE_REGIONS = "infrastructure.manage_regions"


# ===============================================================================
# PERMISSION CHECKS
# ===============================================================================


def is_staff_or_superuser(user: User) -> bool:
    """Check if user is staff or superuser"""
    return user.is_authenticated and (user.is_staff or user.is_superuser)


def can_view_infrastructure(user: User) -> bool:
    """
    Check if user can view infrastructure dashboard and listings.

    Staff and superusers always have access.
    """
    if not user.is_authenticated:
        return False

    if user.is_superuser or user.is_staff:
        return True

    return user.has_perm(PERM_VIEW_INFRASTRUCTURE)


def can_manage_deployments(user: User) -> bool:
    """
    Check if user can manage deployments (view details, logs).

    Staff and superusers always have access.
    """
    if not user.is_authenticated:
        return False

    if user.is_superuser or user.is_staff:
        return True

    return user.has_perm(PERM_MANAGE_DEPLOYMENTS)


def can_deploy_nodes(user: User) -> bool:
    """
    Check if user can create new node deployments.

    Requires elevated permissions beyond basic view access.
    """
    if not user.is_authenticated:
        return False

    if user.is_superuser:
        return True

    # Staff with deploy permission
    if user.is_staff and user.has_perm(PERM_DEPLOY_NODES):
        return True

    return user.has_perm(PERM_DEPLOY_NODES)


def can_destroy_nodes(user: User) -> bool:
    """
    Check if user can destroy nodes.

    Requires explicit destroy permission - very destructive action.
    """
    if not user.is_authenticated:
        return False

    if user.is_superuser:
        return True

    return user.has_perm(PERM_DESTROY_NODES)


def can_retry_deployments(user: User) -> bool:
    """
    Check if user can retry failed deployments.

    Same permission level as deploying new nodes.
    """
    return can_deploy_nodes(user)


def can_manage_providers(user: User) -> bool:
    """
    Check if user can manage cloud providers.

    Requires admin-level access.
    """
    if not user.is_authenticated:
        return False

    if user.is_superuser:
        return True

    return user.has_perm(PERM_MANAGE_PROVIDERS)


def can_manage_sizes(user: User) -> bool:
    """
    Check if user can manage node sizes.

    Requires admin-level access.
    """
    if not user.is_authenticated:
        return False

    if user.is_superuser:
        return True

    return user.has_perm(PERM_MANAGE_SIZES)


def can_manage_regions(user: User) -> bool:
    """
    Check if user can manage regions (enable/disable).

    Requires admin-level access.
    """
    if not user.is_authenticated:
        return False

    if user.is_superuser:
        return True

    return user.has_perm(PERM_MANAGE_REGIONS)


# ===============================================================================
# DECORATORS
# ===============================================================================


def require_infrastructure_view(view_func: Callable) -> Callable:
    """
    Decorator requiring infrastructure view permission.

    Usage:
        @require_infrastructure_view
        def my_view(request):
            ...
    """

    @wraps(view_func)
    def wrapper(request: HttpRequest, *args, **kwargs) -> HttpResponse:
        if not can_view_infrastructure(request.user):
            logger.warning(
                f"[Permissions] Access denied: {request.user.email} tried to view infrastructure"
            )
            raise PermissionDenied("You do not have permission to view infrastructure.")
        return view_func(request, *args, **kwargs)

    return wrapper


def require_deployment_management(view_func: Callable) -> Callable:
    """
    Decorator requiring deployment management permission.

    Usage:
        @require_deployment_management
        def deployment_detail(request, pk):
            ...
    """

    @wraps(view_func)
    def wrapper(request: HttpRequest, *args, **kwargs) -> HttpResponse:
        if not can_manage_deployments(request.user):
            logger.warning(
                f"[Permissions] Access denied: {request.user.email} tried to manage deployment"
            )
            raise PermissionDenied("You do not have permission to manage deployments.")
        return view_func(request, *args, **kwargs)

    return wrapper


def require_deploy_permission(view_func: Callable) -> Callable:
    """
    Decorator requiring node deployment permission.

    Usage:
        @require_deploy_permission
        def deployment_create(request):
            ...
    """

    @wraps(view_func)
    def wrapper(request: HttpRequest, *args, **kwargs) -> HttpResponse:
        if not can_deploy_nodes(request.user):
            logger.warning(
                f"[Permissions] Access denied: {request.user.email} tried to deploy node"
            )
            raise PermissionDenied("You do not have permission to deploy nodes.")
        return view_func(request, *args, **kwargs)

    return wrapper


def require_destroy_permission(view_func: Callable) -> Callable:
    """
    Decorator requiring node destruction permission.

    Usage:
        @require_destroy_permission
        def deployment_destroy(request, pk):
            ...
    """

    @wraps(view_func)
    def wrapper(request: HttpRequest, *args, **kwargs) -> HttpResponse:
        if not can_destroy_nodes(request.user):
            logger.warning(
                f"[Permissions] Access denied: {request.user.email} tried to destroy node"
            )
            raise PermissionDenied("You do not have permission to destroy nodes.")
        return view_func(request, *args, **kwargs)

    return wrapper


def require_provider_management(view_func: Callable) -> Callable:
    """
    Decorator requiring provider management permission.

    Usage:
        @require_provider_management
        def provider_create(request):
            ...
    """

    @wraps(view_func)
    def wrapper(request: HttpRequest, *args, **kwargs) -> HttpResponse:
        if not can_manage_providers(request.user):
            logger.warning(
                f"[Permissions] Access denied: {request.user.email} tried to manage providers"
            )
            raise PermissionDenied("You do not have permission to manage providers.")
        return view_func(request, *args, **kwargs)

    return wrapper


def require_size_management(view_func: Callable) -> Callable:
    """
    Decorator requiring size management permission.

    Usage:
        @require_size_management
        def size_create(request):
            ...
    """

    @wraps(view_func)
    def wrapper(request: HttpRequest, *args, **kwargs) -> HttpResponse:
        if not can_manage_sizes(request.user):
            logger.warning(
                f"[Permissions] Access denied: {request.user.email} tried to manage sizes"
            )
            raise PermissionDenied("You do not have permission to manage sizes.")
        return view_func(request, *args, **kwargs)

    return wrapper


def require_region_management(view_func: Callable) -> Callable:
    """
    Decorator requiring region management permission.

    Usage:
        @require_region_management
        def region_toggle(request, pk):
            ...
    """

    @wraps(view_func)
    def wrapper(request: HttpRequest, *args, **kwargs) -> HttpResponse:
        if not can_manage_regions(request.user):
            logger.warning(
                f"[Permissions] Access denied: {request.user.email} tried to manage regions"
            )
            raise PermissionDenied("You do not have permission to manage regions.")
        return view_func(request, *args, **kwargs)

    return wrapper


# ===============================================================================
# CLASS-BASED VIEW MIXINS
# ===============================================================================


class InfrastructureViewMixin:
    """Mixin requiring infrastructure view permission"""

    def dispatch(self, request, *args, **kwargs):
        if not can_view_infrastructure(request.user):
            raise PermissionDenied("You do not have permission to view infrastructure.")
        return super().dispatch(request, *args, **kwargs)


class DeploymentManagementMixin:
    """Mixin requiring deployment management permission"""

    def dispatch(self, request, *args, **kwargs):
        if not can_manage_deployments(request.user):
            raise PermissionDenied("You do not have permission to manage deployments.")
        return super().dispatch(request, *args, **kwargs)


class DeployNodeMixin:
    """Mixin requiring node deployment permission"""

    def dispatch(self, request, *args, **kwargs):
        if not can_deploy_nodes(request.user):
            raise PermissionDenied("You do not have permission to deploy nodes.")
        return super().dispatch(request, *args, **kwargs)


class DestroyNodeMixin:
    """Mixin requiring node destruction permission"""

    def dispatch(self, request, *args, **kwargs):
        if not can_destroy_nodes(request.user):
            raise PermissionDenied("You do not have permission to destroy nodes.")
        return super().dispatch(request, *args, **kwargs)
