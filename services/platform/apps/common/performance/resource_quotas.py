"""
Resource Quotas and Customer Isolation for PRAHO Platform

Provides customer-level resource quotas and isolation including:
- API request quotas
- Storage quotas
- Service limits
- Bandwidth limits
- Operation rate limits
"""

from __future__ import annotations

import functools
import logging
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any, TypeVar

from django.core.cache import cache
from django.db import models
from django.http import HttpRequest, JsonResponse
from django.utils import timezone

logger = logging.getLogger(__name__)

WARNING_USAGE_PERCENT = 80.0
DECEMBER = 12


T = TypeVar("T")


class QuotaType(Enum):
    """Types of quotas that can be enforced."""

    API_REQUESTS = "api_requests"
    STORAGE_MB = "storage_mb"
    BANDWIDTH_MB = "bandwidth_mb"
    SERVICES = "services"
    DOMAINS = "domains"
    EMAIL_ACCOUNTS = "email_accounts"
    DATABASES = "databases"
    BACKUPS = "backups"
    USERS = "users"
    API_KEYS = "api_keys"


@dataclass
class CustomerQuota:
    """Customer quota configuration."""

    customer_id: int
    quota_type: QuotaType
    limit: int
    current_usage: int
    period: str = "monthly"  # daily, weekly, monthly, lifetime
    reset_at: Any | None = None

    @property
    def remaining(self) -> int:
        """Calculate remaining quota."""
        return max(0, self.limit - self.current_usage)

    @property
    def usage_percentage(self) -> float:
        """Calculate usage as percentage."""
        if self.limit == 0:
            return 100.0
        return (self.current_usage / self.limit) * 100

    @property
    def is_exceeded(self) -> bool:
        """Check if quota is exceeded."""
        return self.current_usage >= self.limit

    @property
    def is_warning(self) -> bool:
        """Check if quota is approaching limit (80%)."""
        return self.usage_percentage >= WARNING_USAGE_PERCENT

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "quota_type": self.quota_type.value,
            "limit": self.limit,
            "current_usage": self.current_usage,
            "remaining": self.remaining,
            "usage_percentage": round(self.usage_percentage, 2),
            "period": self.period,
            "reset_at": self.reset_at.isoformat() if self.reset_at else None,
            "is_exceeded": self.is_exceeded,
            "is_warning": self.is_warning,
        }


# Default quota limits by customer tier
DEFAULT_QUOTAS = {
    "basic": {
        QuotaType.API_REQUESTS: 10000,  # per month
        QuotaType.STORAGE_MB: 5120,  # 5 GB
        QuotaType.BANDWIDTH_MB: 102400,  # 100 GB
        QuotaType.SERVICES: 3,
        QuotaType.DOMAINS: 5,
        QuotaType.EMAIL_ACCOUNTS: 10,
        QuotaType.DATABASES: 3,
        QuotaType.BACKUPS: 5,
        QuotaType.USERS: 2,
        QuotaType.API_KEYS: 2,
    },
    "professional": {
        QuotaType.API_REQUESTS: 100000,
        QuotaType.STORAGE_MB: 51200,  # 50 GB
        QuotaType.BANDWIDTH_MB: 512000,  # 500 GB
        QuotaType.SERVICES: 10,
        QuotaType.DOMAINS: 25,
        QuotaType.EMAIL_ACCOUNTS: 100,
        QuotaType.DATABASES: 25,
        QuotaType.BACKUPS: 30,
        QuotaType.USERS: 10,
        QuotaType.API_KEYS: 10,
    },
    "enterprise": {
        QuotaType.API_REQUESTS: 1000000,
        QuotaType.STORAGE_MB: 512000,  # 500 GB
        QuotaType.BANDWIDTH_MB: 5120000,  # 5 TB
        QuotaType.SERVICES: 100,
        QuotaType.DOMAINS: 500,
        QuotaType.EMAIL_ACCOUNTS: 1000,
        QuotaType.DATABASES: 250,
        QuotaType.BACKUPS: 90,
        QuotaType.USERS: 100,
        QuotaType.API_KEYS: 50,
    },
}


class QuotaEnforcer:
    """
    Enforces customer quotas and tracks usage.
    Uses caching for performance with periodic database sync.
    """

    CACHE_PREFIX = "quota"
    CACHE_TIMEOUT = 3600  # 1 hour

    def __init__(self) -> None:
        self._custom_quotas: dict[tuple[int, QuotaType], int] = {}

    def get_quota_limit(
        self,
        customer_id: int,
        quota_type: QuotaType,
        tier: str = "basic",
    ) -> int:
        """Get the quota limit for a customer."""
        # Check for custom quota override
        custom_key = (customer_id, quota_type)
        if custom_key in self._custom_quotas:
            return self._custom_quotas[custom_key]

        # Check cache for custom quota
        cache_key = f"{self.CACHE_PREFIX}:limit:{customer_id}:{quota_type.value}"
        cached_limit = cache.get(cache_key)
        if cached_limit is not None:
            return cached_limit

        # Fall back to tier defaults
        tier_quotas = DEFAULT_QUOTAS.get(tier, DEFAULT_QUOTAS["basic"])
        return tier_quotas.get(quota_type, 0)

    def get_current_usage(
        self,
        customer_id: int,
        quota_type: QuotaType,
    ) -> int:
        """Get current usage for a quota."""
        cache_key = f"{self.CACHE_PREFIX}:usage:{customer_id}:{quota_type.value}"
        usage = cache.get(cache_key)

        if usage is None:
            # Calculate from database
            usage = self._calculate_usage_from_db(customer_id, quota_type)
            cache.set(cache_key, usage, self.CACHE_TIMEOUT)

        return usage

    def increment_usage(
        self,
        customer_id: int,
        quota_type: QuotaType,
        amount: int = 1,
    ) -> int:
        """Increment usage counter and return new value."""
        cache_key = f"{self.CACHE_PREFIX}:usage:{customer_id}:{quota_type.value}"

        # Try atomic increment
        try:
            new_value = cache.incr(cache_key, amount)
        except ValueError:
            # Key doesn't exist, calculate and set
            current = self._calculate_usage_from_db(customer_id, quota_type)
            new_value = current + amount
            cache.set(cache_key, new_value, self.CACHE_TIMEOUT)

        return new_value

    def check_quota(
        self,
        customer_id: int,
        quota_type: QuotaType,
        required_amount: int = 1,
        tier: str = "basic",
    ) -> tuple[bool, CustomerQuota]:
        """
        Check if a customer has sufficient quota.
        Returns (allowed, quota_info).
        """
        limit = self.get_quota_limit(customer_id, quota_type, tier)
        current_usage = self.get_current_usage(customer_id, quota_type)

        quota = CustomerQuota(
            customer_id=customer_id,
            quota_type=quota_type,
            limit=limit,
            current_usage=current_usage,
            reset_at=self._get_reset_time(quota_type),
        )

        allowed = (current_usage + required_amount) <= limit
        return allowed, quota

    def get_all_quotas(
        self,
        customer_id: int,
        tier: str = "basic",
    ) -> list[CustomerQuota]:
        """Get all quotas for a customer."""
        quotas = []
        for quota_type in QuotaType:
            _, quota = self.check_quota(customer_id, quota_type, 0, tier)
            quotas.append(quota)
        return quotas

    def set_custom_quota(
        self,
        customer_id: int,
        quota_type: QuotaType,
        limit: int,
    ) -> None:
        """Set a custom quota override for a customer."""
        cache_key = f"{self.CACHE_PREFIX}:limit:{customer_id}:{quota_type.value}"
        cache.set(cache_key, limit, None)  # No timeout for custom limits
        self._custom_quotas[(customer_id, quota_type)] = limit

        logger.info(f"Custom quota set: customer={customer_id}, " f"type={quota_type.value}, limit={limit}")

    def reset_usage(
        self,
        customer_id: int,
        quota_type: QuotaType | None = None,
    ) -> None:
        """Reset usage counters for a customer."""
        if quota_type:
            cache_key = f"{self.CACHE_PREFIX}:usage:{customer_id}:{quota_type.value}"
            cache.delete(cache_key)
        else:
            # Reset all quotas
            for qt in QuotaType:
                cache_key = f"{self.CACHE_PREFIX}:usage:{customer_id}:{qt.value}"
                cache.delete(cache_key)

    def _calculate_usage_from_db(  # noqa: PLR0911
        self,
        customer_id: int,
        quota_type: QuotaType,
    ) -> int:
        """Calculate current usage from database."""
        # Import models here to avoid circular imports
        try:
            if quota_type == QuotaType.SERVICES:
                from apps.provisioning.models import Service  # noqa: PLC0415

                return Service.objects.filter(
                    customer_id=customer_id,
                    status__in=["active", "pending", "provisioning"],
                ).count()

            elif quota_type == QuotaType.DOMAINS:
                from apps.provisioning.models import (  # noqa: PLC0415
                    ServiceDomain,
                )

                return ServiceDomain.objects.filter(
                    service__customer_id=customer_id,
                ).count()

            elif quota_type == QuotaType.STORAGE_MB:
                from apps.provisioning.models import Service  # noqa: PLC0415

                total = Service.objects.filter(
                    customer_id=customer_id,
                    status="active",
                ).aggregate(total=models.Sum("disk_usage_mb"))["total"]
                return total or 0

            elif quota_type == QuotaType.BANDWIDTH_MB:
                from apps.provisioning.models import Service  # noqa: PLC0415

                total = Service.objects.filter(
                    customer_id=customer_id,
                    status="active",
                ).aggregate(total=models.Sum("bandwidth_usage_mb"))["total"]
                return total or 0

            elif quota_type == QuotaType.EMAIL_ACCOUNTS:
                from apps.provisioning.models import Service  # noqa: PLC0415

                total = Service.objects.filter(
                    customer_id=customer_id,
                    status="active",
                ).aggregate(total=models.Sum("email_accounts_used"))["total"]
                return total or 0

            elif quota_type == QuotaType.DATABASES:
                from apps.provisioning.models import Service  # noqa: PLC0415

                total = Service.objects.filter(
                    customer_id=customer_id,
                    status="active",
                ).aggregate(total=models.Sum("databases_used"))["total"]
                return total or 0

            elif quota_type == QuotaType.API_REQUESTS:
                # API requests are tracked in cache only, no DB query needed
                return 0

            elif quota_type == QuotaType.USERS:
                from apps.users.models import CustomerMembership  # noqa: PLC0415

                return CustomerMembership.objects.filter(
                    customer_id=customer_id,
                ).count()

        except Exception as e:
            logger.warning(f"Error calculating usage for {quota_type}: {e}")

        return 0

    def _get_reset_time(self, quota_type: QuotaType) -> Any:
        """Get the next reset time for a quota."""
        now = timezone.now()

        # API requests reset monthly
        if quota_type == QuotaType.API_REQUESTS:
            # First day of next month
            if now.month == DECEMBER:
                return now.replace(year=now.year + 1, month=1, day=1, hour=0, minute=0, second=0)
            return now.replace(month=now.month + 1, day=1, hour=0, minute=0, second=0)

        # Bandwidth resets monthly
        if quota_type == QuotaType.BANDWIDTH_MB:
            if now.month == DECEMBER:
                return now.replace(year=now.year + 1, month=1, day=1, hour=0, minute=0, second=0)
            return now.replace(month=now.month + 1, day=1, hour=0, minute=0, second=0)

        # Other quotas don't reset (lifetime limits)
        return None


# Global quota enforcer instance
_quota_enforcer: QuotaEnforcer | None = None


def get_quota_enforcer() -> QuotaEnforcer:
    """Get the global quota enforcer instance."""
    global _quota_enforcer  # noqa: PLW0603
    if _quota_enforcer is None:
        _quota_enforcer = QuotaEnforcer()
    return _quota_enforcer


def check_quota(
    customer_id: int,
    quota_type: QuotaType,
    required_amount: int = 1,
    tier: str = "basic",
) -> tuple[bool, CustomerQuota]:
    """Check if a customer has sufficient quota."""
    return get_quota_enforcer().check_quota(customer_id, quota_type, required_amount, tier)


def get_customer_usage(customer_id: int, tier: str = "basic") -> list[CustomerQuota]:
    """Get all quota usage for a customer."""
    return get_quota_enforcer().get_all_quotas(customer_id, tier)


# Decorators for quota enforcement


def enforce_quota(
    quota_type: QuotaType,
    amount: int = 1,
    tier_attr: str = "customer_tier",
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator to enforce quota before executing a view.

    Usage:
        @enforce_quota(QuotaType.API_REQUESTS)
        def api_view(request):
            ...

        @enforce_quota(QuotaType.SERVICES, amount=1)
        def create_service(request):
            ...
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
            # Get customer ID from request
            customer_id = getattr(request, "current_customer_id", None)
            if customer_id is None:
                customer_id = request.session.get("current_customer_id")

            if customer_id is None:
                # No customer context, allow the request
                return func(request, *args, **kwargs)

            # Get tier
            tier = getattr(request, tier_attr, "basic")

            # Check quota
            allowed, quota = check_quota(customer_id, quota_type, amount, tier)

            if not allowed:
                logger.warning(
                    f"Quota exceeded: customer={customer_id}, "
                    f"type={quota_type.value}, usage={quota.current_usage}/{quota.limit}"
                )
                return JsonResponse(
                    {
                        "error": "Quota exceeded",
                        "quota": quota.to_dict(),
                    },
                    status=429,
                )

            # Increment usage after successful check
            if quota_type == QuotaType.API_REQUESTS:
                get_quota_enforcer().increment_usage(customer_id, quota_type, amount)

            return func(request, *args, **kwargs)

        return wrapper

    return decorator


def track_api_usage(func: Callable[..., T]) -> Callable[..., T]:
    """
    Decorator to track API request usage for quota purposes.
    Lighter weight than enforce_quota - just tracks, doesn't block.
    """

    @functools.wraps(func)
    def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
        # Get customer ID
        customer_id = getattr(request, "current_customer_id", None)
        if customer_id is None:
            customer_id = request.session.get("current_customer_id")

        # Track usage
        if customer_id:
            get_quota_enforcer().increment_usage(customer_id, QuotaType.API_REQUESTS, 1)

        return func(request, *args, **kwargs)

    return wrapper


# Customer isolation utilities


class CustomerIsolationMixin:
    """
    Mixin for querysets to automatically filter by customer.
    Ensures data isolation between customers.

    Usage:
        class ServiceQuerySet(CustomerIsolationMixin, models.QuerySet):
            pass

        class Service(models.Model):
            objects = ServiceQuerySet.as_manager()
    """

    def for_customer(self, customer_id: int) -> models.QuerySet[Any]:
        """Filter queryset by customer ID."""
        return self.filter(customer_id=customer_id)  # type: ignore[attr-defined]

    def for_request(self, request: HttpRequest) -> models.QuerySet[Any]:
        """Filter queryset by customer from request."""
        customer_id = getattr(request, "current_customer_id", None)
        if customer_id is None:
            customer_id = request.session.get("current_customer_id")

        if customer_id:
            return self.for_customer(customer_id)

        # No customer context - return empty queryset for safety
        return self.none()  # type: ignore[attr-defined]


def get_customer_isolated_queryset(
    model: type[models.Model],
    customer_id: int,
    base_queryset: models.QuerySet[Any] | None = None,
) -> models.QuerySet[Any]:
    """
    Get a queryset filtered by customer ID.
    Works with any model that has a customer foreign key.
    """
    if base_queryset is None:
        base_queryset = model.objects.all()

    # Check for direct customer field
    if hasattr(model, "customer_id") or hasattr(model, "customer"):
        return base_queryset.filter(customer_id=customer_id)

    # Check for customer through another relation
    for field in model._meta.get_fields():
        if hasattr(field, "related_model"):
            related = field.related_model
            if related and hasattr(related, "customer"):
                return base_queryset.filter(**{f"{field.name}__customer_id": customer_id})

    logger.warning(f"Model {model.__name__} doesn't have a customer relationship")
    return base_queryset
