"""
Caching utilities for PRAHO Platform

Provides multi-tier caching with support for:
- Redis for high-throughput production caching
- Database cache for simpler deployments
- Local memory cache for single-instance development
- Model-level caching with automatic invalidation
- Query result caching
"""

from __future__ import annotations

import functools
import hashlib
import logging
from collections.abc import Callable
from typing import Any, ClassVar, TypeVar, cast

from django.conf import settings
from django.core.cache import cache, caches
from django.db import models

logger = logging.getLogger(__name__)

T = TypeVar("T")

# Cache timeout constants (seconds)
_DEFAULT_CACHE_TIMEOUT_SHORT = 60  # 1 minute
CACHE_TIMEOUT_SHORT = _DEFAULT_CACHE_TIMEOUT_SHORT
_DEFAULT_CACHE_TIMEOUT_MEDIUM = 300  # 5 minutes
CACHE_TIMEOUT_MEDIUM = _DEFAULT_CACHE_TIMEOUT_MEDIUM
_DEFAULT_CACHE_TIMEOUT_LONG = 3600  # 1 hour
CACHE_TIMEOUT_LONG = _DEFAULT_CACHE_TIMEOUT_LONG
_DEFAULT_CACHE_TIMEOUT_VERY_LONG = 86400  # 24 hours
CACHE_TIMEOUT_VERY_LONG = _DEFAULT_CACHE_TIMEOUT_VERY_LONG


def get_cache_timeout_short() -> int:
    """Get cache timeout short from SettingsService (runtime)."""
    from apps.settings.services import SettingsService  # noqa: PLC0415

    return SettingsService.get_integer_setting("common.cache_timeout_short", _DEFAULT_CACHE_TIMEOUT_SHORT)


def get_cache_timeout_medium() -> int:
    """Get cache timeout medium from SettingsService (runtime)."""
    from apps.settings.services import SettingsService  # noqa: PLC0415

    return SettingsService.get_integer_setting("common.cache_timeout_medium", _DEFAULT_CACHE_TIMEOUT_MEDIUM)


def get_cache_timeout_long() -> int:
    """Get cache timeout long from SettingsService (runtime)."""
    from apps.settings.services import SettingsService  # noqa: PLC0415

    return SettingsService.get_integer_setting("common.cache_timeout_long", _DEFAULT_CACHE_TIMEOUT_LONG)


def get_cache_timeout_very_long() -> int:
    """Get cache timeout very long from SettingsService (runtime)."""
    from apps.settings.services import SettingsService  # noqa: PLC0415

    return SettingsService.get_integer_setting("common.cache_timeout_very_long", _DEFAULT_CACHE_TIMEOUT_VERY_LONG)


class CacheService:
    """
    Centralized cache service with multi-tier caching support.

    Provides consistent caching patterns across the application with:
    - Automatic cache key generation
    - Cache versioning for invalidation
    - Performance metrics logging
    - Fallback handling
    """

    # Cache key prefixes for different data types
    PREFIX_MODEL = "model"
    PREFIX_QUERYSET = "qs"
    PREFIX_VIEW = "view"
    PREFIX_COMPUTED = "computed"
    PREFIX_SESSION = "session"
    PREFIX_RATE_LIMIT = "rate"

    def __init__(self, cache_alias: str = "default") -> None:
        self._cache = caches[cache_alias]
        self._version = getattr(settings, "CACHE_VERSION", 1)

    def get(self, key: str, default: Any = None) -> Any:
        """Get a value from cache with automatic key prefixing."""
        full_key = self._make_key(key)
        value = self._cache.get(full_key, default)

        if value is not None:
            logger.debug(f"Cache HIT: {key}")
        else:
            logger.debug(f"Cache MISS: {key}")

        return value

    def set(
        self,
        key: str,
        value: Any,
        timeout: int = CACHE_TIMEOUT_MEDIUM,
        version: int | None = None,
    ) -> bool:
        """Set a value in cache with automatic key prefixing."""
        full_key = self._make_key(key, version)
        try:
            self._cache.set(full_key, value, timeout)
            logger.debug(f"Cache SET: {key} (timeout={timeout}s)")
            return True
        except Exception as e:
            logger.warning(f"Cache SET failed for {key}: {e}")
            return False

    def delete(self, key: str) -> bool:
        """Delete a value from cache."""
        full_key = self._make_key(key)
        try:
            self._cache.delete(full_key)
            logger.debug(f"Cache DELETE: {key}")
            return True
        except Exception as e:
            logger.warning(f"Cache DELETE failed for {key}: {e}")
            return False

    def get_or_set(
        self,
        key: str,
        factory: Callable[[], T],
        timeout: int = CACHE_TIMEOUT_MEDIUM,
    ) -> T:
        """Get from cache or compute and cache the value."""
        value = self.get(key)
        if value is None:
            value = factory()
            self.set(key, value, timeout)
        return cast(T, value)

    def delete_pattern(self, pattern: str) -> int:
        """
        Delete all keys matching a pattern.
        Note: Pattern deletion is only efficient with Redis backend.
        For database cache, this is a no-op.
        """
        # Check if Redis backend is available
        if hasattr(self._cache, "delete_pattern"):
            try:
                return cast(int, self._cache.delete_pattern(f"{self._version}:{pattern}"))
            except Exception as e:
                logger.warning(f"Pattern delete failed for {pattern}: {e}")
        return 0

    def _make_key(self, key: str, version: int | None = None) -> str:
        """Create a versioned cache key."""
        v = version if version is not None else self._version
        return f"praho:{v}:{key}"

    # Specialized cache methods for common patterns

    def cache_model(
        self,
        model_instance: models.Model,
        fields: list[str] | None = None,
        timeout: int = CACHE_TIMEOUT_MEDIUM,
    ) -> bool:
        """Cache a model instance."""
        key = cache_key_for_model(model_instance)

        if fields:
            data = {f: getattr(model_instance, f, None) for f in fields}
        else:
            data = {
                "pk": model_instance.pk,
                "model": f"{model_instance._meta.app_label}.{model_instance._meta.model_name}",
            }

        return self.set(key, data, timeout)

    def get_cached_model(
        self,
        model_class: type[models.Model],
        pk: Any,
    ) -> dict[str, Any] | None:
        """Get a cached model instance data."""
        key = f"{self.PREFIX_MODEL}:{model_class._meta.app_label}.{model_class._meta.model_name}:{pk}"
        return cast("dict[str, Any] | None", self.get(key))

    def cache_queryset_count(
        self,
        queryset: models.QuerySet[Any],
        timeout: int = CACHE_TIMEOUT_SHORT,
    ) -> int:
        """Cache a queryset count to avoid repeated COUNT queries."""
        key = self._queryset_count_key(queryset)

        count = self.get(key)
        if count is None:
            count = queryset.count()
            self.set(key, count, timeout)

        return cast(int, count)

    def _queryset_count_key(self, queryset: models.QuerySet[Any]) -> str:
        """Generate a cache key for a queryset count."""
        # Create a hash of the query SQL
        sql = str(queryset.query)
        query_hash = hashlib.md5(sql.encode()).hexdigest()[:12]  # noqa: S324
        model = queryset.model._meta.label
        return f"{self.PREFIX_QUERYSET}:count:{model}:{query_hash}"


# Global cache service instance
_cache_service: CacheService | None = None


def get_cache_service() -> CacheService:
    """Get the global cache service instance."""
    global _cache_service  # noqa: PLW0603
    if _cache_service is None:
        _cache_service = CacheService()
    return _cache_service


def cache_key_for_model(instance: models.Model, suffix: str = "") -> str:
    """Generate a cache key for a model instance."""
    model_label = f"{instance._meta.app_label}.{instance._meta.model_name}"
    key = f"{CacheService.PREFIX_MODEL}:{model_label}:{instance.pk}"
    if suffix:
        key = f"{key}:{suffix}"
    return key


def invalidate_model_cache(instance: models.Model, suffix: str = "") -> bool:
    """Invalidate cache for a model instance."""
    key = cache_key_for_model(instance, suffix)
    return get_cache_service().delete(key)


def cached_model_property(
    timeout: int = CACHE_TIMEOUT_MEDIUM,
    key_suffix: str = "",
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator to cache expensive model property calculations.

    Usage:
        class Customer(models.Model):
            @cached_model_property(timeout=300, key_suffix="total_spend")
            def calculate_total_spend(self) -> Decimal:
                return self.invoices.aggregate(total=Sum("total_cents"))["total"] or 0
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(self: models.Model, *args: Any, **kwargs: Any) -> T:
            suffix = key_suffix or func.__name__
            key = cache_key_for_model(self, suffix)

            cached_value = cache.get(key)
            if cached_value is not None:
                return cast(T, cached_value)

            value = func(self, *args, **kwargs)
            cache.set(key, value, timeout)
            return value

        return wrapper

    return decorator


def cached_queryset(
    timeout: int = CACHE_TIMEOUT_SHORT,
    key_prefix: str = "",
    max_size: int = 1000,
) -> Callable[[Callable[..., Any]], Callable[..., list[Any]]]:
    """
    Decorator to cache queryset results.

    Warning: Use with caution on large querysets. Set max_size to limit cached items.

    Usage:
        @cached_queryset(timeout=60, key_prefix="active_products")
        def get_active_products() -> QuerySet[Product]:
            return Product.objects.filter(is_active=True)
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., list[Any]]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> list[Any]:
            # Create a unique cache key based on function name and arguments
            key_parts = [key_prefix or func.__name__]

            # Add args to key
            for arg in args:
                if hasattr(arg, "pk"):
                    key_parts.append(f"pk={arg.pk}")
                else:
                    key_parts.append(str(arg)[:50])

            # Add kwargs to key
            for k, v in sorted(kwargs.items()):
                if hasattr(v, "pk"):
                    key_parts.append(f"{k}=pk:{v.pk}")
                else:
                    key_parts.append(f"{k}={str(v)[:50]}")

            key = f"{CacheService.PREFIX_QUERYSET}:{':'.join(key_parts)}"
            key_hash = hashlib.md5(key.encode()).hexdigest()[:16]  # noqa: S324
            cache_key = f"qs:{func.__name__}:{key_hash}"

            cached_result = cache.get(cache_key)
            if cached_result is not None:
                logger.debug(f"QuerySet cache HIT: {func.__name__}")
                return cast("list[Any]", cached_result)

            # Execute queryset and cache results
            queryset = func(*args, **kwargs)
            result = list(queryset[:max_size])

            cache.set(cache_key, result, timeout)
            logger.debug(f"QuerySet cache SET: {func.__name__} ({len(result)} items)")

            return result

        return wrapper

    return decorator


class CacheInvalidationMixin:
    """
    Mixin for models to automatically invalidate cache on save/delete.

    Usage:
        class Customer(CacheInvalidationMixin, models.Model):
            cache_dependencies = ["billing_profile", "tax_profile"]
            ...
    """

    # Override in subclass to specify related models that should be invalidated
    cache_dependencies: ClassVar[list[str]] = []

    def save(self, *args: Any, **kwargs: Any) -> None:
        super().save(*args, **kwargs)  # type: ignore[misc]
        self._invalidate_caches()

    def delete(self, *args: Any, **kwargs: Any) -> Any:
        result = super().delete(*args, **kwargs)  # type: ignore[misc]
        self._invalidate_caches()
        return result

    def _invalidate_caches(self) -> None:
        """Invalidate all related caches."""
        # Invalidate own cache
        invalidate_model_cache(self)  # type: ignore[arg-type]

        # Invalidate dependent caches
        for dep in self.cache_dependencies:
            if hasattr(self, dep):
                related = getattr(self, dep)
                if related is not None and hasattr(related, "pk"):
                    invalidate_model_cache(related)


# Customer-specific caching utilities


def get_customer_cache_key(customer_id: int, data_type: str) -> str:
    """Generate a cache key for customer-specific data."""
    return f"customer:{customer_id}:{data_type}"


def cache_customer_data(
    customer_id: int,
    data_type: str,
    data: Any,
    timeout: int = CACHE_TIMEOUT_MEDIUM,
) -> bool:
    """Cache customer-specific data."""
    key = get_customer_cache_key(customer_id, data_type)
    return get_cache_service().set(key, data, timeout)


def get_cached_customer_data(customer_id: int, data_type: str) -> Any:
    """Get cached customer-specific data."""
    key = get_customer_cache_key(customer_id, data_type)
    return get_cache_service().get(key)


def invalidate_customer_cache(customer_id: int, data_types: list[str] | None = None) -> None:
    """Invalidate all or specific customer caches."""
    service = get_cache_service()

    if data_types:
        for data_type in data_types:
            key = get_customer_cache_key(customer_id, data_type)
            service.delete(key)
    else:
        # Invalidate all customer caches using pattern (Redis only)
        service.delete_pattern(f"customer:{customer_id}:*")
