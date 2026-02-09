"""
Performance & Scalability Module for PRAHO Platform

This module provides comprehensive performance optimizations including:
- Database query optimization utilities
- Multi-tier caching with Redis support
- API rate limiting and throttling (DRF)
- Connection pooling for external services
- Resource quotas and customer isolation
- Async processing utilities with progress tracking
"""

from .async_tasks import (
    BulkOperationProcessor,
    DistributedLock,
    TaskPriority,
    TaskProgressTracker,
    TaskResult,
    TaskStatus,
    async_task,
    generate_task_id,
    get_task_status,
    schedule_task,
    with_lock,
)
from .cache import (
    CACHE_TIMEOUT_LONG,
    CACHE_TIMEOUT_MEDIUM,
    CACHE_TIMEOUT_SHORT,
    CACHE_TIMEOUT_VERY_LONG,
    CacheInvalidationMixin,
    CacheService,
    cache_customer_data,
    cache_key_for_model,
    cached_model_property,
    cached_queryset,
    get_cache_service,
    get_cached_customer_data,
    invalidate_customer_cache,
    invalidate_model_cache,
)
from .connection_pool import (
    ConnectionPool,
    ExternalServicePool,
    HTTPConnectionPool,
    SSHConnectionPool,
    cleanup_pools,
    get_database_pool_config,
    get_http_session,
)
from .query_optimization import (
    INDEX_RECOMMENDATIONS,
    CustomerQueryOptimization,
    InvoiceQueryOptimization,
    OptimizedManager,
    OptimizedQuerySetMixin,
    OrderQueryOptimization,
    QueryProfiler,
    ServiceQueryOptimization,
    annotate_counts,
    bulk_select_related,
    get_missing_indexes,
    prefetch_related_for_list,
    profile_queries,
    select_related_for_detail,
)
from .rate_limiting import (
    AnonymousRateThrottle,
    BurstRateThrottle,
    CustomerRateThrottle,
    EndpointThrottle,
    ServiceRateThrottle,
    SustainedRateThrottle,
    WriteOperationThrottle,
    add_rate_limit_headers,
    get_rate_limit_headers,
    get_throttle_rate_for_endpoint,
)
from .resource_quotas import (
    CustomerIsolationMixin,
    CustomerQuota,
    QuotaEnforcer,
    QuotaType,
    check_quota,
    enforce_quota,
    get_customer_isolated_queryset,
    get_customer_usage,
    get_quota_enforcer,
    track_api_usage,
)

__all__ = [
    # Async task processing
    "BulkOperationProcessor",
    "DistributedLock",
    "TaskPriority",
    "TaskProgressTracker",
    "TaskResult",
    "TaskStatus",
    "async_task",
    "generate_task_id",
    "get_task_status",
    "schedule_task",
    "with_lock",
    # Cache utilities
    "CACHE_TIMEOUT_LONG",
    "CACHE_TIMEOUT_MEDIUM",
    "CACHE_TIMEOUT_SHORT",
    "CACHE_TIMEOUT_VERY_LONG",
    "CacheInvalidationMixin",
    "CacheService",
    "cache_customer_data",
    "cache_key_for_model",
    "cached_model_property",
    "cached_queryset",
    "get_cache_service",
    "get_cached_customer_data",
    "invalidate_customer_cache",
    "invalidate_model_cache",
    # Connection pooling
    "ConnectionPool",
    "ExternalServicePool",
    "HTTPConnectionPool",
    "SSHConnectionPool",
    "cleanup_pools",
    "get_database_pool_config",
    "get_http_session",
    # Query optimization
    "CustomerQueryOptimization",
    "INDEX_RECOMMENDATIONS",
    "InvoiceQueryOptimization",
    "OptimizedManager",
    "OptimizedQuerySetMixin",
    "OrderQueryOptimization",
    "QueryProfiler",
    "ServiceQueryOptimization",
    "annotate_counts",
    "bulk_select_related",
    "get_missing_indexes",
    "prefetch_related_for_list",
    "profile_queries",
    "select_related_for_detail",
    # Rate limiting
    "AnonymousRateThrottle",
    "BurstRateThrottle",
    "CustomerRateThrottle",
    "EndpointThrottle",
    "ServiceRateThrottle",
    "SustainedRateThrottle",
    "WriteOperationThrottle",
    "add_rate_limit_headers",
    "get_rate_limit_headers",
    "get_throttle_rate_for_endpoint",
    # Resource quotas
    "CustomerIsolationMixin",
    "CustomerQuota",
    "QuotaEnforcer",
    "QuotaType",
    "check_quota",
    "enforce_quota",
    "get_customer_isolated_queryset",
    "get_customer_usage",
    "get_quota_enforcer",
    "track_api_usage",
]
