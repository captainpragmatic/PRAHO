"""
Database Query Optimization Utilities for PRAHO Platform

Provides utilities for:
- Automatic select_related/prefetch_related optimization
- N+1 query detection and prevention
- Query profiling and logging
- Optimized manager classes
"""

from __future__ import annotations

import functools
import logging
import time
from typing import Any, TypeVar

from django.conf import settings
from django.db import connection, models, reset_queries
from django.db.models import Count, Prefetch, QuerySet

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=models.Model)


class OptimizedQuerySetMixin:
    """
    Mixin for QuerySets to automatically apply select_related and prefetch_related
    based on defined optimization rules.

    Usage:
        class CustomerQuerySet(OptimizedQuerySetMixin, models.QuerySet):
            select_related_fields = ["billing_profile", "tax_profile"]
            prefetch_related_fields = ["addresses", "services"]

            def active(self):
                return self.filter(status="active").optimized()
    """

    # Override in subclass to define default relations to select/prefetch
    select_related_fields: list[str] = []
    prefetch_related_fields: list[str] = []

    def optimized(self, select: list[str] | None = None, prefetch: list[str] | None = None) -> QuerySet[Any]:
        """Apply optimizations to the queryset."""
        qs = self

        # Apply select_related
        select_fields = select if select is not None else self.select_related_fields
        if select_fields:
            qs = qs.select_related(*select_fields)  # type: ignore[attr-defined]

        # Apply prefetch_related
        prefetch_fields = prefetch if prefetch is not None else self.prefetch_related_fields
        if prefetch_fields:
            qs = qs.prefetch_related(*prefetch_fields)  # type: ignore[attr-defined]

        return qs  # type: ignore[return-value]

    def optimized_for_list(self) -> QuerySet[Any]:
        """Apply light optimizations suitable for list views."""
        return self.optimized()

    def optimized_for_detail(self) -> QuerySet[Any]:
        """Apply full optimizations suitable for detail views."""
        return self.optimized()


class OptimizedManager(models.Manager[T]):
    """
    Manager that uses OptimizedQuerySet and provides optimized query methods.

    Usage:
        class Customer(models.Model):
            objects = OptimizedManager()

            class OptimizedQuerySet(OptimizedQuerySetMixin, models.QuerySet):
                select_related_fields = ["billing_profile"]
    """

    def get_queryset(self) -> QuerySet[T]:
        queryset_class = getattr(self.model, "OptimizedQuerySet", None)
        if queryset_class:
            return queryset_class(self.model, using=self._db)
        return super().get_queryset()

    def optimized(self) -> QuerySet[T]:
        """Get an optimized queryset."""
        qs = self.get_queryset()
        if hasattr(qs, "optimized"):
            return qs.optimized()  # type: ignore[return-value]
        return qs


def select_related_for_detail(*relations: str) -> list[str]:
    """
    Helper to define select_related fields for detail views.
    Returns a list that can be used with select_related().

    Usage:
        queryset.select_related(*select_related_for_detail(
            "customer",
            "customer__billing_profile",
            "customer__tax_profile",
        ))
    """
    return list(relations)


def prefetch_related_for_list(*relations: str | Prefetch) -> list[str | Prefetch]:
    """
    Helper to define prefetch_related fields for list views.
    Returns a list that can be used with prefetch_related().

    Usage:
        queryset.prefetch_related(*prefetch_related_for_list(
            "items",
            Prefetch("services", queryset=Service.objects.filter(status="active")),
        ))
    """
    return list(relations)


# Common optimization patterns for PRAHO models


class CustomerQueryOptimization:
    """Optimization patterns for Customer queries."""

    @staticmethod
    def for_list() -> dict[str, list[str]]:
        return {
            "select_related": [],
            "prefetch_related": ["addresses"],
        }

    @staticmethod
    def for_detail() -> dict[str, list[str]]:
        return {
            "select_related": ["assigned_account_manager"],
            "prefetch_related": [
                "addresses",
                "services",
                "invoices",
            ],
        }

    @staticmethod
    def for_billing() -> dict[str, list[str]]:
        return {
            "select_related": [],
            "prefetch_related": [
                "invoices",
                "payments",
            ],
        }


class InvoiceQueryOptimization:
    """Optimization patterns for Invoice queries."""

    @staticmethod
    def for_list() -> dict[str, list[str]]:
        return {
            "select_related": ["customer", "currency"],
            "prefetch_related": [],
        }

    @staticmethod
    def for_detail() -> dict[str, list[str] | list[Prefetch]]:
        return {
            "select_related": ["customer", "currency", "created_by"],
            "prefetch_related": [
                "lines",
                "payments",
            ],
        }


class OrderQueryOptimization:
    """Optimization patterns for Order queries."""

    @staticmethod
    def for_list() -> dict[str, list[str]]:
        return {
            "select_related": ["customer", "currency"],
            "prefetch_related": [],
        }

    @staticmethod
    def for_detail() -> dict[str, list[str] | list[Prefetch]]:
        return {
            "select_related": ["customer", "currency", "invoice"],
            "prefetch_related": [
                "items",
                "items__product",
                "items__service",
                "status_history",
            ],
        }


class ServiceQueryOptimization:
    """Optimization patterns for Service queries."""

    @staticmethod
    def for_list() -> dict[str, list[str]]:
        return {
            "select_related": ["customer", "service_plan"],
            "prefetch_related": [],
        }

    @staticmethod
    def for_detail() -> dict[str, list[str]]:
        return {
            "select_related": ["customer", "service_plan", "server"],
            "prefetch_related": [
                "provisioning_tasks",
                "order_items",
            ],
        }


# Query profiling utilities


class QueryProfiler:
    """
    Context manager for profiling database queries.

    Usage:
        with QueryProfiler("customer_list") as profiler:
            customers = list(Customer.objects.all())
        print(f"Queries: {profiler.query_count}, Time: {profiler.total_time}ms")
    """

    def __init__(self, name: str, log_queries: bool = False) -> None:
        self.name = name
        self.log_queries = log_queries
        self.query_count = 0
        self.total_time = 0.0
        self._start_queries = 0
        self._start_time = 0.0

    def __enter__(self) -> QueryProfiler:
        if settings.DEBUG:
            reset_queries()
            self._start_queries = len(connection.queries)
        self._start_time = time.perf_counter()
        return self

    def __exit__(self, *args: Any) -> None:
        self.total_time = (time.perf_counter() - self._start_time) * 1000  # ms

        if settings.DEBUG:
            self.query_count = len(connection.queries) - self._start_queries

            if self.log_queries or self.query_count > 10:
                logger.warning(
                    f"⚠️ Query profiler [{self.name}]: " f"{self.query_count} queries in {self.total_time:.2f}ms"
                )
                if self.log_queries:
                    for query in connection.queries[-self.query_count :]:
                        logger.debug(f"  SQL: {query['sql'][:200]}...")


def profile_queries(name: str = "", warn_threshold: int = 5) -> Any:
    """
    Decorator to profile queries in a function.

    Usage:
        @profile_queries("get_customer_orders", warn_threshold=10)
        def get_customer_orders(customer_id):
            ...
    """

    def decorator(func: Any) -> Any:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            profiler_name = name or func.__name__

            if not settings.DEBUG:
                return func(*args, **kwargs)

            with QueryProfiler(profiler_name) as profiler:
                result = func(*args, **kwargs)

            if profiler.query_count > warn_threshold:
                logger.warning(
                    f"⚠️ [{profiler_name}] High query count: "
                    f"{profiler.query_count} queries (threshold: {warn_threshold})"
                )

            return result

        return wrapper

    return decorator


# Bulk operation utilities


def bulk_select_related(
    queryset: QuerySet[T],
    field_name: str,
    ids: list[Any],
) -> dict[Any, T]:
    """
    Efficiently load related objects for a list of IDs.
    Returns a dict mapping ID to object.

    Usage:
        customers = bulk_select_related(Customer.objects, "id", customer_ids)
        for order in orders:
            order._cached_customer = customers.get(order.customer_id)
    """
    objects = queryset.filter(**{f"{field_name}__in": ids})
    return {getattr(obj, field_name): obj for obj in objects}


def annotate_counts(
    queryset: QuerySet[T],
    count_relations: dict[str, str],
) -> QuerySet[T]:
    """
    Annotate a queryset with counts of related objects.

    Usage:
        customers = annotate_counts(
            Customer.objects.all(),
            {"invoice_count": "invoices", "service_count": "services"}
        )
    """
    annotations = {name: Count(relation) for name, relation in count_relations.items()}
    return queryset.annotate(**annotations)


# Common index recommendations

INDEX_RECOMMENDATIONS = {
    "customers.Customer": [
        ("status", "created_at"),  # For filtering active customers
        ("primary_email",),  # For email lookups
        ("customer_type", "status"),  # For filtered lists
    ],
    "billing.Invoice": [
        ("customer", "status", "created_at"),  # Customer invoices by status
        ("status", "due_at"),  # Overdue invoice queries
        ("efactura_sent", "status"),  # e-Factura processing
    ],
    "orders.Order": [
        ("customer", "status", "created_at"),  # Customer orders
        ("status", "payment_method"),  # Payment processing
        ("order_number",),  # Order lookups
    ],
    "provisioning.Service": [
        ("customer", "status"),  # Customer services
        ("status", "expires_at"),  # Expiring services
        ("auto_renew", "expires_at", "status"),  # Auto-renewal processing
    ],
}


def get_missing_indexes() -> list[dict[str, Any]]:
    """
    Check for recommended indexes that may be missing.
    Returns a list of recommended index additions.
    """
    # This would need to be implemented based on database introspection
    # For now, return the recommendations
    recommendations = []
    for model_path, indexes in INDEX_RECOMMENDATIONS.items():
        for index_fields in indexes:
            recommendations.append(
                {
                    "model": model_path,
                    "fields": index_fields,
                    "recommendation": "Consider adding composite index",
                }
            )
    return recommendations
