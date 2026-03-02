"""
Prometheus metrics for e-Factura observability.

Provides comprehensive metrics for monitoring:
- Submission success/failure rates
- Processing times
- Quota usage
- Error tracking

Metrics are only collected if enabled in settings.
"""

from __future__ import annotations

import functools
import logging
import time
from collections.abc import Callable, Generator
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

from .settings import CIUS_RO_VERSION, efactura_settings

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Try to import prometheus_client, fall back to no-op if not installed
try:
    from prometheus_client import Counter, Gauge, Histogram, Info

    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    logger.debug("prometheus_client not installed, metrics will be no-op")


class NoOpMetric:
    """No-op metric for when prometheus_client is not installed."""

    def labels(self, *args: Any, **kwargs: Any) -> NoOpMetric:
        return self

    def inc(self, amount: float = 1) -> None:
        pass

    def dec(self, amount: float = 1) -> None:
        pass

    def set(self, value: float) -> None:
        pass

    def observe(self, value: float) -> None:
        pass

    def info(self, val: dict[str, str]) -> None:
        pass


def _create_counter(name: str, description: str, labels: list[str]) -> Any:
    """Create a Prometheus counter or no-op."""
    if PROMETHEUS_AVAILABLE and efactura_settings.metrics_enabled:
        prefix = efactura_settings.metrics_prefix
        return Counter(f"{prefix}_{name}", description, labels)
    return NoOpMetric()


def _create_histogram(name: str, description: str, labels: list[str], buckets: tuple[float, ...] | None = None) -> Any:
    """Create a Prometheus histogram or no-op."""
    if PROMETHEUS_AVAILABLE and efactura_settings.metrics_enabled:
        prefix = efactura_settings.metrics_prefix
        if buckets:
            return Histogram(f"{prefix}_{name}", description, labels, buckets=buckets)
        return Histogram(f"{prefix}_{name}", description, labels)
    return NoOpMetric()


def _create_gauge(name: str, description: str, labels: list[str]) -> Any:
    """Create a Prometheus gauge or no-op."""
    if PROMETHEUS_AVAILABLE and efactura_settings.metrics_enabled:
        prefix = efactura_settings.metrics_prefix
        return Gauge(f"{prefix}_{name}", description, labels)
    return NoOpMetric()


def _create_info(name: str, description: str) -> Any:
    """Create a Prometheus info metric or no-op."""
    if PROMETHEUS_AVAILABLE and efactura_settings.metrics_enabled:
        prefix = efactura_settings.metrics_prefix
        return Info(f"{prefix}_{name}", description)
    return NoOpMetric()


# ===============================================================================
# METRICS DEFINITIONS
# ===============================================================================


class EFacturaMetrics:
    """
    e-Factura metrics collection.

    All metrics are prefixed with the configured prefix (default: 'efactura').
    """

    def __init__(self) -> None:
        """Initialize metrics."""
        self._initialized = False
        self._init_metrics()

    def _init_metrics(self) -> None:
        """Initialize all metrics."""
        if self._initialized:
            return

        # Submission metrics
        self.submissions_total = _create_counter(
            "submissions_total",
            "Total number of e-Factura submissions",
            ["status", "environment", "document_type"],
        )

        self.submission_duration_seconds = _create_histogram(
            "submission_duration_seconds",
            "Time spent submitting e-Factura",
            ["status", "environment"],
            buckets=(0.5, 1, 2, 5, 10, 30, 60, 120),
        )

        # Status polling metrics
        self.status_checks_total = _create_counter(
            "status_checks_total",
            "Total number of status checks",
            ["result", "environment"],
        )

        self.status_check_duration_seconds = _create_histogram(
            "status_check_duration_seconds",
            "Time spent checking status",
            ["environment"],
            buckets=(0.1, 0.25, 0.5, 1, 2, 5),
        )

        # Validation metrics
        self.validations_total = _create_counter(
            "validations_total",
            "Total number of XML validations",
            ["type", "result"],  # values: xsd, schematron, cius-ro
        )

        self.validation_errors_total = _create_counter(
            "validation_errors_total",
            "Total validation errors by rule",
            ["rule_id", "severity"],
        )

        # XML generation metrics
        self.xml_generations_total = _create_counter(
            "xml_generations_total",
            "Total XML documents generated",
            ["document_type", "status"],
        )

        self.xml_generation_duration_seconds = _create_histogram(
            "xml_generation_duration_seconds",
            "Time spent generating XML",
            ["document_type"],
            buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1),
        )

        # API metrics
        self.api_requests_total = _create_counter(
            "api_requests_total",
            "Total ANAF API requests",
            ["endpoint", "status_code", "environment"],
        )

        self.api_request_duration_seconds = _create_histogram(
            "api_request_duration_seconds",
            "ANAF API request duration",
            ["endpoint", "environment"],
            buckets=(0.5, 1, 2, 5, 10, 30),
        )

        self.api_retries_total = _create_counter(
            "api_retries_total",
            "Total API retry attempts",
            ["endpoint", "reason"],
        )

        # Quota metrics
        self.quota_usage = _create_gauge(
            "quota_usage",
            "Current quota usage",
            ["endpoint", "cui"],
        )

        self.quota_exceeded_total = _create_counter(
            "quota_exceeded_total",
            "Times quota was exceeded",
            ["endpoint", "cui"],
        )

        # Document status metrics
        self.documents_by_status = _create_gauge(
            "documents_by_status",
            "Number of documents by status",
            ["status"],
        )

        self.pending_documents = _create_gauge(
            "pending_documents",
            "Number of documents pending submission",
            [],
        )

        self.awaiting_response = _create_gauge(
            "awaiting_response",
            "Number of documents awaiting ANAF response",
            [],
        )

        # Deadline metrics
        self.deadline_warnings_total = _create_counter(
            "deadline_warnings_total",
            "Total deadline warnings issued",
            ["hours_remaining_bucket"],
        )

        self.deadline_violations_total = _create_counter(
            "deadline_violations_total",
            "Total deadline violations (5-day limit exceeded)",
            [],
        )

        # Error metrics
        self.errors_total = _create_counter(
            "errors_total",
            "Total errors by type",
            ["error_type", "component"],
        )

        # Token metrics
        self.token_refreshes_total = _create_counter(
            "token_refreshes_total",
            "Total OAuth token refreshes",
            ["status"],
        )

        # Info metric for version and configuration
        self.info = _create_info(
            "info",
            "e-Factura module information",
        )

        self._initialized = True

    def set_info(self) -> None:
        """Set info metric with current configuration."""
        self.info.info(
            {
                "cius_ro_version": CIUS_RO_VERSION,
                "environment": efactura_settings.environment.value,
                "b2b_enabled": str(efactura_settings.b2b_enabled),
                "b2c_enabled": str(efactura_settings.b2c_enabled),
            }
        )

    # ===== Convenience Methods =====

    def record_submission(
        self,
        status: str,
        document_type: str = "invoice",
        duration: float | None = None,
    ) -> None:
        """Record a submission attempt."""
        env = efactura_settings.environment.value
        self.submissions_total.labels(
            status=status,
            environment=env,
            document_type=document_type,
        ).inc()

        if duration is not None:
            self.submission_duration_seconds.labels(
                status=status,
                environment=env,
            ).observe(duration)

    def record_status_check(
        self,
        result: str,
        duration: float | None = None,
    ) -> None:
        """Record a status check."""
        env = efactura_settings.environment.value
        self.status_checks_total.labels(
            result=result,
            environment=env,
        ).inc()

        if duration is not None:
            self.status_check_duration_seconds.labels(
                environment=env,
            ).observe(duration)

    def record_validation(
        self,
        validation_type: str,
        is_valid: bool,
        error_rules: list[str] | None = None,
    ) -> None:
        """Record a validation result."""
        self.validations_total.labels(
            type=validation_type,
            result="valid" if is_valid else "invalid",
        ).inc()

        if error_rules:
            for rule_id in error_rules:
                self.validation_errors_total.labels(
                    rule_id=rule_id,
                    severity="error",
                ).inc()

    def record_api_request(
        self,
        endpoint: str,
        status_code: int,
        duration: float,
        is_retry: bool = False,
        retry_reason: str = "",
    ) -> None:
        """Record an API request."""
        env = efactura_settings.environment.value
        self.api_requests_total.labels(
            endpoint=endpoint,
            status_code=str(status_code),
            environment=env,
        ).inc()

        self.api_request_duration_seconds.labels(
            endpoint=endpoint,
            environment=env,
        ).observe(duration)

        if is_retry:
            self.api_retries_total.labels(
                endpoint=endpoint,
                reason=retry_reason,
            ).inc()

    def record_error(self, error_type: str, component: str) -> None:
        """Record an error."""
        self.errors_total.labels(
            error_type=error_type,
            component=component,
        ).inc()

    def update_quota_usage(self, endpoint: str, cui: str, current: int) -> None:
        """Update quota usage gauge."""
        self.quota_usage.labels(
            endpoint=endpoint,
            cui=cui,
        ).set(current)

    def record_quota_exceeded(self, endpoint: str, cui: str) -> None:
        """Record quota exceeded event."""
        self.quota_exceeded_total.labels(
            endpoint=endpoint,
            cui=cui,
        ).inc()

    @contextmanager
    def time_submission(
        self,
        document_type: str = "invoice",
    ) -> Generator[None]:
        """Context manager to time and record submissions."""
        start = time.monotonic()
        status = "success"
        try:
            yield
        except Exception:
            status = "error"
            raise
        finally:
            duration = time.monotonic() - start
            self.record_submission(status, document_type, duration)

    @contextmanager
    def time_api_request(self, endpoint: str) -> Generator[dict[str, Any]]:
        """Context manager to time API requests."""
        start = time.monotonic()
        context: dict[str, Any] = {"status_code": 0}
        try:
            yield context
        finally:
            duration = time.monotonic() - start
            self.record_api_request(
                endpoint=endpoint,
                status_code=context.get("status_code", 0),
                duration=duration,
            )


def timed_operation(metric_name: str) -> Callable[..., Any]:
    """
    Decorator to time operations and record to histogram.

    Args:
        metric_name: Name of the metric to record to

    Usage:
        @timed_operation("xml_generation")
        def generate_xml():
            ...
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if not efactura_settings.metrics_enabled:
                return func(*args, **kwargs)

            start = time.monotonic()
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                duration = time.monotonic() - start
                logger.debug(f"[Metrics] {metric_name}: {duration:.3f}s")

        return wrapper

    return decorator


# Module-level metrics instance
metrics = EFacturaMetrics()
