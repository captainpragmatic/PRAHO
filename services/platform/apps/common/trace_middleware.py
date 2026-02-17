"""
Trace-Based Dynamic Analysis Middleware for PRAHO Platform.

This middleware provides automatic runtime tracing for debugging and
performance analysis. It can be enabled via settings or request headers.

Features:
- Automatic query tracing with N+1 detection
- Request timing and performance metrics
- Side effect detection for debugging
- Structured logging with request correlation

Usage:
    # Enable via environment variable
    ENABLE_TRACE_MIDDLEWARE=true

    # Or add to MIDDLEWARE in settings:
    MIDDLEWARE = [
        ...
        "apps.common.trace_middleware.TraceMiddleware",
    ]

    # View traces via response header:
    X-Trace-Summary: {"queries": 5, "time_ms": 123.45, ...}
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from typing import Any

from django.conf import settings
from django.http import HttpRequest, HttpResponse

from apps.common.logging import (
    QueryBudget,
    QueryTracer,
    RuntimeAnalyzer,
    SideEffectDetector,
    get_request_id,
)

logger = logging.getLogger(__name__)

_DEFAULT_MAX_HEADER_JSON_LENGTH = 1000
MAX_HEADER_JSON_LENGTH = _DEFAULT_MAX_HEADER_JSON_LENGTH


def get_max_header_json_length() -> int:
    """Get max header json length from SettingsService (runtime)."""
    from apps.settings.services import SettingsService  # noqa: PLC0415

    return SettingsService.get_integer_setting("common.max_header_json_length", _DEFAULT_MAX_HEADER_JSON_LENGTH)


class TraceMiddleware:
    """
    Middleware for automatic request tracing and performance analysis.

    Configuration via settings:
        TRACE_MIDDLEWARE_ENABLED = True  # Enable tracing
        TRACE_MIDDLEWARE_QUERY_BUDGET = 50  # Max queries per request
        TRACE_MIDDLEWARE_LOG_SLOW_REQUESTS = True  # Log requests > threshold
        TRACE_MIDDLEWARE_SLOW_REQUEST_THRESHOLD_MS = 500  # Threshold in ms
        TRACE_MIDDLEWARE_DETECT_SIDE_EFFECTS = False  # Track DB writes
        TRACE_MIDDLEWARE_HEADER_PREFIX = "X-Trace"  # Response header prefix

    Can also be enabled per-request via header:
        X-Enable-Trace: true
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response
        self._enabled = getattr(settings, "TRACE_MIDDLEWARE_ENABLED", False)
        self._query_budget = getattr(settings, "TRACE_MIDDLEWARE_QUERY_BUDGET", 100)
        self._log_slow = getattr(settings, "TRACE_MIDDLEWARE_LOG_SLOW_REQUESTS", True)
        self._slow_threshold_ms = getattr(settings, "TRACE_MIDDLEWARE_SLOW_REQUEST_THRESHOLD_MS", 500)
        self._detect_side_effects = getattr(settings, "TRACE_MIDDLEWARE_DETECT_SIDE_EFFECTS", False)
        self._header_prefix = getattr(settings, "TRACE_MIDDLEWARE_HEADER_PREFIX", "X-Trace")

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Check if tracing is enabled for this request
        if not self._should_trace(request):
            return self.get_response(request)

        return self._traced_request(request)

    def _should_trace(self, request: HttpRequest) -> bool:
        """Determine if this request should be traced."""
        # Check global setting
        if self._enabled:
            return True

        # Check per-request header
        if request.META.get("HTTP_X_ENABLE_TRACE", "").lower() == "true":
            return True

        # Check DEBUG mode
        return bool(getattr(settings, "DEBUG", False) and request.META.get("HTTP_X_DEBUG_TRACE", "").lower() == "true")

    def _traced_request(self, request: HttpRequest) -> HttpResponse:
        """Process request with full tracing enabled."""
        start_time = time.time()
        trace_data: dict[str, Any] = {
            "request_id": get_request_id(),
            "path": request.path,
            "method": request.method,
        }

        # Set up tracers
        query_budget = QueryBudget(
            max_queries=self._query_budget,
            warn_on_exceed=True,
            raise_on_exceed=False,
        )
        query_tracer = QueryTracer(budget=query_budget)
        side_effect_detector = SideEffectDetector() if self._detect_side_effects else None

        try:
            # Enter tracers
            query_tracer.__enter__()
            if side_effect_detector:
                side_effect_detector.__enter__()

            # Process request
            response = self.get_response(request)

            return response

        except Exception as e:
            trace_data["error"] = str(e)
            raise

        finally:
            # Exit tracers and collect data
            query_tracer.__exit__(None, None, None)
            if side_effect_detector:
                side_effect_detector.__exit__(None, None, None)

            # Calculate timing
            duration_ms = (time.time() - start_time) * 1000
            trace_data["duration_ms"] = round(duration_ms, 2)

            # Collect query data
            query_summary = query_tracer.get_summary()
            trace_data["queries"] = {
                "total": query_summary["total_queries"],
                "time_ms": round(query_summary["total_time_ms"], 2),
                "duplicates": query_summary["duplicate_count"],
            }

            # Collect side effect data
            if side_effect_detector:
                se_report = side_effect_detector.get_report()
                trace_data["side_effects"] = {
                    "database_writes": se_report["database_writes"],
                }

            # Add trace headers to response
            if "response" in dir():
                self._add_trace_headers(response, trace_data)

            # Log if slow
            if self._log_slow and duration_ms > self._slow_threshold_ms:
                self._log_slow_request(request, trace_data)

            # Log N+1 detection
            if query_summary["duplicate_count"] > 0:
                self._log_n_plus_one(request, query_tracer.get_n_plus_one_report())

    def _add_trace_headers(self, response: HttpResponse, trace_data: dict[str, Any]) -> None:
        """Add trace information to response headers."""
        prefix = self._header_prefix

        response[f"{prefix}-Duration-Ms"] = str(trace_data.get("duration_ms", 0))
        response[f"{prefix}-Query-Count"] = str(trace_data.get("queries", {}).get("total", 0))
        response[f"{prefix}-Query-Time-Ms"] = str(trace_data.get("queries", {}).get("time_ms", 0))
        response[f"{prefix}-Duplicate-Queries"] = str(trace_data.get("queries", {}).get("duplicates", 0))

        # Add summary as JSON
        try:
            summary_json = json.dumps(trace_data, default=str)
            if len(summary_json) < MAX_HEADER_JSON_LENGTH:  # Only if not too large
                response[f"{prefix}-Summary"] = summary_json
        except (TypeError, ValueError):
            pass

    def _log_slow_request(self, request: HttpRequest, trace_data: dict[str, Any]) -> None:
        """Log slow request with trace data."""
        logger.warning(
            f"Slow request detected: {request.method} {request.path}",
            extra={
                "trace_data": trace_data,
                "threshold_ms": self._slow_threshold_ms,
            },
        )

    def _log_n_plus_one(self, request: HttpRequest, n_plus_one_report: list[dict[str, Any]]) -> None:
        """Log potential N+1 queries."""
        logger.warning(
            f"Potential N+1 queries detected: {request.method} {request.path}",
            extra={
                "n_plus_one_patterns": n_plus_one_report[:5],  # Top 5 patterns
                "path": request.path,
            },
        )


class DebugTraceMiddleware(TraceMiddleware):
    """
    Extended trace middleware for development with additional features.

    Includes:
    - Method tracing with call graphs
    - Memory profiling
    - Detailed side effect tracking
    - HTML trace report injection (for browser debugging)
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        super().__init__(get_response)
        self._inject_html_report = getattr(settings, "TRACE_MIDDLEWARE_INJECT_HTML", False)

    def _traced_request(self, request: HttpRequest) -> HttpResponse:
        """Process request with extended tracing."""
        analyzer = RuntimeAnalyzer(
            query_budget=QueryBudget(max_queries=self._query_budget),
            trace_methods=True,
            profile_performance=True,
        )

        operation_name = f"{request.method} {request.path}"

        with analyzer.analyze(operation_name):
            response = self.get_response(request)

        # Get full analysis
        analysis = analyzer.get_analysis(operation_name)

        if analysis:
            # Add headers
            self._add_trace_headers(response, analysis)

            # Inject HTML report for browser debugging
            if self._inject_html_report and self._is_html_response(response):
                self._inject_trace_report(response, analysis)

        return response

    def _is_html_response(self, response: HttpResponse) -> bool:
        """Check if response is HTML."""
        content_type = response.get("Content-Type", "")
        return "text/html" in content_type

    def _inject_trace_report(self, response: HttpResponse, analysis: dict[str, Any]) -> None:
        """Inject trace report into HTML response."""
        if not hasattr(response, "content"):
            return

        try:
            content = response.content.decode("utf-8")
            if "</body>" in content:
                report_html = self._generate_html_report(analysis)
                content = content.replace("</body>", f"{report_html}</body>")
                response.content = content.encode("utf-8")
        except Exception as e:
            logger.error(f"Failed to inject trace report: {e}")

    def _generate_html_report(self, analysis: dict[str, Any]) -> str:
        """Generate HTML trace report for browser display."""
        query_trace = analysis.get("query_trace", {})
        performance = analysis.get("performance", {})

        return f"""
        <div id="trace-report" style="
            position: fixed; bottom: 10px; right: 10px;
            background: #1a1a2e; color: #eee; padding: 15px;
            border-radius: 8px; font-family: monospace; font-size: 12px;
            z-index: 99999; max-width: 400px; box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        ">
            <div style="font-weight: bold; margin-bottom: 10px; color: #00d9ff;">
                🔍 Trace Report
            </div>
            <div style="margin-bottom: 5px;">
                <strong>Duration:</strong> {performance.get('duration_ms', 0):.2f}ms
            </div>
            <div style="margin-bottom: 5px;">
                <strong>Queries:</strong> {query_trace.get('total_queries', 0)}
                ({query_trace.get('total_time_ms', 0):.2f}ms)
            </div>
            <div style="margin-bottom: 5px; color: {'#ff6b6b' if query_trace.get('duplicate_count', 0) > 0 else '#4ecdc4'};">
                <strong>N+1 Detected:</strong> {query_trace.get('duplicate_count', 0)} patterns
            </div>
            <button onclick="this.parentElement.remove()" style="
                margin-top: 10px; background: #ff6b6b; border: none;
                color: white; padding: 5px 10px; border-radius: 4px;
                cursor: pointer;
            ">Close</button>
        </div>
        """


# =============================================================================
# VIEW DECORATORS FOR TARGETED TRACING
# =============================================================================


def trace_view(
    max_queries: int = 50,
    warn_on_n_plus_one: bool = True,
    log_performance: bool = True,
) -> Callable[..., Any]:
    """
    Decorator to trace a specific view function.

    Usage:
        @trace_view(max_queries=10, warn_on_n_plus_one=True)
        def my_view(request):
            return render(request, "template.html")
    """
    from functools import wraps  # noqa: PLC0415

    def decorator(view_func: Callable[..., Any]) -> Any:
        @wraps(view_func)
        def wrapped(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
            budget = QueryBudget(
                max_queries=max_queries,
                warn_on_exceed=warn_on_n_plus_one,
                raise_on_exceed=False,
            )

            start_time = time.time()

            with QueryTracer(budget=budget) as tracer:
                response = view_func(request, *args, **kwargs)

            duration_ms = (time.time() - start_time) * 1000
            summary = tracer.get_summary()

            if log_performance:
                logger.debug(
                    f"View trace: {view_func.__name__}",
                    extra={
                        "duration_ms": duration_ms,
                        "queries": summary["total_queries"],
                        "duplicates": summary["duplicate_count"],
                    },
                )

            return response

        return wrapped

    return decorator


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    "DebugTraceMiddleware",
    "TraceMiddleware",
    "trace_view",
]
