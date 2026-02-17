"""
Trace-Based Dynamic Analysis and Logging Infrastructure for PRAHO Platform.

This module provides comprehensive runtime tracing, logging, and debugging tools
for analyzing system behavior at runtime. It includes:

- RequestIDFilter: Structured logging with request correlation
- SecurityEventFilter: Security-related log event filtering
- SensitiveDataFilter: Sensitive data redaction in logs
- StructuredLogAdapter: Structured context logging
- QueryTracer: Database query monitoring and N+1 detection
- MethodTracer: Execution timing and call graph analysis
- PerformanceProfiler: Resource usage tracking
- RuntimeAnalyzer: Comprehensive runtime behavior analysis

Usage:
    from apps.common.logging import QueryTracer, MethodTracer

    # Trace database queries in a view
    with QueryTracer() as tracer:
        result = MyModel.objects.filter(...)
    print(tracer.get_summary())

    # Trace method execution
    @MethodTracer.trace
    def my_function():
        pass
"""

from __future__ import annotations

import contextlib
import functools
import logging
import threading
import time
import traceback
from collections import defaultdict
from collections.abc import Callable, Generator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar, TypeVar

from django.conf import settings
from django.db import connection, reset_queries

# Thread-local storage for request context
_request_context = threading.local()

logger = logging.getLogger(__name__)

SQL_DISPLAY_LIMIT = 200
MAX_SUMMARIZED_ARGS = 3
VALUE_SUMMARY_LIMIT = 50


F = TypeVar("F", bound=Callable[..., Any])


# =============================================================================
# REQUEST CONTEXT FUNCTIONS
# =============================================================================


def set_request_id(request_id: str) -> None:
    """Set the current request ID in thread-local storage."""
    _request_context.request_id = request_id


def get_request_id() -> str | None:
    """Get the current request ID from thread-local storage."""
    return getattr(_request_context, "request_id", None)


def clear_request_id() -> None:
    """Clear the request ID from thread-local storage."""
    _request_context.request_id = None


def set_request_context(**kwargs: Any) -> None:
    """Set request context for the current thread"""
    for key, value in kwargs.items():
        setattr(_request_context, key, value)


def get_request_context() -> dict[str, Any]:
    """Get request context for the current thread"""
    return {
        "request_id": getattr(_request_context, "request_id", "-"),
        "user_id": getattr(_request_context, "user_id", None),
        "user_email": getattr(_request_context, "user_email", None),
        "ip_address": getattr(_request_context, "ip_address", None),
        "session_id": getattr(_request_context, "session_id", None),
    }


def clear_request_context() -> None:
    """Clear request context for the current thread"""
    for attr in ["request_id", "user_id", "user_email", "ip_address", "session_id"]:
        if hasattr(_request_context, attr):
            delattr(_request_context, attr)


# =============================================================================
# REQUEST ID FILTER - Structured Logging with Request Correlation
# =============================================================================


class RequestIDFilter(logging.Filter):
    """
    Add request ID and context to log records.

    This filter injects the request ID from thread-local storage
    into every log record, enabling request tracing across logs.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Add request_id attribute to log record"""
        if not hasattr(record, "request_id"):
            record.request_id = getattr(_request_context, "request_id", "-")  # type: ignore[attr-defined]

        # Add other context if available
        if not hasattr(record, "user_id"):
            record.user_id = getattr(_request_context, "user_id", None)  # type: ignore[attr-defined]
        if not hasattr(record, "user_email"):
            record.user_email = getattr(_request_context, "user_email", None)  # type: ignore[attr-defined]
        if not hasattr(record, "ip_address"):
            record.ip_address = getattr(_request_context, "ip_address", None)  # type: ignore[attr-defined]
        if not hasattr(record, "session_id"):
            record.session_id = getattr(_request_context, "session_id", None)  # type: ignore[attr-defined]

        return True


class SecurityEventFilter(logging.Filter):
    """
    Filter for security-related log events.

    Only allows log records that are marked as security events
    or come from security-related loggers.
    """

    SECURITY_LOGGERS: ClassVar[list] = [
        "apps.users",
        "apps.audit",
        "django.security",
        "apps.common.middleware",
    ]

    SECURITY_KEYWORDS: ClassVar[list] = [
        "login",
        "logout",
        "auth",
        "password",
        "security",
        "permission",
        "access",
        "denied",
        "blocked",
        "suspicious",
        "breach",
        "attack",
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        """Filter for security events"""
        # Check if from security logger
        if any(record.name.startswith(sec_logger) for sec_logger in self.SECURITY_LOGGERS):
            return True

        # Check for security keywords in message
        message = record.getMessage().lower()
        if any(keyword in message for keyword in self.SECURITY_KEYWORDS):
            return True

        # Check for security level
        return record.levelno >= logging.WARNING


class SensitiveDataFilter(logging.Filter):
    """
    Filter to redact sensitive data from log records.

    Prevents sensitive information like passwords, tokens,
    and credit card numbers from appearing in logs.
    """

    SENSITIVE_PATTERNS: ClassVar[list] = [
        "password",
        "secret",
        "token",
        "api_key",
        "apikey",
        "auth",
        "credential",
        "credit_card",
        "card_number",
        "cvv",
        "ssn",
        "cui",  # Romanian tax ID
    ]

    REDACTION_TEXT = "[REDACTED]"

    def filter(self, record: logging.LogRecord) -> bool:
        """Redact sensitive data from log record"""
        if hasattr(record, "msg") and isinstance(record.msg, str):
            for pattern in self.SENSITIVE_PATTERNS:
                if pattern in record.msg.lower():
                    # Simple redaction - in production, use regex
                    record.msg = record.msg.replace(pattern, self.REDACTION_TEXT)

        return True


class StructuredLogAdapter(logging.LoggerAdapter):
    """
    Log adapter that adds structured context to all log messages.

    Usage:
        logger = StructuredLogAdapter(
            logging.getLogger(__name__),
            {"component": "billing"}
        )
        logger.info("Invoice created", invoice_id=123)
    """

    def process(self, msg: str, kwargs: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """Process log message and add structured context"""
        # Merge extra context
        extra = kwargs.get("extra", {})
        extra.update(self.extra)

        # Add any keyword arguments as extra fields
        for key, value in list(kwargs.items()):
            if key not in ("exc_info", "stack_info", "stacklevel", "extra"):
                extra[key] = value
                del kwargs[key]

        kwargs["extra"] = extra
        return msg, kwargs


def get_logger(name: str, **context: Any) -> StructuredLogAdapter:
    """
    Get a structured logger with context.

    Args:
        name: Logger name (usually __name__)
        **context: Additional context to include in all log messages

    Returns:
        StructuredLogAdapter with context
    """
    return StructuredLogAdapter(logging.getLogger(name), context)


# =============================================================================
# QUERY TRACER - Database Query Monitoring and N+1 Detection
# =============================================================================


@dataclass
class QueryInfo:
    """Information about a single database query."""

    sql: str
    time_ms: float
    stack_trace: list[str]
    timestamp: datetime = field(default_factory=datetime.now)
    params: tuple[Any, ...] | None = None
    is_duplicate: bool = False


@dataclass
class QueryBudget:
    """Query budget configuration for N+1 detection."""

    max_queries: int = 10
    max_duplicates: int = 2
    max_total_time_ms: float = 100.0
    warn_on_exceed: bool = True
    raise_on_exceed: bool = False


class QueryBudgetExceeded(Exception):  # noqa: N818
    """Exception raised when query budget is exceeded."""

    def __init__(self, message: str, summary: dict[str, Any]) -> None:
        super().__init__(message)
        self.summary = summary


class QueryTracer:
    """
    Context manager for tracing database queries.

    Provides detailed analysis of database queries including:
    - Total query count and timing
    - N+1 query detection through duplicate query analysis
    - Stack traces for each query
    - Query budget enforcement

    Usage:
        # Basic tracing
        with QueryTracer() as tracer:
            users = list(User.objects.all())
            for user in users:
                print(user.profile.bio)  # N+1 detected!

        print(tracer.get_summary())

        # With budget enforcement
        budget = QueryBudget(max_queries=5, raise_on_exceed=True)
        with QueryTracer(budget=budget) as tracer:
            # Will raise if more than 5 queries
            pass
    """

    def __init__(
        self,
        budget: QueryBudget | None = None,
        capture_stack: bool = True,
        stack_depth: int = 10,
    ) -> None:
        self.budget = budget or QueryBudget()
        self.capture_stack = capture_stack
        self.stack_depth = stack_depth
        self.queries: list[QueryInfo] = []
        self._query_hashes: dict[str, int] = defaultdict(int)
        self._start_time: float = 0
        self._enabled = getattr(settings, "DEBUG", False)

    def __enter__(self) -> QueryTracer:
        if self._enabled:
            reset_queries()
            self._start_time = time.time()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        if not self._enabled:
            return

        # Collect queries from Django's query log
        for query in connection.queries:
            sql = query.get("sql", "")
            time_str = query.get("time", "0")

            # Parse time (Django stores as string)
            try:
                time_ms = float(time_str) * 1000
            except (ValueError, TypeError):
                time_ms = 0.0

            # Capture stack trace
            stack_trace: list[str] = []
            if self.capture_stack:
                stack_trace = self._capture_stack()

            # Check for duplicate queries (N+1 detection)
            query_hash = self._normalize_sql(sql)
            self._query_hashes[query_hash] += 1
            is_duplicate = self._query_hashes[query_hash] > 1

            self.queries.append(
                QueryInfo(
                    sql=sql,
                    time_ms=time_ms,
                    stack_trace=stack_trace,
                    is_duplicate=is_duplicate,
                )
            )

        # Check budget
        self._check_budget()

    def _capture_stack(self) -> list[str]:
        """Capture current stack trace, filtering framework internals."""
        stack = traceback.extract_stack()
        relevant_frames = []

        for frame in stack[: -self.stack_depth]:
            # Skip framework and library frames
            if any(skip in frame.filename for skip in ["django/", "site-packages/", "logging.py"]):
                continue
            relevant_frames.append(f"{frame.filename}:{frame.lineno} in {frame.name}")

        return relevant_frames[-self.stack_depth :]

    def _normalize_sql(self, sql: str) -> str:
        """Normalize SQL for duplicate detection (remove parameter values)."""
        import re  # noqa: PLC0415

        # Replace numeric values
        normalized = re.sub(r"\b\d+\b", "?", sql)
        # Replace string values
        normalized = re.sub(r"'[^']*'", "?", normalized)
        # Remove extra whitespace
        normalized = " ".join(normalized.split())
        return normalized

    def _check_budget(self) -> None:
        """Check if query budget has been exceeded."""
        if not self.budget:
            return

        summary = self.get_summary()
        violations: list[str] = []

        if summary["total_queries"] > self.budget.max_queries:
            violations.append(f"Query count {summary['total_queries']} exceeds budget {self.budget.max_queries}")

        if summary["duplicate_count"] > self.budget.max_duplicates:
            violations.append(
                f"Duplicate queries {summary['duplicate_count']} exceeds budget {self.budget.max_duplicates}"
            )

        if summary["total_time_ms"] > self.budget.max_total_time_ms:
            violations.append(
                f"Total query time {summary['total_time_ms']:.2f}ms exceeds budget {self.budget.max_total_time_ms}ms"
            )

        if violations:
            message = "Query budget exceeded: " + "; ".join(violations)

            if self.budget.warn_on_exceed:
                logger.warning(message, extra={"query_summary": summary})

            if self.budget.raise_on_exceed:
                raise QueryBudgetExceeded(message, summary)

    def get_summary(self) -> dict[str, Any]:
        """Get summary of traced queries."""
        total_time = sum(q.time_ms for q in self.queries)
        duplicates = [q for q in self.queries if q.is_duplicate]

        return {
            "total_queries": len(self.queries),
            "total_time_ms": total_time,
            "average_time_ms": total_time / len(self.queries) if self.queries else 0,
            "duplicate_count": len(duplicates),
            "unique_queries": len(self._query_hashes),
            "queries": [
                {
                    "sql": q.sql[:SQL_DISPLAY_LIMIT] + "..." if len(q.sql) > SQL_DISPLAY_LIMIT else q.sql,
                    "time_ms": q.time_ms,
                    "is_duplicate": q.is_duplicate,
                    "stack": q.stack_trace[:3] if q.stack_trace else [],
                }
                for q in self.queries
            ],
            "potential_n_plus_one": [
                {"pattern": pattern, "count": count} for pattern, count in self._query_hashes.items() if count > 1
            ],
        }

    def get_n_plus_one_report(self) -> list[dict[str, Any]]:
        """Get detailed report of potential N+1 queries."""
        report = []
        for pattern, count in self._query_hashes.items():
            if count > 1:
                # Find all queries matching this pattern
                matching = [q for q in self.queries if self._normalize_sql(q.sql) == pattern]
                report.append(
                    {
                        "pattern": pattern,
                        "count": count,
                        "total_time_ms": sum(q.time_ms for q in matching),
                        "sample_stacks": [q.stack_trace for q in matching[:3]],
                    }
                )
        return sorted(report, key=lambda x: x["count"], reverse=True)


# =============================================================================
# METHOD TRACER - Execution Timing and Call Graph Analysis
# =============================================================================


@dataclass
class MethodTrace:
    """Information about a single method execution."""

    method_name: str
    module: str
    start_time: float
    end_time: float
    duration_ms: float
    args_summary: str
    return_summary: str | None
    exception: str | None
    children: list[MethodTrace] = field(default_factory=list)


class MethodTracer:
    """
    Decorator and context manager for tracing method execution.

    Provides:
    - Execution timing with millisecond precision
    - Call graph construction
    - Argument and return value summarization
    - Exception tracking

    Usage:
        # As decorator
        @MethodTracer.trace
        def my_function(arg1, arg2):
            return result

        # As context manager
        with MethodTracer.context("operation_name") as trace:
            # do work
            pass
        print(f"Took {trace.duration_ms}ms")

        # Get all traces
        traces = MethodTracer.get_all_traces()
    """

    _traces: ClassVar[list[MethodTrace]] = []
    _trace_stack: ClassVar[list[MethodTrace]] = []
    _lock = threading.Lock()
    _enabled = True

    @classmethod
    def enable(cls) -> None:
        """Enable method tracing."""
        cls._enabled = True

    @classmethod
    def disable(cls) -> None:
        """Disable method tracing."""
        cls._enabled = False

    @classmethod
    def clear(cls) -> None:
        """Clear all collected traces."""
        with cls._lock:
            cls._traces.clear()
            cls._trace_stack.clear()

    @classmethod
    def trace(cls, func: F) -> F:
        """Decorator to trace method execution."""

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if not cls._enabled:
                return func(*args, **kwargs)

            method_name = func.__name__
            module = func.__module__

            # Summarize arguments
            args_summary = cls._summarize_args(args, kwargs)

            start_time = time.time()
            exception_str: str | None = None
            return_summary: str | None = None

            try:
                result = func(*args, **kwargs)
                return_summary = cls._summarize_value(result)
                return result
            except Exception as e:
                exception_str = f"{type(e).__name__}: {e!s}"
                raise
            finally:
                end_time = time.time()
                duration_ms = (end_time - start_time) * 1000

                trace = MethodTrace(
                    method_name=method_name,
                    module=module,
                    start_time=start_time,
                    end_time=end_time,
                    duration_ms=duration_ms,
                    args_summary=args_summary,
                    return_summary=return_summary,
                    exception=exception_str,
                )

                with cls._lock:
                    if cls._trace_stack:
                        cls._trace_stack[-1].children.append(trace)
                    else:
                        cls._traces.append(trace)

        return wrapper  # type: ignore[return-value]

    @classmethod
    @contextlib.contextmanager
    def context(cls, name: str) -> Generator[MethodTrace, None, None]:
        """Context manager for tracing a block of code."""
        trace = MethodTrace(
            method_name=name,
            module="<context>",
            start_time=time.time(),
            end_time=0,
            duration_ms=0,
            args_summary="",
            return_summary=None,
            exception=None,
        )

        with cls._lock:
            if cls._trace_stack:
                cls._trace_stack[-1].children.append(trace)
            else:
                cls._traces.append(trace)
            cls._trace_stack.append(trace)

        try:
            yield trace
        except Exception as e:
            trace.exception = f"{type(e).__name__}: {e!s}"
            raise
        finally:
            trace.end_time = time.time()
            trace.duration_ms = (trace.end_time - trace.start_time) * 1000
            with cls._lock:
                cls._trace_stack.pop()

    @classmethod
    def _summarize_args(cls, args: tuple[Any, ...], kwargs: dict[str, Any]) -> str:
        """Create a summary of function arguments."""
        parts = []
        for i, arg in enumerate(args[:MAX_SUMMARIZED_ARGS]):  # Limit to first 3 args
            parts.append(f"arg{i}={cls._summarize_value(arg)}")
        for key, value in list(kwargs.items())[:MAX_SUMMARIZED_ARGS]:  # Limit to first 3 kwargs
            parts.append(f"{key}={cls._summarize_value(value)}")
        if len(args) > MAX_SUMMARIZED_ARGS or len(kwargs) > MAX_SUMMARIZED_ARGS:
            parts.append("...")
        return ", ".join(parts)

    @classmethod
    def _summarize_value(cls, value: Any) -> str:
        """Create a summary of a value for logging."""
        if value is None:
            return "None"
        if isinstance(value, str):
            return f'"{value[:VALUE_SUMMARY_LIMIT]}..."' if len(value) > VALUE_SUMMARY_LIMIT else f'"{value}"'
        if isinstance(value, (list, tuple)):
            return f"{type(value).__name__}[{len(value)}]"
        if isinstance(value, dict):
            return f"dict[{len(value)}]"
        if hasattr(value, "__class__"):
            return f"<{value.__class__.__name__}>"
        return str(value)[:50]

    @classmethod
    def get_all_traces(cls) -> list[MethodTrace]:
        """Get all collected traces."""
        with cls._lock:
            return list(cls._traces)

    @classmethod
    def get_trace_report(cls) -> dict[str, Any]:
        """Get a summary report of all traces."""
        traces = cls.get_all_traces()

        def flatten_traces(trace_list: list[MethodTrace]) -> list[MethodTrace]:
            result = []
            for trace in trace_list:
                result.append(trace)
                result.extend(flatten_traces(trace.children))
            return result

        flat_traces = flatten_traces(traces)

        total_time = sum(t.duration_ms for t in traces)  # Only top-level for total
        method_times: dict[str, list[float]] = defaultdict(list)
        for trace in flat_traces:
            key = f"{trace.module}.{trace.method_name}"
            method_times[key].append(trace.duration_ms)

        return {
            "total_traces": len(flat_traces),
            "total_time_ms": total_time,
            "methods": {
                name: {
                    "count": len(times),
                    "total_ms": sum(times),
                    "avg_ms": sum(times) / len(times),
                    "max_ms": max(times),
                    "min_ms": min(times),
                }
                for name, times in method_times.items()
            },
            "exceptions": [t.exception for t in flat_traces if t.exception],
            "slowest_methods": sorted(
                [(f"{t.module}.{t.method_name}", t.duration_ms) for t in flat_traces],
                key=lambda x: x[1],
                reverse=True,
            )[:10],
        }


# =============================================================================
# PERFORMANCE PROFILER - Resource Usage Tracking
# =============================================================================


@dataclass
class PerformanceSnapshot:
    """Snapshot of system performance metrics."""

    timestamp: datetime
    memory_mb: float
    cpu_percent: float | None
    thread_count: int
    open_connections: int
    cache_stats: dict[str, Any]


class PerformanceProfiler:
    """
    Context manager for profiling system resource usage.

    Tracks:
    - Memory usage
    - Database connection count
    - Cache hit/miss rates
    - Thread count

    Usage:
        with PerformanceProfiler() as profiler:
            # Do work
            pass

        print(profiler.get_report())
    """

    def __init__(self) -> None:
        self.start_snapshot: PerformanceSnapshot | None = None
        self.end_snapshot: PerformanceSnapshot | None = None
        self._start_time: float = 0

    def __enter__(self) -> PerformanceProfiler:
        self._start_time = time.time()
        self.start_snapshot = self._take_snapshot()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        self.end_snapshot = self._take_snapshot()

    def _take_snapshot(self) -> PerformanceSnapshot:
        """Take a snapshot of current system metrics."""
        import gc  # noqa: PLC0415

        from django.core.cache import cache  # noqa: PLC0415

        # Memory usage (requires psutil for accurate measurement)
        memory_mb = 0.0
        try:
            import psutil  # noqa: PLC0415

            process = psutil.Process()
            memory_mb = process.memory_info().rss / 1024 / 1024
            cpu_percent = process.cpu_percent()
        except ImportError:
            # Fallback: use gc to estimate
            gc.collect()
            cpu_percent = None

        # Thread count
        thread_count = threading.active_count()

        # Database connections
        open_connections = len(connection.queries)

        # Cache stats (if available)
        cache_stats: dict[str, Any] = {}
        try:
            if hasattr(cache, "_cache"):
                cache_stats = {"type": type(cache._cache).__name__}
        except (AttributeError, TypeError):
            logger.debug("Cache backend does not expose internal cache stats")

        return PerformanceSnapshot(
            timestamp=datetime.now(),
            memory_mb=memory_mb,
            cpu_percent=cpu_percent,
            thread_count=thread_count,
            open_connections=open_connections,
            cache_stats=cache_stats,
        )

    def get_report(self) -> dict[str, Any]:
        """Get performance report."""
        if not self.start_snapshot or not self.end_snapshot:
            return {"error": "Profiler not properly used as context manager"}

        duration_ms = (time.time() - self._start_time) * 1000

        return {
            "duration_ms": duration_ms,
            "memory_delta_mb": self.end_snapshot.memory_mb - self.start_snapshot.memory_mb,
            "start_memory_mb": self.start_snapshot.memory_mb,
            "end_memory_mb": self.end_snapshot.memory_mb,
            "thread_count": self.end_snapshot.thread_count,
            "queries_executed": self.end_snapshot.open_connections - self.start_snapshot.open_connections,
        }


# =============================================================================
# RUNTIME ANALYZER - Comprehensive Runtime Behavior Analysis
# =============================================================================


class RuntimeAnalyzer:
    """
    Comprehensive runtime behavior analyzer combining all tracing tools.

    Provides a unified interface for:
    - Query tracing with N+1 detection
    - Method execution timing
    - Performance profiling
    - Side effect detection

    Usage:
        analyzer = RuntimeAnalyzer()

        with analyzer.analyze("user_registration") as analysis:
            # Perform operation
            user = User.objects.create(...)

        report = analysis.get_full_report()
    """

    def __init__(
        self,
        query_budget: QueryBudget | None = None,
        trace_methods: bool = True,
        profile_performance: bool = True,
    ) -> None:
        self.query_budget = query_budget
        self.trace_methods = trace_methods
        self.profile_performance = profile_performance
        self._analyses: dict[str, dict[str, Any]] = {}

    @contextlib.contextmanager
    def analyze(self, operation_name: str) -> Generator[dict[str, Any], None, None]:
        """Context manager to analyze an operation."""
        analysis: dict[str, Any] = {
            "operation": operation_name,
            "start_time": datetime.now().isoformat(),
            "query_trace": None,
            "method_trace": None,
            "performance": None,
            "errors": [],
        }

        query_tracer = QueryTracer(budget=self.query_budget) if getattr(settings, "DEBUG", False) else None
        perf_profiler = PerformanceProfiler() if self.profile_performance else None

        if self.trace_methods:
            MethodTracer.clear()

        try:
            # Enter all tracers
            if query_tracer:
                query_tracer.__enter__()
            if perf_profiler:
                perf_profiler.__enter__()

            yield analysis

        except Exception as e:
            analysis["errors"].append(f"{type(e).__name__}: {e!s}")
            raise

        finally:
            # Exit all tracers and collect results
            if query_tracer:
                query_tracer.__exit__(None, None, None)
                analysis["query_trace"] = query_tracer.get_summary()

            if perf_profiler:
                perf_profiler.__exit__(None, None, None)
                analysis["performance"] = perf_profiler.get_report()

            if self.trace_methods:
                analysis["method_trace"] = MethodTracer.get_trace_report()

            analysis["end_time"] = datetime.now().isoformat()
            self._analyses[operation_name] = analysis

    def get_analysis(self, operation_name: str) -> dict[str, Any] | None:
        """Get analysis results for a specific operation."""
        return self._analyses.get(operation_name)

    def get_all_analyses(self) -> dict[str, dict[str, Any]]:
        """Get all analysis results."""
        return dict(self._analyses)

    def generate_report(self) -> str:
        """Generate a human-readable report of all analyses."""
        lines = ["=" * 60, "RUNTIME ANALYSIS REPORT", "=" * 60, ""]

        for name, analysis in self._analyses.items():
            lines.append(f"Operation: {name}")
            lines.append("-" * 40)

            # Query summary
            if analysis.get("query_trace"):
                qt = analysis["query_trace"]
                lines.append(f"  Queries: {qt['total_queries']} ({qt['total_time_ms']:.2f}ms)")
                lines.append(f"  Duplicates: {qt['duplicate_count']} (potential N+1)")

                if qt.get("potential_n_plus_one"):
                    lines.append("  N+1 Patterns:")
                    lines.extend(
                        f"    - {pattern['pattern'][:60]}... ({pattern['count']}x)"
                        for pattern in qt["potential_n_plus_one"][:3]
                    )

            # Performance summary
            if analysis.get("performance"):
                perf = analysis["performance"]
                lines.append(f"  Duration: {perf['duration_ms']:.2f}ms")
                lines.append(f"  Memory Delta: {perf['memory_delta_mb']:.2f}MB")

            # Method trace summary
            if analysis.get("method_trace"):
                mt = analysis["method_trace"]
                lines.append(f"  Methods Traced: {mt['total_traces']}")
                if mt.get("slowest_methods"):
                    lines.append("  Slowest Methods:")
                    for method, time_ms in mt["slowest_methods"][:3]:
                        lines.append(f"    - {method}: {time_ms:.2f}ms")

            # Errors
            if analysis.get("errors"):
                lines.append("  ERRORS:")
                lines.extend(f"    - {error}" for error in analysis["errors"])

            lines.append("")

        return "\n".join(lines)


# =============================================================================
# SIDE EFFECT DETECTOR - Track Unintended Mutations
# =============================================================================


class SideEffectDetector:
    """
    Detect and track side effects during code execution.

    Monitors:
    - Database writes (INSERT, UPDATE, DELETE)
    - Cache modifications
    - File system changes
    - Global state mutations

    Usage:
        with SideEffectDetector() as detector:
            # Execute code
            pass

        if detector.has_side_effects:
            print(detector.get_report())
    """

    def __init__(self) -> None:
        self.writes: list[dict[str, Any]] = []
        self.cache_ops: list[dict[str, Any]] = []
        self._initial_query_count = 0

    def __enter__(self) -> SideEffectDetector:
        self._initial_query_count = len(connection.queries)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        # Analyze queries for writes
        for query in connection.queries[self._initial_query_count :]:
            sql = query.get("sql", "").upper()
            if any(keyword in sql for keyword in ["INSERT", "UPDATE", "DELETE"]):
                self.writes.append({"sql": query.get("sql", "")[:200], "time": query.get("time")})

    @property
    def has_side_effects(self) -> bool:
        """Check if any side effects were detected."""
        return len(self.writes) > 0 or len(self.cache_ops) > 0

    def get_report(self) -> dict[str, Any]:
        """Get detailed side effects report."""
        return {
            "has_side_effects": self.has_side_effects,
            "database_writes": len(self.writes),
            "cache_operations": len(self.cache_ops),
            "write_details": self.writes,
            "cache_details": self.cache_ops,
        }


# =============================================================================
# TRACE ASSERTION HELPERS - For Testing
# =============================================================================


def assert_max_queries(
    max_count: int = 10,
    max_duplicates: int = 2,
    raise_on_fail: bool = True,
) -> contextlib.AbstractContextManager[QueryTracer]:
    """
    Context manager that asserts query budget is not exceeded.

    Usage in tests:
        def test_user_list():
            with assert_max_queries(max_count=5, max_duplicates=0):
                users = list(User.objects.select_related('profile').all())
    """
    budget = QueryBudget(
        max_queries=max_count,
        max_duplicates=max_duplicates,
        raise_on_exceed=raise_on_fail,
        warn_on_exceed=True,
    )
    return QueryTracer(budget=budget)


def trace_execution(func: F) -> F:
    """
    Decorator to trace function execution with full analysis.

    Combines query tracing, method timing, and performance profiling.

    Usage:
        @trace_execution
        def my_view(request):
            # Automatically traced
            pass
    """

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        analyzer = RuntimeAnalyzer()
        with analyzer.analyze(func.__name__):
            result = func(*args, **kwargs)

        # Log the analysis
        report = analyzer.get_analysis(func.__name__)
        if report and report.get("query_trace", {}).get("duplicate_count", 0) > 0:
            logger.warning(
                f"Potential N+1 in {func.__name__}",
                extra={"analysis": report},
            )

        return result

    return wrapper  # type: ignore[return-value]


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    "MethodTrace",
    # Method Tracing
    "MethodTracer",
    # Performance
    "PerformanceProfiler",
    "PerformanceSnapshot",
    "QueryBudget",
    "QueryBudgetExceeded",
    "QueryInfo",
    # Query Tracing
    "QueryTracer",
    # Request ID & Context
    "RequestIDFilter",
    # Analysis
    "RuntimeAnalyzer",
    # Security Filters
    "SecurityEventFilter",
    "SensitiveDataFilter",
    "SideEffectDetector",
    # Structured Logging
    "StructuredLogAdapter",
    # Helpers
    "assert_max_queries",
    "clear_request_context",
    "clear_request_id",
    "get_logger",
    "get_request_context",
    "get_request_id",
    "set_request_context",
    "set_request_id",
    "trace_execution",
]
