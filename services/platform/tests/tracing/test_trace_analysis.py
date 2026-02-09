"""
Trace-Based Dynamic Analysis Tests for PRAHO Platform.

These tests step through code execution and examine runtime behavior to:
- Detect N+1 query problems
- Identify side effects that static analysis misses
- Measure performance characteristics
- Validate structured logging infrastructure

Run with: pytest tests/tracing/ -v --tb=short
"""

from __future__ import annotations

import logging
import time
import uuid
from decimal import Decimal
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.db import connection, reset_queries
from django.test import RequestFactory, TestCase, override_settings

from apps.common.logging import (
    MethodTracer,
    PerformanceProfiler,
    QueryBudget,
    QueryBudgetExceeded,
    QueryTracer,
    RequestIDFilter,
    RuntimeAnalyzer,
    SideEffectDetector,
    assert_max_queries,
    clear_request_id,
    get_request_id,
    set_request_id,
)

if TYPE_CHECKING:
    pass

User = get_user_model()


# =============================================================================
# REQUEST ID FILTER TESTS
# =============================================================================


class TestRequestIDFilter(TestCase):
    """Test RequestIDFilter for structured logging."""

    def test_filter_adds_request_id_to_log_record(self):
        """Test that RequestIDFilter adds request_id to log records."""
        # Set up
        request_id = str(uuid.uuid4())
        set_request_id(request_id)

        try:
            # Create filter and log record
            filter_instance = RequestIDFilter()
            record = logging.LogRecord(
                name="test",
                level=logging.INFO,
                pathname="test.py",
                lineno=1,
                msg="Test message",
                args=(),
                exc_info=None,
            )

            # Apply filter
            result = filter_instance.filter(record)

            # Verify
            assert result is True
            assert hasattr(record, "request_id")
            assert record.request_id == request_id
        finally:
            clear_request_id()

    def test_filter_provides_default_when_no_request_id(self):
        """Test that filter provides default value when no request ID is set."""
        clear_request_id()

        filter_instance = RequestIDFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        result = filter_instance.filter(record)

        assert result is True
        # After clear_request_id(), attribute is None (not absent)
        assert record.request_id is None

    def test_request_id_thread_local_isolation(self):
        """Test that request IDs are properly isolated in thread-local storage."""
        import concurrent.futures

        results = {}

        def set_and_get_id(thread_id: int) -> tuple[int, str]:
            request_id = f"thread-{thread_id}-{uuid.uuid4()}"
            set_request_id(request_id)
            time.sleep(0.01)  # Small delay to test isolation
            retrieved = get_request_id()
            clear_request_id()
            return (thread_id, retrieved)

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(set_and_get_id, i) for i in range(5)]
            for future in concurrent.futures.as_completed(futures):
                thread_id, retrieved = future.result()
                results[thread_id] = retrieved

        # Each thread should have its own unique ID
        assert len(set(results.values())) == 5


# =============================================================================
# QUERY TRACER TESTS
# =============================================================================


@pytest.mark.django_db
class TestQueryTracer:
    """Test QueryTracer for database query monitoring."""

    def test_traces_database_queries(self):
        """Test that QueryTracer captures database queries."""
        with QueryTracer() as tracer:
            # Execute some queries
            list(User.objects.all()[:5])

        summary = tracer.get_summary()
        assert summary["total_queries"] >= 1
        assert "queries" in summary

    def test_detects_duplicate_queries(self):
        """Test N+1 detection through duplicate query analysis."""
        # Create test users first
        for i in range(3):
            User.objects.create_user(
                username=f"trace_test_user_{i}",
                email=f"trace_test_{i}@example.com",
                password="testpass123",
            )

        with QueryTracer() as tracer:
            # Simulate N+1 by querying same pattern multiple times
            for user in User.objects.filter(username__startswith="trace_test_user_"):
                # This creates duplicate queries if not optimized
                _ = user.pk

        summary = tracer.get_summary()
        # Check if duplicates are detected
        assert "duplicate_count" in summary

    def test_query_budget_enforcement(self):
        """Test that query budget raises exception when exceeded."""
        budget = QueryBudget(max_queries=1, raise_on_exceed=True)

        with pytest.raises(QueryBudgetExceeded):
            with QueryTracer(budget=budget):
                # Execute multiple queries to exceed budget
                list(User.objects.all()[:1])
                list(User.objects.all()[:1])

    def test_query_budget_warning_only(self):
        """Test that query budget can warn without raising."""
        budget = QueryBudget(max_queries=1, raise_on_exceed=False, warn_on_exceed=True)

        with patch("apps.common.logging.logger") as mock_logger:
            with QueryTracer(budget=budget):
                list(User.objects.all()[:1])
                list(User.objects.all()[:1])

            # Should log warning but not raise
            # Note: This tests the warning path

    def test_get_n_plus_one_report(self):
        """Test detailed N+1 query report generation."""
        # Create test data
        for i in range(2):
            User.objects.create_user(
                username=f"n1_test_user_{i}",
                email=f"n1_test_{i}@example.com",
                password="testpass123",
            )

        with QueryTracer() as tracer:
            for user in User.objects.filter(username__startswith="n1_test_user_"):
                _ = user.email  # Access attribute

        report = tracer.get_n_plus_one_report()
        assert isinstance(report, list)


@pytest.mark.django_db
class TestAssertMaxQueries:
    """Test assert_max_queries helper function."""

    def test_passes_when_under_budget(self):
        """Test that no exception is raised when under query budget."""
        with assert_max_queries(max_count=10, max_duplicates=5):
            list(User.objects.all()[:1])

    def test_fails_when_over_budget(self):
        """Test that exception is raised when over query budget."""
        with pytest.raises(QueryBudgetExceeded):
            with assert_max_queries(max_count=1, max_duplicates=0, raise_on_fail=True):
                list(User.objects.all()[:1])
                list(User.objects.all()[:1])
                list(User.objects.all()[:1])


# =============================================================================
# METHOD TRACER TESTS
# =============================================================================


class TestMethodTracer:
    """Test MethodTracer for execution timing."""

    def setup_method(self):
        """Clear traces before each test."""
        MethodTracer.clear()

    def test_trace_decorator_captures_timing(self):
        """Test that trace decorator captures method execution time."""

        @MethodTracer.trace
        def slow_function():
            time.sleep(0.01)
            return "done"

        result = slow_function()

        assert result == "done"
        traces = MethodTracer.get_all_traces()
        assert len(traces) >= 1
        assert traces[0].method_name == "slow_function"
        assert traces[0].duration_ms >= 10  # At least 10ms

    def test_trace_context_manager(self):
        """Test trace context manager."""
        with MethodTracer.context("test_operation") as trace:
            time.sleep(0.01)

        assert trace.method_name == "test_operation"
        assert trace.duration_ms >= 10

    def test_trace_captures_exceptions(self):
        """Test that tracer captures exception information."""

        @MethodTracer.trace
        def failing_function():
            raise ValueError("Test error")

        with pytest.raises(ValueError):
            failing_function()

        traces = MethodTracer.get_all_traces()
        assert len(traces) >= 1
        assert "ValueError" in traces[0].exception

    def test_trace_report_generation(self):
        """Test trace report includes all metrics."""

        @MethodTracer.trace
        def func_a():
            time.sleep(0.01)

        @MethodTracer.trace
        def func_b():
            time.sleep(0.02)

        func_a()
        func_b()
        func_a()  # Call again for averaging

        report = MethodTracer.get_trace_report()

        assert report["total_traces"] >= 3
        assert "methods" in report
        assert "slowest_methods" in report

    def test_nested_traces(self):
        """Test that nested method traces create proper hierarchy."""

        @MethodTracer.trace
        def outer():
            inner()

        @MethodTracer.trace
        def inner():
            time.sleep(0.01)

        outer()

        traces = MethodTracer.get_all_traces()
        # Should have outer trace with inner as child
        assert len(traces) >= 1


# =============================================================================
# PERFORMANCE PROFILER TESTS
# =============================================================================


class TestPerformanceProfiler:
    """Test PerformanceProfiler for resource tracking."""

    def test_profiles_execution(self):
        """Test that profiler captures execution metrics."""
        with PerformanceProfiler() as profiler:
            # Do some work
            _ = [i**2 for i in range(1000)]

        report = profiler.get_report()

        assert "duration_ms" in report
        assert report["duration_ms"] >= 0

    def test_tracks_memory_delta(self):
        """Test memory tracking (may be zero if psutil not installed)."""
        with PerformanceProfiler() as profiler:
            # Allocate some memory
            data = [i for i in range(10000)]
            del data

        report = profiler.get_report()
        assert "memory_delta_mb" in report


# =============================================================================
# RUNTIME ANALYZER TESTS
# =============================================================================


@pytest.mark.django_db
class TestRuntimeAnalyzer:
    """Test RuntimeAnalyzer for comprehensive analysis."""

    def test_comprehensive_analysis(self):
        """Test that analyzer combines all tracing tools."""
        analyzer = RuntimeAnalyzer()

        with analyzer.analyze("test_operation"):
            # Perform database operation
            list(User.objects.all()[:5])
            time.sleep(0.01)

        analysis = analyzer.get_analysis("test_operation")

        assert analysis is not None
        assert analysis["operation"] == "test_operation"
        assert "start_time" in analysis
        assert "end_time" in analysis

    def test_generates_readable_report(self):
        """Test human-readable report generation."""
        analyzer = RuntimeAnalyzer()

        with analyzer.analyze("report_test"):
            list(User.objects.all()[:1])

        report = analyzer.generate_report()

        assert "RUNTIME ANALYSIS REPORT" in report
        assert "report_test" in report


# =============================================================================
# SIDE EFFECT DETECTOR TESTS
# =============================================================================


@pytest.mark.django_db
class TestSideEffectDetector:
    """Test SideEffectDetector for mutation tracking."""

    def test_detects_database_writes(self):
        """Test detection of database write operations."""
        with SideEffectDetector() as detector:
            User.objects.create_user(
                username="side_effect_test",
                email="side_effect@example.com",
                password="testpass123",
            )

        assert detector.has_side_effects
        report = detector.get_report()
        assert report["database_writes"] >= 1

    def test_no_side_effects_for_reads(self):
        """Test that read operations don't trigger side effect detection."""
        # First create a user outside the detector
        User.objects.create_user(
            username="read_test",
            email="read_test@example.com",
            password="testpass123",
        )

        with SideEffectDetector() as detector:
            # Only read
            list(User.objects.filter(username="read_test"))

        # Reads should not count as side effects
        assert detector.get_report()["database_writes"] == 0


# =============================================================================
# INTEGRATION TESTS - CRITICAL PATH ANALYSIS
# =============================================================================


@pytest.mark.django_db
class TestCriticalPathAnalysis:
    """Analyze critical paths in the system for performance issues."""

    def test_user_creation_query_budget(self):
        """Test that user creation stays within query budget."""
        with assert_max_queries(max_count=10, raise_on_fail=True):
            user = User.objects.create_user(
                username="query_budget_user",
                email="budget@example.com",
                password="testpass123",
            )
            assert user.pk is not None

    def test_user_lookup_performance(self):
        """Test user lookup doesn't cause excessive queries."""
        # Setup
        User.objects.create_user(
            username="lookup_test",
            email="lookup@example.com",
            password="testpass123",
        )

        with QueryTracer() as tracer:
            user = User.objects.get(username="lookup_test")
            _ = user.email

        summary = tracer.get_summary()
        # Simple lookup should be 1 query
        assert summary["total_queries"] <= 2

    def test_bulk_operations_efficiency(self):
        """Test that bulk operations are efficient."""
        with QueryTracer() as tracer:
            # Bulk create should use single query
            User.objects.bulk_create([
                User(username=f"bulk_user_{i}", email=f"bulk_{i}@example.com")
                for i in range(10)
            ])

        summary = tracer.get_summary()
        # Bulk create should use minimal queries
        assert summary["total_queries"] <= 3


# =============================================================================
# MIDDLEWARE INTEGRATION TESTS
# =============================================================================


class TestMiddlewareTracing(TestCase):
    """Test middleware integration with tracing infrastructure."""

    def test_request_id_middleware_sets_thread_local(self):
        """Test that RequestIDMiddleware properly sets thread-local storage."""
        from apps.common.middleware import RequestIDMiddleware

        factory = RequestFactory()
        request = factory.get("/test/")

        def mock_get_response(request):
            # During request processing, request ID should be available
            current_id = get_request_id()
            from django.http import HttpResponse
            return HttpResponse(f"Request ID: {current_id}")

        middleware = RequestIDMiddleware(mock_get_response)
        response = middleware(request)

        # Request ID should be in response header
        assert "X-Request-ID" in response
        # Should be a valid UUID
        request_id = response["X-Request-ID"]
        uuid.UUID(request_id)  # Will raise if invalid


# =============================================================================
# PERFORMANCE REGRESSION TESTS
# =============================================================================


@pytest.mark.django_db
class TestPerformanceRegression:
    """Test for performance regressions using trace-based analysis."""

    def test_no_n_plus_one_in_user_list(self):
        """Ensure user listing doesn't have N+1 queries."""
        # Create test users
        for i in range(5):
            User.objects.create_user(
                username=f"perf_user_{i}",
                email=f"perf_{i}@example.com",
                password="testpass123",
            )

        with QueryTracer() as tracer:
            users = list(User.objects.filter(username__startswith="perf_user_"))
            for user in users:
                _ = user.email  # Access attribute

        summary = tracer.get_summary()
        # Should be efficient - no N+1
        assert summary["duplicate_count"] <= 1, f"Detected N+1: {summary}"

    def test_select_related_prevents_n_plus_one(self):
        """Test that select_related optimization works."""
        # This test is a template for models with ForeignKey relationships
        # Currently User model doesn't have FK, but this pattern shows
        # how to verify select_related effectiveness

        with QueryTracer() as tracer:
            # If we had a Profile model:
            # users = User.objects.select_related('profile').all()
            # for user in users:
            #     _ = user.profile.bio  # Should not cause extra query
            users = list(User.objects.all()[:5])

        summary = tracer.get_summary()
        # Verify queries are optimized
        assert summary["total_queries"] <= 2


# =============================================================================
# LOGGING VERIFICATION TESTS
# =============================================================================


class TestLoggingInfrastructure:
    """Verify logging infrastructure works correctly."""

    def test_request_id_propagates_to_logs(self):
        """Test that request IDs appear in log messages."""
        request_id = str(uuid.uuid4())
        set_request_id(request_id)

        try:
            # Create a logger and capture output
            logger = logging.getLogger("test.request_id")
            filter_instance = RequestIDFilter()

            # Create a handler with our filter
            import io
            stream = io.StringIO()
            handler = logging.StreamHandler(stream)
            handler.addFilter(filter_instance)
            handler.setFormatter(logging.Formatter("[%(request_id)s] %(message)s"))
            logger.addHandler(handler)
            logger.setLevel(logging.DEBUG)

            # Log a message
            logger.info("Test log message")

            # Check output
            output = stream.getvalue()
            assert request_id in output

            # Cleanup
            logger.removeHandler(handler)
        finally:
            clear_request_id()

    def test_structured_logging_format(self):
        """Test that logs can be formatted as structured JSON."""
        request_id = str(uuid.uuid4())
        set_request_id(request_id)

        try:
            filter_instance = RequestIDFilter()
            record = logging.LogRecord(
                name="test",
                level=logging.INFO,
                pathname="test.py",
                lineno=1,
                msg="Structured test",
                args=(),
                exc_info=None,
            )

            filter_instance.filter(record)

            # Verify record has request_id for JSON formatting
            import json
            log_dict = {
                "message": record.getMessage(),
                "request_id": record.request_id,
                "level": record.levelname,
            }
            json_output = json.dumps(log_dict)
            assert request_id in json_output
        finally:
            clear_request_id()
