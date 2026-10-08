"""Diagnostics preserve responses, exceptions and findings during a settings outage."""

import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

from django.core.cache import cache
from django.db import DatabaseError, OperationalError, connection
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory, TestCase, override_settings

from apps.common import trace_middleware
from apps.common.flow_analysis.base import (
    AnalysisContext,
    AnalysisMode,
    AnalysisSeverity,
    CodeLocation,
    FlowIssue,
    IssueCategory,
)
from apps.common.flow_analysis.hybrid_analyzer import HybridFlowAnalyzer
from apps.common.performance.query_optimization import QueryProfiler
from apps.common.trace_middleware import TraceMiddleware
from apps.settings.models import SystemSetting


@contextmanager
def settings_offline() -> Iterator[None]:
    """Fail actual settings SQL while letting the diagnosed operation use its database."""

    def fail_settings_sql(
        execute: Callable[..., object],
        sql: str,
        params: object,
        many: bool,
        context: dict[str, object],
    ) -> object:
        if SystemSetting._meta.db_table in sql:
            raise OperationalError("settings offline")
        return execute(sql, params, many, context)

    with connection.execute_wrapper(fail_settings_sql):
        yield


class DiagnosticSettingsOutageTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)

    def test_traced_response_and_default_header_cutoff_survive_settings_outage(
        self,
    ) -> None:
        expected = HttpResponse("alive")

        def view(request: HttpRequest) -> HttpResponse:
            return expected

        request = RequestFactory().get("/trace-outage/", HTTP_X_ENABLE_TRACE="true")
        middleware = TraceMiddleware(view)
        with settings_offline():
            try:
                response = middleware(request)
                self.assertIs(response, expected)
                self.assertEqual(response.content, b"alive")
                self.assertEqual(json.loads(response["X-Trace-Summary"])["path"], "/trace-outage/")
                self.assertEqual(response["X-Trace-Query-Count"], "0")
                # JSON syntax contributes 15 bytes, putting these on either side of the 1000-byte cutoff.
                for length, included in ((984, True), (985, False)):
                    limited = HttpResponse("alive")
                    middleware._add_trace_headers(limited, {"payload": "x" * length})
                    self.assertEqual("X-Trace-Summary" in limited, included)
            except DatabaseError:
                self.fail("diagnostic settings failure must not discard a successful traced response")

    @override_settings(DEBUG=True)
    def test_query_profiler_preserves_the_original_exception_during_settings_outage(
        self,
    ) -> None:
        original = ValueError("original application error")
        profiler = QueryProfiler("original-error", log_queries=True)
        with settings_offline():
            try:
                with profiler, connection.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    raise original
            except ValueError as caught:
                self.assertIs(caught, original)
            except DatabaseError:
                self.fail("diagnostic settings failure must not replace the original application exception")
            else:
                self.fail("the original application exception must propagate")
        self.assertEqual(profiler.query_count, 1)
        self.assertGreaterEqual(profiler.total_time, 0)

    @override_settings(DEBUG=True)
    def test_query_profiler_uses_the_default_warning_threshold_during_settings_outage(
        self,
    ) -> None:
        with (
            settings_offline(),
            self.assertLogs("apps.common.performance.query_optimization", level="WARNING") as warnings,
        ):
            try:
                with (
                    QueryProfiler("outage-threshold") as profiler,
                    connection.cursor() as cursor,
                ):
                    for _ in range(11):
                        cursor.execute("SELECT 1")
            except DatabaseError:
                self.fail("diagnostic settings failure must not interrupt successful query profiling")
        self.assertEqual(profiler.query_count, 11)
        self.assertTrue(any("[outage-threshold]: 11 queries" in message for message in warnings.output))

    def test_hybrid_analysis_and_default_proximity_findings_survive_settings_outage(
        self,
    ) -> None:
        analyzer = HybridFlowAnalyzer()
        path = Path(trace_middleware.__file__).parents[1] / "settings" / "__init__.py"
        context = AnalysisContext(file_path="outage.py", source_code="pass")
        exception_issue = FlowIssue(
            category=IssueCategory.EXCEPTION_FLOW,
            severity=AnalysisSeverity.MEDIUM,
            message="Unhandled exception",
            location=CodeLocation("outage.py", 10),
            mode=AnalysisMode.CONTROL_FLOW,
        )
        data_issues = [
            FlowIssue(
                category=IssueCategory.TAINTED_DATA,
                severity=AnalysisSeverity.HIGH,
                message="Unsanitized input",
                location=CodeLocation("outage.py", line),
                mode=AnalysisMode.DATA_FLOW,
            )
            for line in (14, 15, 16)
        ]
        with settings_offline():
            try:
                result = analyzer.analyze_file(path)
                correlated = analyzer._cross_reference_findings([exception_issue, *data_issues], context)
            except DatabaseError:
                self.fail("diagnostic settings failure must not abort hybrid file analysis")
        self.assertEqual(result.files_analyzed, 1)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.analysis_mode, AnalysisMode.HYBRID)
        self.assertEqual([issue.location.line_number for issue in correlated], [14, 15])
        self.assertTrue(all(issue.metadata["cross_reference"] == "exception_handling" for issue in correlated))
