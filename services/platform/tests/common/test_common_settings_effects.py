"""Stored common settings govern their consumers at call time."""

from __future__ import annotations

import logging
import time
from collections.abc import Generator
from contextlib import contextmanager
from io import StringIO
from typing import ClassVar, cast
from unittest.mock import patch

from django.core.cache import cache
from django.core.management import call_command
from django.core.paginator import Paginator
from django.db import OperationalError, connection, models, transaction
from django.db.models import QuerySet
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.views.generic import ListView

from apps.audit.models import AuditAlert
from apps.common.flow_analysis.base import (
    AnalysisContext,
    AnalysisMode,
    AnalysisSeverity,
    CodeLocation,
    FlowIssue,
    IssueCategory,
)
from apps.common.flow_analysis.hybrid_analyzer import HybridFlowAnalyzer
from apps.common.logging import MethodTracer, QueryInfo, QueryTracer
from apps.common.mixins import PaginationMixin, get_pagination_context
from apps.common.performance.cache import (
    CacheService,
    cache_customer_data,
    cache_key_for_model,
    cached_model_property,
    cached_queryset,
    get_cached_customer_data,
)
from apps.common.performance.query_optimization import QueryProfiler
from apps.common.trace_middleware import TraceMiddleware
from apps.settings.catalog import CATALOG_BY_KEY, SettingDef
from apps.settings.management.commands import setup_default_settings as sync
from apps.settings.models import SettingActivation, SystemSetting
from apps.settings.services import SettingsService
from apps.users.models import User

CONFIGURED = {
    "common.cache_timeout_medium": 2,
    "common.cache_timeout_short": 2,
    "common.default_orphans": 0,
    "common.max_header_json_length": 1,
    "common.max_summarized_args": 1,
    "common.proximity_line_threshold": 2,
    "common.query_warning_threshold": 1,
    "common.sql_display_limit": 4,
    "common.value_summary_limit": 3,
}
LOCMEM = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "common-settings-effects",
    }
}


def model_email(instance: models.Model) -> str:
    return str(getattr(instance, "email", ""))


def empty_queryset() -> QuerySet[SystemSetting]:
    return SystemSetting.objects.none()


def response(request: HttpRequest) -> HttpResponse:
    return HttpResponse(request.path)


def exception_findings(distance: int) -> list[FlowIssue]:
    return [
        FlowIssue(
            category=IssueCategory.EXCEPTION_FLOW,
            severity=AnalysisSeverity.HIGH,
            message="Missing handler",
            location=CodeLocation("sample.py", 10),
            mode=AnalysisMode.CONTROL_FLOW,
        ),
        FlowIssue(
            category=IssueCategory.TAINTED_DATA,
            severity=AnalysisSeverity.HIGH,
            message="Tainted input",
            location=CodeLocation("sample.py", 10 + distance),
            mode=AnalysisMode.DATA_FLOW,
        ),
    ]


class DefaultList(PaginationMixin, ListView):
    model = SystemSetting


class ExplicitList(DefaultList):
    paginate_orphans = 3


class ReentrantSummaryHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.summaries: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.summaries.append(MethodTracer._summarize_args(("nested", "second"), {}))


@override_settings(CACHES=LOCMEM, DISABLE_AUDIT_SIGNALS=True)
class CommonSettingsEffectTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.service = CacheService()

    def set_setting(self, key: str, value: int) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            result = SettingsService.update_setting(key, value)
        self.assertTrue(result.is_ok(), result)

    def test_set_uses_constant_timeout_when_settings_lookup_fails(self) -> None:
        now = time.time()
        with (
            patch("apps.settings.services.SystemSetting.objects.get", side_effect=OperationalError("settings offline")),
            patch("django.core.cache.backends.locmem.time.time", return_value=now) as clock,
        ):
            try:
                stored = self.service.set("unavailable-setting", "retained")
            except OperationalError:
                self.fail("set must tolerate an unavailable settings table")
            self.assertTrue(stored)
            self.assertEqual(self.service.get("unavailable-setting"), "retained")
            clock.return_value = now + 299
            self.assertEqual(self.service.get("unavailable-setting"), "retained")
            clock.return_value = now + 301
            self.assertIsNone(self.service.get("unavailable-setting"))

    def test_get_or_set_retains_computed_value_when_settings_lookup_fails(self) -> None:
        value = {"computed": "retained"}
        with patch(
            "apps.settings.services.SystemSetting.objects.get", side_effect=OperationalError("settings offline")
        ):
            try:
                result = self.service.get_or_set("computed-without-settings", lambda: value)
            except OperationalError:
                self.fail("get_or_set must return the computed value when settings are unavailable")
            self.assertIs(result, value)
            self.assertEqual(self.service.get("computed-without-settings"), value)

    def test_every_default_timeout_consumer_falls_back_when_settings_lookup_fails(self) -> None:
        def rows() -> QuerySet[User]:
            return User.objects.filter(email__startswith="offline-").order_by("email")

        User.objects.create(email="offline-a@example.test")
        property_reader = cached_model_property(key_suffix="offline-email")(model_email)
        queryset_reader = cached_queryset(key_prefix="offline-rows")(rows)
        user = User(pk=456, email="offline@example.test")
        now = time.time()
        with (
            patch("apps.settings.services.SystemSetting.objects.get", side_effect=OperationalError("settings offline")),
            patch("django.core.cache.backends.locmem.time.time", return_value=now) as clock,
        ):
            try:
                self.assertEqual(property_reader(user), "offline@example.test")
                self.assertEqual([row.email for row in queryset_reader()], ["offline-a@example.test"])
                self.assertEqual(self.service.cache_queryset_count(rows()), 1)
            except OperationalError:
                self.fail("cache consumers must use the constant timeout when settings are unavailable")
            user.email = "changed@example.test"
            User.objects.create(email="offline-b@example.test")
            # Short consumers keep the 60 s constant, the property keeps the 300 s one.
            clock.return_value = now + 59
            self.assertEqual(property_reader(user), "offline@example.test")
            self.assertEqual(len(queryset_reader()), 1)
            self.assertEqual(self.service.cache_queryset_count(rows()), 1)
            clock.return_value = now + 61
            self.assertEqual(len(queryset_reader()), 2)
            self.assertEqual(self.service.cache_queryset_count(rows()), 2)
            self.assertEqual(property_reader(user), "offline@example.test")
            clock.return_value = now + 301
            self.assertEqual(property_reader(user), "changed@example.test")

    def test_cache_timeout_medium_expires_every_default_consumer(self) -> None:
        property_reader = cached_model_property(key_suffix="medium-email")(model_email)
        user = User(pk=123, email="before@example.test")
        self.set_setting("common.cache_timeout_medium", 2)
        now = time.time()
        with patch("django.core.cache.backends.locmem.time.time", return_value=now) as clock:
            self.assertTrue(self.service.set("medium-set", "before"))
            self.assertEqual(self.service.get_or_set("medium-factory", lambda: "before"), "before")
            self.assertTrue(self.service.cache_model(user, fields=["email"]))
            self.assertTrue(cache_customer_data(123, "medium-effect", "before"))
            self.assertEqual(property_reader(user), "before@example.test")
            for timeout in (300, None, 0):
                self.assertTrue(self.service.set(f"explicit-{timeout}", "explicit", timeout=timeout))
            explicit_property = cached_model_property(timeout=300, key_suffix="explicit-email")(model_email)
            self.assertEqual(explicit_property(user), "before@example.test")

            user.email = "after@example.test"
            clock.return_value = now + 3
            self.assertIsNone(self.service.get("medium-set"))
            self.assertEqual(self.service.get_or_set("medium-factory", lambda: "after"), "after")
            self.assertIsNone(self.service.get(cache_key_for_model(user)))
            self.assertIsNone(get_cached_customer_data(123, "medium-effect"))
            self.assertEqual(property_reader(user), "after@example.test")
            self.assertEqual(explicit_property(user), "before@example.test")
            self.assertEqual(self.service.get("explicit-300"), "explicit")
            self.assertEqual(self.service.get("explicit-None"), "explicit")
            self.assertIsNone(self.service.get("explicit-0"))

    def test_cache_timeout_short_refreshes_counts_and_existing_wrappers(self) -> None:
        def rows() -> QuerySet[SystemSetting]:
            return SystemSetting.objects.filter(key__startswith="short-effect.").order_by("key")

        reader = cached_queryset(key_prefix="short-effect")(rows)
        explicit_reader = cached_queryset(timeout=60, key_prefix="short-explicit")(rows)
        self.set_setting("common.cache_timeout_short", 2)
        first = SystemSetting.objects.create(
            key="short-effect.first", name="First", data_type="integer", value=1, default_value=1
        )
        now = time.time()
        with patch("django.core.cache.backends.locmem.time.time", return_value=now) as clock:
            self.assertEqual(self.service.cache_queryset_count(rows()), 1)
            self.assertEqual([row.key for row in reader()], [first.key])
            self.assertEqual([row.key for row in explicit_reader()], [first.key])
            SystemSetting.objects.create(
                key="short-effect.second", name="Second", data_type="integer", value=2, default_value=2
            )

            clock.return_value = now + 3
            self.assertEqual(self.service.cache_queryset_count(rows()), 2)
            self.assertEqual([row.key for row in reader()], ["short-effect.first", "short-effect.second"])
            self.assertEqual([row.key for row in explicit_reader()], [first.key])

    def test_default_orphans_changes_function_and_mixin_pagination(self) -> None:
        User.objects.bulk_create(User(email=f"pagination-{number}@example.test") for number in range(23))
        rows = User.objects.filter(email__startswith="pagination-").order_by("pk")
        request = RequestFactory().get("/")
        self.set_setting("common.default_orphans", 0)
        context = get_pagination_context(request, rows)
        self.assertEqual(cast("Paginator[User]", context["paginator"]).num_pages, 2)
        view = DefaultList()
        view.setup(request)
        self.assertEqual(view.paginate_queryset(rows, 20)[0].num_pages, 2)
        explicit = get_pagination_context(request, rows, orphans=3)
        self.assertEqual(cast("Paginator[User]", explicit["paginator"]).num_pages, 1)
        explicit_view = ExplicitList()
        explicit_view.setup(request)
        self.assertEqual(explicit_view.paginate_queryset(rows, 20)[0].num_pages, 1)
        self.set_setting("common.default_orphans", 3)
        self.assertEqual(view.paginate_queryset(rows, 20)[0].num_pages, 1)

    def test_max_header_json_length_suppresses_only_the_summary_header(self) -> None:
        middleware = TraceMiddleware(response)
        self.set_setting("common.max_header_json_length", 1)
        result = HttpResponse()
        middleware._add_trace_headers(result, {"duration_ms": 1})
        self.assertNotIn("X-Trace-Summary", result)
        self.assertEqual(result["X-Trace-Duration-Ms"], "1")
        self.set_setting("common.max_header_json_length", len('{"duration_ms": 1}'))
        boundary = HttpResponse()
        middleware._add_trace_headers(boundary, {"duration_ms": 1})
        self.assertNotIn("X-Trace-Summary", boundary)
        self.set_setting("common.max_header_json_length", len('{"duration_ms": 1}') + 1)
        allowed = HttpResponse()
        middleware._add_trace_headers(allowed, {"duration_ms": 1})
        self.assertEqual(allowed["X-Trace-Summary"], '{"duration_ms": 1}')

    def test_max_summarized_args_limits_both_loops_without_logging_reentry(self) -> None:
        self.set_setting("common.max_summarized_args", 1)
        settings_logger = logging.getLogger("apps.settings.services")
        handler = ReentrantSummaryHandler()
        previous_level = settings_logger.level
        settings_logger.setLevel(logging.DEBUG)
        settings_logger.addHandler(handler)
        self.addCleanup(settings_logger.setLevel, previous_level)
        self.addCleanup(settings_logger.removeHandler, handler)
        summary = MethodTracer._summarize_args(("first", "second"), {"first": "one", "second": "two"})
        self.assertNotIn("arg1=", summary)
        self.assertNotIn("second=", summary)
        self.assertEqual(summary, 'arg0="first", first="one", ...')
        self.assertTrue(handler.summaries)

    def test_proximity_line_threshold_changes_exception_cross_references(self) -> None:
        self.set_setting("common.proximity_line_threshold", 2)
        analyzer = HybridFlowAnalyzer()
        context = AnalysisContext("sample.py", "")
        self.assertEqual(analyzer._cross_reference_findings(exception_findings(3), context), [])
        self.assertEqual(len(analyzer._cross_reference_findings(exception_findings(2), context)), 1)
        self.assertEqual(len(analyzer._cross_reference_findings(exception_findings(1), context)), 1)

    @override_settings(DEBUG=True)
    def test_query_warning_threshold_uses_only_profiled_queries(self) -> None:
        self.set_setting("common.query_warning_threshold", 1)
        with (
            self.assertLogs("apps.common.performance.query_optimization", level="WARNING") as logs,
            QueryProfiler("common-effect", log_queries=False) as profiler,
            connection.cursor() as cursor,
        ):
            cursor.execute("SELECT 1")
            cursor.execute("SELECT 2")
        self.assertEqual(profiler.query_count, 2)
        self.assertIn("2 queries", logs.output[0])
        self.set_setting("common.query_warning_threshold", 2)
        with (
            self.assertNoLogs("apps.common.performance.query_optimization", level="WARNING"),
            QueryProfiler("common-boundary") as profiler,
            connection.cursor() as cursor,
        ):
            cursor.execute("SELECT 1")
            cursor.execute("SELECT 2")
        self.assertEqual(profiler.query_count, 2)

    @override_settings(DEBUG=True)
    def test_query_profiler_logs_sql_using_one_display_limit_read_per_loop(self) -> None:
        for limit in (4, 0):
            self.set_setting("common.sql_display_limit", limit)
            with self.subTest(limit=limit):
                with (
                    self.assertLogs("apps.common.performance.query_optimization", level="DEBUG") as logs,
                    QueryProfiler("sql-limit", log_queries=True) as profiler,
                    connection.cursor() as cursor,
                ):
                    cursor.execute("SELECT 12345")
                    cursor.execute("SELECT 67890")
                self.assertEqual(profiler.query_count, 2)
                sql_messages = [record.getMessage() for record in logs.records if record.levelno == logging.DEBUG]
                self.assertEqual(
                    sql_messages, [f"  SQL: {'SELECT 12345'[:limit]}...", f"  SQL: {'SELECT 67890'[:limit]}..."]
                )
                setting_reads = [
                    query["sql"]
                    for query in connection.queries[profiler.query_count :]
                    if "common.sql_display_limit" in query["sql"]
                ]
                self.assertEqual(len(setting_reads), 1)

    def test_sql_display_limit_truncates_each_sql_summary(self) -> None:
        self.set_setting("common.sql_display_limit", 4)
        tracer = QueryTracer()
        tracer.queries = [QueryInfo("SELECT 1", 0, []), QueryInfo("ABCD", 0, [])]
        summary = tracer.get_summary()
        self.assertEqual(summary["queries"][0]["sql"], "SELE...")
        self.assertEqual(summary["queries"][1]["sql"], "ABCD")

    def test_value_summary_limit_applies_to_direct_and_argument_summaries(self) -> None:
        self.set_setting("common.value_summary_limit", 3)
        self.assertEqual(MethodTracer._summarize_value("abcdef"), '"abc..."')
        summary = MethodTracer._summarize_args(("abcdef",), {"value": "abcdef"})
        self.assertEqual(summary, 'arg0="abc...", value="abc..."')
        self.assertEqual(MethodTracer._summarize_value("abc"), '"abc"')
        self.assertEqual(MethodTracer._summarize_value("ab"), '"ab"')
        self.assertEqual(MethodTracer._summarize_value(None), "None")


@override_settings(CACHES=LOCMEM, DISABLE_AUDIT_SIGNALS=True, DEBUG=True)
class CommonSettingsQueryTests(SimpleTestCase):
    databases: ClassVar[set[str]] = {"default"}

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    @contextmanager
    def setting_mode(self, atomic: bool) -> Generator[None]:
        if atomic:
            with transaction.atomic():
                try:
                    for key, value in CONFIGURED.items():
                        result = SettingsService.update_setting(key, value)
                        self.assertTrue(result.is_ok(), result)
                    yield
                finally:
                    transaction.set_rollback(True)
        else:
            self.assertTrue(connection.get_autocommit())
            for key, value in CONFIGURED.items():
                cache.set(SettingsService._get_cache_key(key), value, version=SettingsService.CACHE_VERSION)
            yield

    def check_hot_paths(self, atomic: bool) -> None:
        reads = int(atomic)
        with self.setting_mode(atomic):
            self.check_cache_queries(reads)
            for size in (1, 25):
                with self.subTest(path="sql", size=size):
                    tracer = QueryTracer()
                    tracer.queries = [QueryInfo("SELECT 1", 0, []) for _ in range(size)]
                    with CaptureQueriesContext(connection) as queries:
                        summary = tracer.get_summary()
                    self.assertEqual(len(queries), reads)
                    self.assertEqual([row["sql"] for row in summary["queries"]], ["SELE..."] * size)
                with self.subTest(path="arguments", size=size):
                    with CaptureQueriesContext(connection) as queries:
                        summary = MethodTracer._summarize_args(("abcdef",) * size, {"value": "abcdef"})
                    self.assertEqual(len(queries), 2 * reads)
                    self.assertNotIn("arg1=", summary)
                    self.assertIn('arg0="abc..."', summary)
            self.check_logging_queries(reads)
            with self.subTest(path="header"):
                result = HttpResponse()
                middleware = TraceMiddleware(response)
                with CaptureQueriesContext(connection) as queries:
                    middleware._add_trace_headers(result, {"duration_ms": 1})
                self.assertEqual(len(queries), reads)
                self.assertNotIn("X-Trace-Summary", result)
            with self.subTest(path="pagination"):
                request = RequestFactory().get("/")
                with CaptureQueriesContext(connection) as queries:
                    context = get_pagination_context(request, SystemSetting.objects.none())
                self.assertEqual(len(queries), reads)
                self.assertEqual(cast("Paginator[SystemSetting]", context["paginator"]).orphans, 0)
                with CaptureQueriesContext(connection) as queries:
                    orphans = DefaultList().get_paginate_orphans()
                self.assertEqual(len(queries), reads)
                self.assertEqual(orphans, 0)
            with self.subTest(path="profiler"):
                connection.queries_log.clear()
                with CaptureQueriesContext(connection) as queries, QueryProfiler("empty-effect") as profiler:
                    pass
                self.assertEqual(len(queries), reads)
                self.assertEqual(profiler.query_count, 0)

    def check_logging_queries(self, reads: int) -> None:
        with self.subTest(path="value"):
            with CaptureQueriesContext(connection) as queries:
                summary = MethodTracer._summarize_value("abcdef")
            self.assertEqual(len(queries), reads)
            self.assertEqual(summary, '"abc..."')
        with self.subTest(path="proximity"):
            analyzer = HybridFlowAnalyzer()
            issues = exception_findings(3) * 25
            with CaptureQueriesContext(connection) as queries:
                findings = analyzer._cross_reference_findings(issues, AnalysisContext("sample.py", ""))
            self.assertEqual(len(queries), reads)
            self.assertEqual(findings, [])

    def check_cache_queries(self, reads: int) -> None:
        service = CacheService()
        user = User(pk=123, email="before@example.test")
        count_rows = SystemSetting.objects.filter(key="query-count-missing")
        now = time.time()
        with patch("django.core.cache.backends.locmem.time.time", return_value=now) as clock:
            with CaptureQueriesContext(connection) as queries:
                service.set("query-medium", "value")
            self.assertEqual(len(queries), reads)
            clock.return_value = now + 3
            self.assertIsNone(service.get("query-medium"))
            clock.return_value = now
            with CaptureQueriesContext(connection) as queries:
                self.assertEqual(service.cache_queryset_count(count_rows), 0)
            self.assertEqual(len(queries), reads + 1)
            clock.return_value = now + 3
            self.assertIsNone(service.get(service._queryset_count_key(count_rows)))
            clock.return_value = now
            property_reader = cached_model_property(key_suffix="query-email")(model_email)
            with CaptureQueriesContext(connection) as queries:
                self.assertEqual(property_reader(user), "before@example.test")
            self.assertEqual(len(queries), reads)
            reader = cached_queryset(key_prefix="query-rows")(empty_queryset)
            with CaptureQueriesContext(connection) as queries:
                self.assertEqual(reader(), [])
            self.assertEqual(len(queries), reads)
            clock.return_value = now + 3
            user.email = "after@example.test"
            self.assertEqual(property_reader(user), "after@example.test")

    def test_hot_paths_use_warm_cache_without_database_queries(self) -> None:
        self.check_hot_paths(atomic=False)

    def test_hot_paths_read_once_per_operation_inside_atomic(self) -> None:
        self.check_hot_paths(atomic=True)


class CommonSettingsActivationTests(TestCase):
    def test_batch_activates_all_nine_keys_and_alerts_once_for_retained_values(self) -> None:
        keys = set(CONFIGURED)
        definitions = tuple(CATALOG_BY_KEY[key] for key in CONFIGURED)
        for key, value in CONFIGURED.items():
            result = SettingsService.update_setting(key, value)
            self.assertTrue(result.is_ok(), result)
        SystemSetting.objects.filter(key__in=keys).update(name="Metadata reconciled before activation")
        output = StringIO()
        with patch.object(sync, "CATALOG", definitions):
            call_command("setup_default_settings", stdout=output)
        self.assertEqual(SettingActivation.objects.filter(key__in=keys, completed_at__isnull=False).count(), 9)
        alert = AuditAlert.objects.get(metadata__activation_version="wp18-v1")
        self.assertEqual(set(alert.metadata["keys"]), keys)
        self.assertEqual(alert.evidence["retained_values"], CONFIGURED)
        self.assertEqual(alert.evidence["previous_enforced_values"], {d.key: d.default for d in definitions})
        self.assertEqual(dict(SystemSetting.objects.filter(key__in=keys).values_list("key", "value")), CONFIGURED)
        for key in keys:
            self.assertIn(key, output.getvalue())
        result = SettingsService.update_setting("common.cache_timeout_medium", 300)
        self.assertTrue(result.is_ok(), result)
        with patch.object(sync, "CATALOG", definitions):
            call_command("setup_default_settings", stdout=StringIO())
        self.assertEqual(AuditAlert.objects.filter(metadata__activation_version="wp18-v1").count(), 1)
        self.assertEqual(SettingsService.get_integer_setting("common.cache_timeout_medium"), 300)
        self.check_default_activation(definitions)

    def check_default_activation(self, definitions: tuple[SettingDef, ...]) -> None:
        keys = [definition.key for definition in definitions]
        for seed in (False, True):
            with self.subTest(seed_defaults=seed), transaction.atomic():
                try:
                    SettingActivation.objects.filter(key__in=keys).delete()
                    SystemSetting.objects.filter(key__in=keys).delete()
                    before = AuditAlert.objects.filter(metadata__activation_version="wp18-v1").count()
                    if seed:
                        for definition in definitions:
                            result = SettingsService.update_setting(definition.key, definition.default)
                            self.assertTrue(result.is_ok(), result)
                        SystemSetting.objects.filter(key__in=keys).update(name="Metadata already reconciled")
                    with patch.object(sync, "CATALOG", definitions):
                        call_command("setup_default_settings", stdout=StringIO())
                    self.assertEqual(
                        dict(SystemSetting.objects.filter(key__in=keys).values_list("key", "value")),
                        {definition.key: definition.default for definition in definitions},
                    )
                    self.assertEqual(
                        SettingActivation.objects.filter(key__in=keys, completed_at__isnull=False).count(), 9
                    )
                    self.assertEqual(AuditAlert.objects.filter(metadata__activation_version="wp18-v1").count(), before)
                finally:
                    transaction.set_rollback(True)
