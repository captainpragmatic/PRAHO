"""Real failed settings SQL must not abort a caller's PostgreSQL transaction."""

from collections.abc import Callable

from django.core.cache import cache
from django.db import DatabaseError, connection, transaction
from django.test import TestCase, override_settings

from apps.common.flow_analysis.hybrid_analyzer import get_proximity_line_threshold
from apps.common.performance.cache import _CacheTimeout, _resolve_timeout, get_cache_timeout_medium
from apps.common.performance.query_optimization import get_query_warning_threshold
from apps.common.trace_middleware import get_max_header_json_length
from apps.settings.models import SystemSetting


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class SettingsFallbackPostgresTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        if connection.vendor != "postgresql":
            self.skipTest("statement-aborts-transaction behavior requires PostgreSQL")
        cache.clear()
        self.addCleanup(cache.clear)
        self.row = SystemSetting.objects.create(
            key="test.fallback_savepoint", category="test", data_type="string", value="alive", default_value=""
        )

    def assert_usable_transaction(self, reader: Callable[[], int | None], expected: int) -> None:
        attempts: list[str] = []
        table = connection.ops.quote_name(SystemSetting._meta.db_table)

        def fail_settings_query(
            execute: Callable[..., object],
            sql: str,
            params: object,
            many: bool,
            context: dict[str, object],
        ) -> object:
            if SystemSetting._meta.db_table in sql:
                attempts.append(sql)
                # PostgreSQL executes this statement: this is not a Python-raised database exception.
                # The table name comes only from ORM metadata and is quoted above.
                return execute(f"SELECT 1 / 0 FROM {table}", None, many, context)  # noqa: S608
            return execute(sql, params, many, context)

        error: DatabaseError | None = None
        with transaction.atomic():
            with connection.execute_wrapper(fail_settings_query):
                self.assertEqual(reader(), expected)
            self.assertEqual(len(attempts), 1, "The runtime settings read must actually reach PostgreSQL")
            try:
                self.assertTrue(SystemSetting.objects.filter(pk=self.row.pk, value="alive").exists())
            except DatabaseError as exc:
                error = exc
            self.assertIsNone(error, "The fallback must leave the caller's transaction usable")

    def test_query_warning_fallback_preserves_the_callers_transaction(self) -> None:
        self.assert_usable_transaction(get_query_warning_threshold, 10)

    def test_trace_header_fallback_preserves_the_callers_transaction(self) -> None:
        self.assert_usable_transaction(get_max_header_json_length, 1000)

    def test_hybrid_analysis_fallback_preserves_the_callers_transaction(self) -> None:
        self.assert_usable_transaction(get_proximity_line_threshold, 5)

    def test_cache_timeout_fallback_preserves_the_callers_transaction(self) -> None:
        self.assert_usable_transaction(
            lambda: _resolve_timeout(_CacheTimeout.SETTING, get_cache_timeout_medium, 300), 300
        )
