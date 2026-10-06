"""The serial CI runner isolates cache aliases while keeping them functional."""

from __future__ import annotations

from io import StringIO
from unittest import TestCase as UnitTestCase
from unittest import TestSuite, TextTestRunner
from unittest.mock import patch

from django.core.cache import caches
from django.db import connection
from django.test import SimpleTestCase, TestCase, override_settings
from django.test.runner import DebugSQLTextTestResult, PDBDebugResult

from tests.runner import CacheClearingTestResult, PostgreSQLSafeRunner

TEST_CACHES = {
    alias: {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": f"ci-isolation-{alias}"}
    for alias in ("default", "secondary")
}


@override_settings(CACHES=TEST_CACHES)
class CICacheIsolationTests(SimpleTestCase):
    def setUp(self) -> None:
        self.addCleanup(self._clear_caches)

    def test_every_test_starts_with_empty_caches_and_can_reuse_its_own_values(self) -> None:
        for backend in caches.all():
            backend.set("previous-test", True)

        class CacheConsumer(UnitTestCase):
            def setUp(self) -> None:
                for backend in caches.all():
                    self.assertIsNone(backend.get("previous-test"))
                    self.assertIsNone(backend.get("this-test"))

            def test_cache_is_functional(self) -> None:
                for backend in caches.all():
                    backend.set("this-test", 42)
                    self.assertEqual(backend.get("this-test"), 42)

        runner = PostgreSQLSafeRunner(verbosity=0)
        suite = TestSuite([CacheConsumer("test_cache_is_functional"), CacheConsumer("test_cache_is_functional")])
        with patch("tests.runner._ensure_healthy_connection"), patch("sys.stderr", new=StringIO()):
            result = runner.run_suite(suite)

        self.assertEqual(result.testsRun, 2)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.failures, [])

    def test_debug_result_modes_keep_django_behavior_and_cache_isolation(self) -> None:
        for options, expected_class in (
            ({"debug_sql": True}, DebugSQLTextTestResult),
            ({"pdb": True}, PDBDebugResult),
        ):
            with self.subTest(options=options):
                for backend in caches.all():
                    backend.set("previous-test", True)
                result_class = PostgreSQLSafeRunner(
                    verbosity=0,
                    debug_sql=options.get("debug_sql", False),
                    pdb=options.get("pdb", False),
                ).get_resultclass()
                self.assertIsNotNone(result_class)
                if result_class is None:
                    self.fail("CI runner must provide a cache-isolating result class")
                result = result_class(TextTestRunner(stream=StringIO()).stream, False, 0)
                self.assertIsInstance(result, expected_class)

                result.startTest(UnitTestCase())

                for backend in caches.all():
                    self.assertIsNone(backend.get("previous-test"))

    def test_cache_clear_failure_does_not_abort_or_skip_other_locmem_caches(self) -> None:
        default_cache = caches["default"]
        secondary_cache = caches["secondary"]
        secondary_cache.set("previous-test", True)
        result = CacheClearingTestResult(TextTestRunner(stream=StringIO()).stream, False, 0)

        with (
            patch.object(default_cache, "clear", side_effect=RuntimeError("cache clear failed")) as clear_default,
            self.assertLogs("tests.runner", level="WARNING"),
        ):
            result.startTest(UnitTestCase())

        clear_default.assert_called_once_with()
        self.assertEqual(result.testsRun, 1)
        self.assertEqual(result.errors, [])
        self.assertIsNone(secondary_cache.get("previous-test"))

    def test_locmem_store_is_cleared_after_settings_reset_cache_handlers(self) -> None:
        for backend in caches.all():
            backend.set("previous-test", True)

        with override_settings(CACHES=TEST_CACHES):
            self.assertEqual(caches.all(initialized_only=True), [])
            result = CacheClearingTestResult(TextTestRunner(stream=StringIO()).stream, False, 0)

            result.startTest(UnitTestCase())

            self.assertEqual(result.testsRun, 1)
            for backend in caches.all():
                self.assertIsNone(backend.get("previous-test"))

    @staticmethod
    def _clear_caches() -> None:
        for backend in caches.all():
            backend.clear()


@override_settings(
    CACHES={
        **TEST_CACHES,
        "database": {
            "BACKEND": "django.core.cache.backends.db.DatabaseCache",
            "LOCATION": "ci_missing_cache_table",
        },
    }
)
class CIDatabaseCacheIsolationTests(TestCase):
    def test_start_test_skips_missing_database_cache_table_and_clears_locmem(self) -> None:
        self.assertNotIn("ci_missing_cache_table", connection.introspection.table_names())
        database_cache = caches["database"]
        for alias in TEST_CACHES:
            backend = caches[alias]
            self.addCleanup(backend.clear)
            backend.set("previous-test", True)
        result = CacheClearingTestResult(TextTestRunner(stream=StringIO()).stream, False, 0)

        with patch.object(database_cache, "clear", wraps=database_cache.clear) as clear_database:
            result.startTest(UnitTestCase())

        clear_database.assert_not_called()
        self.assertEqual(result.testsRun, 1)
        self.assertEqual(result.errors, [])
        for alias in TEST_CACHES:
            self.assertIsNone(caches[alias].get("previous-test"))
