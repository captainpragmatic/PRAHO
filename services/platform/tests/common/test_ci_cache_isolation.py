"""The serial CI runner isolates cache aliases while keeping them functional."""

from __future__ import annotations

from io import StringIO
from unittest import TestCase as UnitTestCase
from unittest import TestSuite
from unittest.mock import patch

from django.core.cache import caches
from django.test import SimpleTestCase, override_settings
from django.test.runner import DebugSQLTextTestResult, PDBDebugResult

from tests.runner import PostgreSQLSafeRunner

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
                result_class = PostgreSQLSafeRunner(verbosity=0, **options).get_resultclass()
                self.assertIsNotNone(result_class)
                if result_class is None:
                    self.fail("CI runner must provide a cache-isolating result class")
                result = result_class(StringIO(), False, 0)
                self.assertIsInstance(result, expected_class)

                result.startTest(UnitTestCase())

                for backend in caches.all():
                    self.assertIsNone(backend.get("previous-test"))

    @staticmethod
    def _clear_caches() -> None:
        for backend in caches.all():
            backend.clear()
