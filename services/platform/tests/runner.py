"""
Custom test runner for PostgreSQL CI — works around Django #30448.

Django's close_if_unusable_or_obsolete() prematurely closes connections inside
atomic blocks when CONN_MAX_AGE=0, causing cascade failures on PostgreSQL.
TransactionTestCase tears down connections; subsequent TestCase classes inherit
the dead connection and fail en masse.

Two-layer defense:
1. ci.py sets CONN_MAX_AGE=None (prevents close_if_unusable_or_obsolete from closing)
2. This runner adds ensure_connection() recovery as a safety net

All Django runs isolate media; the PostgreSQL runner additionally protects CI connections.
"""

from __future__ import annotations

import contextlib
import logging
from typing import Any, cast, override
from unittest import TestCase as UnitTestCase
from unittest import TestResult, TestSuite, TextTestResult

from django.conf import settings
from django.core.cache import caches
from django.core.cache.backends import locmem
from django.core.cache.backends.locmem import LocMemCache
from django.db import connection, connections
from django.test.runner import DiscoverRunner, ParallelTestSuite

from tests.media import isolated_media, setup_worker_media
from tests.thread_connections import ThreadConnectionCheck, active_check

logger = logging.getLogger(__name__)


class CacheClearingTestResult(TextTestResult):
    """Clear in-process caches before test setup without interrupting the run."""

    @override
    def startTest(self, test: UnitTestCase) -> None:
        # Preserve configured instances, including mocked clear methods.
        backends = [backend for backend in caches.all() if isinstance(backend, LocMemCache)]
        known_stores = {id(vars(backend)["_cache"]) for backend in backends}
        # Django 5.2 shares named stores, expiry maps and locks process-wide.
        # Method-level overrides start after startTest(), so include inactive stores.
        stores = cast("dict[str, object]", vars(locmem)["_caches"])
        backends.extend(
            LocMemCache(name, {}) for name, store in tuple(stores.items()) if id(store) not in known_stores
        )
        for backend in backends:
            try:
                backend.clear()
            except Exception:
                logger.warning("⚠️ [Tests] Failed to clear LocMem cache before %s", test.id(), exc_info=True)
        super().startTest(test)


class ThreadConnectionTestResult(TextTestResult):
    """Publish the thread connection check's reports at each test boundary and at the end."""

    @override
    def startTest(self, test: UnitTestCase) -> None:
        if (check := active_check()) is not None:
            check.test_started(test)
        super().startTest(test)

    @override
    def stopTest(self, test: UnitTestCase) -> None:
        if (check := active_check()) is not None:
            check.test_stopped(self)
        super().stopTest(test)

    @override
    def stopTestRun(self) -> None:
        # Before the runner prints its summary, so these errors are listed with the others.
        if (check := active_check()) is not None:
            check.finish(self)
        super().stopTestRun()


class MediaIsolatedParallelSuite(ParallelTestSuite):
    """Give spawned workers the same disposable directory inherited by forked workers."""

    # Django passes this bound method's __func__ to the worker initializer.
    process_setup = setup_worker_media

    @property
    def process_setup_args(self) -> tuple[str]:
        return (str(settings.MEDIA_ROOT),)


class MediaIsolatedRunner(DiscoverRunner):
    """Isolate discovery, database setup and test writes, even when a run raises."""

    parallel_test_suite = MediaIsolatedParallelSuite

    @override
    def run_tests(self, test_labels: list[str], **kwargs: object) -> int:
        with isolated_media():
            return super().run_tests(test_labels, **kwargs)


class PostgreSQLSafeRunner(MediaIsolatedRunner):
    """DiscoverRunner with connection recovery and cache isolation for serial CI."""

    def get_resultclass(self) -> type[TextTestResult]:
        """Preserve Django's SQL-debugging and debugger result behavior."""
        result_class = super().get_resultclass()
        bases: tuple[type[TextTestResult], ...] = (ThreadConnectionTestResult, CacheClearingTestResult)
        if result_class is not None:
            bases = (*bases, result_class)
        return type("PostgreSQLSafeResult", bases, {})

    @override
    def run_tests(self, test_labels: list[str], **kwargs: object) -> int:
        """Install the thread connection check around the whole run, discovery and teardown too."""
        check: ThreadConnectionCheck | None = None
        if self.parallel > 1:
            logger.warning("⚠️ [Tests] The thread connection check is serial-only; skipped for --parallel")
        else:
            check = ThreadConnectionCheck()
            check.install()
        try:
            failures = super().run_tests(test_labels, **kwargs)
        finally:
            if check is not None:
                check.uninstall()
        if check is None:
            return failures
        # A thread that reported after the summary printed still fails the run.
        late = check.drain_late_reports()
        for message in late:
            logger.error("🔥 [Tests] Reported after the summary: %s", message)
        return failures + len(late)

    def setup_test_environment(self, **kwargs: Any) -> None:
        """Set up test environment with connection safety patches."""
        super().setup_test_environment(**kwargs)
        # Monkey-patch close_if_unusable_or_obsolete to be a no-op during tests.
        # This is the root cause of Django #30448 cascade failures.
        for alias in connections:
            conn = connections[alias]
            if conn.vendor == "postgresql":
                conn._original_close_if_unusable = conn.close_if_unusable_or_obsolete  # type: ignore[attr-defined]  # monkey-patch for Django #30448
                conn.close_if_unusable_or_obsolete = _safe_close_if_unusable.__get__(conn)

    def teardown_test_environment(self, **kwargs: Any) -> None:
        """Restore original connection behavior."""
        for alias in connections:
            conn = connections[alias]
            if hasattr(conn, '_original_close_if_unusable'):
                conn.close_if_unusable_or_obsolete = conn._original_close_if_unusable  # type: ignore[attr-defined]  # restore monkey-patch
                del conn._original_close_if_unusable  # type: ignore[attr-defined]  # cleanup monkey-patch attr
        super().teardown_test_environment(**kwargs)

    def run_suite(self, suite: TestSuite, **kwargs: Any) -> TestResult:
        """Ensure connection is alive before running the suite."""
        _ensure_healthy_connection()
        return super().run_suite(suite, **kwargs)


def _safe_close_if_unusable(conn: Any) -> None:
    """Replacement for close_if_unusable_or_obsolete that only closes truly broken connections."""
    if conn.connection is not None and not conn.is_usable():
        logger.debug("PostgreSQL connection unusable — closing for reconnect")
        conn.close()


def _ensure_healthy_connection() -> None:
    """Verify the DB connection is alive; reconnect if stale."""
    try:
        if connection.connection is not None and not connection.is_usable():
            logger.debug("PostgreSQL connection stale — reconnecting")
            connection.close()
        connection.ensure_connection()
    except Exception:
        with contextlib.suppress(Exception):
            connection.close()
        connection.ensure_connection()
