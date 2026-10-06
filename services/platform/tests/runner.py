"""
Custom test runner for PostgreSQL CI — works around Django #30448.

Django's close_if_unusable_or_obsolete() prematurely closes connections inside
atomic blocks when CONN_MAX_AGE=0, causing cascade failures on PostgreSQL.
TransactionTestCase tears down connections; subsequent TestCase classes inherit
the dead connection and fail en masse.

Two-layer defense:
1. ci.py sets CONN_MAX_AGE=None (prevents close_if_unusable_or_obsolete from closing)
2. This runner adds ensure_connection() recovery as a safety net

Only activated via TEST_RUNNER in ci.py (PG runs); SQLite tests are unaffected.
"""

from __future__ import annotations

import contextlib
import logging
from typing import Any, override
from unittest import TestCase as UnitTestCase
from unittest import TestResult, TestSuite, TextTestResult

from django.core.cache import caches
from django.core.cache.backends.locmem import LocMemCache
from django.db import connection, connections
from django.test.runner import DiscoverRunner

logger = logging.getLogger(__name__)


class CacheClearingTestResult(TextTestResult):
    """Clear in-process caches before test setup without interrupting the run."""

    @override
    def startTest(self, test: UnitTestCase) -> None:
        # Settings overrides reset handlers, but named LocMem stores survive.
        # Include uninitialized aliases so those stores are cleared as well.
        for backend in caches.all():
            if isinstance(backend, LocMemCache):
                try:
                    backend.clear()
                except Exception:
                    logger.warning("Failed to clear LocMem cache before %s", test.id(), exc_info=True)
        super().startTest(test)


class PostgreSQLSafeRunner(DiscoverRunner):
    """DiscoverRunner with connection recovery and cache isolation for serial CI."""

    def get_resultclass(self) -> type[TextTestResult]:
        """Preserve Django's SQL-debugging and debugger result behavior."""
        result_class = super().get_resultclass()
        if result_class is None:
            return CacheClearingTestResult
        return type("CacheClearingResult", (CacheClearingTestResult, result_class), {})

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
