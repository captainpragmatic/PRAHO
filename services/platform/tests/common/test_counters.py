"""Exercise the shared counter store through its public service API."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from io import StringIO
from threading import Barrier
from unittest.mock import patch

from django.core.checks import Tags, run_checks
from django.core.management import call_command
from django.db import IntegrityError, connection, connections, transaction
from django.test import TestCase, TransactionTestCase, override_settings
from django.test.utils import CaptureQueriesContext

from apps.common import counters
from apps.common.models import Counter


class CounterStoreTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.enterContext(override_settings(DEBUG=False))
        self.clock = self.enterContext(patch("apps.common.counters.time.time", return_value=10_000))
        self.cull_roll = self.enterContext(patch("apps.common.counters.randbelow", return_value=1))

    def test_increment_is_one_upsert_returning_its_own_count(self) -> None:
        for expected in (1, 2, 3):
            with CaptureQueriesContext(connection) as queries:
                actual = counters.increment("hits", 60)
            self.assertEqual(actual, expected)
            self.assertEqual(len(queries), 1)
            self.assertIn("ON CONFLICT", queries[0]["sql"].upper())
            self.assertIn("RETURNING", queries[0]["sql"].upper())

    def test_fixed_window_and_new_window_duration(self) -> None:
        self.assertEqual(counters.increment("window", 60), 1)
        self.clock.return_value = 10_059
        self.assertEqual(counters.increment("window", 900), 2)
        self.assertEqual(Counter.objects.get(key="window").expires_at, 10_060)
        self.clock.return_value = 10_060
        self.assertEqual(counters.peek("window"), 0)
        self.assertEqual(counters.increment("window", 20), 1)
        self.assertEqual(Counter.objects.get(key="window").expires_at, 10_080)
        self.clock.return_value = 10_080
        self.assertEqual(counters.increment("window", 7), 1)
        self.assertEqual(Counter.objects.get(key="window").expires_at, 10_087)

    @override_settings(
        CACHES={
            "default": {
                "BACKEND": "django.core.cache.backends.db.DatabaseCache",
                "LOCATION": "unused_counter_cache",
                "TIMEOUT": 1,
            }
        }
    )
    def test_database_cache_timeout_does_not_change_window(self) -> None:
        self.assertEqual(counters.increment("cache-independent", 60), 1)
        self.clock.return_value = 10_002
        self.assertEqual(counters.peek("cache-independent"), 1)
        self.assertEqual(counters.increment("cache-independent", 60), 2)
        self.clock.return_value = 10_060
        self.assertEqual(counters.peek("cache-independent"), 0)
        self.assertEqual(counters.increment("cache-independent", 15), 1)
        self.assertEqual(Counter.objects.get(key="cache-independent").expires_at, 10_075)

    def test_peek_missing_and_expired(self) -> None:
        self.assertEqual(counters.peek("missing"), 0)
        self.assertEqual(Counter.objects.count(), 0)
        counters.increment("present", 5)
        self.assertEqual(counters.peek("present"), 1)
        self.clock.return_value = 10_005
        self.assertEqual(counters.peek("present"), 0)

    def test_delta_seeds_and_adds(self) -> None:
        self.assertEqual(counters.increment("quota", 60, delta=5), 5)
        self.assertEqual(counters.increment("quota", 60), 6)
        self.assertEqual(counters.increment("quota", 60, delta=5), 11)
        self.clock.return_value = 10_060
        self.assertEqual(counters.increment("quota", 30, delta=5), 5)

    def test_release_floors_at_zero_without_changing_expiry(self) -> None:
        counters.release("missing")
        self.assertFalse(Counter.objects.exists())
        counters.increment("slots", 60, delta=2)
        for expected in (1, 0, 0):
            self.assertIsNone(counters.release("slots"))
            self.assertEqual(counters.peek("slots"), expected)
            self.assertEqual(Counter.objects.get(key="slots").expires_at, 10_060)
        self.assertEqual(counters.increment("slots", 600), 1)
        self.assertEqual(Counter.objects.get(key="slots").expires_at, 10_060)
        self.clock.return_value = 10_060
        counters.release("slots")
        self.assertEqual(Counter.objects.get(key="slots").count, 1)

    def test_reset_deletes_and_next_hit_starts_a_new_window(self) -> None:
        counters.increment("reset", 60)
        counters.reset("reset")
        counters.reset("missing")
        self.assertFalse(Counter.objects.exists())
        self.clock.return_value = 10_010
        self.assertEqual(counters.increment("reset", 5), 1)
        self.assertEqual(Counter.objects.get(key="reset").expires_at, 10_015)

    def test_keys_are_normalized_across_every_operation(self) -> None:
        keys = ("x" * 200, "x" * 201, "email\x00@example.test", "line\nbreak", "ș" * 201, "quote'%s")
        for key in keys:
            with self.subTest(key=key):
                stored = (
                    key
                    if len(key) <= 200 and key.isprintable()
                    else "h:" + hashlib.sha256(key.encode()).hexdigest()
                )
                self.assertEqual(counters.increment(key, 60), 1)
                self.assertTrue(Counter.objects.filter(key=stored).exists())
                self.assertEqual(counters.peek(key), 1)
                counters.release(key)
                self.assertEqual(counters.peek(key), 0)
                counters.reset(key)
                self.assertFalse(Counter.objects.filter(key=stored).exists())
                self.assertTrue(counters.claim(key, 60, "owner"))
                self.assertIsNone(counters.lookup(key))
                self.assertTrue(counters.release(key, "owner"))
                self.assertTrue(counters.claim(key, 60, "next"))
                self.assertTrue(counters.complete(key, "next", "order-1"))
                self.assertEqual(counters.lookup(key), "order-1")
                counters.reset(key)

    def test_claims_cull_expired_rows_too(self) -> None:
        # Request nonces claim a row per request; they must not rely on increments to be cleared.
        Counter.objects.create(key="stale", count=1, expires_at=10_000 - counters.CULL_GRACE_SECONDS - 1)
        with patch("apps.common.counters.randbelow", return_value=0):
            self.assertTrue(counters.claim("hmac_nonce:portal:abc", 330, "nonce"))
        self.assertFalse(Counter.objects.filter(key="stale").exists())

    def test_cull_counters_command_deletes_only_rows_past_grace(self) -> None:
        Counter.objects.bulk_create(
            [
                Counter(key="stale", count=1, expires_at=10_000 - counters.CULL_GRACE_SECONDS - 1),
                Counter(key="graced", count=1, expires_at=10_000 - 10),
                Counter(key="live", count=1, expires_at=10_100),
            ]
        )
        out = StringIO()
        call_command("cull_counters", "--batches", "3", stdout=out)
        self.assertEqual(set(Counter.objects.values_list("key", flat=True)), {"graced", "live"})
        self.assertIn("Deleted 1 expired counter rows.", out.getvalue())
        self.assertEqual(counters.cull_expired(batches=2), 0)

    def test_cull_is_one_bounded_delete_and_preserves_grace_and_live_claims(self) -> None:
        Counter.objects.bulk_create(
            [
                Counter(key=f"old:{index}", count=1, expires_at=10_000 - counters.CULL_GRACE_SECONDS - 1)
                for index in range(501)
            ]
        )
        Counter.objects.create(key="grace-boundary", count=1, expires_at=10_000 - counters.CULL_GRACE_SECONDS)
        Counter.objects.create(key="recent-expiry", count=1, expires_at=9999)
        self.assertTrue(counters.claim("live-claim", 60, "owner"))
        self.assertTrue(counters.claim("completed-claim", 60, "owner"))
        self.assertTrue(counters.complete("completed-claim", "owner", "order-1"))
        self.cull_roll.return_value = 0
        with CaptureQueriesContext(connection) as queries:
            self.assertEqual(counters.increment("live-counter", 60), 1)
        self.assertEqual(len(queries), 2)
        self.assertEqual(sum("DELETE FROM" in query["sql"].upper() for query in queries), 1)
        self.assertEqual(Counter.objects.filter(key__startswith="old:").count(), 1)
        self.assertTrue(Counter.objects.filter(key="grace-boundary").exists())
        self.assertTrue(Counter.objects.filter(key="recent-expiry").exists())
        self.assertFalse(counters.claim("live-claim", 60, "loser"))
        self.assertEqual(counters.lookup("completed-claim"), "order-1")

    def test_database_errors_propagate(self) -> None:
        with self.assertRaises(IntegrityError), transaction.atomic():
            counters.increment("invalid-count", 60, delta=-1)
        self.assertFalse(Counter.objects.filter(key="invalid-count").exists())

    def test_claim_loser_cannot_complete_or_release(self) -> None:
        self.assertIsNone(counters.lookup("order"))
        self.assertTrue(counters.claim("order", 60, "winner"))
        self.assertFalse(counters.claim("order", 600, "loser"))
        self.assertFalse(counters.complete("order", "loser", "bad-result"))
        self.assertFalse(counters.release("order", "loser"))
        counters.release("order")
        self.assertIsNone(counters.lookup("order"))
        self.assertEqual(Counter.objects.get(key="order").expires_at, 10_060)
        self.assertTrue(counters.complete("order", "winner", "loser"))
        self.assertEqual(counters.lookup("order"), "loser")
        self.assertFalse(counters.release("order", "loser"))
        self.assertFalse(counters.complete("order", "winner", "replacement"))
        self.assertFalse(counters.claim("order", 60, "another"))
        self.assertEqual(counters.lookup("order"), "loser")

    def test_failure_release_allows_immediate_retry(self) -> None:
        self.assertTrue(counters.claim("retry", 60, "first"))
        self.assertTrue(counters.release("retry", "first"))
        self.assertFalse(Counter.objects.filter(key="retry").exists())
        self.assertTrue(counters.claim("retry", 60, "second"))
        self.assertFalse(counters.release("retry", "first"))
        self.assertTrue(counters.complete("retry", "second", "order-2"))
        self.assertEqual(counters.lookup("retry"), "order-2")

    def test_expired_claim_reacquisition_rejects_previous_owner(self) -> None:
        self.assertTrue(counters.claim("lease", 60, "old"))
        self.clock.return_value = 10_060
        self.assertFalse(counters.complete("lease", "old", "too-late"))
        self.assertFalse(counters.release("lease", "old"))
        self.assertIsNone(counters.lookup("lease"))
        self.assertTrue(counters.claim("lease", 20, "new"))
        self.assertFalse(counters.complete("lease", "old", "stale"))
        self.assertFalse(counters.release("lease", "old"))
        self.assertTrue(counters.complete("lease", "new", "order-3"))
        self.assertEqual(counters.lookup("lease"), "order-3")
        self.clock.return_value = 10_080
        self.assertIsNone(counters.lookup("lease"))
        self.assertTrue(counters.claim("lease", 10, "last"))
        self.assertIsNone(counters.lookup("lease"))

    def test_completion_preserves_expiry_and_empty_result(self) -> None:
        self.assertTrue(counters.claim("empty-result", 60, "owner"))
        self.clock.return_value = 10_059
        self.assertTrue(counters.complete("empty-result", "owner", ""))
        self.assertEqual(counters.lookup("empty-result"), "")
        self.assertEqual(Counter.objects.get(key="empty-result").expires_at, 10_060)
        self.clock.return_value = 10_060
        self.assertIsNone(counters.lookup("empty-result"))

    def test_completion_can_retain_the_result_beyond_the_claim_lease(self) -> None:
        self.assertTrue(counters.claim("retained", 300, "owner"))
        self.clock.return_value = 10_100
        self.assertTrue(counters.complete("retained", "owner", "order-1", retain_seconds=86_400))
        self.assertEqual(Counter.objects.get(key="retained").expires_at, 96_500)
        self.clock.return_value = 10_300
        self.assertEqual(counters.lookup("retained"), "order-1")
        self.assertFalse(counters.claim("retained", 300, "intruder"))
        self.clock.return_value = 96_500
        self.assertIsNone(counters.lookup("retained"))

    def test_retention_never_shortens_the_lease_or_revives_a_lost_claim(self) -> None:
        self.assertTrue(counters.claim("short", 300, "owner"))
        self.assertTrue(counters.complete("short", "owner", "done", retain_seconds=10))
        self.assertEqual(Counter.objects.get(key="short").expires_at, 10_300)
        self.assertTrue(counters.claim("held", 60, "owner"))
        self.assertFalse(counters.complete("held", "other", "stolen", retain_seconds=86_400))
        self.assertEqual(Counter.objects.get(key="held").expires_at, 10_060)
        self.clock.return_value = 10_060
        self.assertFalse(counters.complete("held", "owner", "late", retain_seconds=86_400))
        self.assertEqual(Counter.objects.get(key="held").expires_at, 10_060)

    def test_claim_value_length_is_consistent_across_backends(self) -> None:
        owner = "t" * 255
        result = "r" * 255
        self.assertTrue(counters.claim("length", 60, owner))
        with self.assertRaises(ValueError):
            counters.complete("length", owner, result + "r")
        self.assertIsNone(counters.lookup("length"))
        self.assertTrue(counters.complete("length", owner, result))
        self.assertEqual(counters.lookup("length"), result)
        with self.assertRaises(ValueError):
            counters.claim("oversized", 60, owner + "t")
        self.assertFalse(Counter.objects.filter(key="oversized").exists())

    def test_sqlite_version_check_is_registered_and_safe_before_migration(self) -> None:
        if connection.vendor != "sqlite":
            self.assertNotIn("common.E001", {error.id for error in run_checks(tags=[Tags.database])})
            return
        for version, expected in (((3, 34, 1), True), ((3, 35, 0), False)):
            with (
                self.subTest(version=version),
                patch("sqlite3.dbapi2.sqlite_version_info", version),
                CaptureQueriesContext(connection) as queries,
            ):
                errors = run_checks(tags=[Tags.database])
            self.assertEqual("common.E001" in {error.id for error in errors}, expected)
            self.assertFalse(any("common_counters" in query["sql"] for query in queries))


def _run_workers[T](operation: Callable[[int], T], workers: int) -> list[T]:
    barrier = Barrier(workers)

    def run(index: int) -> T:
        try:
            barrier.wait(timeout=30)
            return operation(index)
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(run, index) for index in range(workers)]
        return [future.result(timeout=120) for future in futures]


class CounterClaimVisibilityTests(TransactionTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.enterContext(override_settings(DEBUG=False))
        self.enterContext(patch("apps.common.counters.time.time", return_value=10_000))

    def test_second_connection_finds_completed_result(self) -> None:
        self.assertTrue(counters.claim("shared-order", 60, "owner"))
        self.assertTrue(counters.complete("shared-order", "owner", "order-42"))

        def read_result(index: int) -> tuple[str | None, bool, bool]:
            result = counters.lookup("shared-order")
            acquired = counters.claim("shared-order", 60, f"worker-{index}")
            released = counters.release("shared-order", f"worker-{index}")
            return result, acquired, released

        self.assertEqual(_run_workers(read_result, 1), [("order-42", False, False)])


class CounterStoreConcurrencyTests(TransactionTestCase):
    def setUp(self) -> None:
        super().setUp()
        if connection.vendor == "sqlite" and connection.creation.is_in_memory_db(connection.settings_dict["NAME"]):
            self.skipTest("Concurrent SQLite writers require a file-backed test database.")
        self.enterContext(override_settings(DEBUG=False))
        self.enterContext(patch("apps.common.counters.time.time", return_value=10_000))
        self.enterContext(patch("apps.common.counters.randbelow", return_value=1))

    def test_eight_workers_count_every_hit(self) -> None:
        def hit(index: int) -> list[int]:
            return [counters.increment("concurrent", 60) for _ in range(50)]

        counts = [count for batch in _run_workers(hit, 8) for count in batch]
        self.assertEqual(sorted(counts), list(range(1, 401)))
        self.assertEqual(counters.peek("concurrent"), 400)

    def test_each_concurrent_hit_returns_its_own_admission_count(self) -> None:
        counts = _run_workers(lambda index: counters.increment("limit-one", 60), 2)
        self.assertEqual(sorted(counts), [1, 2])
        self.assertEqual(sum(count <= 1 for count in counts), 1)

    def test_two_concurrent_claimants_have_exactly_one_winner(self) -> None:
        winners = _run_workers(lambda index: counters.claim("race", 60, f"owner-{index}"), 2)
        self.assertEqual(sum(winners), 1)
        winner = winners.index(True)
        loser = 1 - winner
        self.assertFalse(counters.complete("race", f"owner-{loser}", "wrong"))
        self.assertFalse(counters.release("race", f"owner-{loser}"))
        self.assertTrue(counters.complete("race", f"owner-{winner}", "order-43"))
        self.assertEqual(counters.lookup("race"), "order-43")
