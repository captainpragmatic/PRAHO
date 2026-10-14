"""DRF throttles count on the shared counter store, never in the default cache (ADR-0030, ADR-0050).

DRF keeps a request history in the cache with a read, a trim and a write. On the default
DatabaseCache that read-modify-write loses concurrent hits, and the cache's own culling can
delete a live history, so a throttle stops throttling. The counter store counts atomically
and is not culled while a window is open.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from typing import Any
from unittest.mock import patch

from django.core.cache import cache
from django.core.management import call_command
from django.db import OperationalError, connections
from django.test import TestCase, TransactionTestCase, override_settings
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.test import APIRequestFactory
from rest_framework.views import APIView

from apps.api.exception_handlers import platform_exception_handler
from apps.common.models import Counter
from apps.common.performance.rate_limiting import (
    AuthThrottle,
    PortalHMACRateThrottle,
    RateLimitStoreUnavailable,
)
from tests.helpers.counter_concurrency import counter_database

WINDOW_START = 1_800_000_001.0  # one second into a minute window
CLOCK = "apps.common.performance.rate_limiting.time.time"

DATABASE_CACHE = {
    "default": {
        "BACKEND": "django.core.cache.backends.db.DatabaseCache",
        "LOCATION": "throttle_store_cache",
        # A cull with CULL_FREQUENCY 0 clears the whole table, as the production cache does under pressure.
        "OPTIONS": {"MAX_ENTRIES": 5, "CULL_FREQUENCY": 0},
        "TIMEOUT": 300,
    }
}


def _request(client_ip: str = "198.51.100.9") -> Request:
    return Request(APIRequestFactory().post("/api/probe/", REMOTE_ADDR=client_ip))


class _ProbeView(APIView):
    authentication_classes: list[Any] = []  # noqa: RUF012 -- DRF view attribute
    permission_classes: list[Any] = []  # noqa: RUF012 -- DRF view attribute
    throttle_classes = [AuthThrottle]  # noqa: RUF012 -- DRF view attribute

    def post(self, request: Request) -> Response:
        return Response({"ok": True})


@override_settings(RATE_LIMITING_ENABLED=True, CACHES=DATABASE_CACHE)
class ThrottleCountsOnTheCounterStoreTests(TestCase):
    def setUp(self) -> None:
        call_command("createcachetable", verbosity=0)
        cache.clear()
        self.addCleanup(cache.clear)
        clock = patch(CLOCK, return_value=WINDOW_START)
        self.clock = clock.start()
        self.addCleanup(clock.stop)

    def _allowed(self) -> bool:
        return AuthThrottle().allow_request(_request(), None)

    def test_a_cache_cull_cannot_erase_a_live_window(self) -> None:
        self.assertEqual([self._allowed() for _ in range(10)], [True] * 10)  # auth: 10/minute

        for index in range(10):  # unrelated entries push the cache past MAX_ENTRIES and cull it
            cache.set(f"filler-{index}", index, 300)
        self.assertIsNone(cache.get("filler-0"), "the cache must really have been culled")

        self.assertFalse(self._allowed(), "the 11th request in the window must still be refused")

    def test_the_wait_is_the_time_left_in_the_window(self) -> None:
        for _ in range(10):
            self.assertTrue(self._allowed())
        throttle = AuthThrottle()
        self.assertFalse(throttle.allow_request(_request(), None))
        self.assertEqual(throttle.wait(), 59)

    def test_the_budget_returns_in_the_next_window(self) -> None:
        for _ in range(11):
            self._allowed()
        self.assertFalse(self._allowed())
        self.clock.return_value = WINDOW_START + 60
        self.assertTrue(self._allowed())

    def test_clients_have_separate_budgets(self) -> None:
        for _ in range(11):
            AuthThrottle().allow_request(_request("198.51.100.1"), None)
        self.assertFalse(AuthThrottle().allow_request(_request("198.51.100.1"), None))
        self.assertTrue(AuthThrottle().allow_request(_request("198.51.100.2"), None))

    def test_a_request_without_a_throttle_key_is_not_counted(self) -> None:
        self.assertTrue(PortalHMACRateThrottle().allow_request(_request(), None))  # not HMAC-authenticated
        self.assertEqual(Counter.objects.count(), 0)

    @override_settings(RATE_LIMITING_ENABLED=False)
    def test_the_kill_switch_never_touches_the_store(self) -> None:
        for _ in range(20):
            self.assertTrue(self._allowed())
        self.assertEqual(Counter.objects.count(), 0)

    def test_a_refused_request_is_a_429_with_retry_after(self) -> None:
        view = _ProbeView.as_view()
        statuses = [view(APIRequestFactory().post("/api/probe/", REMOTE_ADDR="198.51.100.5")).status_code for _ in range(11)]
        self.assertEqual(statuses, [200] * 10 + [429])
        response = view(APIRequestFactory().post("/api/probe/", REMOTE_ADDR="198.51.100.5"))
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response["Retry-After"], "59")

    def test_an_unreachable_store_is_a_503_never_an_admission_or_a_429(self) -> None:
        with patch("apps.common.counters.increment", side_effect=OperationalError("store down")):
            with self.assertRaises(RateLimitStoreUnavailable):
                self._allowed()
            response = _ProbeView.as_view()(APIRequestFactory().post("/api/probe/", REMOTE_ADDR="198.51.100.5"))
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response["Retry-After"], "2")
        self.assertEqual(
            response.data,
            {"success": False, "error": "Platform temporarily unavailable", "status": 503},
        )

    def test_the_handler_answers_the_store_failure_like_the_hmac_middleware(self) -> None:
        response = platform_exception_handler(RateLimitStoreUnavailable(), {})
        assert response is not None
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response["Retry-After"], "2")


@override_settings(RATE_LIMITING_ENABLED=True, CACHES=DATABASE_CACHE)
class ThrottleConcurrencyTests(TransactionTestCase):
    def test_concurrent_requests_are_each_counted(self) -> None:
        barrier = Barrier(8)

        def burst() -> list[bool]:
            try:
                barrier.wait(timeout=30)
                return [AuthThrottle().allow_request(_request(), None) for _ in range(5)]
            finally:
                connections.close_all()

        with (
            counter_database(),
            patch(CLOCK, return_value=WINDOW_START),
            patch("apps.common.counters.randbelow", return_value=1),
        ):
            call_command("createcachetable", verbosity=0)
            cache.clear()
            try:
                with ThreadPoolExecutor(max_workers=8) as executor:
                    futures = [executor.submit(burst) for _ in range(8)]
                    results = [allowed for future in futures for allowed in future.result(timeout=120)]
            finally:
                cache.clear()

        self.assertEqual(len(results), 40)
        self.assertEqual(results.count(True), 10, "exactly the budget (10/minute) is admitted, never more")
