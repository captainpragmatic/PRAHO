"""A Platform call has a total time budget, retries and all.

Under threaded workers a call that never ends holds a thread for good: gunicorn's `timeout` only
checks that the worker is alive, not how long a request takes. These pin the budget on the JSON and
binary paths with a fake clock, so nothing here sleeps.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any, ClassVar
from unittest.mock import MagicMock, patch

import requests
from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase, override_settings

from apps.api_client import services as api_services
from apps.api_client.services import PlatformAPIClient, PlatformAPIError
from config.settings.base import seconds_setting


class _FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _maintenance_503() -> MagicMock:
    response = MagicMock()
    response.status_code = 503
    response.headers = {"content-type": "application/json", "Retry-After": "2"}
    response.json.return_value = {"error": "maintenance"}
    response.content = json.dumps({"error": "maintenance"}).encode()
    return response


@override_settings(
    PLATFORM_API_BASE_URL="http://localhost:8700/api",
    PLATFORM_API_SECRET="test-secret",
    PORTAL_ID="portal-001",
    PLATFORM_API_TOTAL_BUDGET_SECONDS=10,
    PLATFORM_API_TIMEOUT=4,
    PLATFORM_API_READ_MAX_RETRIES=2,
)
class PlatformCallBudgetTests(SimpleTestCase):
    def setUp(self) -> None:
        self.clock = _FakeClock()
        patcher = patch.object(api_services, "_clock", self.clock)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.sent: list[tuple[float, Any]] = []  # (time sent, timeout given)

    def _platform(self, seconds_per_attempt: float, response: Any) -> Any:
        """A Platform that answers in `seconds_per_attempt`, or times out when the attempt's timeouts are shorter."""

        def send(**kwargs: Any) -> Any:
            self.sent.append((self.clock.now, kwargs["timeout"]))
            connect, read = kwargs["timeout"]
            if seconds_per_attempt > connect + read:
                self.clock.now += connect + read
                raise requests.exceptions.ReadTimeout("read timed out")
            self.clock.now += seconds_per_attempt
            return response

        return send

    def _sleep(self, seconds: float) -> None:
        self.clock.now += seconds

    def test_retries_stop_at_the_budget_and_keep_the_platforms_answer(self) -> None:
        # Platform answers in 4 s and asks for a 2 s wait. Attempt 1 ends at 4 s, the retry runs
        # from 6 s to 10 s, and a second retry would start after the 10 s budget has run out.
        with (
            patch("apps.common.outbound_http._send", side_effect=self._platform(4, _maintenance_503())),
            patch.object(api_services.time, "sleep", side_effect=self._sleep),
            self.assertRaises(PlatformAPIError) as raised,
        ):
            PlatformAPIClient()._make_request("GET", "/services/")

        self.assertEqual(len(self.sent), 1 + 1)
        self.assertLessEqual(self.clock.now - self.sent[0][0], 10)
        # The retry that did not fit answers with what Platform said, not a made-up timeout.
        self.assertEqual(raised.exception.status_code, 503)
        self.assertTrue(raised.exception.is_maintenance)

    def test_every_attempt_fits_what_is_left_of_the_budget(self) -> None:
        with (
            patch("apps.common.outbound_http._send", side_effect=self._platform(4, _maintenance_503())),
            patch.object(api_services.time, "sleep", side_effect=self._sleep),
            self.assertRaises(PlatformAPIError),
        ):
            PlatformAPIClient()._make_request("GET", "/services/")

        start = self.sent[0][0]
        for sent_at, timeout in self.sent:
            self.assertIsInstance(timeout, tuple)  # (connect, read): a single number bounds each phase on its own
            connect, read = timeout
            self.assertLessEqual(connect, 4)
            self.assertLessEqual(read, 4)
            self.assertLessEqual(connect + read, 10 - (sent_at - start) + 1e-9)

    def test_a_spent_budget_never_reaches_platform_and_reads_as_a_timeout(self) -> None:
        for budget in (0.3, 0, -1):
            with (
                self.subTest(budget=budget),
                override_settings(PLATFORM_API_TOTAL_BUDGET_SECONDS=budget),
                patch("apps.common.outbound_http._send") as send,
                self.assertRaises(PlatformAPIError) as raised,
            ):
                PlatformAPIClient()._make_request("GET", "/services/")
            send.assert_not_called()
            self.assertTrue(raised.exception.is_unavailable)
            self.assertIsNone(raised.exception.status_code)

    def test_a_body_that_keeps_trickling_in_stops_at_the_budget(self) -> None:
        # Each chunk arrives within the read timeout, so only the deadline can stop it.
        clock = self.clock

        class TricklingResponse:
            status_code = 200
            headers: ClassVar[dict[str, str]] = {}
            _content = False  # requests' marker for a body still on the wire
            closed = False

            def iter_content(self, chunk_size: int) -> Iterator[bytes]:
                for _ in range(100):
                    clock.now += 3
                    yield b"x"

            def close(self) -> None:
                self.closed = True

        for call in ("_make_request", "_make_binary_request"):
            trickling = TricklingResponse()
            with (
                self.subTest(call=call),
                patch("apps.common.outbound_http._send", side_effect=self._platform(0, trickling)),
                self.assertRaises(PlatformAPIError) as raised,
            ):
                started = self.clock.now
                getattr(PlatformAPIClient(), call)("GET", "/billing/invoices/1/pdf/")
            self.assertTrue(raised.exception.is_unavailable)
            self.assertLessEqual(self.clock.now - started, 10 + 3)  # the budget, plus at most one wait
            self.assertTrue(trickling.closed)

    def test_binary_calls_are_bounded_too(self) -> None:
        pdf = MagicMock(status_code=200, content=b"%PDF-1.7", headers={"content-type": "application/pdf"})
        with override_settings(PLATFORM_API_TIMEOUT=30), patch(
            "apps.common.outbound_http._send", side_effect=self._platform(0, pdf)
        ):
            client = PlatformAPIClient()
            client._make_binary_request("GET", "/billing/invoices/1/pdf/")
            client._make_binary_request_with_headers("GET", "/billing/invoices/1/pdf/")

        for _sent_at, (connect, read) in self.sent:
            self.assertLessEqual(connect + read, 10)

    def test_settings_changed_after_the_client_was_built_still_apply(self) -> None:
        client = PlatformAPIClient()  # the module singleton is built once, at import
        with override_settings(PLATFORM_API_TIMEOUT=2), patch(
            "apps.common.outbound_http._send", side_effect=self._platform(0, MagicMock(status_code=200, headers={}, json=lambda: {"success": True}))
        ):
            client._make_request("GET", "/services/")
        self.assertEqual(self.sent[0][1], (2, 2))


class PlatformCallSettingsTests(SimpleTestCase):
    def test_unset_or_empty_means_the_default(self) -> None:
        for raw in (None, "", "  "):
            with self.subTest(raw=raw):
                self.assertEqual(seconds_setting("X", raw, 45.0, minimum=5, maximum=45), 45.0)

    def test_a_valid_value_is_used(self) -> None:
        for raw, value in (("5", 5.0), ("20.5", 20.5), ("45", 45.0)):
            with self.subTest(raw=raw):
                self.assertEqual(seconds_setting("X", raw, 45.0, minimum=5, maximum=45), value)

    def test_values_outside_the_range_refuse_to_start(self) -> None:
        for raw in ("abc", "0", "4.9", "45.1", "-1", "nan", "inf"):
            with self.subTest(raw=raw), self.assertRaises(ImproperlyConfigured):
                seconds_setting("X", raw, 45.0, minimum=5, maximum=45)

    def test_a_default_outside_the_range_refuses_to_start_too(self) -> None:
        # e.g. PLATFORM_API_TIMEOUT left at its 30 s default under a 5 s budget.
        with self.assertRaises(ImproperlyConfigured):
            seconds_setting("PLATFORM_API_TIMEOUT", None, 30.0, minimum=1, maximum=5)

    def test_the_middleware_takes_its_lease_for_that_long(self) -> None:
        from django.core.cache import cache  # noqa: PLC0415

        from apps.users.middleware import PortalAuthenticationMiddleware  # noqa: PLC0415

        middleware = PortalAuthenticationMiddleware(lambda request: None)
        with patch.object(cache, "add", return_value=True) as add:
            middleware._should_revalidate_async("session-key")
        self.assertEqual(add.call_args.kwargs["timeout"], middleware._validation_lease_seconds())

    def test_the_validation_lease_outlasts_a_whole_platform_call(self) -> None:
        from apps.users.middleware import PortalAuthenticationMiddleware  # noqa: PLC0415

        # A call ends within its budget plus at most one read wait.
        with override_settings(PLATFORM_API_TOTAL_BUDGET_SECONDS=45, PLATFORM_API_TIMEOUT=30):
            lease = PortalAuthenticationMiddleware(lambda request: None)._validation_lease_seconds()
        self.assertGreater(lease, 45 + 30)
