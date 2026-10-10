"""A configured minimum login duration hides how fast Platform answered.

Without padding, a wrong password that Platform rejects quickly is distinguishable from a slow
success. These tests drive the real padding in authenticate_customer with a fake clock, so the
outcome never depends on how busy the machine is.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from unittest.mock import Mock, patch

from django.test import SimpleTestCase, override_settings

from apps.api_client import services as api_services
from apps.api_client.services import PlatformAPIClient, PlatformAPIError

MIN_DURATION = 0.5
HEADERS = {
    "X-Portal-Id": "portal-001",
    "X-Signature": "a" * 64,
    "X-Nonce": "n" * 32,
    "X-Timestamp": "1700000000",
    "X-Body-Hash": "a" * 43 + "=",
    "Content-Type": "application/json",
    "Accept": "application/json",
}


class FakeClock:
    """perf_counter advances a little on every read, and sleep jumps it forward."""

    tick = 0.0001

    def __init__(self) -> None:
        self.now = 100.0
        self.sleeps: list[float] = []

    def perf_counter(self) -> float:
        self.now += self.tick
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


@override_settings(
    PLATFORM_API_BASE_URL="http://localhost:8700/api",
    PLATFORM_API_TIMEOUT=5,
    PORTAL_HMAC_SECRET="authenticate-customer-padding-secret",
    PORTAL_ID="portal-001",
)
class AuthenticateCustomerPaddingTests(SimpleTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.api_client = PlatformAPIClient()

    @contextmanager
    def platform_answers(
        self, status: int, payload: dict[str, object], minimum: float = MIN_DURATION
    ) -> Iterator[FakeClock]:
        response = Mock(status_code=status, headers={"Content-Type": "application/json"})
        response.json.return_value = payload
        response.text = ""
        clock = FakeClock()
        # Set in the test body: the portal conftest pins this setting per test before setUp runs
        with (
            override_settings(PLATFORM_API_AUTH_MIN_DURATION_SECONDS=minimum),
            patch("apps.api_client.services.portal_request", return_value=response),
            patch.object(self.api_client, "_generate_hmac_headers", return_value=HEADERS),
            patch("apps.api_client.services.time.perf_counter", side_effect=clock.perf_counter),
            patch("apps.api_client.services.time.sleep", side_effect=clock.sleep),
        ):
            yield clock

    def elapsed(self, clock: FakeClock, start: float) -> float:
        return clock.now - start

    def test_a_fast_rejection_and_a_fast_success_both_take_the_minimum(self) -> None:
        outcomes = {}
        for name, status, payload in (
            ("rejected", 401, {"error": "Invalid credentials"}),
            ("accepted", 200, {"success": True, "user": {"id": 7, "customer_id": 3}}),
        ):
            with self.subTest(outcome=name), self.platform_answers(status, payload) as clock:
                start = clock.now
                result = self.api_client.authenticate_customer("a@b.com", "pw")
                outcomes[name] = (result is not None, self.elapsed(clock, start), len(clock.sleeps))
        self.assertEqual(outcomes["rejected"][0], False)
        self.assertEqual(outcomes["accepted"][0], True)
        for name, (_valid, elapsed, sleeps) in outcomes.items():
            with self.subTest(outcome=name):
                # Padded to the minimum, overshooting by at most a few clock reads
                self.assertGreaterEqual(elapsed, MIN_DURATION)
                self.assertLess(elapsed, MIN_DURATION + 0.01)
                self.assertEqual(sleeps, 1)

    def test_an_outage_is_padded_too(self) -> None:
        with self.platform_answers(503, {"error": "unavailable"}) as clock:
            start = clock.now
            with self.assertRaises(PlatformAPIError):
                self.api_client.authenticate_customer("a@b.com", "pw")
        self.assertGreaterEqual(self.elapsed(clock, start), MIN_DURATION)

    def test_every_exit_is_padded(self) -> None:
        # A failure that leaves authenticate_customer by any path must still take the minimum,
        # or the path itself becomes a timing sign.
        exits = (
            ("platform refuses the signature", 401, {"error": "HMAC authentication failed"}, PlatformAPIError),
            ("throttled", 429, {"error": "Too many requests"}, PlatformAPIError),
            ("platform error", 500, {"error": "boom"}, PlatformAPIError),
        )
        for name, status, payload, raised in exits:
            with self.subTest(exit=name), self.platform_answers(status, payload) as clock:
                start = clock.now
                with self.assertRaises(raised):
                    self.api_client.authenticate_customer("a@b.com", "pw")
                self.assertGreaterEqual(self.elapsed(clock, start), MIN_DURATION)
        with self.platform_answers(200, {}) as clock:
            start = clock.now
            with patch("apps.api_client.services.portal_request", side_effect=RuntimeError("unexpected")), self.assertRaises(
                RuntimeError
            ):
                self.api_client.authenticate_customer("a@b.com", "pw")
            self.assertGreaterEqual(self.elapsed(clock, start), MIN_DURATION)

    def test_a_login_longer_than_the_floor_is_reported_once(self) -> None:
        api_services._login_floor_overrun_log_gate.last_logged_at = None
        with self.platform_answers(401, {"error": "Invalid credentials"}) as clock:
            clock.tick = 2 * MIN_DURATION  # every clock read jumps past the floor
            with self.assertLogs("apps.api_client.services", level="WARNING") as logs:
                self.api_client.authenticate_customer("a@b.com", "pw")
                self.api_client.authenticate_customer("b@c.com", "pw")
        overruns = [r for r in logs.records if "timing floor" in r.getMessage()]
        self.assertEqual(len(overruns), 1)
        self.assertNotIn("a@b.com", overruns[0].getMessage())
        self.assertEqual(clock.sleeps, [])  # already past the floor: nothing to pad

    def test_no_padding_when_no_minimum_is_configured(self) -> None:
        with self.platform_answers(401, {"error": "Invalid credentials"}, minimum=0) as clock:
            self.assertIsNone(self.api_client.authenticate_customer("a@b.com", "pw"))
        self.assertEqual(clock.sleeps, [])
