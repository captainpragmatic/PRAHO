"""The Stripe SDK must give up before the web worker is killed.

The SDK defaults to an 80 second timeout per attempt and two automatic retries. During a
Stripe brownout a single payment call could hold a gunicorn worker for several minutes,
longer than the worker timeout, so the worker was killed mid-request with the outcome of
the money call unknown.
"""

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import patch

import stripe
from django.test import SimpleTestCase

from apps.billing.gateways.stripe_gateway import StripeGateway

ENTRYPOINT = Path(__file__).resolve().parents[4] / "deploy" / "platform" / "entrypoint.sh"


def _gunicorn_timeout_seconds() -> int:
    match = re.search(r"--timeout\s+(\d+)", ENTRYPOINT.read_text())
    assert match, f"no gunicorn --timeout in {ENTRYPOINT}"
    return int(match.group(1))


class StripeClientBudgetTests(SimpleTestCase):
    def setUp(self) -> None:
        for name in ("api_key", "api_version", "max_network_retries", "default_http_client"):
            self.addCleanup(setattr, stripe, name, getattr(stripe, name))

    def _initialise(self) -> None:
        with patch("apps.settings.services.SettingsService.get_setting", return_value="sk_test_x"):
            StripeGateway()

    def _budget(self) -> tuple[float, float, int]:
        client = stripe.default_http_client
        self.assertIsNotNone(client, "the gateway must install an explicit HTTP client")
        timeout = getattr(client, "_timeout", None)
        self.assertIsInstance(timeout, tuple, "connect and read timeouts must be set separately")
        connect, read = timeout
        return connect, read, stripe.max_network_retries

    def test_stripe_client_worst_case_stays_below_gunicorn_timeout(self) -> None:
        self._initialise()
        connect, read, retries = self._budget()

        attempts = retries + 1
        backoff = retries * stripe._http_client.HTTPClient.MAX_DELAY
        worst_case = attempts * (connect + read) + backoff

        self.assertLess(worst_case, _gunicorn_timeout_seconds())

    def test_one_sdk_retry_is_allowed_for_idempotency_keyed_writes(self) -> None:
        self._initialise()

        self.assertEqual(stripe.max_network_retries, 1)
