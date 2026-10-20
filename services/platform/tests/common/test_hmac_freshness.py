"""Freshness must still hold after blocking authentication work."""

import io
from unittest.mock import patch

from django.http import HttpResponse
from django.test import RequestFactory, TestCase, override_settings

from apps.common import counters
from apps.common.middleware import PortalServiceHMACMiddleware
from tests.helpers.hmac import HMAC_TEST_SECRET, hmac_headers


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, PORTAL_HMAC_MODE="legacy")
class HMACFreshnessTests(TestCase):
    def setUp(self) -> None:
        self.now = 100_000
        self.middleware = PortalServiceHMACMiddleware(lambda request: HttpResponse("ok"))
        self.clock = patch("time.time", side_effect=lambda: self.now)
        self.clock.start()
        self.addCleanup(self.clock.stop)

    def request(self):
        body = b'{"timestamp":100000}'
        headers = hmac_headers(
            "POST",
            "/api/users/password-reset/",
            body,
            nonce="freshness-test-nonce-0123456789abcdef",
            timestamp="100000",
        )
        return RequestFactory().post(
            "/api/users/password-reset/",
            body,
            content_type="application/json",
            **headers,
        )

    def test_replay_with_body_delay_past_nonce_expiry_is_rejected(self) -> None:
        self.assertTrue(self.middleware._validate_hmac_signature(self.request())[0])
        self.now += 300
        request = self.request()
        clock_owner = self

        class DelayedBody(io.BytesIO):
            def read(self, *args):
                clock_owner.now = 100_400
                return super().read(*args)

        request._stream = DelayedBody(b'{"timestamp":100000}')
        self.assertFalse(self.middleware._validate_hmac_signature(request)[0])

    def test_timestamp_expiring_while_claiming_nonce_is_rejected(self) -> None:
        claim = counters.claim

        def delayed_claim(*args, **kwargs):
            self.now += 301
            return claim(*args, **kwargs)

        with patch("apps.common.middleware.counters.claim", side_effect=delayed_claim):
            self.assertFalse(self.middleware._validate_hmac_signature(self.request())[0])

    def test_replay_boundaries_remain_rejected(self) -> None:
        self.assertTrue(self.middleware._validate_hmac_signature(self.request())[0])
        for age in (300, 301, 302, 400):
            with self.subTest(age=age):
                self.now = 100_000 + age
                self.assertFalse(self.middleware._validate_hmac_signature(self.request())[0])
