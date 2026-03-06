"""
Regression tests for portal security fixes.

Covers:
- Webhook authentication requires HMAC-SHA256 signature (#49)
- Portal IP extraction: get_safe_client_ip() behaviour (#51/#69)

Portal tests must NOT access the database (enforced by pytest -p no:django_db).
All test classes use SimpleTestCase or RequestFactory.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import cast

from django.http import HttpRequest
from django.test import RequestFactory, SimpleTestCase, override_settings

from apps.common.request_ip import get_safe_client_ip

# ===============================================================================
# WEBHOOK AUTHENTICATION TESTS (#49)
# ===============================================================================


_TEST_WEBHOOK_SECRET = "test-webhook-secret-do-not-use-in-prod"
_WEBHOOK_URL = "/orders/payment/webhook/"


def _build_valid_sig(body: bytes, ts: str, secret: str = _TEST_WEBHOOK_SECRET) -> str:
    """Compute a valid HMAC-SHA256 signature matching _verify_platform_webhook."""
    payload = ts.encode() + b"." + body
    return hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


class WebhookAuthenticationTests(SimpleTestCase):
    """Payment webhook must be rejected unless Platform's HMAC signature is valid."""

    def setUp(self) -> None:
        self.factory = RequestFactory()
        self.body = json.dumps({"order_id": "1", "status": "paid"}).encode()
        self.url = _WEBHOOK_URL

    @override_settings(PLATFORM_TO_PORTAL_WEBHOOK_SECRET=_TEST_WEBHOOK_SECRET)
    def test_webhook_rejected_without_signature(self) -> None:
        """POST without X-Platform-Signature header must return 401."""
        request = self.factory.post(
            self.url,
            data=self.body,
            content_type="application/json",
        )
        # No X-Platform-Signature header set
        from apps.orders.views import payment_success_webhook  # noqa: PLC0415

        response = payment_success_webhook(request)
        self.assertEqual(response.status_code, 401)

    @override_settings(PLATFORM_TO_PORTAL_WEBHOOK_SECRET=_TEST_WEBHOOK_SECRET)
    def test_webhook_rejected_with_invalid_signature(self) -> None:
        """POST with a wrong signature must return 401."""
        ts = str(int(time.time()))
        request = self.factory.post(
            self.url,
            data=self.body,
            content_type="application/json",
            HTTP_X_PLATFORM_SIGNATURE="0" * 64,
            HTTP_X_PLATFORM_TIMESTAMP=ts,
        )

        from apps.orders.views import payment_success_webhook  # noqa: PLC0415

        response = payment_success_webhook(request)
        self.assertEqual(response.status_code, 401)

    @override_settings(PLATFORM_TO_PORTAL_WEBHOOK_SECRET=_TEST_WEBHOOK_SECRET)
    def test_webhook_rejected_with_old_timestamp(self) -> None:
        """Valid signature but timestamp older than 300 s must return 401 (replay protection)."""
        stale_ts = str(int(time.time()) - 400)  # 400 seconds old — outside the 300 s window
        sig = _build_valid_sig(self.body, stale_ts)

        request = self.factory.post(
            self.url,
            data=self.body,
            content_type="application/json",
            HTTP_X_PLATFORM_SIGNATURE=sig,
            HTTP_X_PLATFORM_TIMESTAMP=stale_ts,
        )

        from apps.orders.views import payment_success_webhook  # noqa: PLC0415

        response = payment_success_webhook(request)
        self.assertEqual(response.status_code, 401)

    @override_settings(PLATFORM_TO_PORTAL_WEBHOOK_SECRET=_TEST_WEBHOOK_SECRET)
    def test_webhook_accepted_with_valid_signature(self) -> None:
        """Correct HMAC with a fresh timestamp must NOT return 401."""
        ts = str(int(time.time()))
        sig = _build_valid_sig(self.body, ts)

        request = self.factory.post(
            self.url,
            data=self.body,
            content_type="application/json",
            HTTP_X_PLATFORM_SIGNATURE=sig,
            HTTP_X_PLATFORM_TIMESTAMP=ts,
        )

        from apps.orders.views import payment_success_webhook  # noqa: PLC0415

        response = payment_success_webhook(request)
        self.assertNotEqual(
            response.status_code,
            401,
            msg=f"Webhook with valid signature returned {response.status_code}; expected non-401",
        )


# ===============================================================================
# WEBHOOK HARDENING TESTS (PR #76 follow-up)
# ===============================================================================


class WebhookHardeningTests(SimpleTestCase):
    """Extended webhook security tests: format validation, replay dedup, future timestamps."""

    def setUp(self) -> None:
        self.factory = RequestFactory()
        self.body = json.dumps({"order_id": "1", "status": "paid"}).encode()
        self.url = _WEBHOOK_URL

    def _make_webhook_request(
        self, body: bytes, ts: str, sig: str,
    ) -> HttpRequest:
        return self.factory.post(
            self.url,
            data=body,
            content_type="application/json",
            HTTP_X_PLATFORM_SIGNATURE=sig,
            HTTP_X_PLATFORM_TIMESTAMP=ts,
        )

    @override_settings(PLATFORM_TO_PORTAL_WEBHOOK_SECRET=_TEST_WEBHOOK_SECRET)
    def test_webhook_rejected_body_tampering(self) -> None:
        """Valid sig over original body + tampered body = 401."""
        ts = str(int(time.time()))
        sig = _build_valid_sig(self.body, ts)
        tampered_body = json.dumps({"order_id": "999", "status": "paid"}).encode()

        request = self._make_webhook_request(tampered_body, ts, sig)

        from apps.orders.views import payment_success_webhook  # noqa: PLC0415

        response = payment_success_webhook(request)
        self.assertEqual(response.status_code, 401)

    @override_settings(PLATFORM_TO_PORTAL_WEBHOOK_SECRET=_TEST_WEBHOOK_SECRET)
    def test_webhook_rejected_future_timestamp(self) -> None:
        """Timestamp 400s in the future must return 401 (preplay prevention)."""
        future_ts = str(int(time.time()) + 400)
        sig = _build_valid_sig(self.body, future_ts)

        request = self._make_webhook_request(self.body, future_ts, sig)

        from apps.orders.views import payment_success_webhook  # noqa: PLC0415

        response = payment_success_webhook(request)
        self.assertEqual(response.status_code, 401)

    @override_settings(PLATFORM_TO_PORTAL_WEBHOOK_SECRET="")
    def test_webhook_rejected_empty_secret(self) -> None:
        """Empty secret must return 401 (fail-secure)."""
        ts = str(int(time.time()))
        sig = _build_valid_sig(self.body, ts, secret="")

        request = self._make_webhook_request(self.body, ts, sig)

        from apps.orders.views import payment_success_webhook  # noqa: PLC0415

        response = payment_success_webhook(request)
        self.assertEqual(response.status_code, 401)

    @override_settings(PLATFORM_TO_PORTAL_WEBHOOK_SECRET=_TEST_WEBHOOK_SECRET)
    def test_webhook_rejected_missing_timestamp(self) -> None:
        """No X-Platform-Timestamp header must return 401."""
        request = self.factory.post(
            self.url,
            data=self.body,
            content_type="application/json",
            HTTP_X_PLATFORM_SIGNATURE="a" * 64,
        )

        from apps.orders.views import payment_success_webhook  # noqa: PLC0415

        response = payment_success_webhook(request)
        self.assertEqual(response.status_code, 401)

    @override_settings(PLATFORM_TO_PORTAL_WEBHOOK_SECRET=_TEST_WEBHOOK_SECRET)
    def test_webhook_replay_rejected(self) -> None:
        """Same valid request twice = second gets 401 (per-process dedup)."""
        from django.core.cache import cache as _cache  # noqa: PLC0415

        _cache.clear()

        ts = str(int(time.time()))
        sig = _build_valid_sig(self.body, ts)

        from apps.orders.views import payment_success_webhook  # noqa: PLC0415

        req1 = self._make_webhook_request(self.body, ts, sig)
        resp1 = payment_success_webhook(req1)
        self.assertNotEqual(resp1.status_code, 401, "First request should pass HMAC verification")

        req2 = self._make_webhook_request(self.body, ts, sig)
        resp2 = payment_success_webhook(req2)
        self.assertEqual(resp2.status_code, 401, "Replayed request should be rejected")

        _cache.clear()

    @override_settings(PLATFORM_TO_PORTAL_WEBHOOK_SECRET=_TEST_WEBHOOK_SECRET)
    def test_webhook_accepts_unicode_body(self) -> None:
        """Romanian chars in body with valid sig should not cause 401."""
        unicode_body = json.dumps({"order_id": "1", "status": "plătit"}).encode()
        ts = str(int(time.time()))
        sig = _build_valid_sig(unicode_body, ts)

        request = self._make_webhook_request(unicode_body, ts, sig)

        from apps.orders.views import payment_success_webhook  # noqa: PLC0415

        response = payment_success_webhook(request)
        self.assertNotEqual(response.status_code, 401)

    @override_settings(PLATFORM_TO_PORTAL_WEBHOOK_SECRET=_TEST_WEBHOOK_SECRET)
    def test_webhook_rejected_empty_body(self) -> None:
        """Empty body with valid sig returns 400 (no order_id)."""
        empty_body = b""
        ts = str(int(time.time()))
        sig = _build_valid_sig(empty_body, ts)

        request = self._make_webhook_request(empty_body, ts, sig)

        from apps.orders.views import payment_success_webhook  # noqa: PLC0415

        response = payment_success_webhook(request)
        # Empty body can't be parsed as JSON or has no order_id — expect 400 or 500
        self.assertIn(response.status_code, (400, 500))

    @override_settings(PLATFORM_TO_PORTAL_WEBHOOK_SECRET=_TEST_WEBHOOK_SECRET)
    def test_webhook_rejected_invalid_sig_format(self) -> None:
        """Non-hex or wrong-length sig must return 401 (format validation)."""
        ts = str(int(time.time()))
        invalid_sigs = [
            "too-short",
            "g" * 64,  # non-hex character
            "a" * 63,  # one char too short
            "a" * 65,  # one char too long
            "",
        ]

        from apps.orders.views import payment_success_webhook  # noqa: PLC0415

        for bad_sig in invalid_sigs:
            with self.subTest(sig=bad_sig[:20]):
                request = self._make_webhook_request(self.body, ts, bad_sig)
                response = payment_success_webhook(request)
                self.assertEqual(response.status_code, 401, f"Bad sig {bad_sig[:20]!r} should be rejected")


# ===============================================================================
# PORTAL IP EXTRACTION TESTS (#51/#69)
# ===============================================================================


class GetSafeClientIpTests(SimpleTestCase):
    """get_safe_client_ip must behave correctly across proxy trust configurations."""

    def _make_request(self, remote_addr: str = "1.2.3.4", **extra_meta: str) -> object:
        """Return a minimal HttpRequest with the given META values."""
        factory = RequestFactory()
        request = factory.get("/")
        request.META["REMOTE_ADDR"] = remote_addr
        for key, value in extra_meta.items():
            request.META[key] = value
        return request

    @override_settings(TRUSTED_PROXY_LIST=[])
    def test_get_safe_client_ip_uses_remote_addr_without_proxy_config(self) -> None:
        """With TRUSTED_PROXY_LIST=[], XFF header is ignored; REMOTE_ADDR is returned."""
        request = self._make_request(
            remote_addr="203.0.113.10",
            HTTP_X_FORWARDED_FOR="10.0.0.1, 192.168.1.1",
        )

        result = get_safe_client_ip(cast(HttpRequest, request))

        self.assertEqual(result, "203.0.113.10")

    @override_settings(TRUSTED_PROXY_LIST=["10.0.0.0/8"])
    def test_get_safe_client_ip_trusts_xff_from_trusted_proxy(self) -> None:
        """When REMOTE_ADDR is within TRUSTED_PROXY_LIST, X-Forwarded-For is trusted.

        The implementation uses its own CIDR validation (_is_trusted_proxy) and extracts
        the leftmost XFF entry when the direct connection comes from a trusted CIDR range.
        """
        # 10.0.0.1 falls inside 10.0.0.0/8, so XFF should be trusted
        request = self._make_request(
            remote_addr="10.0.0.1",
            HTTP_X_FORWARDED_FOR="203.0.113.99",
        )

        result = get_safe_client_ip(cast(HttpRequest, request))

        self.assertEqual(result, "203.0.113.99")

    @override_settings(TRUSTED_PROXY_LIST=[])
    def test_get_safe_client_ip_ignores_cf_ip_without_cf_ray(self) -> None:
        """CF-Connecting-IP must be ignored when HTTP_CF_RAY is absent.

        Without CF-Ray, the request did not pass through Cloudflare, so trusting
        CF-Connecting-IP would allow an attacker to spoof their IP.
        """
        request = self._make_request(
            remote_addr="203.0.113.20",
            HTTP_CF_CONNECTING_IP="1.2.3.4",
            # Deliberately NO HTTP_CF_RAY header
        )

        result = get_safe_client_ip(cast(HttpRequest, request))

        # Must return REMOTE_ADDR, not the spoofed CF-Connecting-IP
        self.assertEqual(result, "203.0.113.20")

    @override_settings(TRUSTED_PROXY_LIST=["0.0.0.0/0"])
    def test_get_safe_client_ip_ignores_cf_ip_without_cf_ray_even_with_proxy_list(self) -> None:
        """Even with a broad TRUSTED_PROXY_LIST, CF-Connecting-IP requires CF-Ray to be trusted."""
        request = self._make_request(
            remote_addr="10.0.0.1",
            HTTP_CF_CONNECTING_IP="5.5.5.5",
            # Still no HTTP_CF_RAY
        )

        result = get_safe_client_ip(cast(HttpRequest, request))

        self.assertNotEqual(
            result,
            "5.5.5.5",
            msg="CF-Connecting-IP must NOT be trusted when CF-Ray header is absent",
        )
