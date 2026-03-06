import base64
import hashlib
import hmac
import json
import os
import time
import urllib.parse
from unittest.mock import patch

from django.http import HttpResponse
from django.test import RequestFactory, TestCase, override_settings

from apps.common import middleware as _middleware_module
from apps.common.middleware import PortalServiceHMACMiddleware
from config.settings.test import LOCMEM_TEST_CACHE

LOCMEM_TEST_CACHE = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "hmac-middleware-tests",
    }
}


@override_settings(CACHES=LOCMEM_TEST_CACHE)
class PortalHMACTests(TestCase):
    def setUp(self) -> None:
        self.factory = RequestFactory()
        self.secret = "unit-test-secret"
        # Nonces must be >= HMAC_NONCE_MIN_LENGTH (32) chars.
        self.nonce = "a" * 32
        self.nonce_alt = "b" * 32

    def _sign(self, method: str, path: str, body: bytes, portal_id: str, nonce: str, timestamp: str) -> str:  # noqa: PLR0913
        # Server canonicalization: normalize path/query and content-type
        parsed = urllib.parse.urlsplit(path)
        pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        pairs.sort(key=lambda kv: (kv[0], kv[1]))
        normalized_query = urllib.parse.urlencode(pairs, doseq=True)
        normalized_path = parsed.path + ("?" + normalized_query if normalized_query else "")

        content_type = "application/json"
        body_hash = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")

        canonical = "\n".join(
            [
                method,
                normalized_path,
                content_type,
                body_hash,
                portal_id,
                nonce,
                timestamp,
            ]
        )
        return hmac.new(self.secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()

    @override_settings(PLATFORM_API_SECRET="unit-test-secret")
    def test_valid_signature_allows_request(self):
        ts = int(time.time())
        body = json.dumps({"user_id": 1, "customer_id": 2, "timestamp": ts}).encode()
        method = "POST"
        raw_path = "/api/test/?b=2&a=1"
        portal_id = "portal-xyz"
        nonce = self.nonce
        timestamp = str(ts)

        # Compute signature
        signature = self._sign(method, raw_path, body, portal_id, nonce, timestamp)

        # Build request
        request = self.factory.post(raw_path, data=body, content_type="application/json")
        request.META["HTTP_X_PORTAL_ID"] = portal_id
        request.META["HTTP_X_NONCE"] = nonce
        request.META["HTTP_X_TIMESTAMP"] = timestamp
        request.META["HTTP_X_BODY_HASH"] = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
        request.META["HTTP_X_SIGNATURE"] = signature

        middleware = PortalServiceHMACMiddleware(lambda req: HttpResponse("ok", status=200))
        response = middleware(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["X-Portal-Auth"], "hmac-verified")

    @override_settings(PLATFORM_API_SECRET="unit-test-secret")
    def test_invalid_signature_rejected(self):
        ts = int(time.time())
        body = json.dumps({"user_id": 1, "customer_id": 2, "timestamp": ts}).encode()
        raw_path = "/api/test/?x=1"
        portal_id = "portal-xyz"
        nonce = self.nonce_alt
        timestamp = str(ts)

        # Intentionally wrong signature
        signature = "0" * 64

        request = self.factory.post(raw_path, data=body, content_type="application/json")
        request.META["HTTP_X_PORTAL_ID"] = portal_id
        request.META["HTTP_X_NONCE"] = nonce
        request.META["HTTP_X_TIMESTAMP"] = timestamp
        request.META["HTTP_X_BODY_HASH"] = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
        request.META["HTTP_X_SIGNATURE"] = signature

        middleware = PortalServiceHMACMiddleware(lambda req: HttpResponse("ok", status=200))
        response = middleware(request)

        body_text = response.content.decode()
        self.assertEqual(response.status_code, 401)
        self.assertIn("HMAC authentication failed", body_text)
        # Should not leak specific verification reason
        self.assertNotIn("HMAC signature verification failed", body_text)

    @override_settings(PLATFORM_API_SECRET="unit-test-secret")
    def test_stale_timestamp_rejected(self):
        # Stale timestamp (unix epoch 222 = 1970) is outside the 5-minute window.
        # The body-timestamp cross-check was removed; the window check alone covers this.
        body = json.dumps({"user_id": 1, "customer_id": 2}).encode()
        method = "POST"
        raw_path = "/api/test/"
        portal_id = "portal-xyz"
        nonce = self.nonce
        header_ts = "222"  # unix timestamp 222 — far in the past
        signature = self._sign(method, raw_path, body, portal_id, nonce, header_ts)

        request = self.factory.post(raw_path, data=body, content_type="application/json")
        request.META["HTTP_X_PORTAL_ID"] = portal_id
        request.META["HTTP_X_NONCE"] = nonce
        request.META["HTTP_X_TIMESTAMP"] = header_ts
        request.META["HTTP_X_BODY_HASH"] = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
        request.META["HTTP_X_SIGNATURE"] = signature

        middleware = PortalServiceHMACMiddleware(lambda req: HttpResponse("ok", status=200))
        response = middleware(request)
        self.assertEqual(response.status_code, 401)
        self.assertIn("HMAC authentication failed", response.content.decode())

    @override_settings(PLATFORM_API_SECRET="unit-test-secret")
    def test_non_json_body_passes_hmac_validation(self):
        # Non-JSON body (e.g., form data) must pass HMAC if the signature is valid.
        # The body-timestamp cross-check was removed; body_hash alone covers integrity.
        ts = str(int(time.time()))
        body = b"field=value&other=data"
        method = "POST"
        raw_path = "/api/test/"
        portal_id = "portal-xyz"
        nonce = self.nonce

        import urllib.parse

        parsed = urllib.parse.urlsplit(raw_path)
        normalized_path = parsed.path
        content_type = "application/x-www-form-urlencoded"
        body_hash = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
        canonical = "\n".join([method, normalized_path, content_type, body_hash, portal_id, nonce, ts])
        signature = hmac.new(self.secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()

        request = self.factory.post(raw_path, data=body, content_type=content_type)
        request.META["HTTP_X_PORTAL_ID"] = portal_id
        request.META["HTTP_X_NONCE"] = nonce
        request.META["HTTP_X_TIMESTAMP"] = ts
        request.META["HTTP_X_BODY_HASH"] = body_hash
        request.META["HTTP_X_SIGNATURE"] = signature

        middleware_instance = PortalServiceHMACMiddleware(lambda req: HttpResponse("ok", status=200))
        response = middleware_instance(request)
        self.assertEqual(response.status_code, 200, f"Non-JSON body rejected: {response.content.decode()}")

    def test_legacy_auth_middleware_removed(self):
        """PortalServiceAuthMiddleware was removed in favour of PortalServiceHMACMiddleware.
        This test prevents accidental re-addition of the weaker shared-secret middleware."""
        self.assertFalse(
            hasattr(_middleware_module, "PortalServiceAuthMiddleware"),
            "PortalServiceAuthMiddleware must not exist — use PortalServiceHMACMiddleware instead.",
        )

    @override_settings(
        PLATFORM_API_SECRET="unit-test-secret",
        HMAC_RATE_LIMIT_WINDOW=60,
        HMAC_RATE_LIMIT_MAX_CALLS=2,
        RATELIMIT_ENABLED=True,
        CACHES=LOCMEM_TEST_CACHE,
    )
    def test_rate_limit_triggers(self):
        # Hit more than 2 times within window -> 429
        method = "POST"
        raw_path = "/api/test/"
        portal_id = "portal-rl"
        nonce_base = "test-rate-limit-nonce-unique-id-"  # 32 chars (meets HMAC_NONCE_MIN_LENGTH)
        ts = str(int(time.time()))

        def make_req(i: int):
            body = json.dumps({"user_id": 1, "customer_id": 2, "timestamp": int(ts)}).encode()
            signature = self._sign(method, raw_path, body, portal_id, f"{nonce_base}{i}", ts)
            req = self.factory.post(raw_path, data=body, content_type="application/json")
            req.META["HTTP_X_PORTAL_ID"] = portal_id
            req.META["HTTP_X_NONCE"] = f"{nonce_base}{i}"
            req.META["HTTP_X_TIMESTAMP"] = ts
            req.META["HTTP_X_BODY_HASH"] = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
            req.META["HTTP_X_SIGNATURE"] = signature
            return req

        middleware = PortalServiceHMACMiddleware(lambda req: HttpResponse("ok", status=200))
        r1 = middleware(make_req(1))
        r2 = middleware(make_req(2))
        r3 = middleware(make_req(3))
        self.assertEqual(r1.status_code, 200)
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(r3.status_code, 429)
        retry_after = int(r3["Retry-After"])
        self.assertGreaterEqual(retry_after, 1)
        self.assertLessEqual(retry_after, 60)
        payload = json.loads(r3.content.decode())
        self.assertEqual(payload["error"], "Too many requests")
        self.assertEqual(payload["status"], 429)
        self.assertEqual(payload["retry_after"], retry_after)

    @override_settings(PLATFORM_API_SECRET='unit-test-secret', HMAC_RATE_LIMIT_WINDOW=60, HMAC_RATE_LIMIT_MAX_CALLS=2)
    def test_rate_limit_returns_remaining_window_seconds(self):
        middleware = PortalServiceHMACMiddleware(lambda req: HttpResponse('ok', status=200))

        with patch("apps.common.middleware.time.time", return_value=1000.0):
            is_limited, retry_after = middleware._rate_limited("portal-rl", "127.0.0.1")
        self.assertFalse(is_limited)
        self.assertEqual(retry_after, 0)

        with patch("apps.common.middleware.time.time", return_value=1000.0):
            is_limited, retry_after = middleware._rate_limited("portal-rl", "127.0.0.1")
        self.assertFalse(is_limited)
        self.assertEqual(retry_after, 0)

        with patch("apps.common.middleware.time.time", return_value=1005.0):
            is_limited, retry_after = middleware._rate_limited("portal-rl", "127.0.0.1")
        self.assertTrue(is_limited)
        self.assertEqual(retry_after, 55)

    @override_settings(PLATFORM_API_SECRET="unit-test-secret", CACHES=LOCMEM_TEST_CACHE)
    def test_nonce_replay_rejected(self):
        # Same nonce should be rejected on second use
        method = "POST"
        raw_path = "/api/test/"
        portal_id = "portal-replay"
        nonce = self.nonce  # must be >= HMAC_NONCE_MIN_LENGTH (32) chars
        ts = str(int(time.time()))
        body = json.dumps({"user_id": 1, "customer_id": 2, "timestamp": int(ts)}).encode()
        signature = self._sign(method, raw_path, body, portal_id, nonce, ts)

        request1 = self.factory.post(raw_path, data=body, content_type="application/json")
        for meta in (
            ("HTTP_X_PORTAL_ID", portal_id),
            ("HTTP_X_NONCE", nonce),
            ("HTTP_X_TIMESTAMP", ts),
            ("HTTP_X_BODY_HASH", base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")),
            ("HTTP_X_SIGNATURE", signature),
        ):
            request1.META[meta[0]] = meta[1]

        request2 = self.factory.post(raw_path, data=body, content_type="application/json")
        for meta in (
            ("HTTP_X_PORTAL_ID", portal_id),
            ("HTTP_X_NONCE", nonce),
            ("HTTP_X_TIMESTAMP", ts),
            ("HTTP_X_BODY_HASH", base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")),
            ("HTTP_X_SIGNATURE", signature),
        ):
            request2.META[meta[0]] = meta[1]

        middleware = PortalServiceHMACMiddleware(lambda req: HttpResponse("ok", status=200))
        r1 = middleware(request1)
        r2 = middleware(request2)
        self.assertEqual(r1.status_code, 200)
        self.assertEqual(r2.status_code, 401)
