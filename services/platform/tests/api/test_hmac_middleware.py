import base64
import hashlib
import hmac
import json
import time
import urllib.parse
import uuid
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.http import HttpResponse
from django.test import RequestFactory, TestCase, override_settings

from apps.common import middleware as _middleware_module
from apps.common.middleware import PortalServiceHMACMiddleware, _is_auth_exempt
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin, sign_request

User = get_user_model()

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
        # Use a unique nonce — self.nonce may be consumed by earlier tests
        # that share the LocMemCache within this class.
        nonce = "valid-sig-test-unique-nonce-1234"
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
    def test_role_only_staff_session_bypass_allowed(self):
        """#271: a role-only staff user (staff_role set, is_staff=False) is admitted to the
        session-auth GET bypass for /api/customers/ (the ticket form's browser fetch)."""
        user = User.objects.create_user(email="support@test.com", password="x", staff_role="support")
        self.assertFalse(user.is_staff)
        self.assertTrue(user.is_staff_user)

        request = self.factory.get("/api/customers/")  # no HMAC headers → HMAC fails → bypass check
        request.user = user
        middleware = PortalServiceHMACMiddleware(lambda req: HttpResponse("ok", status=200))
        response = middleware(request)

        self.assertEqual(response.status_code, 200)

    @override_settings(PLATFORM_API_SECRET="unit-test-secret")
    def test_customer_user_session_bypass_denied(self):
        """A non-staff customer user gets no session bypass — HMAC remains required."""
        user = User.objects.create_user(email="cust@test.com", password="x")
        self.assertFalse(user.is_staff_user)

        request = self.factory.get("/api/customers/")
        request.user = user
        middleware = PortalServiceHMACMiddleware(lambda req: HttpResponse("ok", status=200))
        response = middleware(request)

        self.assertEqual(response.status_code, 401)

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
        RATE_LIMITING_ENABLED=True,
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

    @override_settings(PLATFORM_API_SECRET="unit-test-secret", HMAC_RATE_LIMIT_WINDOW=60, HMAC_RATE_LIMIT_MAX_CALLS=2)
    def test_rate_limit_returns_remaining_window_seconds(self):
        middleware = PortalServiceHMACMiddleware(lambda req: HttpResponse("ok", status=200))

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
        self.assertEqual(retry_after, 15)

    @override_settings(HMAC_RATE_LIMIT_MAX_AUTH_CALLS=2)
    def test_auth_paths_use_a_separate_bucket(self) -> None:
        middleware = PortalServiceHMACMiddleware(lambda req: HttpResponse("ok"))
        results = [middleware._rate_limited("portal-x", "10.0.0.1", path="/api/users/login/") for _ in range(3)]
        self.assertEqual(results[:2], [(False, 0), (False, 0)])
        self.assertTrue(results[2][0])
        self.assertGreaterEqual(results[2][1], 1)
        self.assertEqual(
            middleware._rate_limited("portal-x", "10.0.0.1", path="/api/billing/documents/"),
            (False, 0),
        )

    def test_password_reset_path_is_no_longer_exempt(self) -> None:
        self.assertFalse(_is_auth_exempt(RequestFactory().get("/api/users/password/reset/")))
        self.assertFalse(_is_auth_exempt(RequestFactory().get("/api/users/register/")))

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


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    PORTAL_HMAC_MODE="legacy",
    RATE_LIMITING_ENABLED=True,
    HMAC_RATE_LIMIT_MAX_AUTH_CALLS=2,
    HMAC_RATE_LIMIT_MAX_CALLS=3,
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "hmac-auth-bucket-routing-tests",
        }
    },
)
class HMACAuthBucketRoutingTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    def test_signed_auth_paths_share_a_bucket_without_charging_general_traffic(self) -> None:
        login = self.portal_post("/api/users/login/", {})
        reset = self.portal_post("/api/users/password/reset/", {})
        confirm = self.portal_post("/api/users/password/reset/confirm/", {})
        self.assertEqual(login.status_code, 400)
        self.assertEqual(reset.status_code, 400)
        self.assertEqual(reset["X-Portal-Auth"], "hmac-verified")
        self.assertEqual(confirm.status_code, 429)
        self.assertGreaterEqual(int(confirm["Retry-After"]), 1)

        responses = [self.portal_post("/api/users/user/", {}) for _ in range(4)]
        for response in responses[:3]:
            self.assertNotEqual(response.status_code, 429)
            self.assertEqual(response["X-Portal-Auth"], "hmac-verified")
        self.assertEqual(responses[3].status_code, 429)

    def test_unsigned_password_reset_is_rejected_before_the_view(self) -> None:
        response = self.client.post("/api/users/password/reset/", {}, content_type="application/json")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"error": "HMAC authentication failed"})


# The one response every rejection gets: nothing in it may say WHY a request failed.
_UNIFORM_REJECTION = (401, "application/json", {"error": "HMAC authentication failed"})
_FROZEN_NOW = 1_800_000_000


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    PORTAL_HMAC_MODE="legacy",
    RATE_LIMITING_ENABLED=False,
    CACHES=LOCMEM_TEST_CACHE,
)
class HMACRejectionUniformityTests(TestCase):
    """Deterministic checks of what an attacker can learn from a rejected request.

    These replace timing tests that measured a mocked Platform: here the real middleware decides,
    against a frozen clock, so each assertion holds or fails for the same reason on every run.
    """

    path = "/api/test/"
    portal_id = "portal-uniformity"
    body = json.dumps({"user_id": 1, "customer_id": 2}).encode()

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.view_calls = 0
        clock = patch("apps.common.middleware.time.time", return_value=float(_FROZEN_NOW))
        clock.start()
        self.addCleanup(clock.stop)

    def _view(self, request: object) -> HttpResponse:
        self.view_calls += 1
        return HttpResponse("ok", status=200)

    def _headers(
        self, *, timestamp: str, nonce: str | None = None, signed_body: bytes | None = None, **overrides: str
    ) -> dict[str, str]:
        """Headers signing ``signed_body`` (default: the body that is sent), so they can disagree."""
        nonce = nonce or f"nonce-{uuid.uuid4().hex}"
        signed_body = self.body if signed_body is None else signed_body
        headers = {
            "HTTP_X_PORTAL_ID": self.portal_id,
            "HTTP_X_NONCE": nonce,
            "HTTP_X_TIMESTAMP": timestamp,
            "HTTP_X_BODY_HASH": base64.b64encode(hashlib.sha256(signed_body).digest()).decode("ascii"),
        }
        headers.update({key: value for key, value in overrides.items() if key != "HTTP_X_SIGNATURE"})
        headers["HTTP_X_SIGNATURE"] = overrides.get(
            "HTTP_X_SIGNATURE",
            sign_request(
                "POST", self.path, signed_body, headers["HTTP_X_PORTAL_ID"], headers["HTTP_X_NONCE"], timestamp
            ),
        )
        return headers

    def _send(self, headers: dict[str, str], *, drop: str = "") -> HttpResponse:
        request = RequestFactory().post(self.path, data=self.body, content_type="application/json")
        request.META.update({key: value for key, value in headers.items() if key != drop})
        return PortalServiceHMACMiddleware(self._view)(request)

    @staticmethod
    def _shape(response: HttpResponse) -> tuple[int, str, object]:
        return response.status_code, response["Content-Type"], json.loads(response.content)

    def test_the_timestamp_window_is_exactly_300s_back_and_2s_forward(self) -> None:
        for offset, accepted in ((0, True), (-300, True), (2, True), (-301, False), (3, False)):
            with self.subTest(offset=offset):
                response = self._send(self._headers(timestamp=str(_FROZEN_NOW + offset)))
                if accepted:
                    self.assertEqual(response.status_code, 200)
                else:
                    self.assertEqual(self._shape(response), _UNIFORM_REJECTION)
        for malformed in ("invalid_timestamp", "1.8e9x", " "):
            with self.subTest(timestamp=malformed):
                self.assertEqual(self._shape(self._send(self._headers(timestamp=malformed))), _UNIFORM_REJECTION)
        self.assertEqual(self.view_calls, 3)

    def test_every_rejection_reason_gets_the_same_response(self) -> None:
        now = str(_FROZEN_NOW)
        valid = self._headers(timestamp=now)
        wrong_signature = valid["HTTP_X_SIGNATURE"][:-1] + ("0" if valid["HTTP_X_SIGNATURE"][-1] != "0" else "1")
        replayed = self._headers(timestamp=now)
        self.assertEqual(self._send(replayed).status_code, 200)
        cases = {
            **{
                f"missing {header}": (self._headers(timestamp=now), header)
                for header in (
                    "HTTP_X_PORTAL_ID",
                    "HTTP_X_NONCE",
                    "HTTP_X_TIMESTAMP",
                    "HTTP_X_BODY_HASH",
                    "HTTP_X_SIGNATURE",
                )
            },
            "empty timestamp": (self._headers(timestamp=""), ""),
            "bad portal id": (self._headers(timestamp=now, HTTP_X_PORTAL_ID="bad portal!"), ""),
            "bad nonce format": (self._headers(timestamp=now, nonce="short"), ""),
            "bad signature format": (self._headers(timestamp=now, HTTP_X_SIGNATURE="XYZ"), ""),
            # Validly signed, but for a different body than the one sent
            "body hash mismatch": (self._headers(timestamp=now, signed_body=b"{}"), ""),
            "wrong signature": (self._headers(timestamp=now, HTTP_X_SIGNATURE=wrong_signature), ""),
            "stale timestamp": (self._headers(timestamp=str(_FROZEN_NOW - 301)), ""),
            "future timestamp": (self._headers(timestamp=str(_FROZEN_NOW + 3)), ""),
            "malformed timestamp": (self._headers(timestamp="invalid_timestamp"), ""),
            "replayed nonce": (replayed, ""),
        }
        for reason, (headers, drop) in cases.items():
            with self.subTest(reason=reason):
                self.assertEqual(self._shape(self._send(headers, drop=drop)), _UNIFORM_REJECTION)
        self.assertEqual(self.view_calls, 1)

    def test_a_signature_wrong_at_any_position_is_rejected_the_same_way(self) -> None:
        for position in (0, 31, 63):
            with self.subTest(position=position):
                headers = self._headers(timestamp=str(_FROZEN_NOW))
                signature = headers["HTTP_X_SIGNATURE"]
                flipped = "0" if signature[position] != "0" else "1"
                headers["HTTP_X_SIGNATURE"] = signature[:position] + flipped + signature[position + 1 :]
                self.assertEqual(self._shape(self._send(headers)), _UNIFORM_REJECTION)
        self.assertEqual(self.view_calls, 0)

    def test_the_signature_is_compared_in_constant_time(self) -> None:
        # Constant time cannot be observed deterministically; prove the constant-time primitive
        # compares the submitted signature with the expected one, and that its answer decides.
        headers = self._headers(timestamp=str(_FROZEN_NOW))
        with patch("apps.common.middleware.hmac.compare_digest", wraps=hmac.compare_digest) as compare:
            self.assertEqual(self._send(headers).status_code, 200)
        expected = sign_request("POST", self.path, self.body, self.portal_id, headers["HTTP_X_NONCE"], str(_FROZEN_NOW))
        self.assertIn((headers["HTTP_X_SIGNATURE"], expected), [call.args for call in compare.call_args_list])

        refused = self._headers(timestamp=str(_FROZEN_NOW))
        with patch("apps.common.middleware.hmac.compare_digest", return_value=False):
            self.assertEqual(self._shape(self._send(refused)), _UNIFORM_REJECTION)
        self.assertEqual(self.view_calls, 1)

    def test_a_rejected_request_does_not_use_up_its_nonce(self) -> None:
        for reason, overrides in (
            ("stale timestamp", {"timestamp": str(_FROZEN_NOW - 301)}),
            ("wrong signature", {"timestamp": str(_FROZEN_NOW), "HTTP_X_SIGNATURE": "0" * 64}),
        ):
            with self.subTest(reason=reason):
                nonce = f"nonce-{uuid.uuid4().hex}"
                self.assertEqual(self._shape(self._send(self._headers(nonce=nonce, **overrides))), _UNIFORM_REJECTION)
                retry = self._headers(timestamp=str(_FROZEN_NOW), nonce=nonce)
                self.assertEqual(self._send(retry).status_code, 200)
                self.assertEqual(self._shape(self._send(retry)), _UNIFORM_REJECTION)
