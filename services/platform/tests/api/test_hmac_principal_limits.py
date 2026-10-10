"""One customer cannot use up the Platform budget every customer of a portal shares (ADR-0030).

Requests go through the real HMAC middleware with rate limiting on. A signed request that passes
the middleware reaches no route here, so 404 means "admitted" and 429 means "refused".
"""

from __future__ import annotations

import json
import time
from unittest.mock import patch

from django.apps import apps
from django.core.exceptions import ImproperlyConfigured
from django.test import RequestFactory, TestCase, override_settings
from rest_framework.request import Request

from apps.api.users.views import SessionValidationThrottle
from apps.common.apps import _validate_hmac_rate_limits_at_startup
from apps.common.performance.rate_limiting import PortalHMACCreateUserThrottle
from apps.common.portal_hmac import portal_principal
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin, hmac_headers

PROBE = "/api/principal-probe/"
ADMITTED, REFUSED = 404, 429


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    PORTAL_HMAC_MODE="legacy",
    RATE_LIMITING_ENABLED=True,
    HMAC_RATE_LIMIT_WINDOW=60,
    HMAC_RATE_LIMIT_MAX_CALLS=6,
    HMAC_RATE_LIMIT_PRINCIPAL_PER_MINUTE=3,
    HMAC_RATE_LIMIT_PRINCIPAL_BURST=100,
    HMAC_RATE_LIMIT_ANONYMOUS_PER_MINUTE=4,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "principal-limits"}},
)
class PrincipalLimitTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        # Mid-window, so a run cannot straddle a minute boundary (signing reads the same clock).
        self.enterContext(patch("time.time", return_value=1_800_000_030.0))

    def _as(self, body: dict[str, object], **headers: str) -> int:
        return self.portal_post(PROBE, dict(body), **headers).status_code

    def test_a_customer_flooding_beyond_its_budget_leaves_others_theirs(self) -> None:
        flood = [self._as({"user_id": 1}) for _ in range(10)]
        self.assertEqual(flood, [ADMITTED] * 3 + [REFUSED] * 7)
        # Had customer 1's refused requests been charged to the shared ceiling (6), these would fail.
        self.assertEqual([self._as({"user_id": 2}) for _ in range(3)], [ADMITTED] * 3)

    def test_an_anonymous_flood_does_not_consume_a_customers_budget(self) -> None:
        flood = [self._as({}) for _ in range(10)]
        self.assertEqual(flood.count(ADMITTED), 4)  # the anonymous budget, not a customer's (3)
        self.assertEqual(self._as({"user_id": 2}), ADMITTED)

    def test_the_portal_wide_ceiling_still_trips(self) -> None:
        answers = [self._as({"user_id": user_id}) for user_id in range(1, 8)]
        self.assertEqual(answers, [ADMITTED] * 6 + [REFUSED])

    def test_an_unsigned_header_cannot_pick_the_bucket(self) -> None:
        for _ in range(4):
            self._as({"user_id": 1}, HTTP_X_USER_ID="2")
        self.assertEqual(self._as({"user_id": 2}), ADMITTED)  # customer 2's bucket was never charged

    def test_a_body_with_duplicate_keys_counts_as_anonymous(self) -> None:
        body = b'{"user_id": 1, "user_id": 2, "timestamp": %d}' % int(time.time())
        for _ in range(3):
            headers = hmac_headers("POST", PROBE, body, portal_id=self.portal_id)  # a fresh nonce each time
            self.client.post(PROBE, body, content_type="application/json", **headers)
        self._as({})  # the fourth anonymous request uses up the anonymous budget
        self.assertEqual(self._as({}), REFUSED)
        self.assertEqual(self._as({"user_id": 1}), ADMITTED)


LOGIN = "/api/users/login/"


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    PORTAL_HMAC_MODE="legacy",
    RATE_LIMITING_ENABLED=True,
    HMAC_RATE_LIMIT_WINDOW=60,
    HMAC_RATE_LIMIT_MAX_CALLS=100,
    HMAC_RATE_LIMIT_MAX_AUTH_CALLS=100,
    HMAC_RATE_LIMIT_PRINCIPAL_PER_MINUTE=50,
    HMAC_RATE_LIMIT_PRINCIPAL_BURST=2,
    HMAC_RATE_LIMIT_PRINCIPAL_BURST_WINDOW=10,
    HMAC_RATE_LIMIT_PRINCIPAL_AUTH_PER_MINUTE=2,
    HMAC_RATE_LIMIT_ANONYMOUS_AUTH_PER_MINUTE=3,
    HMAC_RATE_LIMIT_ANONYMOUS_PER_MINUTE=50,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "principal-burst"}},
)
class PrincipalBurstAndAuthTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        self.enterContext(patch("time.time", return_value=1_800_000_001.0))  # early in a 10 s window

    def test_a_customer_burst_is_limited_on_its_own(self) -> None:
        self.assertEqual(
            [self.portal_post(PROBE, {"user_id": 1}).status_code for _ in range(4)],
            [ADMITTED, ADMITTED, REFUSED, REFUSED],
        )
        self.assertEqual(self.portal_post(PROBE, {"user_id": 2}).status_code, ADMITTED)

    def test_login_attempts_from_one_address_leave_other_addresses_theirs(self) -> None:
        def login(client_ip: str) -> int:
            body = {"email": "nobody@example.ro", "password": "x", "client_ip": client_ip}
            return self.portal_post(LOGIN, body).status_code

        flood = [login("203.0.113.9") for _ in range(4)]
        self.assertEqual(flood[2:], [REFUSED, REFUSED])
        self.assertNotEqual(login("198.51.100.7"), REFUSED)

    def test_a_login_without_a_signed_address_shares_the_anonymous_auth_bucket(self) -> None:
        def login() -> int:
            return self.portal_post(LOGIN, {"email": "nobody@example.ro", "password": "x"}).status_code

        # The anonymous auth budget (3) is its own, separate from each signed address's (2).
        self.assertEqual([login() for _ in range(4)], [401, 401, 401, REFUSED])
        self.assertNotEqual(
            self.portal_post(
                LOGIN, {"email": "a@example.ro", "password": "x", "client_ip": "198.51.100.7"}
            ).status_code,
            REFUSED,
        )


class PortalPrincipalTests(TestCase):
    def test_principals(self) -> None:
        cases = {
            b'{"user_id": 7}': "user:7",
            b'{"user_id": "7"}': "user:7",
            b'{"client_ip": "203.0.113.9"}': "ip:203.0.113.9",
            b'{"user_id": 7, "client_ip": "203.0.113.9"}': "user:7",
            b"{}": "anonymous",
            b'{"user_id": true}': "anonymous",
            b'{"user_id": 0}': "anonymous",
            b'{"user_id": "7x"}': "anonymous",
            b'{"user_id": "%s"}' % (b"9" * 4301): "anonymous",  # past int()'s digit limit
            b'{"user_id": %s}' % (b"9" * 25): "anonymous",
            b'{"client_ip": "not-an-ip"}': "anonymous",
            b'{"client_ip": "fe80::1"}': "ip:fe80::1",
            # A scope id is free text, so "fe80::1%eth0:auth" would name another address's auth counter.
            b'{"client_ip": "fe80::1%eth0:auth"}': "anonymous",
            b'{"client_ip": "fe80::1%eth0"}': "anonymous",
            b'{"user_id": 1, "user_id": 2}': "anonymous",
            b"[1, 2]": "anonymous",
            b"not json": "anonymous",
            b"\xff\xfe": "anonymous",
        }
        for body, expected in cases.items():
            with self.subTest(body=body):
                self.assertEqual(portal_principal(body), expected)


class ThrottleIdentityTests(TestCase):
    def _request(self, principal: str | None) -> Request:
        request = RequestFactory().post("/api/x/", data=json.dumps({}), content_type="application/json")
        # What the HMAC middleware sets on a verified request.
        setattr(request, "_portal_authenticated", True)  # noqa: B010
        setattr(request, "_portal_id", "portal-1")  # noqa: B010
        if principal is not None:
            setattr(request, "_portal_principal", principal)  # noqa: B010
        return Request(request)

    def test_endpoint_throttles_count_each_principal_separately(self) -> None:
        # Session validation is the dangerous one: five refused revalidations log a portal user out.
        throttle = SessionValidationThrottle()
        first = throttle.get_cache_key(self._request("user:1"), None)
        second = throttle.get_cache_key(self._request("user:2"), None)
        self.assertNotEqual(first, second)
        self.assertEqual(
            throttle.get_cache_key(self._request(None), None), throttle.get_cache_key(self._request("anonymous"), None)
        )

    def test_user_creation_stays_limited_per_portal(self) -> None:
        throttle = PortalHMACCreateUserThrottle()
        self.assertEqual(
            throttle.get_cache_key(self._request("user:1"), None), throttle.get_cache_key(self._request("user:2"), None)
        )


class HMACLimitSettingsTests(TestCase):
    def test_a_principal_budget_at_or_above_its_ceiling_refuses_to_start(self) -> None:
        for overrides in (
            {"HMAC_RATE_LIMIT_PRINCIPAL_PER_MINUTE": 1000, "HMAC_RATE_LIMIT_MAX_CALLS": 1000},
            {"HMAC_RATE_LIMIT_PRINCIPAL_AUTH_PER_MINUTE": 700, "HMAC_RATE_LIMIT_MAX_AUTH_CALLS": 600},
            {"HMAC_RATE_LIMIT_ANONYMOUS_PER_MINUTE": 0},
            {"HMAC_RATE_LIMIT_ANONYMOUS_PER_MINUTE": 600, "HMAC_RATE_LIMIT_MAX_CALLS": 600},
            {"HMAC_RATE_LIMIT_MAX_CALLS": "1000"},
        ):
            with (
                self.subTest(overrides=overrides),
                override_settings(**overrides),
                self.assertRaises(ImproperlyConfigured),
            ):
                _validate_hmac_rate_limits_at_startup()

    def test_the_shipped_defaults_are_valid(self) -> None:
        _validate_hmac_rate_limits_at_startup()

    def test_the_check_runs_when_the_app_starts(self) -> None:
        # A zero window would otherwise only surface as a division error on signed requests.
        with override_settings(HMAC_RATE_LIMIT_WINDOW=0), self.assertRaises(ImproperlyConfigured):
            apps.get_app_config("common").ready()
