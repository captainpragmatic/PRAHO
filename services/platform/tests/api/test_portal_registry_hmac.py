"""Per-portal HMAC credential registry (#277).

The platform used a single shared PLATFORM_API_SECRET to verify every Portal→Platform
request regardless of X-Portal-Id, so a shared-secret holder could rotate X-Portal-Id to
mint unlimited nonce/throttle buckets. These pin the registry behavior: enforce mode binds
the signature to the portal's own secret and rejects unregistered ids; audit mode surfaces
unregistered-but-legitimate portals without an outage; legacy mode is unchanged.

Signed through the real PortalServiceHMACMiddleware via the shared HMAC test helpers.
"""

from __future__ import annotations

import json
import time
import uuid

from django.core.exceptions import ImproperlyConfigured
from django.http import JsonResponse
from django.test import SimpleTestCase, override_settings
from django.urls import path
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, hmac_headers

from apps.common import portal_hmac

SHARED = "shared-platform-secret-value-01234567"
PORTAL_A_SECRET = "portal-a-distinct-secret-abcdefghij"
PORTAL_A_ROTATED = "portal-a-rotated-secret-zyxwvutsrq"

# A tiny always-200 view mounted under /api/ so a request that passes the middleware reaches
# a body, proving HMAC auth was actually used (not a generic 404/500 that would also pass a
# broken assertion).
_URLCONF = "tests.api.test_portal_registry_hmac"


def _ok_view(request):  # pragma: no cover - trivial
    return JsonResponse({"ok": True})


urlpatterns = [path("api/_registry_probe/", _ok_view)]

_PROBE = "/api/_registry_probe/"


def _signed(portal_id: str, secret: str, nonce: str | None = None) -> dict[str, str]:
    body = json.dumps({"timestamp": time.time()}).encode()
    return hmac_headers("POST", _PROBE, body, portal_id=portal_id, nonce=nonce, secret=secret), body


@override_settings(
    ROOT_URLCONF=_URLCONF,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    PLATFORM_API_SECRET=SHARED,
    PORTAL_HMAC_BYPASS=False,
    RATE_LIMITING_ENABLED=False,
)
class PortalRegistryEnforceModeTests(SimpleTestCase):
    def _post(self, portal_id: str, secret: str, nonce: str | None = None):
        portal_hmac._parse.cache_clear()
        headers, body = _signed(portal_id, secret, nonce)
        return self.client.post(_PROBE, body, content_type="application/json", **headers)

    @override_settings(PORTAL_HMAC_MODE="enforce", PORTAL_HMAC_CREDENTIALS=json.dumps({"portal-a": PORTAL_A_SECRET}))
    def test_registered_portal_with_its_own_secret_is_accepted(self):
        self.assertEqual(self._post("portal-a", PORTAL_A_SECRET).status_code, 200)

    @override_settings(PORTAL_HMAC_MODE="enforce", PORTAL_HMAC_CREDENTIALS=json.dumps({"portal-a": PORTAL_A_SECRET}))
    def test_registered_portal_signed_with_old_shared_secret_is_rejected(self):
        # THE core discriminator: master ignores portal_id and verifies with the shared
        # secret, so this passes (200) on master. Enforce mode must reject it (401).
        self.assertEqual(self._post("portal-a", SHARED).status_code, 401)

    @override_settings(PORTAL_HMAC_MODE="enforce", PORTAL_HMAC_CREDENTIALS=json.dumps({"portal-a": PORTAL_A_SECRET}))
    def test_unregistered_portal_id_is_rejected(self):
        # Signed with the shared secret (which master accepts) under an UNREGISTERED id.
        self.assertEqual(self._post("portal-b", SHARED).status_code, 401)

    @override_settings(
        PORTAL_HMAC_MODE="enforce",
        PORTAL_HMAC_CREDENTIALS=json.dumps({"portal-a": [PORTAL_A_ROTATED, PORTAL_A_SECRET]}),
    )
    def test_keyring_accepts_either_secret_but_not_a_third(self):
        self.assertEqual(self._post("portal-a", PORTAL_A_SECRET).status_code, 200)
        self.assertEqual(self._post("portal-a", PORTAL_A_ROTATED).status_code, 200)
        self.assertEqual(self._post("portal-a", SHARED).status_code, 401)

    @override_settings(
        PORTAL_HMAC_MODE="enforce",
        PORTAL_HMAC_CREDENTIALS=json.dumps({"portal-a": PORTAL_A_SECRET, "portal-b": PORTAL_A_ROTATED}),
    )
    def test_one_portals_secret_cannot_authenticate_as_another(self):
        # portal-b's secret used to claim portal-a → reject (cross-id isolation).
        self.assertEqual(self._post("portal-a", PORTAL_A_ROTATED).status_code, 401)

    @override_settings(PORTAL_HMAC_MODE="enforce", PORTAL_HMAC_CREDENTIALS=json.dumps({"portal-a": PORTAL_A_SECRET}))
    def test_failed_auth_does_not_burn_a_nonce(self):
        # A bad-secret request must not reserve the nonce; a later VALID request reusing that
        # same nonce must still succeed (proves reservation happens post-authentication).
        nonce = f"reuse-{uuid.uuid4().hex}"
        self.assertEqual(self._post("portal-a", SHARED, nonce=nonce).status_code, 401)
        self.assertEqual(self._post("portal-a", PORTAL_A_SECRET, nonce=nonce).status_code, 200)


@override_settings(
    ROOT_URLCONF=_URLCONF,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    PLATFORM_API_SECRET=SHARED,
    PORTAL_HMAC_BYPASS=False,
    RATE_LIMITING_ENABLED=False,
)
class PortalRegistryLegacyAndAuditTests(SimpleTestCase):
    def _post(self, portal_id, secret, nonce=None):
        portal_hmac._parse.cache_clear()
        headers, body = _signed(portal_id, secret, nonce)
        return self.client.post(_PROBE, body, content_type="application/json", **headers)

    @override_settings(PORTAL_HMAC_MODE="legacy", PORTAL_HMAC_CREDENTIALS=json.dumps({"portal-a": PORTAL_A_SECRET}))
    def test_legacy_ignores_the_registry(self):
        # Registry present with a DIFFERENT secret, but legacy verifies with the shared
        # secret and must accept it — proving legacy ignores the registry entirely.
        self.assertEqual(self._post("portal-a", SHARED).status_code, 200)

    @override_settings(PORTAL_HMAC_MODE="audit", PORTAL_HMAC_CREDENTIALS=json.dumps({"portal-a": PORTAL_A_SECRET}))
    def test_audit_accepts_registry_match_without_warning(self):
        with self.assertNoLogs("apps.common.middleware", level="WARNING"):
            self.assertEqual(self._post("portal-a", PORTAL_A_SECRET).status_code, 200)

    @override_settings(PORTAL_HMAC_MODE="audit", PORTAL_HMAC_CREDENTIALS=json.dumps({"portal-a": PORTAL_A_SECRET}))
    def test_audit_accepts_legacy_fallback_and_warns(self):
        # Unregistered id via the shared secret → accepted (no outage) AND a warning fires.
        with self.assertLogs("apps.common.middleware", level="WARNING") as logs:
            self.assertEqual(self._post("portal-unregistered", SHARED).status_code, 200)
        self.assertTrue(any("portal-unregistered" in m for m in logs.output))

    @override_settings(PORTAL_HMAC_MODE="audit", PORTAL_HMAC_CREDENTIALS=json.dumps({"portal-a": PORTAL_A_SECRET}))
    def test_audit_bad_under_both_is_401_without_fallback_warning(self):
        # A 401 logs a generic "Authentication failed" WARNING; what must NOT appear is the
        # audit "accepted via legacy fallback" line — an unauthenticated caller can't forge it.
        with self.assertLogs("apps.common.middleware", level="WARNING") as logs:
            self.assertEqual(self._post("portal-unregistered", "totally-wrong-secret-value-000000").status_code, 401)
        self.assertFalse(any("legacy shared-secret fallback" in m for m in logs.output))


class PortalHmacStartupValidationTests(SimpleTestCase):
    @override_settings(PORTAL_HMAC_MODE="bogus")
    def test_invalid_mode_rejected(self):
        with self.assertRaises(ImproperlyConfigured):
            portal_hmac.validate_at_startup()

    @override_settings(PORTAL_HMAC_MODE="enforce", PORTAL_HMAC_CREDENTIALS=None)
    def test_enforce_requires_non_empty_registry(self):
        with self.assertRaises(ImproperlyConfigured):
            portal_hmac.validate_at_startup()

    @override_settings(PORTAL_HMAC_MODE="audit", PORTAL_HMAC_CREDENTIALS="{not valid json")
    def test_invalid_json_fails_at_the_parsing_boundary(self):
        portal_hmac._parse.cache_clear()
        with self.assertRaises(ImproperlyConfigured):
            portal_hmac.validate_at_startup()

    @override_settings(PORTAL_HMAC_MODE="audit", PORTAL_HMAC_CREDENTIALS=json.dumps({"portal-a": ""}))
    def test_empty_secret_rejected(self):
        portal_hmac._parse.cache_clear()
        with self.assertRaises(ImproperlyConfigured):
            portal_hmac.validate_at_startup()

    @override_settings(PORTAL_HMAC_MODE="audit", PORTAL_HMAC_CREDENTIALS=json.dumps({"bad id!!": "x" * 32}))
    def test_invalid_portal_id_rejected(self):
        portal_hmac._parse.cache_clear()
        with self.assertRaises(ImproperlyConfigured):
            portal_hmac.validate_at_startup()

    @override_settings(PORTAL_HMAC_CREDENTIALS=json.dumps({"portal-a": "sekret-value-aaaaaaaaaaaaaaaaaaaa"}))
    def test_bare_string_secret_is_normalized_to_a_keyring(self):
        portal_hmac._parse.cache_clear()
        self.assertEqual(portal_hmac.resolve_secrets("portal-a"), ("sekret-value-aaaaaaaaaaaaaaaaaaaa",))
