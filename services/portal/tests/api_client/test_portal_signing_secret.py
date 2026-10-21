"""#277: the portal signs Platform requests with its per-portal secret when provisioned.

A fresh PlatformAPIClient() must be built under each override — the module-level singleton
binds its secret in __init__, so override_settings can't reach an already-constructed client.
"""

from __future__ import annotations

from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase, override_settings

from apps.api_client.services import PlatformAPIClient, _resolve_portal_signing_secret

SHARED = "shared-platform-secret-value-01234567"
PER_PORTAL = "this-portals-own-secret-abcdefghij"


@override_settings(PLATFORM_API_SECRET=SHARED)
class PortalSigningSecretTests(SimpleTestCase):
    @override_settings(PORTAL_HMAC_REQUIRE_ISOLATION=True, PORTAL_HMAC_SECRET=None)
    def test_deployed_portal_refuses_shared_secret_fallback(self):
        with self.assertRaises(ImproperlyConfigured):
            _resolve_portal_signing_secret()

    @override_settings(PORTAL_HMAC_SECRET=None)
    def test_development_fallback_must_be_a_real_secret(self):
        for secret in (None, "", "   ", 42):
            with (
                self.subTest(secret=secret),
                override_settings(PLATFORM_API_SECRET=secret),
                self.assertRaises(ImproperlyConfigured),
            ):
                _resolve_portal_signing_secret()

    @override_settings(PORTAL_HMAC_SECRET=PER_PORTAL)
    def test_signing_refuses_corrupted_cached_credentials(self):
        client = PlatformAPIClient()
        client.portal_secret = ""
        with self.assertRaises(ImproperlyConfigured):
            client._generate_hmac_headers("POST", "/api/x/", b"{}")

    def test_falls_back_to_shared_secret_when_per_portal_absent(self):
        with override_settings(PORTAL_HMAC_SECRET=None):
            self.assertEqual(_resolve_portal_signing_secret(), SHARED)
            self.assertEqual(PlatformAPIClient().portal_secret, SHARED)

    def test_uses_per_portal_secret_when_set(self):
        with override_settings(PORTAL_HMAC_SECRET=PER_PORTAL):
            self.assertEqual(_resolve_portal_signing_secret(), PER_PORTAL)
            self.assertEqual(PlatformAPIClient().portal_secret, PER_PORTAL)

    def test_explicitly_empty_per_portal_secret_raises(self):
        with override_settings(PORTAL_HMAC_SECRET=""), self.assertRaises(ImproperlyConfigured):
            _resolve_portal_signing_secret()

    def test_per_portal_secret_actually_changes_the_generated_signature(self):
        # Prove the resolved secret flows into signing, not just into an attribute: the same
        # request signed under two different PORTAL_HMAC_SECRETs must produce different sigs.
        body = b'{"user_id": 1}'
        with override_settings(PORTAL_HMAC_SECRET=PER_PORTAL):
            sig_per_portal = PlatformAPIClient()._generate_hmac_headers(
                "POST", "/api/x/", body, fixed_timestamp="1700000000"
            )["X-Signature"]
        with override_settings(PORTAL_HMAC_SECRET=None):  # shared
            sig_shared = PlatformAPIClient()._generate_hmac_headers(
                "POST", "/api/x/", body, fixed_timestamp="1700000000"
            )["X-Signature"]
        self.assertNotEqual(sig_per_portal, sig_shared)
