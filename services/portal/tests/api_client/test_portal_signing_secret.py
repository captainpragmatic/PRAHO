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
