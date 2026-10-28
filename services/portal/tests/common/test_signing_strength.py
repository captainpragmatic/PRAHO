"""A deployed Portal refuses a weak signing key, the platform's secret as its key, and a malformed id.

Follow-up to #751 (M18 and the PORTAL_ID check): the portal's outbound signing secret only had to be
non-empty, so a short key, or PLATFORM_API_SECRET reused as the per-portal key, passed; and PORTAL_ID was
taken as any string, so an inline comment in an EnvironmentFile became part of the id the platform never
matched.
"""

from __future__ import annotations

import pytest
from django.apps import apps
from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase, override_settings

from apps.common.signing import resolve_signing_secret

PLATFORM_SECRET = "p" * 40
STRONG = "s" * 40


@override_settings(
    PORTAL_HMAC_REQUIRE_ISOLATION=True, PLATFORM_API_SECRET=PLATFORM_SECRET, PORTAL_ID="portal-001", PORTAL_HMAC_SECRET=STRONG
)
class DeployedSigningKeyTests(SimpleTestCase):
    def test_a_key_shorter_than_32_characters_is_refused(self) -> None:
        with override_settings(PORTAL_HMAC_SECRET="x" * 31), pytest.raises(ImproperlyConfigured):
            resolve_signing_secret()

    def test_the_platform_api_secret_is_refused_as_the_portal_key(self) -> None:
        with override_settings(PORTAL_HMAC_SECRET=PLATFORM_SECRET), pytest.raises(ImproperlyConfigured):
            resolve_signing_secret()

    def test_a_strong_distinct_key_is_accepted(self) -> None:
        with override_settings(PORTAL_HMAC_SECRET=STRONG):
            assert resolve_signing_secret() == STRONG

    def test_a_malformed_portal_id_stops_startup(self) -> None:
        for portal_id in ("portal-001 # the main portal", "", "portal 001"):
            with (
                self.subTest(portal_id=portal_id),
                override_settings(PORTAL_HMAC_SECRET=STRONG, PORTAL_ID=portal_id),
                pytest.raises(ImproperlyConfigured),
            ):
                apps.get_app_config("common").ready()


class DevelopmentSigningKeyTests(SimpleTestCase):
    @override_settings(PORTAL_HMAC_REQUIRE_ISOLATION=False, PORTAL_HMAC_SECRET="dev")
    def test_a_development_portal_keeps_its_short_key(self) -> None:
        assert resolve_signing_secret() == "dev"
