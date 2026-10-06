"""A bare API token can inspect and revoke itself, and reach nothing else (#569).

`POST /api/users/token/` was public, but `token/me/` and `token/revoke/` sat behind the
inter-service HMAC gate, so a token holder could mint a key and then neither check nor
revoke it. Both now answer a bare token. Business routes still require the signature.

`config/settings/test.py` strips `PortalServiceHMACMiddleware`, so these tests add it back:
without it, every assertion here would pass on master and prove nothing.
"""

from __future__ import annotations

from unittest.mock import patch

from django.conf import settings
from django.core.cache import cache
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.api.core.throttling import BurstAPIThrottle
from apps.audit.models import AuditEvent
from apps.users.models import APIToken, User

HMAC_REJECTION = {"error": "HMAC authentication failed"}
WITH_HMAC_GATE = [*settings.MIDDLEWARE, "apps.common.middleware.PortalServiceHMACMiddleware"]
TOKEN_ME = "/api/users/token/me/"
TOKEN_REVOKE = "/api/users/token/revoke/"


def _make_token(user: User) -> tuple[APIToken, str]:
    raw_key = APIToken.generate_key()
    token = APIToken.objects.create(
        user=user, key_hash=APIToken.hash_key(raw_key), key_prefix=raw_key[:8], name="lifecycle"
    )
    return token, raw_key


class _BareTokenCase(TestCase):
    def setUp(self) -> None:
        self.client = APIClient()
        self.user = User.objects.create_user(email="bare-token@example.com", password="Bare-token-pass123!")
        self.token, self.raw_key = _make_token(self.user)

    def authorize(self) -> None:
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.raw_key}")


@override_settings(MIDDLEWARE=WITH_HMAC_GATE)
class TokenLifecycleIsPublicTests(_BareTokenCase):
    def test_a_bare_token_can_read_itself(self) -> None:
        """FAILS on master: the HMAC gate answers before the view."""
        self.authorize()

        response = self.client.get(TOKEN_ME)

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["key_prefix"], self.token.key_prefix)

    def test_a_bare_token_can_revoke_itself_and_the_revocation_is_audited(self) -> None:
        """FAILS on master. Revoking deletes the token, which the APIToken pre_delete signal audits."""
        self.authorize()

        response = self.client.delete(TOKEN_REVOKE)

        self.assertEqual(response.status_code, 200, response.content)
        self.assertFalse(APIToken.objects.filter(pk=self.token.pk).exists())
        self.assertTrue(AuditEvent.objects.filter(action="api_token_deleted").exists())
        self.assertEqual(self.client.get(TOKEN_ME).status_code, 401)

    def test_no_token_is_refused_by_authentication_not_by_the_gate(self) -> None:
        """FAILS on master: the refusal came from the HMAC gate, not from token authentication."""
        response = self.client.get(TOKEN_ME)

        self.assertEqual(response.status_code, 401)
        self.assertNotEqual(response.json(), HMAC_REJECTION)

    def test_a_bare_token_still_cannot_reach_a_business_route(self) -> None:
        """Guard: the boundary that must not move. Business views stay behind the signature."""
        self.authorize()

        response = self.client.get("/api/customers/search/")

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), HMAC_REJECTION)


@override_settings(
    MIDDLEWARE=WITH_HMAC_GATE,
    RATE_LIMITING_ENABLED=True,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "token-lifecycle"}},
)
class TokenLifecycleThrottleTests(_BareTokenCase):
    """Test settings turn rate limiting off and use DummyCache; both are overridden here."""

    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)

    @patch.object(BurstAPIThrottle, "rate", "2/min", create=True)
    def test_token_reads_are_throttled_per_user(self) -> None:
        """FAILS on master: every request stops at the HMAC gate, so none is ever throttled."""
        self.authorize()

        codes = [self.client.get(TOKEN_ME).status_code for _ in range(3)]

        self.assertEqual(codes, [200, 200, 429])
