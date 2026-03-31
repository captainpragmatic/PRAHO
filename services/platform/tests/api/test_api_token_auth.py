"""
Tests for the custom APIToken authentication system (ADR-0031 Gaps 2-6, 8).

Covers:
- APIToken model: generate_key, hash_key, is_expired
- HashedTokenAuthentication backend: auth flow, expiry, last_used_at throttle, Bearer + Token
- obtain_token: multi-token creation, name field, raw key returned once
- revoke_token: only revokes authenticating token, siblings survive
- token_info: returns new fields (name, key_prefix, expires_at, last_used_at)
"""

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from apps.users.models import APIToken

User = get_user_model()


def _create_token(user, name="test", **kwargs):
    """Helper: create an APIToken and return (token_instance, raw_key)."""
    raw_key = APIToken.generate_key()
    token = APIToken.objects.create(
        user=user,
        key_hash=APIToken.hash_key(raw_key),
        key_prefix=raw_key[:8],
        name=name,
        **kwargs,
    )
    return token, raw_key


# ===============================================================================
# MODEL TESTS
# ===============================================================================


class APITokenModelTests(TestCase):
    """Unit tests for the APIToken model."""

    def test_generate_key_returns_40_hex_chars(self) -> None:
        key = APIToken.generate_key()
        self.assertEqual(len(key), 40)
        # Must be valid hex
        int(key, 16)

    def test_generate_key_is_unique(self) -> None:
        keys = {APIToken.generate_key() for _ in range(100)}
        self.assertEqual(len(keys), 100)

    def test_hash_key_returns_64_hex_chars(self) -> None:
        h = APIToken.hash_key("abcdef1234567890abcdef1234567890abcdef12")
        self.assertEqual(len(h), 64)
        int(h, 16)

    def test_hash_key_is_deterministic(self) -> None:
        key = "some-token-value"
        self.assertEqual(APIToken.hash_key(key), APIToken.hash_key(key))

    def test_is_expired_returns_false_when_no_expiry(self) -> None:
        user = User.objects.create_user(email="exp@test.com", password="StrongPass123!")
        token, _ = _create_token(user)
        self.assertFalse(token.is_expired)

    def test_is_expired_returns_false_when_future(self) -> None:
        user = User.objects.create_user(email="exp2@test.com", password="StrongPass123!")
        token, _ = _create_token(user, expires_at=timezone.now() + timedelta(hours=1))
        self.assertFalse(token.is_expired)

    def test_is_expired_returns_true_when_past(self) -> None:
        user = User.objects.create_user(email="exp3@test.com", password="StrongPass123!")
        token, _ = _create_token(user, expires_at=timezone.now() - timedelta(seconds=1))
        self.assertTrue(token.is_expired)

    def test_str_representation(self) -> None:
        user = User.objects.create_user(email="str@test.com", password="StrongPass123!")
        token, _ = _create_token(user, name="ci-pipeline")
        s = str(token)
        self.assertIn("ci-pipeline", s)
        self.assertIn(token.key_prefix, s)


# ===============================================================================
# AUTHENTICATION BACKEND TESTS
# ===============================================================================


class HashedTokenAuthenticationTests(TestCase):
    """Tests for the HashedTokenAuthentication DRF backend."""

    def setUp(self) -> None:
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="auth@test.com", password="StrongPass123!", first_name="Auth", last_name="Test"
        )
        self.token, self.raw_key = _create_token(self.user)
        self.url = "/api/users/token/me/"

    def test_valid_token_authenticates(self) -> None:
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {self.raw_key}")
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)

    def test_bearer_scheme_authenticates(self) -> None:
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.raw_key}")
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)

    def test_invalid_token_returns_401(self) -> None:
        self.client.credentials(HTTP_AUTHORIZATION="Token invalid_key_that_does_not_exist")
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 401)

    def test_expired_token_returns_401(self) -> None:
        _expired_token, expired_key = _create_token(
            self.user,
            name="expired",
            expires_at=timezone.now() - timedelta(hours=1),
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {expired_key}")
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 401)
        self.assertIn("expired", response.json()["detail"].lower())

    def test_inactive_user_returns_401(self) -> None:
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {self.raw_key}")
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 401)

    def test_last_used_at_updated_on_first_use(self) -> None:
        self.assertIsNone(self.token.last_used_at)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {self.raw_key}")
        self.client.get(self.url)
        self.token.refresh_from_db()
        self.assertIsNotNone(self.token.last_used_at)

    def test_last_used_at_not_updated_within_5_minutes(self) -> None:
        """Subsequent requests within 5 minutes should not trigger a DB write."""
        recent = timezone.now() - timedelta(minutes=2)
        APIToken.objects.filter(pk=self.token.pk).update(last_used_at=recent)

        self.client.credentials(HTTP_AUTHORIZATION=f"Token {self.raw_key}")
        self.client.get(self.url)

        self.token.refresh_from_db()
        # last_used_at should still be the value we set (within seconds tolerance)
        self.assertAlmostEqual(
            self.token.last_used_at.timestamp(),
            recent.timestamp(),
            delta=2,
        )

    def test_last_used_at_updated_after_5_minutes(self) -> None:
        stale = timezone.now() - timedelta(minutes=10)
        APIToken.objects.filter(pk=self.token.pk).update(last_used_at=stale)

        self.client.credentials(HTTP_AUTHORIZATION=f"Token {self.raw_key}")
        self.client.get(self.url)

        self.token.refresh_from_db()
        self.assertGreater(self.token.last_used_at, stale)

    def test_no_auth_header_returns_none(self) -> None:
        """Requests without Authorization header should fall through (not 401)."""
        # Without credentials, the endpoint should still return 401 because
        # IsAuthenticated permission blocks it, but the backend itself returns None
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 401)


# ===============================================================================
# OBTAIN TOKEN TESTS
# ===============================================================================


class ObtainTokenTests(TestCase):
    """Tests for POST /api/users/token/ with the new APIToken model."""

    def setUp(self) -> None:
        self.client = APIClient()
        self.password = "StrongPass123!"
        self.user = User.objects.create_user(
            email="obtain@test.com", password=self.password, first_name="Obtain", last_name="Test"
        )
        self.url = "/api/users/token/"

    def test_obtain_returns_raw_key_and_metadata(self) -> None:
        response = self.client.post(self.url, {"email": self.user.email, "password": self.password}, format="json")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("token", data)
        self.assertIn("key_prefix", data)
        self.assertIn("name", data)
        self.assertEqual(len(data["token"]), 40)
        self.assertEqual(data["key_prefix"], data["token"][:8])

    def test_obtain_creates_new_token_each_call(self) -> None:
        """Multi-token: successive calls create distinct tokens (Gap 4)."""
        resp1 = self.client.post(self.url, {"email": self.user.email, "password": self.password}, format="json")
        resp2 = self.client.post(self.url, {"email": self.user.email, "password": self.password}, format="json")
        self.assertNotEqual(resp1.json()["token"], resp2.json()["token"])
        self.assertEqual(APIToken.objects.filter(user=self.user).count(), 2)

    def test_obtain_accepts_name_field(self) -> None:
        response = self.client.post(
            self.url,
            {"email": self.user.email, "password": self.password, "name": "ci-pipeline"},
            format="json",
        )
        self.assertEqual(response.json()["name"], "ci-pipeline")

    def test_obtain_default_name(self) -> None:
        response = self.client.post(self.url, {"email": self.user.email, "password": self.password}, format="json")
        self.assertEqual(response.json()["name"], "default")

    def test_raw_key_authenticates(self) -> None:
        """The raw key returned by obtain_token must work for authentication."""
        response = self.client.post(self.url, {"email": self.user.email, "password": self.password}, format="json")
        raw_key = response.json()["token"]

        self.client.credentials(HTTP_AUTHORIZATION=f"Token {raw_key}")
        info_response = self.client.get("/api/users/token/me/")
        self.assertEqual(info_response.status_code, 200)

    def test_obtain_rejects_when_at_token_limit(self) -> None:
        """Per-user token limit prevents token sprawl."""
        for i in range(APIToken.MAX_TOKENS_PER_USER):
            _create_token(self.user, name=f"token-{i}")

        response = self.client.post(self.url, {"email": self.user.email, "password": self.password}, format="json")
        self.assertEqual(response.status_code, 400)
        self.assertIn("Maximum", response.json()["error"])


# ===============================================================================
# REVOKE TOKEN TESTS
# ===============================================================================


class RevokeTokenTests(TestCase):
    """Tests for DELETE /api/users/token/revoke/ with APIToken."""

    def setUp(self) -> None:
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="revoke@test.com", password="StrongPass123!", first_name="Revoke", last_name="Test"
        )
        self.url = "/api/users/token/revoke/"

    def test_revoke_deletes_authenticating_token_only(self) -> None:
        """Revoking token A must not affect token B for the same user."""
        token_a, key_a = _create_token(self.user, name="token-a")
        token_b, _key_b = _create_token(self.user, name="token-b")

        self.client.credentials(HTTP_AUTHORIZATION=f"Token {key_a}")
        response = self.client.delete(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertFalse(APIToken.objects.filter(pk=token_a.pk).exists())
        self.assertTrue(APIToken.objects.filter(pk=token_b.pk).exists())

    def test_revoke_requires_auth(self) -> None:
        response = self.client.delete(self.url)
        self.assertEqual(response.status_code, 401)

    def test_revoked_token_cannot_be_reused(self) -> None:
        _, raw_key = _create_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {raw_key}")

        self.client.delete(self.url)

        response = self.client.get("/api/users/token/me/")
        self.assertEqual(response.status_code, 401)


# ===============================================================================
# TOKEN INFO TESTS
# ===============================================================================


class TokenInfoTests(TestCase):
    """Tests for GET /api/users/token/me/ with APIToken."""

    def setUp(self) -> None:
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="info@test.com", password="StrongPass123!", first_name="Info", last_name="Test"
        )
        self.token, self.raw_key = _create_token(self.user, name="my-script")
        self.url = "/api/users/token/me/"

    def test_returns_token_metadata(self) -> None:
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {self.raw_key}")
        response = self.client.get(self.url)
        data = response.json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["user_id"], self.user.id)
        self.assertEqual(data["token_name"], "my-script")
        self.assertEqual(data["key_prefix"], self.token.key_prefix)
        self.assertIn("created_at", data)
        self.assertIn("expires_at", data)
        self.assertIn("last_used_at", data)

    def test_does_not_leak_is_staff(self) -> None:
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {self.raw_key}")
        response = self.client.get(self.url)
        self.assertNotIn("is_staff", response.json())
