"""
Comprehensive tests for OAuth Token Storage.

Tests cover:
- OAuthToken model
- OAuthTokenManager
- TokenStorageService
- Token encryption/decryption
- Token lifecycle management
- Cache integration
- Edge cases and error handling
"""

from datetime import timedelta
from unittest.mock import MagicMock, Mock, patch

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.efactura.token_storage import (
    OAuthToken,
    OAuthTokenManager,
    TokenStorageService,
)


class OAuthTokenModelTestCase(TestCase):
    """Test OAuthToken model."""

    def setUp(self):
        cache.clear()

    def test_create_token(self):
        """Test creating a basic token."""
        expires_at = timezone.now() + timedelta(hours=1)
        token = OAuthToken.objects.create(
            cui="12345678",
            access_token="test-access-token",
            refresh_token="test-refresh-token",
            token_type="Bearer",
            expires_at=expires_at,
            environment="test",
        )
        self.assertEqual(token.cui, "12345678")
        self.assertIsNotNone(token.id)
        self.assertTrue(token.is_active)

    def test_token_str_representation(self):
        """Test string representation of token."""
        expires_at = timezone.now() + timedelta(hours=1)
        token = OAuthToken.objects.create(
            cui="12345678",
            access_token="test-token",
            expires_at=expires_at,
        )
        self.assertIn("12345678", str(token))
        self.assertIn("active", str(token))

    def test_token_str_expired(self):
        """Test string representation of expired token."""
        expires_at = timezone.now() - timedelta(hours=1)
        token = OAuthToken.objects.create(
            cui="12345678",
            access_token="test-token",
            expires_at=expires_at,
        )
        self.assertIn("expired", str(token))

    def test_is_expired_false(self):
        """Test is_expired returns False for valid token."""
        expires_at = timezone.now() + timedelta(hours=1)
        token = OAuthToken.objects.create(
            cui="12345678",
            access_token="test-token",
            expires_at=expires_at,
        )
        self.assertFalse(token.is_expired)

    def test_is_expired_true(self):
        """Test is_expired returns True for expired token."""
        expires_at = timezone.now() - timedelta(hours=1)
        token = OAuthToken.objects.create(
            cui="12345678",
            access_token="test-token",
            expires_at=expires_at,
        )
        self.assertTrue(token.is_expired)

    def test_expires_in_seconds(self):
        """Test expires_in_seconds calculation."""
        expires_at = timezone.now() + timedelta(seconds=3600)
        token = OAuthToken.objects.create(
            cui="12345678",
            access_token="test-token",
            expires_at=expires_at,
        )
        # Should be close to 3600 (within a few seconds)
        self.assertGreater(token.expires_in_seconds, 3590)
        self.assertLessEqual(token.expires_in_seconds, 3600)

    def test_expires_in_seconds_expired(self):
        """Test expires_in_seconds returns 0 for expired token."""
        expires_at = timezone.now() - timedelta(hours=1)
        token = OAuthToken.objects.create(
            cui="12345678",
            access_token="test-token",
            expires_at=expires_at,
        )
        self.assertEqual(token.expires_in_seconds, 0)

    def test_can_refresh_with_refresh_token(self):
        """Test can_refresh with valid refresh token."""
        expires_at = timezone.now() + timedelta(hours=1)
        token = OAuthToken.objects.create(
            cui="12345678",
            access_token="test-token",
            refresh_token="refresh-token",
            expires_at=expires_at,
        )
        self.assertTrue(token.can_refresh)

    def test_can_refresh_without_refresh_token(self):
        """Test can_refresh without refresh token."""
        expires_at = timezone.now() + timedelta(hours=1)
        token = OAuthToken.objects.create(
            cui="12345678",
            access_token="test-token",
            refresh_token="",
            expires_at=expires_at,
        )
        self.assertFalse(token.can_refresh)

    def test_can_refresh_with_expired_refresh(self):
        """Test can_refresh with expired refresh token."""
        expires_at = timezone.now() + timedelta(hours=1)
        refresh_expires_at = timezone.now() - timedelta(hours=1)
        token = OAuthToken.objects.create(
            cui="12345678",
            access_token="test-token",
            refresh_token="refresh-token",
            expires_at=expires_at,
            refresh_expires_at=refresh_expires_at,
        )
        self.assertFalse(token.can_refresh)

    def test_mark_used(self):
        """Test mark_used updates timestamp and count."""
        expires_at = timezone.now() + timedelta(hours=1)
        token = OAuthToken.objects.create(
            cui="12345678",
            access_token="test-token",
            expires_at=expires_at,
        )
        self.assertIsNone(token.last_used_at)
        self.assertEqual(token.use_count, 0)

        token.mark_used()
        token.refresh_from_db()

        self.assertIsNotNone(token.last_used_at)
        self.assertEqual(token.use_count, 1)

    def test_deactivate(self):
        """Test deactivating a token."""
        expires_at = timezone.now() + timedelta(hours=1)
        token = OAuthToken.objects.create(
            cui="12345678",
            access_token="test-token",
            expires_at=expires_at,
        )
        self.assertTrue(token.is_active)

        token.deactivate()
        token.refresh_from_db()

        self.assertFalse(token.is_active)

    def test_to_dict(self):
        """Test serialization to dict."""
        expires_at = timezone.now() + timedelta(hours=1)
        token = OAuthToken.objects.create(
            cui="12345678",
            access_token="test-token",
            expires_at=expires_at,
            environment="test",
        )
        data = token.to_dict()

        self.assertEqual(data["cui"], "12345678")
        self.assertEqual(data["token_type"], "Bearer")
        self.assertEqual(data["environment"], "test")
        self.assertIn("expires_at", data)
        self.assertIn("is_expired", data)
        self.assertFalse(data["is_expired"])


class OAuthTokenStoreMethodTestCase(TestCase):
    """Test OAuthToken.store_token class method."""

    def setUp(self):
        cache.clear()

    def test_store_token_creates_new(self):
        """Test store_token creates new token."""
        token = OAuthToken.store_token(
            cui="12345678",
            access_token="access-token",
            expires_in=3600,
            refresh_token="refresh-token",
            environment="test",
        )
        self.assertIsNotNone(token.id)
        self.assertEqual(token.cui, "12345678")
        self.assertTrue(token.is_active)

    def test_store_token_deactivates_existing(self):
        """Test store_token deactivates existing tokens."""
        # Create first token
        token1 = OAuthToken.store_token(
            cui="12345678",
            access_token="token-1",
            expires_in=3600,
        )

        # Create second token
        token2 = OAuthToken.store_token(
            cui="12345678",
            access_token="token-2",
            expires_in=3600,
        )

        # Refresh first token
        token1.refresh_from_db()
        self.assertFalse(token1.is_active)
        self.assertTrue(token2.is_active)

    def test_store_token_calculates_expiration(self):
        """Test store_token calculates expiration correctly."""
        before = timezone.now()
        token = OAuthToken.store_token(
            cui="12345678",
            access_token="token",
            expires_in=3600,
        )
        after = timezone.now()

        expected_min = before + timedelta(seconds=3600)
        expected_max = after + timedelta(seconds=3600)

        self.assertGreaterEqual(token.expires_at, expected_min)
        self.assertLessEqual(token.expires_at, expected_max)

    def test_store_token_with_refresh_expiration(self):
        """Test store_token with refresh token expiration."""
        token = OAuthToken.store_token(
            cui="12345678",
            access_token="token",
            expires_in=3600,
            refresh_token="refresh",
            refresh_expires_in=86400,
        )
        self.assertIsNotNone(token.refresh_expires_at)


class OAuthTokenManagerTestCase(TestCase):
    """Test OAuthTokenManager."""

    def setUp(self):
        cache.clear()

    def test_get_valid_token_returns_active(self):
        """Test get_valid_token returns active non-expired token."""
        expires_at = timezone.now() + timedelta(hours=1)
        token = OAuthToken.objects.create(
            cui="12345678",
            access_token="test-token",
            expires_at=expires_at,
            is_active=True,
        )

        result = OAuthToken.objects.get_valid_token("12345678")
        self.assertEqual(result.id, token.id)

    def test_get_valid_token_skips_expired(self):
        """Test get_valid_token skips expired tokens."""
        expires_at = timezone.now() - timedelta(hours=1)
        OAuthToken.objects.create(
            cui="12345678",
            access_token="expired-token",
            expires_at=expires_at,
            is_active=True,
        )

        result = OAuthToken.objects.get_valid_token("12345678")
        self.assertIsNone(result)

    def test_get_valid_token_skips_inactive(self):
        """Test get_valid_token skips inactive tokens."""
        expires_at = timezone.now() + timedelta(hours=1)
        OAuthToken.objects.create(
            cui="12345678",
            access_token="inactive-token",
            expires_at=expires_at,
            is_active=False,
        )

        result = OAuthToken.objects.get_valid_token("12345678")
        self.assertIsNone(result)

    def test_get_valid_token_returns_most_recent(self):
        """Test get_valid_token returns most recent token."""
        expires_at = timezone.now() + timedelta(hours=1)

        OAuthToken.objects.create(
            cui="12345678",
            access_token="older-token",
            expires_at=expires_at,
            is_active=True,
        )

        newer = OAuthToken.objects.create(
            cui="12345678",
            access_token="newer-token",
            expires_at=expires_at,
            is_active=True,
        )

        result = OAuthToken.objects.get_valid_token("12345678")
        self.assertEqual(result.id, newer.id)

    def test_get_refreshable_token(self):
        """Test get_refreshable_token returns token with refresh."""
        expires_at = timezone.now() + timedelta(hours=1)
        token = OAuthToken.objects.create(
            cui="12345678",
            access_token="test-token",
            refresh_token="refresh-token",
            expires_at=expires_at,
            is_active=True,
        )

        result = OAuthToken.objects.get_refreshable_token("12345678")
        self.assertEqual(result.id, token.id)

    def test_get_refreshable_token_skips_empty_refresh(self):
        """Test get_refreshable_token skips empty refresh tokens."""
        expires_at = timezone.now() + timedelta(hours=1)
        OAuthToken.objects.create(
            cui="12345678",
            access_token="test-token",
            refresh_token="",
            expires_at=expires_at,
            is_active=True,
        )

        result = OAuthToken.objects.get_refreshable_token("12345678")
        self.assertIsNone(result)

    def test_deactivate_all(self):
        """Test deactivate_all deactivates all tokens for CUI."""
        expires_at = timezone.now() + timedelta(hours=1)

        OAuthToken.objects.create(
            cui="12345678",
            access_token="token-1",
            expires_at=expires_at,
            is_active=True,
        )
        OAuthToken.objects.create(
            cui="12345678",
            access_token="token-2",
            expires_at=expires_at,
            is_active=True,
        )
        # Different CUI
        token3 = OAuthToken.objects.create(
            cui="87654321",
            access_token="token-3",
            expires_at=expires_at,
            is_active=True,
        )

        count = OAuthToken.objects.deactivate_all("12345678")
        self.assertEqual(count, 2)

        # Verify all for 12345678 are inactive
        active = OAuthToken.objects.filter(cui="12345678", is_active=True).count()
        self.assertEqual(active, 0)

        # Token for 87654321 should still be active
        token3.refresh_from_db()
        self.assertTrue(token3.is_active)


class OAuthTokenEncryptionTestCase(TestCase):
    """Test token encryption functionality."""

    def test_encryption_with_mock(self):
        """Test encryption uses encryption service."""
        with patch("apps.billing.efactura.token_storage.OAuthToken._encrypt") as mock_encrypt:
            mock_encrypt.return_value = "encrypted-value"

            expires_at = timezone.now() + timedelta(hours=1)
            token = OAuthToken(
                cui="12345678",
                access_token="plain-token",
                expires_at=expires_at,
            )
            token.save()

    def test_decryption_property(self):
        """Test decrypted_access_token property."""
        expires_at = timezone.now() + timedelta(hours=1)
        token = OAuthToken.objects.create(
            cui="12345678",
            access_token="test-token",
            expires_at=expires_at,
        )
        # Without encryption service, should return as-is
        self.assertEqual(token.decrypted_access_token, "test-token")

    def test_is_encrypted_without_service(self):
        """Test _is_encrypted returns False without encryption service."""
        expires_at = timezone.now() + timedelta(hours=1)
        token = OAuthToken(
            cui="12345678",
            access_token="test-token",
            expires_at=expires_at,
        )
        self.assertFalse(token._is_encrypted("test-token"))


class TokenStorageServiceTestCase(TestCase):
    """Test TokenStorageService."""

    def setUp(self):
        cache.clear()

    def test_get_access_token_from_db(self):
        """Test getting access token from database."""
        expires_at = timezone.now() + timedelta(hours=1)
        OAuthToken.objects.create(
            cui="12345678",
            access_token="test-token",
            expires_at=expires_at,
            is_active=True,
        )

        mock_settings = Mock()
        mock_settings.company_cui = "12345678"
        mock_settings.environment.value = "test"

        service = TokenStorageService(settings=mock_settings)
        token = service.get_access_token("12345678")

        self.assertEqual(token, "test-token")

    def test_get_access_token_uses_cache(self):
        """Test access token is cached."""
        expires_at = timezone.now() + timedelta(hours=1)
        OAuthToken.objects.create(
            cui="12345678",
            access_token="test-token",
            expires_at=expires_at,
            is_active=True,
        )

        mock_settings = Mock()
        mock_settings.company_cui = "12345678"
        mock_settings.environment.value = "test"

        service = TokenStorageService(settings=mock_settings)

        # First call
        token1 = service.get_access_token("12345678")

        # Delete from DB
        OAuthToken.objects.all().delete()

        # Second call should still work from cache
        token2 = service.get_access_token("12345678")
        self.assertEqual(token1, token2)

    def test_get_access_token_uses_settings_cui(self):
        """Test get_access_token uses settings CUI when not provided."""
        expires_at = timezone.now() + timedelta(hours=1)
        OAuthToken.objects.create(
            cui="12345678",
            access_token="test-token",
            expires_at=expires_at,
            is_active=True,
        )

        mock_settings = Mock()
        mock_settings.company_cui = "12345678"
        mock_settings.environment.value = "test"

        service = TokenStorageService(settings=mock_settings)
        token = service.get_access_token()

        self.assertEqual(token, "test-token")

    def test_get_access_token_returns_none_for_no_cui(self):
        """Test get_access_token returns None when no CUI."""
        mock_settings = Mock()
        mock_settings.company_cui = ""

        service = TokenStorageService(settings=mock_settings)
        token = service.get_access_token()

        self.assertIsNone(token)

    def test_store_token(self):
        """Test storing a new token."""
        mock_settings = Mock()
        mock_settings.company_cui = "12345678"
        mock_settings.environment.value = "test"

        service = TokenStorageService(settings=mock_settings)
        token = service.store_token(
            access_token="new-token",
            expires_in=3600,
            refresh_token="refresh-token",
        )

        self.assertIsNotNone(token)
        self.assertEqual(token.cui, "12345678")

    def test_store_token_raises_without_cui(self):
        """Test store_token raises error without CUI."""
        mock_settings = Mock()
        mock_settings.company_cui = ""

        service = TokenStorageService(settings=mock_settings)

        with self.assertRaises(ValueError):
            service.store_token(
                access_token="token",
                expires_in=3600,
            )

    def test_invalidate_token(self):
        """Test invalidating tokens."""
        expires_at = timezone.now() + timedelta(hours=1)
        token = OAuthToken.objects.create(
            cui="12345678",
            access_token="test-token",
            expires_at=expires_at,
            is_active=True,
        )

        mock_settings = Mock()
        mock_settings.company_cui = "12345678"
        mock_settings.environment.value = "test"

        service = TokenStorageService(settings=mock_settings)
        service.invalidate_token("12345678")

        token.refresh_from_db()
        self.assertFalse(token.is_active)

    def test_get_refreshable_token(self):
        """Test getting refreshable token via service."""
        expires_at = timezone.now() + timedelta(hours=1)
        OAuthToken.objects.create(
            cui="12345678",
            access_token="test-token",
            refresh_token="refresh-token",
            expires_at=expires_at,
            is_active=True,
        )

        mock_settings = Mock()
        mock_settings.company_cui = "12345678"
        mock_settings.environment.value = "test"

        service = TokenStorageService(settings=mock_settings)
        token = service.get_refreshable_token()

        self.assertIsNotNone(token)
        self.assertEqual(token.refresh_token, "refresh-token")


class TokenStorageEdgeCasesTestCase(TestCase):
    """Test edge cases and error conditions."""

    def setUp(self):
        cache.clear()

    def test_multiple_cuis_isolation(self):
        """Test tokens for different CUIs are isolated."""
        expires_at = timezone.now() + timedelta(hours=1)

        OAuthToken.objects.create(
            cui="11111111",
            access_token="token-1",
            expires_at=expires_at,
            is_active=True,
        )
        OAuthToken.objects.create(
            cui="22222222",
            access_token="token-2",
            expires_at=expires_at,
            is_active=True,
        )

        token1 = OAuthToken.objects.get_valid_token("11111111")
        token2 = OAuthToken.objects.get_valid_token("22222222")

        self.assertEqual(token1.access_token, "token-1")
        self.assertEqual(token2.access_token, "token-2")

    def test_environment_field(self):
        """Test environment field is stored correctly."""
        expires_at = timezone.now() + timedelta(hours=1)

        test_token = OAuthToken.objects.create(
            cui="12345678",
            access_token="test-token",
            expires_at=expires_at,
            environment="test",
        )
        prod_token = OAuthToken.objects.create(
            cui="12345678",
            access_token="prod-token",
            expires_at=expires_at,
            environment="production",
        )

        self.assertEqual(test_token.environment, "test")
        self.assertEqual(prod_token.environment, "production")

    def test_scope_field(self):
        """Test scope field storage."""
        expires_at = timezone.now() + timedelta(hours=1)
        token = OAuthToken.objects.create(
            cui="12345678",
            access_token="test-token",
            expires_at=expires_at,
            scope="read write admin",
        )
        self.assertEqual(token.scope, "read write admin")

    def test_token_type_default(self):
        """Test token type defaults to Bearer."""
        expires_at = timezone.now() + timedelta(hours=1)
        token = OAuthToken.objects.create(
            cui="12345678",
            access_token="test-token",
            expires_at=expires_at,
        )
        self.assertEqual(token.token_type, "Bearer")

    def test_use_count_increments(self):
        """Test use_count increments correctly."""
        expires_at = timezone.now() + timedelta(hours=1)
        token = OAuthToken.objects.create(
            cui="12345678",
            access_token="test-token",
            expires_at=expires_at,
        )

        for _ in range(5):
            token.mark_used()

        token.refresh_from_db()
        self.assertEqual(token.use_count, 5)

    def test_ordering(self):
        """Test tokens are ordered by created_at descending."""
        expires_at = timezone.now() + timedelta(hours=1)

        token1 = OAuthToken.objects.create(
            cui="12345678",
            access_token="token-1",
            expires_at=expires_at,
        )
        token2 = OAuthToken.objects.create(
            cui="12345678",
            access_token="token-2",
            expires_at=expires_at,
        )

        tokens = list(OAuthToken.objects.all())
        # Most recent first
        self.assertEqual(tokens[0].id, token2.id)
        self.assertEqual(tokens[1].id, token1.id)

    def test_get_valid_access_token_class_method(self):
        """Test OAuthToken.get_valid_access_token class method."""
        expires_at = timezone.now() + timedelta(hours=1)
        OAuthToken.objects.create(
            cui="12345678",
            access_token="test-token",
            expires_at=expires_at,
            is_active=True,
        )

        token = OAuthToken.get_valid_access_token("12345678")
        self.assertEqual(token, "test-token")

    def test_get_valid_access_token_returns_none(self):
        """Test get_valid_access_token returns None for no token."""
        token = OAuthToken.get_valid_access_token("nonexistent")
        self.assertIsNone(token)
