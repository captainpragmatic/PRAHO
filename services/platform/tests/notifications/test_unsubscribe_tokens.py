"""
Tests for UnsubscribeToken model and opaque unsubscribe URL flow.

Verifies GDPR Art. 5(1)(c) data minimization — no email addresses in URLs.
"""

from datetime import timedelta
from unittest.mock import MagicMock, patch
from uuid import uuid4

from django.test import TestCase
from django.utils import timezone

from apps.customers.models import Customer
from apps.notifications.models import TOKEN_EXPIRY_DAYS, UnsubscribeToken
from apps.notifications.services import EmailPreferenceService, EmailService


class UnsubscribeTokenModelTests(TestCase):
    """Tests for UnsubscribeToken model lifecycle."""

    def test_create_token(self) -> None:
        """Test basic token creation."""
        token = UnsubscribeToken.objects.create(
            email="test@example.com",
            template_key="marketing",
        )
        self.assertIsNotNone(token.id)
        self.assertEqual(token.email, "test@example.com")
        self.assertEqual(token.template_key, "marketing")
        self.assertIsNone(token.used_at)
        self.assertIsNotNone(token.created_at)

    def test_token_str_masks_email(self) -> None:
        """Test string representation masks email for privacy."""
        token = UnsubscribeToken.objects.create(
            email="test@example.com",
            template_key="newsletter",
        )
        display = str(token)
        # Should contain token ID and masked email
        self.assertIn("tes***", display)
        self.assertNotIn("example.com", display)

    def test_token_uniqueness(self) -> None:
        """Test multiple tokens for same email get unique UUIDs."""
        t1 = UnsubscribeToken.objects.create(email="user@test.com", template_key="a")
        t2 = UnsubscribeToken.objects.create(email="user@test.com", template_key="a")
        self.assertNotEqual(t1.id, t2.id)

    def test_consume_success(self) -> None:
        """Test consuming a valid, unused token."""
        token = UnsubscribeToken.objects.create(
            email="test@example.com",
            template_key="marketing",
        )
        result = token.consume()
        self.assertTrue(result)
        self.assertIsNotNone(token.used_at)

    def test_consume_already_used(self) -> None:
        """Test consuming an already-used token returns False."""
        token = UnsubscribeToken.objects.create(
            email="test@example.com",
            template_key="marketing",
        )
        token.consume()

        # Second consume should fail
        result = token.consume()
        self.assertFalse(result)

    def test_consume_expired(self) -> None:
        """Test consuming an expired token returns False."""
        token = UnsubscribeToken.objects.create(
            email="test@example.com",
            template_key="marketing",
        )
        # Backdate creation to make it expired
        expired_time = timezone.now() - timedelta(days=TOKEN_EXPIRY_DAYS + 1)
        UnsubscribeToken.objects.filter(id=token.id).update(created_at=expired_time)
        token.refresh_from_db()

        result = token.consume()
        self.assertFalse(result)
        self.assertIsNone(token.used_at)

    def test_is_expired_false_for_new_token(self) -> None:
        """Test new token is not expired."""
        token = UnsubscribeToken.objects.create(
            email="test@example.com",
            template_key="marketing",
        )
        self.assertFalse(token.is_expired())

    def test_is_expired_true_for_old_token(self) -> None:
        """Test old token is expired."""
        token = UnsubscribeToken.objects.create(
            email="test@example.com",
            template_key="marketing",
        )
        old_time = timezone.now() - timedelta(days=TOKEN_EXPIRY_DAYS + 1)
        UnsubscribeToken.objects.filter(id=token.id).update(created_at=old_time)
        token.refresh_from_db()

        self.assertTrue(token.is_expired())

    def test_is_expired_boundary(self) -> None:
        """Test expiry at exact boundary."""
        token = UnsubscribeToken.objects.create(
            email="test@example.com",
            template_key="marketing",
        )
        # Set to exactly TOKEN_EXPIRY_DAYS ago (should be expired)
        boundary_time = timezone.now() - timedelta(days=TOKEN_EXPIRY_DAYS, seconds=1)
        UnsubscribeToken.objects.filter(id=token.id).update(created_at=boundary_time)
        token.refresh_from_db()

        self.assertTrue(token.is_expired())


class UnsubscribeURLGenerationTests(TestCase):
    """Tests for unsubscribe URL generation using opaque tokens."""

    def test_url_contains_no_email(self) -> None:
        """GDPR Art. 5: URL must not contain email address."""
        url = EmailService._generate_unsubscribe_url(
            "user@example.com", "marketing"
        )
        self.assertNotIn("user@example.com", url)
        self.assertNotIn("user%40example.com", url)
        self.assertNotIn("email=", url)

    def test_url_contains_uuid(self) -> None:
        """Test URL contains the opaque token UUID."""
        url = EmailService._generate_unsubscribe_url(
            "user@example.com", "marketing"
        )
        # URL should be like {base}/email/unsubscribe/{uuid}/
        self.assertIn("/email/unsubscribe/", url)
        # Should end with a UUID pattern
        parts = url.rstrip("/").split("/")
        token_id = parts[-1]
        # Verify it's a valid UUID by looking it up
        token = UnsubscribeToken.objects.get(id=token_id)
        self.assertEqual(token.email, "user@example.com")
        self.assertEqual(token.template_key, "marketing")

    def test_url_creates_db_record(self) -> None:
        """Test URL generation creates a DB token record."""
        count_before = UnsubscribeToken.objects.count()
        EmailService._generate_unsubscribe_url("a@b.com", "billing")
        count_after = UnsubscribeToken.objects.count()

        self.assertEqual(count_after, count_before + 1)

    def test_multiple_urls_create_separate_tokens(self) -> None:
        """Test each URL generation creates a new token."""
        url1 = EmailService._generate_unsubscribe_url("a@b.com", "marketing")
        url2 = EmailService._generate_unsubscribe_url("a@b.com", "marketing")
        self.assertNotEqual(url1, url2)


class ProcessUnsubscribeTests(TestCase):
    """Tests for the updated process_unsubscribe using DB tokens."""

    def test_valid_token_processes_unsubscribe(self) -> None:
        """Test valid token triggers unsubscribe flow."""
        token = UnsubscribeToken.objects.create(
            email="unsub@example.com",
            template_key="marketing",
        )

        with patch("apps.customers.models.Customer.objects") as mock_mgr:
            mock_mgr.get.side_effect = Customer.DoesNotExist()
            with patch("apps.notifications.services.EmailSuppressionService.suppress_email"):
                result = EmailPreferenceService.process_unsubscribe(str(token.id))
                self.assertTrue(result)

        # Token should be consumed
        token.refresh_from_db()
        self.assertIsNotNone(token.used_at)

    def test_invalid_token_rejected(self) -> None:
        """Test invalid token ID is rejected."""
        result = EmailPreferenceService.process_unsubscribe(str(uuid4()))
        self.assertFalse(result)

    def test_already_used_token_rejected(self) -> None:
        """Test already-consumed token is rejected."""
        token = UnsubscribeToken.objects.create(
            email="used@example.com",
            template_key="marketing",
        )
        token.consume()

        result = EmailPreferenceService.process_unsubscribe(str(token.id))
        self.assertFalse(result)

    def test_expired_token_rejected(self) -> None:
        """Test expired token is rejected."""
        token = UnsubscribeToken.objects.create(
            email="expired@example.com",
            template_key="marketing",
        )
        old_time = timezone.now() - timedelta(days=TOKEN_EXPIRY_DAYS + 1)
        UnsubscribeToken.objects.filter(id=token.id).update(created_at=old_time)

        result = EmailPreferenceService.process_unsubscribe(str(token.id))
        self.assertFalse(result)

    def test_unsubscribe_with_customer(self) -> None:
        """Test unsubscribe when customer exists updates preferences."""
        token = UnsubscribeToken.objects.create(
            email="customer@example.com",
            template_key="marketing",
        )

        mock_customer = MagicMock()
        mock_customer.id = uuid4()
        mock_customer.marketing_consent = True

        with patch("apps.customers.models.Customer.objects") as mock_mgr:
            mock_mgr.get.return_value = mock_customer
            with patch("apps.notifications.services.validators"):
                result = EmailPreferenceService.process_unsubscribe(
                    str(token.id), "marketing"
                )
                self.assertTrue(result)
                self.assertFalse(mock_customer.marketing_consent)
                mock_customer.save.assert_called_once()
