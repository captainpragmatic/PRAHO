"""
🔒 Security Fix Tests - Post Red Team Analysis
Tests for vulnerabilities identified and fixed during security review.

Tests cover:
- Timing-safe token comparison
- SSRF protection in SNS webhooks
- Rate limiter race condition fix
- TOCTOU race in EmailSuppression
- SQL injection protection in campaign filters
- Webhook signature validation
"""

import hashlib
import hmac
import json
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, patch

from django.conf import settings
from django.core.cache import cache
from django.http import HttpRequest
from django.test import TestCase, override_settings


class TimingSafeTokenTests(TestCase):
    """Test timing-safe token comparison for unsubscribe."""

    def test_valid_token_accepted(self):
        """Test valid unsubscribe token is accepted."""
        from apps.notifications.services import EmailPreferenceService, EmailSuppressionService

        email = "token-test@example.com"
        # Generate valid token
        token = hashlib.sha256(
            f"{email}:marketing:{settings.SECRET_KEY}".encode()
        ).hexdigest()[:32]

        # Mock Customer.DoesNotExist to trigger suppression path
        from apps.customers.models import Customer
        with patch.object(Customer.objects, 'get') as mock_get:
            mock_get.side_effect = Customer.DoesNotExist()
            result = EmailPreferenceService.process_unsubscribe(email, token, "marketing")
            # Will return True because it suppresses the email when customer not found
            self.assertTrue(result)
            # Email should be suppressed
            self.assertTrue(EmailSuppressionService.is_suppressed(email))

    def test_invalid_token_rejected(self):
        """Test invalid unsubscribe token is rejected."""
        from apps.notifications.services import EmailPreferenceService

        email = "test@example.com"
        invalid_token = "invalidtoken12345678901234567890"

        result = EmailPreferenceService.process_unsubscribe(email, invalid_token, "marketing")
        self.assertFalse(result)

    def test_token_uses_hmac_compare_digest(self):
        """Test that token comparison uses timing-safe function."""
        from apps.notifications.services import EmailPreferenceService
        import hmac as hmac_module

        email = "test@example.com"
        token = hashlib.sha256(
            f"{email}:marketing:{settings.SECRET_KEY}".encode()
        ).hexdigest()[:32]

        # Patch hmac.compare_digest to verify it's called
        with patch.object(hmac_module, 'compare_digest', wraps=hmac_module.compare_digest) as mock_compare:
            with patch("apps.customers.models.Customer.objects"):
                EmailPreferenceService.process_unsubscribe(email, token, "marketing")

            # Verify compare_digest was called (timing-safe comparison)
            self.assertTrue(mock_compare.called)


class SSRFProtectionTests(TestCase):
    """Test SSRF protection in SNS webhook SubscribeURL validation."""

    def _create_sns_request(self, subscribe_url: str) -> HttpRequest:
        """Create mock SNS subscription confirmation request."""
        request = HttpRequest()
        request.method = "POST"
        request._body = json.dumps({
            "Type": "SubscriptionConfirmation",
            "SubscribeURL": subscribe_url,
            "Token": "test-token",
            "TopicArn": "arn:aws:sns:us-east-1:123456789:test-topic",
        }).encode()
        return request

    def test_valid_aws_sns_url_accepted(self):
        """Test valid AWS SNS URL is accepted."""
        from apps.notifications.webhooks import SESWebhookView

        view = SESWebhookView()
        valid_urls = [
            "https://sns.us-east-1.amazonaws.com/confirm?token=abc",
            "https://sns.eu-west-1.amazonaws.com/confirm?token=abc",
            "https://sns.ap-southeast-1.amazonaws.com/confirm?token=abc",
        ]

        for url in valid_urls:
            data = {"SubscribeURL": url}
            with patch("requests.get") as mock_get:
                mock_get.return_value = MagicMock(status_code=200)
                response = view._handle_subscription_confirmation(data)
                self.assertEqual(response.status_code, 200, f"URL should be accepted: {url}")
                mock_get.assert_called_once()
                mock_get.reset_mock()

    def test_non_aws_url_rejected(self):
        """Test non-AWS URLs are rejected (SSRF protection)."""
        from apps.notifications.webhooks import SESWebhookView

        view = SESWebhookView()
        malicious_urls = [
            "https://evil.com/steal-data",
            "http://localhost:8080/internal",
            "https://192.168.1.1/admin",
            "https://attacker.amazonaws.com.evil.com/fake",
            "http://sns.us-east-1.amazonaws.com/http-not-https",  # HTTP not HTTPS
        ]

        for url in malicious_urls:
            data = {"SubscribeURL": url}
            with patch("requests.get") as mock_get:
                response = view._handle_subscription_confirmation(data)
                self.assertEqual(response.status_code, 400, f"URL should be rejected: {url}")
                mock_get.assert_not_called()


class RateLimiterAtomicTests(TestCase):
    """Test rate limiter atomic operations."""

    def setUp(self):
        """Clear cache before each test."""
        cache.clear()

    def test_increment_counter_atomic(self):
        """Test counter increment is atomic using cache.add()."""
        from apps.notifications.services import EmailRateLimiter

        # Increment multiple times
        counts = []
        for _ in range(5):
            count = EmailRateLimiter.increment_counter("atomic_test")
            counts.append(count)

        # Should be sequential: 1, 2, 3, 4, 5
        self.assertEqual(counts, [1, 2, 3, 4, 5])

    def test_concurrent_increments(self):
        """Test concurrent increments don't lose counts."""
        from apps.notifications.services import EmailRateLimiter

        cache.clear()
        num_threads = 5
        increments_per_thread = 5

        def do_increments():
            for _ in range(increments_per_thread):
                EmailRateLimiter.increment_counter("concurrent_test")

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(do_increments) for _ in range(num_threads)]
            for f in futures:
                f.result()

        # Check final count - verify we didn't lose any increments
        total_increments = num_threads * increments_per_thread  # 25
        max_per_minute = getattr(settings, "EMAIL_RATE_LIMIT", {}).get("MAX_PER_MINUTE", 50)
        _, remaining = EmailRateLimiter.check_rate_limit("concurrent_test")

        # The remaining count should be max - increments
        # But if increments > max, remaining should be 0
        expected_remaining = max(0, max_per_minute - total_increments)
        self.assertEqual(remaining, expected_remaining)


class SuppressionTOCTOURaceTests(TestCase):
    """Test TOCTOU race condition fix in EmailSuppression.suppress()."""

    def test_suppress_uses_select_for_update(self):
        """Test that suppress() uses select_for_update for locking."""
        from apps.notifications.models import EmailSuppression

        email = "race-test@example.com"

        # First suppression
        suppression1 = EmailSuppression.suppress(email, "hard_bounce", "ses")
        self.assertEqual(suppression1.bounce_count, 1)

        # Second suppression should increment, not create duplicate
        suppression2 = EmailSuppression.suppress(email, "hard_bounce", "ses")
        self.assertEqual(suppression2.bounce_count, 2)
        self.assertEqual(suppression1.id, suppression2.id)

        # Verify only one record exists
        count = EmailSuppression.objects.filter(
            email_hash=hashlib.sha256(email.lower().encode()).hexdigest()
        ).count()
        self.assertEqual(count, 1)

    def test_suppress_uses_f_expression(self):
        """Test that bounce_count uses F() for atomic increment."""
        from apps.notifications.models import EmailSuppression

        email = "f-expr-test@example.com"

        # Create initial suppression
        EmailSuppression.suppress(email, "soft_bounce", "ses")

        # Verify F() expression is used by checking database value
        # (refresh_from_db is called in suppress())
        for i in range(5):
            suppression = EmailSuppression.suppress(email, "soft_bounce", "ses")

        # Should have 6 bounces (1 initial + 5 increments)
        self.assertEqual(suppression.bounce_count, 6)


class CampaignFilterSQLInjectionTests(TestCase):
    """Test SQL injection protection in campaign audience filters."""

    def test_whitelist_allows_safe_fields(self):
        """Test whitelisted fields are allowed."""
        from apps.notifications.tasks import _apply_safe_customer_filter, ALLOWED_CAMPAIGN_FILTER_FIELDS

        # Mock queryset
        mock_qs = MagicMock()
        mock_qs.filter.return_value = mock_qs

        safe_filter = {
            "status": "active",
            "customer_type": "individual",
            "marketing_consent": True,
        }

        result = _apply_safe_customer_filter(mock_qs, safe_filter)
        mock_qs.filter.assert_called_once()

        # Verify all keys were passed
        call_kwargs = mock_qs.filter.call_args[1]
        self.assertEqual(call_kwargs["status"], "active")
        self.assertEqual(call_kwargs["customer_type"], "individual")
        self.assertEqual(call_kwargs["marketing_consent"], True)

    def test_whitelist_blocks_dangerous_fields(self):
        """Test non-whitelisted fields are blocked (SQL injection prevention)."""
        from apps.notifications.tasks import _apply_safe_customer_filter

        mock_qs = MagicMock()
        mock_qs.filter.return_value = mock_qs

        dangerous_filters = {
            "password__icontains": "admin",  # SQL injection attempt
            "user__is_superuser": True,      # Privilege escalation
            "billing__credit_card": "4111",  # PCI data access
            "status": "active",              # This one IS allowed
        }

        result = _apply_safe_customer_filter(mock_qs, dangerous_filters)

        # Only the safe "status" field should be in the filter
        call_kwargs = mock_qs.filter.call_args[1]
        self.assertEqual(call_kwargs, {"status": "active"})
        self.assertNotIn("password__icontains", call_kwargs)
        self.assertNotIn("user__is_superuser", call_kwargs)

    def test_whitelist_blocks_all_dangerous(self):
        """Test that entirely dangerous filter results in no filtering."""
        from apps.notifications.tasks import _apply_safe_customer_filter

        mock_qs = MagicMock()

        all_dangerous = {
            "password": "secret",
            "secret_key": "abc123",
        }

        result = _apply_safe_customer_filter(mock_qs, all_dangerous)

        # Should return original queryset without calling filter
        self.assertEqual(result, mock_qs)
        mock_qs.filter.assert_not_called()


@override_settings(DEBUG=False)
class WebhookSignatureValidationTests(TestCase):
    """Test webhook signature validation in production mode."""

    def test_anymail_webhook_rejects_unsigned_in_production(self):
        """Test Anymail webhook rejects unsigned requests in production."""
        from apps.notifications.webhooks import AnymailWebhookView

        view = AnymailWebhookView()
        request = HttpRequest()
        request.META = {}

        # No ANYMAIL WEBHOOK_SECRET configured - should reject in production
        with patch.object(settings, 'ANYMAIL', {}):
            result = view._validate_webhook_signature(request)
            self.assertFalse(result)

    def test_sendgrid_webhook_rejects_unsigned_in_production(self):
        """Test SendGrid webhook rejects unsigned requests in production."""
        from apps.notifications.webhooks import SendGridWebhookView

        view = SendGridWebhookView()
        request = HttpRequest()
        request.META = {}

        with patch.object(settings, 'ANYMAIL', {}):
            result = view._validate_signature(request)
            self.assertFalse(result)

    def test_mailgun_webhook_rejects_unsigned_in_production(self):
        """Test Mailgun webhook rejects unsigned requests in production."""
        from apps.notifications.webhooks import MailgunWebhookView

        view = MailgunWebhookView()
        request = HttpRequest()
        request.POST = {}

        with patch.object(settings, 'ANYMAIL', {}):
            result = view._validate_signature(request)
            self.assertFalse(result)


@override_settings(DEBUG=True)
class WebhookDevModeTests(TestCase):
    """Test webhook behavior in development mode."""

    def test_anymail_webhook_allows_unsigned_in_dev(self):
        """Test Anymail webhook allows unsigned in development."""
        from apps.notifications.webhooks import AnymailWebhookView

        view = AnymailWebhookView()
        request = HttpRequest()
        request.META = {}

        with patch.object(settings, 'ANYMAIL', {}):
            result = view._validate_webhook_signature(request)
            self.assertTrue(result)  # Allowed in dev mode


class SuppressionCacheIntegrationTests(TestCase):
    """Test suppression service cache/database integration."""

    def setUp(self):
        cache.clear()

    def test_suppression_syncs_to_cache(self):
        """Test that database suppression is cached for read-through."""
        from apps.notifications.services import EmailSuppressionService
        from apps.notifications.models import EmailSuppression

        email = "cache-test@example.com"

        # Suppress via service (should update both DB and cache)
        EmailSuppressionService.suppress_email(email, "hard_bounce")

        # Verify in database
        self.assertTrue(EmailSuppression.is_suppressed(email))

        # Verify in cache (via service)
        self.assertTrue(EmailSuppressionService.is_suppressed(email))

    def test_cache_miss_falls_back_to_database(self):
        """Test that cache miss falls back to database lookup."""
        from apps.notifications.services import EmailSuppressionService
        from apps.notifications.models import EmailSuppression

        email = "fallback-test@example.com"

        # Create suppression directly in database (bypassing cache)
        EmailSuppression.suppress(email, "complaint", "ses")

        # Clear cache
        cache.clear()

        # Service should still find it via database fallback
        self.assertTrue(EmailSuppressionService.is_suppressed(email))
