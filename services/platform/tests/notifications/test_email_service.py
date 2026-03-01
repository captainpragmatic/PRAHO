"""
Comprehensive tests for PRAHO Email Service.

Tests:
- Email sending (sync and async)
- Template-based emails
- Rate limiting
- Suppression handling
- Bounce/complaint processing
- Email preferences
"""

import hashlib
from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.core import mail
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.notifications.models import (
    EmailCampaign,
    EmailLog,
    EmailPreference,
    EmailSuppression,
    EmailTemplate,
)
from apps.notifications.services import (
    EmailPreferenceService,
    EmailRateLimiter,
    EmailResult,
    EmailService,
    EmailSuppressionService,
    render_template_safely,
    validate_template_context,
)
from config.settings.test import LOCMEM_TEST_CACHE


class EmailServiceBasicTests(TestCase):
    """Test basic email service functionality."""

    def setUp(self):
        """Set up test fixtures."""
        # Clear suppression list and cache to avoid cross-test contamination
        EmailSuppression.objects.all().delete()
        from django.core.cache import cache
        cache.clear()

        self.template = EmailTemplate.objects.create(
            key="test_template",
            locale="en",
            subject="Test Subject: {{ name }}",
            body_html="<p>Hello {{ name }}!</p>",
            body_text="Hello {{ name }}!",
            is_active=True,
            category="system",
        )

    def test_send_email_sync_success(self):
        """Test synchronous email sending."""
        result = EmailService.send_email(
            to="test@example.com",
            subject="Test Email",
            body_text="This is a test email",
            body_html="<p>This is a test email</p>",
            async_send=False,
        )

        self.assertTrue(result.success)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].subject, "Test Email")
        self.assertEqual(mail.outbox[0].to, ["test@example.com"])

    def test_send_email_creates_log(self):
        """Test that email sending creates a log entry."""
        result = EmailService.send_email(
            to="test@example.com",
            subject="Test Email",
            body_text="This is a test email",
            async_send=False,
        )

        self.assertTrue(result.success)
        self.assertIsNotNone(result.email_log_id)

        # Verify log was created
        log = EmailLog.objects.get(id=result.email_log_id)
        self.assertEqual(log.to_addr, "test@example.com")
        self.assertEqual(log.subject, "Test Email")
        self.assertEqual(log.status, "sent")

    def test_send_email_multiple_recipients(self):
        """Test sending email to multiple recipients."""
        result = EmailService.send_email(
            to=["test1@example.com", "test2@example.com"],
            subject="Test Email",
            body_text="This is a test email",
            async_send=False,
        )

        self.assertTrue(result.success)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ["test1@example.com", "test2@example.com"])

    def test_send_email_with_cc_bcc(self):
        """Test sending email with CC and BCC."""
        result = EmailService.send_email(
            to="test@example.com",
            subject="Test Email",
            body_text="This is a test email",
            cc=["cc@example.com"],
            bcc=["bcc@example.com"],
            async_send=False,
        )

        self.assertTrue(result.success)
        self.assertEqual(mail.outbox[0].cc, ["cc@example.com"])
        self.assertEqual(mail.outbox[0].bcc, ["bcc@example.com"])


class EmailServiceTemplateTests(TestCase):
    """Test template-based email sending."""

    def setUp(self):
        """Set up test fixtures."""
        # Clear suppression list and cache to avoid cross-test contamination
        EmailSuppression.objects.all().delete()
        from django.core.cache import cache
        cache.clear()

        self.template_en = EmailTemplate.objects.create(
            key="welcome",
            locale="en",
            subject="Welcome {{ customer_name }}!",
            body_html="<h1>Welcome {{ customer_name }}!</h1><p>Thank you for joining.</p>",
            body_text="Welcome {{ customer_name }}! Thank you for joining.",
            is_active=True,
            category="welcome",
        )
        self.template_ro = EmailTemplate.objects.create(
            key="welcome",
            locale="ro",
            subject="Bine ai venit {{ customer_name }}!",
            body_html="<h1>Bine ai venit {{ customer_name }}!</h1><p>Multumim ca te-ai alaturat.</p>",
            body_text="Bine ai venit {{ customer_name }}! Multumim ca te-ai alaturat.",
            is_active=True,
            category="welcome",
        )

    def test_send_template_email_english(self):
        """Test sending template email in English."""
        result = EmailService.send_template_email(
            template_key="welcome",
            recipient="test@example.com",
            context={"customer_name": "John Doe"},
            locale="en",
            async_send=False,
        )

        self.assertTrue(result.success)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("Welcome John Doe!", mail.outbox[0].subject)

    def test_send_template_email_romanian(self):
        """Test sending template email in Romanian."""
        result = EmailService.send_template_email(
            template_key="welcome",
            recipient="test@example.com",
            context={"customer_name": "Ion Popescu"},
            locale="ro",
            async_send=False,
        )

        self.assertTrue(result.success)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("Bine ai venit Ion Popescu!", mail.outbox[0].subject)

    def test_send_template_email_fallback_to_english(self):
        """Test fallback to English when locale template not found."""
        result = EmailService.send_template_email(
            template_key="welcome",
            recipient="test@example.com",
            context={"customer_name": "Test User"},
            locale="de",  # German - not available
            async_send=False,
        )

        self.assertTrue(result.success)
        self.assertIn("Welcome Test User!", mail.outbox[0].subject)

    def test_send_template_email_not_found(self):
        """Test error when template not found."""
        result = EmailService.send_template_email(
            template_key="nonexistent_template",
            recipient="test@example.com",
            context={},
            async_send=False,
        )

        self.assertFalse(result.success)
        self.assertIn("Template not found", result.error)

    def test_send_template_email_inactive(self):
        """Test error when template is inactive."""
        self.template_en.is_active = False
        self.template_en.save()

        result = EmailService.send_template_email(
            template_key="welcome",
            recipient="test@example.com",
            context={"customer_name": "Test"},
            locale="en",
            async_send=False,
        )

        self.assertFalse(result.success)
        self.assertIn("inactive", result.error)


class EmailSuppressionTests(TestCase):
    """Test email suppression functionality."""

    def test_suppress_email(self):
        """Test adding email to suppression list."""
        EmailSuppressionService.suppress_email("test@example.com", "hard_bounce")

        self.assertTrue(EmailSuppressionService.is_suppressed("test@example.com"))

    def test_suppress_email_temporary(self):
        """Test temporary email suppression."""
        EmailSuppressionService.suppress_email("test@example.com", "soft_bounce", duration_days=7)

        self.assertTrue(EmailSuppressionService.is_suppressed("test@example.com"))

    def test_unsuppress_email(self):
        """Test removing email from suppression list."""
        EmailSuppressionService.suppress_email("test@example.com", "hard_bounce")
        self.assertTrue(EmailSuppressionService.is_suppressed("test@example.com"))

        result = EmailSuppressionService.unsuppress_email("test@example.com")
        self.assertTrue(result)
        self.assertFalse(EmailSuppressionService.is_suppressed("test@example.com"))

    def test_send_to_suppressed_email(self):
        """Test that sending to suppressed email fails gracefully."""
        EmailSuppressionService.suppress_email("suppressed@example.com", "hard_bounce")

        result = EmailService.send_email(
            to="suppressed@example.com",
            subject="Test",
            body_text="Test",
            async_send=False,
        )

        self.assertFalse(result.success)
        self.assertIn("suppressed", result.error)
        self.assertEqual(len(mail.outbox), 0)


class EmailSuppressionModelTests(TestCase):
    """Test EmailSuppression model."""

    def test_create_suppression(self):
        """Test creating suppression record."""
        suppression = EmailSuppression.suppress(
            email="test@example.com",
            reason="hard_bounce",
            provider="ses",
        )

        self.assertIsNotNone(suppression.id)
        self.assertEqual(suppression.reason, "hard_bounce")
        self.assertEqual(suppression.provider, "ses")

    def test_suppression_is_suppressed(self):
        """Test checking if email is suppressed via model."""
        EmailSuppression.suppress("test@example.com", "complaint")

        self.assertTrue(EmailSuppression.is_suppressed("test@example.com"))
        self.assertFalse(EmailSuppression.is_suppressed("other@example.com"))

    def test_suppression_case_insensitive(self):
        """Test suppression is case insensitive."""
        EmailSuppression.suppress("Test@Example.COM", "complaint")

        self.assertTrue(EmailSuppression.is_suppressed("test@example.com"))
        self.assertTrue(EmailSuppression.is_suppressed("TEST@EXAMPLE.COM"))


@override_settings(CACHES=LOCMEM_TEST_CACHE)
class EmailRateLimitTests(TestCase):
    """Test email rate limiting — needs real cache for rate limit counters."""

    def setUp(self):
        cache.clear()

    def test_check_rate_limit_allows(self):
        """Test rate limit allows when under limit."""
        allowed, remaining = EmailRateLimiter.check_rate_limit("test")

        self.assertTrue(allowed)
        self.assertGreater(remaining, 0)

    def test_increment_counter(self):
        """Test rate limit counter increment."""
        # Get initial count
        _, initial_remaining = EmailRateLimiter.check_rate_limit("test_increment")

        # Increment
        EmailRateLimiter.increment_counter("test_increment")

        # Check decreased
        _, new_remaining = EmailRateLimiter.check_rate_limit("test_increment")
        self.assertEqual(new_remaining, initial_remaining - 1)


class TemplateValidationTests(TestCase):
    """Test template rendering and validation."""

    def test_validate_context_safe(self):
        """Test safe context passes validation."""
        context = {
            "customer_name": "John Doe",
            "amount": "100.00",
            "date": "2024-01-01",
        }

        result = validate_template_context(context)
        self.assertEqual(result["customer_name"], "John Doe")

    def test_validate_context_xss_sanitized(self):
        """Test XSS content is sanitized."""
        context = {
            "name": '<script>alert("xss")</script>John',
        }

        result = validate_template_context(context)
        self.assertNotIn("<script>", result["name"])
        self.assertNotIn("alert", result["name"])

    def test_validate_context_truncates_long_values(self):
        """Test long values are truncated."""
        context = {
            "long_value": "x" * 2000,
        }

        result = validate_template_context(context)
        self.assertLessEqual(len(result["long_value"]), 1000)

    def test_render_template_safely(self):
        """Test safe template rendering."""
        template = "Hello {{ name }}, your balance is {{ amount }}."
        context = {"name": "John", "amount": "100.00"}

        result = render_template_safely(template, context)
        self.assertEqual(result, "Hello John, your balance is 100.00.")

    def test_render_template_missing_variable(self):
        """Test template rendering with missing variable."""
        template = "Hello {{ name }}, your balance is {{ amount }}."
        context = {"name": "John"}  # Missing amount

        result = render_template_safely(template, context)
        self.assertIn("Hello John", result)


class EmailPreferenceModelTests(TestCase):
    """Test EmailPreference model."""

    def setUp(self):
        """Set up test fixtures."""
        from apps.customers.models import Customer

        self.customer = Customer.objects.create(
            name="Test Customer",
            customer_type="individual",
            primary_email="test@example.com",
        )
        self.preference = EmailPreference.objects.create(
            customer=self.customer,
        )

    def test_default_preferences(self):
        """Test default email preferences."""
        self.assertTrue(self.preference.transactional)
        self.assertTrue(self.preference.billing)
        self.assertTrue(self.preference.service)
        self.assertTrue(self.preference.security)
        self.assertFalse(self.preference.marketing)
        self.assertFalse(self.preference.newsletter)

    def test_can_receive_transactional(self):
        """Test transactional emails always allowed."""
        self.assertTrue(self.preference.can_receive("transactional"))
        self.assertTrue(self.preference.can_receive("billing"))
        self.assertTrue(self.preference.can_receive("security"))

    def test_can_receive_marketing_requires_consent(self):
        """Test marketing requires consent."""
        self.assertFalse(self.preference.can_receive("marketing"))

        self.preference.marketing = True
        self.preference.save()

        self.assertTrue(self.preference.can_receive("marketing"))

    def test_global_unsubscribe_blocks_non_essential(self):
        """Test global unsubscribe blocks non-essential emails."""
        self.preference.global_unsubscribe = True
        self.preference.save()

        # Critical always allowed
        self.assertTrue(self.preference.can_receive("billing"))
        self.assertTrue(self.preference.can_receive("security"))

        # Non-essential blocked
        self.assertFalse(self.preference.can_receive("service"))
        self.assertFalse(self.preference.can_receive("marketing"))

    def test_update_marketing_consent(self):
        """Test updating marketing consent with tracking."""
        self.preference.update_marketing_consent(True, source="preference_center")

        self.assertTrue(self.preference.marketing)
        self.assertIsNotNone(self.preference.marketing_consent_date)
        self.assertEqual(self.preference.marketing_consent_source, "preference_center")


class DeliveryEventHandlerTests(TestCase):
    """Test email delivery event handling."""

    def setUp(self):
        """Set up test fixtures."""
        self.email_log = EmailLog.objects.create(
            to_addr="test@example.com",
            subject="Test Email",
            body_text="Test body",
            provider="ses",
            provider_id="test-message-id",
            status="sent",
        )

    def test_handle_delivered_event(self):
        """Test handling delivered event."""
        result = EmailService.handle_delivery_event(
            event_type="delivered",
            message_id="test-message-id",
            recipient="test@example.com",
        )

        self.assertTrue(result)
        self.email_log.refresh_from_db()
        self.assertEqual(self.email_log.status, "delivered")
        self.assertIsNotNone(self.email_log.delivered_at)

    def test_handle_bounced_event(self):
        """Test handling bounce event."""
        result = EmailService.handle_delivery_event(
            event_type="bounced",
            message_id="test-message-id",
            recipient="test@example.com",
        )

        self.assertTrue(result)
        self.email_log.refresh_from_db()
        self.assertEqual(self.email_log.status, "bounced")

    def test_handle_complained_event(self):
        """Test handling complaint event."""
        result = EmailService.handle_delivery_event(
            event_type="complained",
            message_id="test-message-id",
            recipient="test@example.com",
        )

        self.assertTrue(result)
        self.email_log.refresh_from_db()
        self.assertEqual(self.email_log.status, "complained")

    def test_handle_opened_event(self):
        """Test handling open tracking event."""
        result = EmailService.handle_delivery_event(
            event_type="opened",
            message_id="test-message-id",
            recipient="test@example.com",
        )

        self.assertTrue(result)
        self.email_log.refresh_from_db()
        self.assertIsNotNone(self.email_log.opened_at)

    def test_handle_clicked_event(self):
        """Test handling click tracking event."""
        result = EmailService.handle_delivery_event(
            event_type="clicked",
            message_id="test-message-id",
            recipient="test@example.com",
        )

        self.assertTrue(result)
        self.email_log.refresh_from_db()
        self.assertIsNotNone(self.email_log.clicked_at)


class EmailCampaignTests(TestCase):
    """Test email campaign functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.template = EmailTemplate.objects.create(
            key="campaign_template",
            locale="en",
            subject="Campaign: {{ subject }}",
            body_html="<p>{{ content }}</p>",
            body_text="{{ content }}",
            is_active=True,
            category="marketing",
        )
        self.campaign = EmailCampaign.objects.create(
            name="Test Campaign",
            template=self.template,
            audience="active_customers",
            status="draft",
        )

    def test_campaign_can_be_sent(self):
        """Test campaign can be sent check."""
        self.assertTrue(self.campaign.can_be_sent())

        self.campaign.status = "sent"
        self.assertFalse(self.campaign.can_be_sent())

    def test_campaign_success_rate(self):
        """Test campaign success rate calculation."""
        self.campaign.total_recipients = 100
        self.campaign.emails_sent = 95
        self.campaign.emails_failed = 5

        self.assertEqual(self.campaign.get_success_rate(), 95.0)

    def test_campaign_success_rate_zero_recipients(self):
        """Test success rate with zero recipients."""
        self.campaign.total_recipients = 0
        self.assertEqual(self.campaign.get_success_rate(), 0)
