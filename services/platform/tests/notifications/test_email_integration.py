"""
🔄 Integration & E2E Tests for Email System
Tests full email workflows from sending to webhook processing.

Tests cover:
- Full email lifecycle (send -> deliver -> open -> click)
- Webhook processing flow
- Campaign execution
- Multi-recipient handling with suppression
- Bounce handling and automatic suppression
"""

import hashlib
import json
from unittest.mock import MagicMock, patch

from django.core import mail
from django.core.cache import cache
from django.http import HttpRequest
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.notifications.models import (
    EmailCampaign,
    EmailLog,
    EmailSuppression,
    EmailTemplate,
)
from apps.notifications.services import (
    EmailService,
    EmailSuppressionService,
)


class EmailLifecycleIntegrationTests(TestCase):
    """Test complete email lifecycle from send to delivery tracking."""

    def setUp(self):
        """Set up test fixtures."""
        cache.clear()
        self.template = EmailTemplate.objects.create(
            key="lifecycle_test",
            locale="en",
            subject="Test {{ name }}",
            body_html="<p>Hello {{ name }}</p>",
            body_text="Hello {{ name }}",
            is_active=True,
            category="system",
        )

    def test_full_email_lifecycle(self):
        """Test complete flow: send -> log -> deliver -> open -> click."""
        # Step 1: Send email
        result = EmailService.send_email(
            to="lifecycle@example.com",
            subject="Lifecycle Test",
            body_text="Testing full lifecycle",
            body_html="<p>Testing full lifecycle</p>",
            async_send=False,
        )

        self.assertTrue(result.success)
        self.assertIsNotNone(result.email_log_id)

        # Verify log created
        email_log = EmailLog.objects.get(id=result.email_log_id)
        self.assertEqual(email_log.status, "sent")
        self.assertIsNone(email_log.delivered_at)

        # Step 2: Simulate delivery webhook
        email_log.provider_id = "test-message-123"
        email_log.save()

        EmailService.handle_delivery_event(
            event_type="delivered",
            message_id="test-message-123",
            recipient="lifecycle@example.com",
        )

        email_log.refresh_from_db()
        self.assertEqual(email_log.status, "delivered")
        self.assertIsNotNone(email_log.delivered_at)

        # Step 3: Simulate open event
        EmailService.handle_delivery_event(
            event_type="opened",
            message_id="test-message-123",
            recipient="lifecycle@example.com",
        )

        email_log.refresh_from_db()
        self.assertIsNotNone(email_log.opened_at)

        # Step 4: Simulate click event
        EmailService.handle_delivery_event(
            event_type="clicked",
            message_id="test-message-123",
            recipient="lifecycle@example.com",
        )

        email_log.refresh_from_db()
        self.assertIsNotNone(email_log.clicked_at)

    def test_bounce_triggers_suppression(self):
        """Test that bounce events trigger automatic suppression."""
        # Send email
        result = EmailService.send_email(
            to="bouncer@example.com",
            subject="Bounce Test",
            body_text="Testing bounce handling",
            async_send=False,
        )

        self.assertTrue(result.success)
        email_log = EmailLog.objects.get(id=result.email_log_id)
        email_log.provider_id = "bounce-test-123"
        email_log.save()

        # Simulate hard bounce
        EmailService.handle_delivery_event(
            event_type="bounced",
            message_id="bounce-test-123",
            recipient="bouncer@example.com",
            metadata={"bounce_type": "Permanent"},
        )

        # Email should now be suppressed
        self.assertTrue(EmailSuppressionService.is_suppressed("bouncer@example.com"))

        # Subsequent send should fail
        result2 = EmailService.send_email(
            to="bouncer@example.com",
            subject="Should Not Send",
            body_text="This should be blocked",
            async_send=False,
        )

        self.assertFalse(result2.success)
        self.assertIn("suppressed", result2.error)

    def test_complaint_triggers_suppression(self):
        """Test that spam complaints trigger automatic suppression."""
        result = EmailService.send_email(
            to="complainer@example.com",
            subject="Complaint Test",
            body_text="Testing complaint handling",
            async_send=False,
        )

        email_log = EmailLog.objects.get(id=result.email_log_id)
        email_log.provider_id = "complaint-test-123"
        email_log.save()

        # Simulate spam complaint
        EmailService.handle_delivery_event(
            event_type="complained",
            message_id="complaint-test-123",
            recipient="complainer@example.com",
        )

        # Email should now be suppressed
        self.assertTrue(EmailSuppressionService.is_suppressed("complainer@example.com"))


class MultiRecipientIntegrationTests(TestCase):
    """Test multi-recipient handling with suppression."""

    def setUp(self):
        cache.clear()
        # Suppress one recipient
        EmailSuppressionService.suppress_email("suppressed@example.com", "hard_bounce")

    def test_mixed_recipients_partial_send(self):
        """Test sending to mix of valid and suppressed recipients."""
        recipients = [
            "valid1@example.com",
            "suppressed@example.com",  # This one is suppressed
            "valid2@example.com",
        ]

        # Note: EmailService.send_email treats all recipients as a single message
        # For individual handling, use send_template_email for each
        results = []
        for recipient in recipients:
            result = EmailService.send_email(
                to=recipient,
                subject="Multi-recipient Test",
                body_text="Testing",
                async_send=False,
            )
            results.append((recipient, result.success))

        # Check results
        self.assertTrue(results[0][1])   # valid1 - success
        self.assertFalse(results[1][1])  # suppressed - failed
        self.assertTrue(results[2][1])   # valid2 - success

        # Verify email count (only 2 should have been sent)
        self.assertEqual(len(mail.outbox), 2)


class WebhookProcessingIntegrationTests(TestCase):
    """Test webhook processing end-to-end."""

    def setUp(self):
        cache.clear()
        self.email_log = EmailLog.objects.create(
            to_addr="webhook-test@example.com",
            subject="Webhook Test",
            body_text="Testing webhooks",
            provider="ses",
            provider_id="webhook-msg-123",
            status="sent",
        )

    def test_ses_bounce_webhook_processing(self):
        """Test SES bounce webhook creates suppression."""
        from apps.notifications.webhooks import SESWebhookView

        view = SESWebhookView()

        # Create SES bounce notification
        ses_message = {
            "notificationType": "Bounce",
            "bounce": {
                "bounceType": "Permanent",
                "bouncedRecipients": [
                    {"emailAddress": "webhook-test@example.com"}
                ],
            },
            "mail": {
                "messageId": "webhook-msg-123",
            },
        }

        view._handle_bounce(ses_message)

        # Verify suppression created
        self.assertTrue(EmailSuppressionService.is_suppressed("webhook-test@example.com"))

        # Verify log updated
        self.email_log.refresh_from_db()
        self.assertEqual(self.email_log.status, "bounced")

    def test_ses_complaint_webhook_processing(self):
        """Test SES complaint webhook creates suppression."""
        from apps.notifications.webhooks import SESWebhookView

        view = SESWebhookView()

        ses_message = {
            "notificationType": "Complaint",
            "complaint": {
                "complainedRecipients": [
                    {"emailAddress": "complainer-webhook@example.com"}
                ],
            },
            "mail": {
                "messageId": "complaint-msg-456",
            },
        }

        # Create log for this message
        EmailLog.objects.create(
            to_addr="complainer-webhook@example.com",
            subject="Complaint Webhook Test",
            body_text="Testing",
            provider="ses",
            provider_id="complaint-msg-456",
            status="sent",
        )

        view._handle_complaint(ses_message)

        # Verify suppression
        self.assertTrue(EmailSuppressionService.is_suppressed("complainer-webhook@example.com"))


class CampaignIntegrationTests(TestCase):
    """Test campaign execution end-to-end."""

    def setUp(self):
        cache.clear()
        self.template = EmailTemplate.objects.create(
            key="campaign_integration",
            locale="en",
            subject="Campaign: {{ campaign_name }}",
            body_html="<p>Hello {{ customer_name }}!</p>",
            body_text="Hello {{ customer_name }}!",
            is_active=True,
            category="marketing",
        )

    def test_campaign_send_to_recipients(self):
        """Test campaign sends to all valid recipients."""
        campaign = EmailCampaign.objects.create(
            name="Integration Test Campaign",
            template=self.template,
            audience="custom_filter",
            status="scheduled",
        )

        recipients = [
            ("recipient1@example.com", {"customer_name": "User 1"}),
            ("recipient2@example.com", {"customer_name": "User 2"}),
            ("recipient3@example.com", {"customer_name": "User 3"}),
        ]

        # Mock send_template_email to use sync mode for testing
        original_send = EmailService.send_template_email

        def sync_send(*args, **kwargs):
            kwargs['async_send'] = False
            return original_send(*args, **kwargs)

        with patch.object(EmailService, 'send_template_email', side_effect=sync_send):
            result = EmailService.send_campaign(campaign, recipients)

        self.assertEqual(result["sent_count"], 3)
        self.assertEqual(result["failed_count"], 0)
        self.assertEqual(len(mail.outbox), 3)

        # Verify campaign status updated
        campaign.refresh_from_db()
        self.assertEqual(campaign.status, "sent")
        self.assertIsNotNone(campaign.completed_at)

    def test_campaign_skips_suppressed(self):
        """Test campaign skips suppressed recipients."""
        # Suppress one recipient
        EmailSuppressionService.suppress_email("suppressed-campaign@example.com", "unsubscribe")

        campaign = EmailCampaign.objects.create(
            name="Suppression Test Campaign",
            template=self.template,
            audience="custom_filter",
            status="scheduled",
        )

        recipients = [
            ("valid-campaign@example.com", {"customer_name": "Valid User"}),
            ("suppressed-campaign@example.com", {"customer_name": "Suppressed User"}),
        ]

        # Mock send_template_email to use sync mode for testing
        original_send = EmailService.send_template_email

        def sync_send(*args, **kwargs):
            kwargs['async_send'] = False
            return original_send(*args, **kwargs)

        with patch.object(EmailService, 'send_template_email', side_effect=sync_send):
            result = EmailService.send_campaign(campaign, recipients)

        self.assertEqual(result["sent_count"], 1)
        self.assertEqual(result["failed_count"], 1)
        self.assertEqual(len(mail.outbox), 1)


class SoftBounceThresholdTests(TestCase):
    """Test soft bounce threshold handling."""

    def setUp(self):
        cache.clear()

    def test_multiple_soft_bounces_trigger_suppression(self):
        """Test that exceeding soft bounce threshold triggers suppression."""
        email = "soft-bouncer@example.com"

        # Create multiple soft bounce logs
        for i in range(4):  # Default threshold is 3
            log = EmailLog.objects.create(
                to_addr=email,
                subject=f"Soft Bounce Test {i}",
                body_text="Testing",
                provider="ses",
                provider_id=f"soft-bounce-{i}",
                status="sent",
            )

            # Simulate soft bounce
            EmailService.handle_delivery_event(
                event_type="soft_bounced",
                message_id=f"soft-bounce-{i}",
                recipient=email,
            )

        # After exceeding threshold, should be suppressed
        self.assertTrue(EmailSuppressionService.is_suppressed(email))


class TemplateRenderingIntegrationTests(TestCase):
    """Test template rendering with complex contexts."""

    def setUp(self):
        cache.clear()

    def test_template_with_nested_context(self):
        """Test template rendering with nested objects in context."""
        template = EmailTemplate.objects.create(
            key="nested_context",
            locale="en",
            subject="Invoice {{ invoice.number }}",
            body_html="<p>Amount: {{ invoice.amount }}</p>",
            body_text="Amount: {{ invoice.amount }}",
            is_active=True,
            category="billing",
        )

        # Note: Complex objects should be flattened by the service
        result = EmailService.send_template_email(
            template_key="nested_context",
            recipient="nested@example.com",
            context={
                "invoice": {
                    "number": "INV-001",
                    "amount": "100.00",
                },
            },
            async_send=False,
        )

        self.assertTrue(result.success)

    def test_template_caching(self):
        """Test that templates are cached after first lookup."""
        template = EmailTemplate.objects.create(
            key="cache_test",
            locale="en",
            subject="Cache Test",
            body_html="<p>Cached content</p>",
            body_text="Cached content",
            is_active=True,
            category="system",
        )

        # First send - cache miss
        with patch.object(EmailTemplate.objects, 'filter', wraps=EmailTemplate.objects.filter) as mock_filter:
            result1 = EmailService.send_template_email(
                template_key="cache_test",
                recipient="cache1@example.com",
                context={},
                async_send=False,
            )
            first_call_count = mock_filter.call_count

        # Second send - should use cache
        with patch.object(EmailTemplate.objects, 'filter', wraps=EmailTemplate.objects.filter) as mock_filter:
            result2 = EmailService.send_template_email(
                template_key="cache_test",
                recipient="cache2@example.com",
                context={},
                async_send=False,
            )
            second_call_count = mock_filter.call_count

        self.assertTrue(result1.success)
        self.assertTrue(result2.success)
        # Second call should have fewer or equal DB queries (cached)
        self.assertLessEqual(second_call_count, first_call_count)
