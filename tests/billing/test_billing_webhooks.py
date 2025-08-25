# ===============================================================================
# BILLING WEBHOOKS TESTS
# ===============================================================================
from typing import Any

from django.test import TestCase, override_settings

from apps.integrations.webhooks.stripe import StripeWebhookProcessor


class StripeWebhookProcessorTests(TestCase):
    """Tests for Stripe webhook processing and deduplication"""

    def setUp(self) -> None:
        self.processor = StripeWebhookProcessor()
        self.payload: dict[str, Any] = {
            'id': 'evt_test_1',
            'type': 'payment_intent.succeeded',
            'data': {'object': {'id': 'pi_123', 'amount_received': 1000}}
        }

    def test_extract_event_id(self) -> None:
        """Test event ID extraction from payload"""
        event_id = self.processor.extract_event_id(self.payload)
        self.assertEqual(event_id, 'evt_test_1')

    def test_extract_event_type(self) -> None:
        """Test event type extraction from payload"""
        event_type = self.processor.extract_event_type(self.payload)
        self.assertEqual(event_type, 'payment_intent.succeeded')

    @override_settings(STRIPE_WEBHOOK_SECRET=None)
    def test_verify_signature_skipped_in_dev_when_secret_missing(self) -> None:
        """Test that signature verification is skipped when secret is missing"""
        result = self.processor.verify_signature(self.payload, signature='', headers={})
        self.assertTrue(result)

    @override_settings(STRIPE_WEBHOOK_SECRET='test_secret')
    def test_verify_signature_with_secret_configured(self) -> None:
        """Test signature verification when secret is configured"""
        # This should fail with invalid signature
        result = self.processor.verify_signature(self.payload, signature='invalid', headers={})
        self.assertFalse(result)
