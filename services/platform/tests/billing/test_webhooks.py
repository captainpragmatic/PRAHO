# ===============================================================================
# BILLING WEBHOOKS TESTS
# ===============================================================================
from typing import Any

from django.test import TestCase, override_settings

from apps.customers.models import Customer
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
    def test_verify_signature_fails_secure_when_secret_missing(self) -> None:
        """Test that signature verification fails secure when secret is missing"""
        result = self.processor.verify_signature(self.payload, signature='', headers={})
        self.assertFalse(result)  # Should fail secure

    @override_settings(STRIPE_WEBHOOK_SECRET='test_secret')
    def test_verify_signature_with_secret_configured(self) -> None:
        """Test signature verification when secret is configured"""
        # This should fail with invalid signature
        result = self.processor.verify_signature(self.payload, signature='invalid', headers={})
        self.assertFalse(result)

    def test_customer_created_preserves_established_customer_id_and_metadata(self) -> None:
        """A delayed webhook must not replace the customer ID selected by the locked writer."""
        customer = Customer.objects.create(
            name="Webhook Merge SRL",
            customer_type="company",
            status="active",
            primary_email="webhook-merge@example.com",
            meta={
                "stripe_customer_id": "cus_concurrent_winner",
                "credit_balance_cents": 900,
            },
        )
        payload = {
            "data": {
                "object": {
                    "id": "cus_delayed_webhook",
                    "email": customer.primary_email,
                }
            }
        }

        success, _message = self.processor.handle_customer_event("customer.created", payload)

        self.assertTrue(success)
        customer.refresh_from_db()
        self.assertEqual(customer.meta["stripe_customer_id"], "cus_concurrent_winner")
        self.assertEqual(customer.meta["credit_balance_cents"], 900)
        self.assertIn("stripe_linked_at", customer.meta)
