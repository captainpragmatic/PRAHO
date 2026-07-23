"""Regression coverage for webhook authentication, retention, and identity handling."""

from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime, timedelta
from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from apps.customers.models import Customer
from apps.integrations.models import WebhookEvent
from apps.integrations.webhooks.base import verify_stripe_signature
from apps.integrations.webhooks.stripe import StripeWebhookProcessor


class StripeSignatureRotationTests(SimpleTestCase):
    """Stripe signs once per active secret while a webhook secret is rotating."""

    payload = b'{"id":"evt_rotation"}'
    secret = "whsec_active"
    now = datetime(2026, 7, 22, 10, 0, tzinfo=UTC)

    def _signature(self, timestamp: int, secret: str | None = None) -> str:
        signed_payload = f"{timestamp}.{self.payload.decode('utf-8')}".encode()
        return hmac.new((secret or self.secret).encode(), signed_payload, hashlib.sha256).hexdigest()

    def _verify(self, header: str, *, tolerance: int = 300) -> bool:
        with patch("apps.integrations.webhooks.base.timezone.now", return_value=self.now):
            return verify_stripe_signature(self.payload, header, self.secret, tolerance=tolerance)

    def test_accepts_matching_signature_when_it_is_not_the_last_v1(self) -> None:
        timestamp = int(self.now.timestamp())
        valid = self._signature(timestamp)

        self.assertTrue(self._verify(f"t={timestamp},v1={valid},v1=invalid"))

    def test_accepts_matching_signature_when_it_is_the_last_v1(self) -> None:
        timestamp = int(self.now.timestamp())
        valid = self._signature(timestamp)

        self.assertTrue(self._verify(f"t={timestamp},v1=invalid,v1={valid}"))

    def test_rejects_header_when_no_v1_signature_matches(self) -> None:
        timestamp = int(self.now.timestamp())

        self.assertFalse(self._verify(f"t={timestamp},v1=invalid,v1=also-invalid"))

    def test_accepts_timestamp_exactly_at_tolerance_boundary(self) -> None:
        timestamp = int(self.now.timestamp()) - 300

        self.assertTrue(self._verify(f"t={timestamp},v1={self._signature(timestamp)}"))

    def test_rejects_timestamp_older_than_tolerance(self) -> None:
        timestamp = int(self.now.timestamp()) - 301

        self.assertFalse(self._verify(f"t={timestamp},v1={self._signature(timestamp)}"))


class WebhookRetentionTests(TestCase):
    def _event(
        self,
        event_id: str,
        *,
        status: str,
        received_at: datetime,
        processed_at: datetime | None = None,
    ) -> WebhookEvent:
        return WebhookEvent.objects.create(
            source="stripe",
            event_id=event_id,
            event_type="test.event",
            status=status,
            payload={},
            received_at=received_at,
            processed_at=processed_at,
        )

    def test_cleanup_uses_received_at_only_when_terminal_processed_at_is_null(self) -> None:
        old = timezone.now() - timedelta(days=31)
        recent = timezone.now() - timedelta(days=29)
        old_processed = self._event("evt_processed", status="processed", received_at=old, processed_at=old)
        old_null_processed = self._event("evt_anaf", status="processed", received_at=old)
        old_null_skipped = self._event("evt_rate_limit", status="skipped", received_at=old)
        recent_null_skipped = self._event("evt_recent", status="skipped", received_at=recent)
        old_failed = self._event("evt_failed", status="failed", received_at=old)

        call_command("process_webhooks", "--cleanup", stdout=StringIO())

        self.assertFalse(WebhookEvent.objects.filter(pk=old_processed.pk).exists())
        self.assertFalse(WebhookEvent.objects.filter(pk=old_null_processed.pk).exists())
        self.assertFalse(WebhookEvent.objects.filter(pk=old_null_skipped.pk).exists())
        self.assertTrue(WebhookEvent.objects.filter(pk=recent_null_skipped.pk).exists())
        self.assertTrue(WebhookEvent.objects.filter(pk=old_failed.pk).exists())

    def test_stats_uses_the_same_terminal_retention_boundary_as_cleanup(self) -> None:
        old = timezone.now() - timedelta(days=31)
        self._event("evt_old_null", status="processed", received_at=old)
        output = StringIO()

        call_command("process_webhooks", "--stats", stdout=output)

        self.assertIn("1 old webhook records can be cleaned up", output.getvalue())


class StripeCustomerIdentityTests(TestCase):
    def setUp(self) -> None:
        self.processor = StripeWebhookProcessor()

    @staticmethod
    def _customer(name: str, email: str) -> Customer:
        return Customer.objects.create(
            name=name,
            customer_type="company",
            status="active",
            primary_email=email,
        )

    @staticmethod
    def _payload(email: str) -> dict[str, object]:
        return {"data": {"object": {"id": "cus_shared", "email": email}}}

    def test_customer_created_links_a_unique_email_match(self) -> None:
        customer = self._customer("Unique SRL", "unique@example.com")

        accepted, message = self.processor.handle_customer_event(
            "customer.created", self._payload(customer.primary_email)
        )

        self.assertTrue(accepted, message)
        customer.refresh_from_db()
        self.assertEqual(customer.meta["stripe_customer_id"], "cus_shared")

    def test_customer_created_acknowledges_ambiguous_email_without_linking_either_customer(self) -> None:
        first = self._customer("First SRL", "shared@example.com")
        second = self._customer("Second SRL", "shared@example.com")

        accepted, message = self.processor.handle_customer_event(
            "customer.created", self._payload("shared@example.com")
        )

        self.assertTrue(accepted, message)
        self.assertIn("ambiguous", message.lower())
        first.refresh_from_db()
        second.refresh_from_db()
        self.assertNotIn("stripe_customer_id", first.meta)
        self.assertNotIn("stripe_customer_id", second.meta)


class PermanentRejectionWordingTests(TestCase):
    """The permanent-rejection acknowledgement is used for charge and generic
    payload malformations too — its alert/response wording must be
    event-agnostic, not claim a 'refund rejection' (review of #374)."""

    def test_malformed_charge_acknowledgement_is_event_agnostic(self) -> None:
        processor = StripeWebhookProcessor()

        success, message = processor.handle_refund_event(
            "refund.updated", {"data": {"object": "not-a-dict"}}
        )

        self.assertTrue(success, "a permanently malformed payload is acknowledged, not retried")
        self.assertNotIn("refund rejection", message.lower())
        self.assertIn("Malformed", message)
