"""Webhook success audits persist signature hashes from real integration events."""

import hashlib
import json

from django.contrib.contenttypes.models import ContentType
from django.test import TestCase

from apps.audit.models import AuditEvent
from apps.integrations.models import WebhookEvent


class WebhookSignatureAuditTests(TestCase):
    def _processed_webhook(self, event_id: str, signature: str) -> WebhookEvent:
        webhook = WebhookEvent(
            source="stripe",
            event_id=event_id,
            event_type="payment_intent.succeeded",
            payload={"id": event_id},
        )
        webhook.set_signature(signature)
        webhook.save()
        webhook.mark_processed()
        return webhook

    def _persisted_audit(self, webhook: WebhookEvent) -> AuditEvent:
        events = AuditEvent.objects.filter(
            action="webhook_delivery_success",
            content_type=ContentType.objects.get_for_model(WebhookEvent),
            object_id=str(webhook.pk),
        )
        self.assertEqual(events.count(), 1)
        return events.get()

    def test_processed_webhook_audit_contains_only_the_signature_hash(self) -> None:
        signature = "private-provider-signature"
        webhook = self._processed_webhook("evt_audit_signed", signature)
        webhook.refresh_from_db()

        audit = self._persisted_audit(webhook)

        expected_hash = hashlib.sha256(signature.encode()).hexdigest()
        self.assertEqual(webhook.signature_hash, expected_hash)
        self.assertEqual(audit.metadata["security_context"]["signature_hash"], expected_hash)
        self.assertIs(audit.metadata["security_context"]["signature_verified"], True)
        self.assertNotIn(signature, json.dumps(audit.metadata))
        self.assertNotIn("signature", audit.metadata["security_context"])

    def test_unsigned_webhook_still_has_a_persisted_success_audit(self) -> None:
        webhook = self._processed_webhook("evt_audit_unsigned", "")

        audit = self._persisted_audit(webhook)

        self.assertEqual(audit.metadata["security_context"]["signature_hash"], "")
        self.assertIs(audit.metadata["security_context"]["signature_verified"], False)
