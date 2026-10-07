"""Signature-hash access must not abort the remaining webhook security analysis."""

from django.test import TestCase

from apps.audit.models import AuditEvent
from apps.integrations.models import WebhookEvent


class WebhookSecurityIndicatorTests(TestCase):
    def test_failure_audit_records_security_indicators_with_and_without_a_signature(self) -> None:
        for signature in ("incoming-signature", ""):
            with self.subTest(signature_present=bool(signature)):
                webhook = WebhookEvent(
                    source="stripe",
                    event_id=f"evt_security_{bool(signature)}",
                    event_type="payment_intent.succeeded",
                    payload={},
                )
                webhook.set_signature(signature)
                webhook.save()

                webhook.mark_failed("Invalid signature; malformed payload; rate limit exceeded")

                audit = AuditEvent.objects.get(action="webhook_delivery_failure", object_id=str(webhook.pk))
                flags = audit.metadata["security_indicators"]
                self.assertEqual(flags["invalid_signature"], bool(signature))
                self.assertIs(flags["malformed_payload"], True)
                self.assertIs(flags["rate_limit_exceeded"], True)
