"""Webhook processing survives optional audit failures."""

from unittest.mock import patch

from django.db import transaction

from apps.audit.models import AuditEvent
from apps.audit.services import AuditService
from apps.integrations.models import WebhookEvent
from tests.common._signal_isolation import SignalIsolationTestCase


class WebhookSignalIsolationTests(SignalIsolationTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.event = WebhookEvent.objects.create(source="other", event_id="isolation", event_type="test", payload={})

    def test_processed_status_survives_failed_audit_write(self) -> None:
        self.event.status = "processed"
        self.run_effect(
            "apps.integrations.signals.IntegrationsAuditService.log_webhook_success",
            lambda: self.event.save(update_fields=["status"]),
        )
        self.assertEqual(WebhookEvent.objects.get(pk=self.event.pk).status, "processed")

    def test_failure_audit_does_not_prevent_retry_exhaustion_audit(self) -> None:
        def record_exhaustion(*args: object, **kwargs: object) -> None:
            AuditService.log_simple_event(event_type="test_retry_exhaustion", content_object=self.event)

        self.event.status = "failed"
        self.event.retry_count = 5
        with (
            patch(
                "apps.integrations.signals.IntegrationsAuditService.log_webhook_failure", side_effect=self.fail_write
            ),
            patch("apps.integrations.signals.IntegrationsAuditService.log_webhook_retry_exhausted", record_exhaustion),
            transaction.atomic(),
        ):
            self.event.save(update_fields=["status", "retry_count"])
        self.assertEqual(WebhookEvent.objects.get(pk=self.event.pk).retry_count, 5)
        self.assertTrue(
            AuditEvent.objects.filter(action="test_retry_exhaustion", object_id=str(self.event.pk)).exists()
        )
