"""
Tests for webhook redelivery of failed events (#234).

A duplicate check that treats a FAILED event the same as a PROCESSED one returns HTTP 200 to the
sender on retry, so the sender (Stripe) stops retrying and the event is never reprocessed — a
payment webhook that hit a transient error is left permanently unhandled.
"""

from __future__ import annotations

from typing import Any

from django.test import TestCase

from apps.integrations.models import WebhookEvent
from apps.integrations.webhooks.base import BaseWebhookProcessor


class _ScriptedProcessor(BaseWebhookProcessor):
    """A processor whose handle_event outcome and signature validity are set per instance."""

    source_name = "test"

    def __init__(self, *, should_succeed: bool) -> None:
        super().__init__()
        self._should_succeed = should_succeed
        self.handle_calls = 0

    def verify_signature(
        self, payload: dict[str, Any], signature: str, headers: dict[str, str], raw_body: bytes | None = None
    ) -> bool:
        # Accept only this suite's real signature; the base class probes with garbage inputs and
        # rejects any processor that accepts them, so a blanket True is not allowed.
        return signature == "valid-test-sig"

    def handle_event(self, webhook_event: WebhookEvent) -> tuple[bool, str]:
        self.handle_calls += 1
        if self._should_succeed:
            return True, "handled"
        return False, "transient downstream error"


class WebhookFailedRedeliveryTestCase(TestCase):
    """#234: a redelivered event that previously FAILED must be reprocessed, not deduped to 200."""

    def setUp(self) -> None:
        WebhookEvent.objects.all().delete()
        self.payload = {"id": "evt_123", "type": "payment_intent.succeeded"}

    def _deliver(self, processor: BaseWebhookProcessor) -> tuple[bool, str, WebhookEvent | None]:
        return processor.process_webhook(self.payload, signature="valid-test-sig", headers={})

    def test_first_delivery_that_fails_is_recorded_failed(self) -> None:
        success, _message, event = self._deliver(_ScriptedProcessor(should_succeed=False))

        self.assertFalse(success)
        self.assertEqual(event.status, "failed")

    def test_redelivery_of_a_failed_event_reprocesses_it(self) -> None:
        """The whole point of #234: Stripe's retry of a transiently-failed webhook must re-run.

        Before the fix the retry was deduped to a success and the handler never ran again.
        """
        first = _ScriptedProcessor(should_succeed=False)
        self._deliver(first)

        # Stripe retries; this time the downstream error has cleared.
        second = _ScriptedProcessor(should_succeed=True)
        success, _message, event = self._deliver(second)

        self.assertEqual(second.handle_calls, 1, "handler must run again on redelivery of a failed event")
        self.assertTrue(success)
        self.assertEqual(event.status, "processed")
        # The same row is reused, not a second one (unique_together (source, event_id)).
        self.assertEqual(WebhookEvent.objects.filter(source="test", event_id="evt_123").count(), 1)

    def test_redelivery_of_a_processed_event_is_a_true_duplicate(self) -> None:
        """Non-regression: once processed, a redelivery is skipped without re-running the handler."""
        self._deliver(_ScriptedProcessor(should_succeed=True))

        second = _ScriptedProcessor(should_succeed=True)
        success, _message, _event = self._deliver(second)

        self.assertEqual(second.handle_calls, 0, "a processed event must not be handled twice")
        self.assertTrue(success)
        self.assertEqual(WebhookEvent.objects.filter(source="test", event_id="evt_123").count(), 1)

    def test_is_duplicate_only_true_for_processed_events(self) -> None:
        """The status-aware guard: a failed/pending row is not a duplicate; a processed one is."""
        WebhookEvent.objects.create(source="test", event_id="evt_failed", event_type="x", payload={}, status="failed")
        WebhookEvent.objects.create(source="test", event_id="evt_done", event_type="x", payload={}, status="processed")
        WebhookEvent.objects.create(source="test", event_id="evt_pending", event_type="x", payload={}, status="pending")

        self.assertFalse(WebhookEvent.is_duplicate("test", "evt_failed"))
        self.assertFalse(WebhookEvent.is_duplicate("test", "evt_pending"))
        self.assertTrue(WebhookEvent.is_duplicate("test", "evt_done"))
