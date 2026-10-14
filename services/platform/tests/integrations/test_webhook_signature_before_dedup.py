"""A webhook must prove who sent it before the platform says anything about its event id.

The duplicate check used to run first. An unsigned POST that reused the id of an event the
platform had already processed was answered with success and the internal id of the stored
event, so anyone who guessed or saw an event id could confirm it and read that internal id.
"""

from __future__ import annotations

import json
from typing import Any

from django.core.cache import cache
from django.test import TestCase
from django.urls import reverse

from apps.integrations.models import WebhookEvent
from apps.integrations.webhooks.base import BaseWebhookProcessor

VALID_SIGNATURE = "valid-test-sig"


class _SignedProcessor(BaseWebhookProcessor):
    source_name = "test"

    def __init__(self) -> None:
        super().__init__()
        self.handle_calls = 0

    def verify_signature(
        self, payload: dict[str, Any], signature: str, headers: dict[str, str], raw_body: bytes | None = None
    ) -> bool:
        return signature == VALID_SIGNATURE

    def handle_event(self, webhook_event: WebhookEvent) -> tuple[bool, str]:
        self.handle_calls += 1
        return True, "handled"


class ProcessorOrderingTests(TestCase):
    def setUp(self) -> None:
        self.payload = {"id": "evt_replayed", "type": "payment_intent.succeeded"}
        self.stored = WebhookEvent.objects.create(
            source="test",
            event_id="evt_replayed",
            event_type="payment_intent.succeeded",
            payload=self.payload,
            status="processed",
        )

    def test_unsigned_redelivery_of_processed_event_is_refused(self) -> None:
        success, message, event = _SignedProcessor().process_webhook(self.payload, signature="", headers={})

        self.assertFalse(success)
        self.assertIsNone(event, "the stored event must not be handed back to an unauthenticated caller")
        self.assertNotIn("Duplicate", message)
        self.assertNotIn(str(self.stored.id), message)

    def test_wrongly_signed_redelivery_of_processed_event_is_refused(self) -> None:
        success, _message, event = _SignedProcessor().process_webhook(self.payload, signature="forged", headers={})

        self.assertFalse(success)
        self.assertIsNone(event)

    def test_refused_redelivery_leaves_the_stored_event_untouched(self) -> None:
        before = WebhookEvent.objects.values().get(pk=self.stored.pk)

        _SignedProcessor().process_webhook(self.payload, signature="forged", headers={})

        self.assertEqual(WebhookEvent.objects.values().get(pk=self.stored.pk), before)
        self.assertEqual(WebhookEvent.objects.filter(source="test", event_id="evt_replayed").count(), 1)

    def test_signed_duplicate_still_answers_the_idempotent_success(self) -> None:
        processor = _SignedProcessor()

        success, message, event = processor.process_webhook(self.payload, signature=VALID_SIGNATURE, headers={})

        self.assertTrue(success)
        self.assertIn("Duplicate webhook skipped", message)
        self.assertEqual(event, self.stored)
        self.assertEqual(processor.handle_calls, 0, "a processed event must not be handled twice")


class StripeEndpointTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.payload = {"id": "evt_stripe_replayed", "type": "payment_intent.succeeded", "data": {"object": {}}}
        self.stored = WebhookEvent.objects.create(
            source="stripe",
            event_id="evt_stripe_replayed",
            event_type="payment_intent.succeeded",
            payload=self.payload,
            status="processed",
        )

    def test_unsigned_redelivery_of_processed_event_is_refused(self) -> None:
        response = self.client.post(
            reverse("integrations:stripe_webhook"),
            data=json.dumps(self.payload),
            content_type="application/json",
        )

        self.assertGreaterEqual(response.status_code, 400, response.content)
        self.assertNotIn(str(self.stored.id), response.content.decode())
        body = response.json()
        self.assertNotEqual(body.get("status"), "success")
        self.assertIsNone(body.get("webhook_id"))
