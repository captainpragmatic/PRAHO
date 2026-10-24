"""Missing PRAHO records must retain recoverable Stripe delivery history."""

from unittest.mock import patch

from django.test import TestCase

from apps.integrations.models import WebhookEvent
from apps.integrations.webhooks.stripe import StripeWebhookProcessor


class StripeMissingObjectTests(TestCase):
    def _deliver(self, event_type: str, object_data: dict, event_id: str = "evt_missing"):
        processor = StripeWebhookProcessor()
        with patch.object(processor, "verify_signature", return_value=True):
            return processor.process_webhook(
                {"id": event_id, "type": event_type, "created": 100, "data": {"object": object_data}},
                signature="valid-delivery",
            )

    def test_missing_expected_local_objects_are_failed_and_retryable(self) -> None:
        cases = (
            ("payment_intent.succeeded", {"id": "pi_missing", "amount_received": 100, "currency": "ron"}),
            ("payment_intent.payment_failed", {"id": "pi_missing"}),
            (
                "refund.created",
                {
                    "id": "re_missing",
                    "payment_intent": "pi_missing",
                    "amount": 100,
                    "currency": "ron",
                    "status": "succeeded",
                },
            ),
            ("customer.created", {"id": "cus_missing", "email": "missing@example.com"}),
            # A dispute for a missing payment is not here: no redelivery can fix it, so it is acknowledged
            # and escalated (test_stripe_unfixable_outcomes).
        )
        for index, (kind, data) in enumerate(cases):
            with self.subTest(kind=kind):
                success, _, event = self._deliver(kind, data, f"evt_missing_{index}")
                self.assertFalse(success)
                event.refresh_from_db()
                self.assertEqual(event.status, "failed")
                self.assertIsNotNone(event.next_retry_at)

    def test_missing_object_alert_is_after_failure_persistence_and_deduplicated(self) -> None:
        data = {"id": "pi_missing", "amount_received": 100, "currency": "ron"}

        def alert(**kwargs):
            self.assertEqual(WebhookEvent.objects.get(event_id="evt_missing").status, "failed")
            return True

        with patch("apps.notifications.services.NotificationService.send_admin_alert", side_effect=alert) as notify:
            with self.captureOnCommitCallbacks(execute=True):
                self._deliver("payment_intent.succeeded", data)
                notify.assert_not_called()
            with self.captureOnCommitCallbacks(execute=True):
                self._deliver("payment_intent.succeeded", data)
        self.assertEqual(notify.call_count, 1)

    def test_unused_event_type_is_acknowledged_without_retry(self) -> None:
        success, _, event = self._deliver("unrelated.event", {"id": "unused"})
        self.assertTrue(success)
        self.assertEqual(event.status, "processed")
