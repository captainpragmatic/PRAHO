"""Rollback handler effects while retaining retryable event history."""

from concurrent.futures import ThreadPoolExecutor
from unittest import skipUnless
from unittest.mock import patch

from django.db import close_old_connections, connection, connections, transaction
from django.test import TestCase, TransactionTestCase

from apps.common.counters import Counter
from apps.integrations.models import WebhookEvent
from apps.integrations.webhooks.base import process_pending_webhooks, retry_failed_webhooks
from tests.integrations.test_webhook_failed_redelivery import _ScriptedProcessor


class WebhookRollbackTests(TestCase):
    def _failure(self, outcome: str) -> None:
        processor = _ScriptedProcessor(should_succeed=True)

        def handler(event):
            Counter.objects.create(key="handler-effect", count=1, expires_at=9_999_999_999)
            if outcome == "sql":
                Counter.objects.create(key="handler-effect", count=1, expires_at=9_999_999_999)
            if outcome == "exception":
                raise RuntimeError("handler failed")
            return False, "handler refused"

        with patch.object(processor, "handle_event", side_effect=handler):
            success, _, _ = processor.process_webhook(
                {"id": "evt_atomic", "type": "payment_intent.succeeded"},
                signature="valid-test-sig",
            )
        self.assertFalse(success)
        self.assertFalse(Counter.objects.filter(key="handler-effect").exists())
        event = WebhookEvent.objects.get(event_id="evt_atomic")
        self.assertEqual(event.status, "failed")
        self.assertEqual(event.retry_count, 1)
        self.assertIsNotNone(event.next_retry_at)

    def test_false_result_rolls_back_effects(self) -> None:
        self._failure("false")

    def test_exception_rolls_back_effects(self) -> None:
        self._failure("exception")

    def test_sql_error_retains_failed_event(self) -> None:
        self._failure("sql")


@skipUnless(connection.vendor == "postgresql", "Row claims require PostgreSQL")
class WebhookClaimPostgresTests(TransactionTestCase):
    def test_pending_worker_skips_a_locked_oldest_event(self) -> None:
        first = WebhookEvent.objects.create(source="test", event_id="oldest", event_type="x", payload={})
        second = WebhookEvent.objects.create(source="test", event_id="next", event_type="x", payload={})
        processor = _ScriptedProcessor(should_succeed=True)

        def drain():
            close_old_connections()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SET statement_timeout = '1500ms'")
                return process_pending_webhooks(limit=1)
            finally:
                connections.close_all()

        with (
            patch("apps.integrations.webhooks.base.get_webhook_processor", return_value=processor),
            ThreadPoolExecutor(max_workers=1) as pool,
            transaction.atomic(),
        ):
            WebhookEvent.objects.select_for_update().get(pk=first.pk)
            stats = pool.submit(drain).result(timeout=4)
        self.assertEqual(stats["processed"], 1)
        first.refresh_from_db()
        second.refresh_from_db()
        self.assertEqual(first.status, "pending")
        self.assertEqual(second.status, "processed")

    def test_pending_and_retry_drains_share_rollback_executor(self) -> None:
        processor = _ScriptedProcessor(should_succeed=False)
        event = WebhookEvent.objects.create(source="test", event_id="drain", event_type="x", payload={})

        def handler(_event):
            Counter.objects.create(key="drain-effect", count=1, expires_at=9_999_999_999)
            return False, "refused"

        with (
            patch("apps.integrations.webhooks.base.get_webhook_processor", return_value=processor),
            patch.object(processor, "handle_event", side_effect=handler),
        ):
            self.assertEqual(process_pending_webhooks()["failed"], 1)
            event.refresh_from_db()
            self.assertFalse(Counter.objects.filter(key="drain-effect").exists())
            WebhookEvent.objects.filter(pk=event.pk).update(next_retry_at=event.received_at)
            self.assertEqual(retry_failed_webhooks()["failed"], 1)
        self.assertFalse(Counter.objects.filter(key="drain-effect").exists())
