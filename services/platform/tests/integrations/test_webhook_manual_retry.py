"""A staff retry of a failed webhook runs like any other processing of it (#751 follow-up, M8).

The retry view called the processor's handler directly: no lock on the event, no savepoint (a handler
that refused kept its partial writes), no failure follow-up, and it could run while a redelivery
processed the same event. It now claims the event under its row lock, re-checks it is still failed, and
runs the handler in the executor's savepoint.
"""

from __future__ import annotations

import threading
from unittest.mock import patch

from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, transaction
from django.test import Client, TestCase, TransactionTestCase
from django.urls import reverse

from apps.customers.models import Customer
from apps.integrations.models import WebhookEvent
from apps.integrations.webhooks.stripe import StripeWebhookProcessor
from apps.users.models import User


def _staff_client(email: str) -> Client:
    staff = User.objects.create_user(email=email, password="testpass123", is_staff=True)
    permission, _ = Permission.objects.get_or_create(
        content_type=ContentType.objects.get_for_model(WebhookEvent),
        codename="retry_webhook",
        defaults={"name": "Can retry failed webhooks"},
    )
    staff.user_permissions.add(permission)
    client = Client()
    client.force_login(staff)
    return client


def _failed_event(event_id: str) -> WebhookEvent:
    return WebhookEvent.objects.create(
        source="stripe", event_id=event_id, event_type="payment_intent.succeeded", payload={}, status="failed",
        retry_count=1,
    )


class ManualRetryTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.client = _staff_client("retry-staff@example.com")
        self.event = _failed_event("evt_manual_retry")

    def _retry(self) -> object:
        return self.client.post(reverse("integrations:retry_webhook", kwargs={"webhook_id": self.event.id}))

    def test_a_refusing_handler_leaves_no_partial_write(self) -> None:
        def writes_then_refuses(event: WebhookEvent) -> tuple[bool, str]:
            Customer.objects.create(name="Partial write", customer_type="company", status="active")
            return False, "refused"

        with patch.object(StripeWebhookProcessor, "handle_event", side_effect=writes_then_refuses):
            response = self._retry()

        self.assertEqual(response.status_code, 400)
        self.assertFalse(Customer.objects.filter(name="Partial write").exists(), "a refusal keeps nothing")
        self.event.refresh_from_db()
        self.assertEqual((self.event.status, self.event.retry_count), ("failed", 2))

    def test_a_successful_retry_marks_the_event_processed(self) -> None:
        with patch.object(StripeWebhookProcessor, "handle_event", return_value=(True, "done")):
            response = self._retry()

        self.assertEqual(response.status_code, 200)
        self.event.refresh_from_db()
        self.assertEqual(self.event.status, "processed")


class ManualRetryLockTests(TransactionTestCase):
    """On PostgreSQL a retry never runs while another transaction holds the event."""

    def test_a_retry_while_the_event_is_held_runs_no_handler(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("row locks need PostgreSQL")
        client = _staff_client("retry-lock@example.com")
        event = _failed_event("evt_manual_retry_locked")
        held, release = threading.Event(), threading.Event()

        def hold_the_event() -> None:
            try:
                with transaction.atomic():
                    WebhookEvent.objects.select_for_update().get(pk=event.pk)
                    held.set()
                    release.wait(10)
            finally:
                connection.close()

        holder = threading.Thread(target=hold_the_event)
        holder.start()
        self.assertTrue(held.wait(10))
        try:
            with patch.object(StripeWebhookProcessor, "handle_event", return_value=(True, "done")) as handler:
                response = client.post(reverse("integrations:retry_webhook", kwargs={"webhook_id": event.id}))
        finally:
            release.set()
            holder.join(10)

        self.assertEqual(response.status_code, 409, "the event is being processed elsewhere")
        handler.assert_not_called()
