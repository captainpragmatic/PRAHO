"""Optional delivery tracking restores the caller's transaction."""

from types import SimpleNamespace
from unittest.mock import patch

from django.db import transaction

from apps.customers.models import Customer
from apps.notifications.signals import handle_anymail_tracking
from tests.common._signal_isolation import SignalIsolationTestCase


class NotificationSignalIsolationTests(SignalIsolationTestCase):
    def test_tracking_failure_preserves_callers_write(self) -> None:
        event = SimpleNamespace(
            event_type="delivered", message_id="test", recipient="recipient@example.com", timestamp=None
        )
        with (
            patch("apps.notifications.services.EmailService.handle_delivery_event", side_effect=self.fail_write),
            transaction.atomic(),
        ):
            customer = Customer.objects.create(name="Isolation", primary_email="tracking-customer@example.com")
            handle_anymail_tracking(sender=object(), event=event, esp_name="test")
        self.assertTrue(Customer.objects.filter(pk=customer.pk).exists())
