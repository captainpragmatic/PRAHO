"""Dunning audit metadata counts overdue days in the active local timezone."""

from datetime import UTC, datetime
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.billing.tasks import start_dunning_process
from tests.factories.billing_factories import create_currency, create_customer, create_invoice


@override_settings(USE_TZ=True, TIME_ZONE="Europe/Bucharest")
class DunningLocalDateTests(TestCase):
    def test_days_overdue_use_local_dates_for_now_and_the_persisted_due_at(self) -> None:
        cases = (
            (datetime(2026, 10, 5, 22, 30, tzinfo=UTC), "2026-10-05T23:59:59+03:00", 1),
            (datetime(2026, 10, 5, 20, 30, tzinfo=UTC), "2026-10-05T00:30:00+03:00", 0),
        )
        with timezone.override("Europe/Bucharest"):
            for index, (now, due_at, expected_days) in enumerate(cases):
                with (
                    self.subTest(now=now, due_at=due_at),
                    patch("django.utils.timezone.now", return_value=now),
                    patch("apps.notifications.services.EmailService.send_payment_reminder"),
                ):
                    invoice = create_invoice(
                        customer=create_customer(),
                        currency=create_currency(),
                        number=f"INV-LOCAL-DUNNING-{index}",
                    )
                    invoice.due_at = datetime.fromisoformat(due_at)
                    invoice.save(update_fields=["due_at"])

                    result = start_dunning_process(str(invoice.pk))

                    self.assertTrue(result["success"], result)
                    event = AuditEvent.objects.get(action="dunning_process_started", object_id=str(invoice.pk))
                    self.assertEqual(event.metadata["days_overdue"], expected_days)
