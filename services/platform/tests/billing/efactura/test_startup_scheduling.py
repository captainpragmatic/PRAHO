"""e-Factura schedules are installed explicitly and survive runtime enablement."""

from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.db import IntegrityError
from django.test import TestCase
from django_q.models import Schedule

from apps.billing.efactura.tasks import schedule_efactura_tasks
from apps.settings.models import SystemSetting


class BillingConfigReadyTestCase(TestCase):
    def _enabled(self, value: bool) -> None:
        SystemSetting.objects.update_or_create(
            key="efactura.enabled",
            defaults={"name": "e-Factura", "data_type": "boolean", "value": value, "default_value": False},
        )

    def test_schedules_tasks_when_efactura_enabled(self) -> None:
        self._enabled(True)
        Schedule.objects.all().delete()
        call_command("setup_scheduled_tasks", stdout=StringIO())
        self.assertTrue(Schedule.objects.filter(name="efactura_reconcile_documents").exists())
        before = list(Schedule.objects.filter(name__startswith="efactura_").order_by("pk").values_list("pk", flat=True))
        call_command("setup_scheduled_tasks", stdout=StringIO())
        self.assertEqual(
            list(Schedule.objects.filter(name__startswith="efactura_").order_by("pk").values_list("pk", flat=True)),
            before,
        )

    def test_skips_scheduling_when_efactura_disabled(self) -> None:
        # Replaces the ready() contract: explicit setup must work before runtime enablement.
        self._enabled(False)
        Schedule.objects.all().delete()
        call_command("setup_scheduled_tasks", stdout=StringIO())
        self.assertTrue(Schedule.objects.filter(name="efactura_process_pending").exists())

    def test_handles_scheduling_failure_gracefully(self) -> None:
        # Startup no longer accesses the DB; explicit registration must fail loudly.
        with (
            patch.object(Schedule.objects, "update_or_create", side_effect=IntegrityError("registration failed")),
            self.assertRaises(IntegrityError),
        ):
            schedule_efactura_tasks()
