"""Real lifecycle ticks expose overruns without replaying or releasing issued work."""

from datetime import timedelta
from io import StringIO
from unittest.mock import patch

from django.apps import apps
from django.core.management import call_command
from django.test import TestCase, override_settings
from django_q.models import Schedule

from apps.infrastructure.node_maintenance_models import NodeMaintenanceWindow
from apps.infrastructure.node_maintenance_tasks import tick_node_maintenance
from tests.infrastructure.test_node_maintenance_admission import MaintenanceAdmissionFixture


@override_settings(Q_CLUSTER={"name": "maintenance-tick", "orm": "default", "retry": 100000})
class NodeMaintenanceTickTests(MaintenanceAdmissionFixture, TestCase):
    def test_canonical_schedule_setup_repairs_a_missing_tick_idempotently(self) -> None:
        service = self.account.service
        service.auto_renew = False  # This maintenance fixture has no recurring-billing subscription.
        service.save(update_fields=["auto_renew"])
        Schedule.objects.filter(name="infra_node_maintenance").delete()
        for _attempt in range(2):
            call_command("setup_scheduled_tasks", stdout=StringIO())
        self.assertEqual(Schedule.objects.filter(name="infra_node_maintenance").count(), 1)

    def test_post_migrate_registers_the_actual_minute_tick(self) -> None:
        config = apps.get_app_config("infrastructure")
        config._schedule_infrastructure_tasks(sender=type(config))
        schedule = Schedule.objects.filter(name="infra_node_maintenance").first()
        self.assertIsNotNone(schedule)
        self.assertEqual(schedule.func, "apps.infrastructure.node_maintenance_tasks.tick_node_maintenance")
        self.assertEqual((schedule.schedule_type, schedule.minutes, schedule.repeats), (Schedule.MINUTES, 1, -1))

    def test_an_actual_started_window_becomes_overran_after_its_planned_end(self) -> None:
        window = self.start(self.window())
        execution_id = window.current_execution_id

        with patch("django.utils.timezone.now", return_value=window.ends_at + timedelta(seconds=1)):
            result = tick_node_maintenance([str(window.pk)])

        current = NodeMaintenanceWindow.objects.get(pk=window.pk)
        self.assertEqual(result["overran"], 1)
        self.assertEqual(current.status, "overran")
        self.assertTrue(current.was_overrun)
        self.assertEqual(current.current_execution_id, execution_id)
        self.assertIsNone(current.finished_at)

    def test_an_explicit_empty_fixture_scope_does_not_touch_any_window(self) -> None:
        window = self.start(self.window())
        with patch("django.utils.timezone.now", return_value=window.ends_at + timedelta(seconds=1)):
            tick_node_maintenance([])
        self.assertEqual(NodeMaintenanceWindow.objects.get(pk=window.pk).status, "running")
