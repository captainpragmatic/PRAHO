"""Upgrading a health cadence also advances obsolete future deadlines."""

from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone
from django_q.models import Schedule

from apps.common.tasks import setup_system_status_scheduled_tasks
from apps.provisioning.virtualmin_tasks import setup_virtualmin_scheduled_tasks


class HealthScheduleDeadlineTests(TestCase):
    def test_reconciliation_bounds_legacy_deadlines_and_preserves_nearby_runs(self) -> None:
        now = timezone.now()
        for name, setup in (
            ("system_status_check", setup_system_status_scheduled_tasks),
            ("virtualmin-health-check", setup_virtualmin_scheduled_tasks),
        ):
            for delay in (
                timedelta(minutes=-1),
                timedelta(minutes=5),
                timedelta(minutes=10),
                timedelta(minutes=10, microseconds=1),
                timedelta(days=1),
            ):
                with self.subTest(name=name, delay=delay):
                    Schedule.objects.filter(name=name).delete()
                    original = now + delay
                    row = Schedule.objects.create(
                        name=name, func="legacy.health", schedule_type=Schedule.DAILY, next_run=original
                    )
                    with patch("django.utils.timezone.now", return_value=now):
                        setup()
                        row.refresh_from_db()
                        expected = now if delay > timedelta(minutes=10) else original
                        self.assertEqual(row.next_run, expected)
                        self.assertEqual(row.schedule_type, Schedule.MINUTES)
                        self.assertEqual(row.minutes, 10)
                        setup()
                    row.refresh_from_db()
                    self.assertEqual(row.next_run, expected)
                    self.assertEqual(Schedule.objects.filter(name=name).count(), 1)

    def test_unrelated_daily_counter_deadline_is_preserved(self) -> None:
        original = timezone.now() + timedelta(days=1)
        row = Schedule.objects.create(
            name="counter_cull", func="apps.common.tasks.cull_counters", schedule_type=Schedule.DAILY, next_run=original
        )
        setup_system_status_scheduled_tasks()
        row.refresh_from_db()
        self.assertEqual(row.next_run, original)
        self.assertEqual(row.schedule_type, Schedule.DAILY)
