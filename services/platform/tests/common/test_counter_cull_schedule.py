"""The Platform sweeps expired counters on a daily schedule."""

from unittest.mock import patch

from django.test import TestCase
from django_q.models import Schedule

from apps.common.models import Counter
from apps.common.tasks import cull_counters, setup_system_status_scheduled_tasks


class CounterCullScheduleTests(TestCase):
    def test_setup_registers_a_daily_cull_next_to_the_status_check(self) -> None:
        self.assertEqual(
            setup_system_status_scheduled_tasks(), {"system_status_check": "created", "counter_cull": "created"}
        )
        schedule = Schedule.objects.get(name="counter_cull")
        self.assertEqual(schedule.func, "apps.common.tasks.cull_counters")
        self.assertEqual(schedule.schedule_type, Schedule.DAILY)
        self.assertEqual(
            setup_system_status_scheduled_tasks(),
            {"system_status_check": "already_exists", "counter_cull": "already_exists"},
        )

    def test_task_deletes_rows_past_grace_and_reports_the_count(self) -> None:
        with patch("apps.common.counters.time.time", return_value=10_000):
            Counter.objects.bulk_create(
                [
                    Counter(key="stale", count=1, expires_at=10_000 - 3_601),
                    Counter(key="live", count=1, expires_at=10_100),
                ]
            )
            self.assertEqual(cull_counters(), {"deleted": 1})
        self.assertEqual(list(Counter.objects.values_list("key", flat=True)), ["live"])
