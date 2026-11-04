"""The registered minute dispatcher remains idempotent and explicitly bounded."""

from django.test import TestCase
from django_q.models import Schedule

from apps.security.tasks import setup_security_scheduled_tasks


class SecurityScheduleTests(TestCase):
    def test_setup_upserts_the_dispatch_and_retention_cadences(self) -> None:
        setup_security_scheduled_tasks()
        setup_security_scheduled_tasks()
        dispatcher = Schedule.objects.get(name="security-source-sync")
        self.assertEqual(dispatcher.func, "apps.security.tasks.dispatch_security_sync")
        self.assertEqual(dispatcher.schedule_type, Schedule.MINUTES)
        self.assertEqual(dispatcher.minutes, 1)
        self.assertEqual(dispatcher.repeats, -1)
        self.assertEqual(dispatcher.cluster, "praho-cluster")
        self.assertEqual(Schedule.objects.get(name="security-history-retention").minutes, 60)
        self.assertEqual(Schedule.objects.filter(name__startswith="security-").count(), 2)
