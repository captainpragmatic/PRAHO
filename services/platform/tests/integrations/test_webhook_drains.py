"""The webhook drains run on a schedule (#751 follow-up, M13).

Pending deliveries and due retries were processed only when someone ran the process_webhooks command. A
webhook that failed once was never retried on its own. setup_scheduled_tasks, which every deploy runs,
now installs both drains.
"""

from __future__ import annotations

from io import StringIO

from django.core.management import call_command
from django.test import TestCase, override_settings
from django_q.models import Schedule

DRAINS = {
    "apps.integrations.webhooks.base.process_pending_webhooks",
    "apps.integrations.webhooks.base.retry_failed_webhooks",
}


@override_settings(AUDIT_CHAIN_ENABLED=False)
class WebhookDrainScheduleTests(TestCase):
    def test_setup_installs_both_webhook_drains(self) -> None:
        Schedule.objects.all().delete()

        call_command("setup_scheduled_tasks", stdout=StringIO())

        installed = set(Schedule.objects.filter(func__in=DRAINS).values_list("func", flat=True))
        self.assertEqual(installed, DRAINS)
