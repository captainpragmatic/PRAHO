"""Pin the complete production catalog installed by migrate and bootstrap."""

import json
from io import StringIO
from pathlib import Path

from django.core.management import call_command
from django.test import TestCase, override_settings
from django_q.models import Schedule

from apps.infrastructure.apps import InfrastructureConfig

FIELDS = ("name", "func", "schedule_type", "minutes", "cron", "repeats", "cluster")
CATALOG = json.loads((Path(__file__).parent / "fixtures/scheduled_tasks.json").read_text())


@override_settings(AUDIT_CHAIN_ENABLED=False)
class ScheduledTaskCatalogTests(TestCase):
    def test_complete_production_catalog_is_installed_idempotently(self) -> None:
        Schedule.objects.all().delete()
        # Production migrates before bootstrap; infrastructure owns a post_migrate receiver.
        InfrastructureConfig._schedule_infrastructure_tasks(InfrastructureConfig)
        call_command("setup_scheduled_tasks", stdout=StringIO())
        self.assertEqual(list(Schedule.objects.order_by("name").values(*FIELDS)), CATALOG)
        identities = dict(Schedule.objects.values_list("name", "pk"))
        operator = Schedule.objects.create(name="operator-one-off", func="operator.maintenance", repeats=1)
        InfrastructureConfig._schedule_infrastructure_tasks(InfrastructureConfig)
        call_command("setup_scheduled_tasks", stdout=StringIO())
        self.assertEqual(dict(Schedule.objects.exclude(pk=operator.pk).values_list("name", "pk")), identities)
        self.assertEqual(Schedule.objects.get(pk=operator.pk).repeats, 1)

    @override_settings(AUDIT_CHAIN_ENABLED=True)
    def test_chain_schedule_is_installed_only_for_enabled_chaining(self) -> None:
        call_command("setup_scheduled_tasks", stdout=StringIO())
        self.assertEqual(Schedule.objects.filter(name="audit-chain-anchor-hourly").count(), 1)
        self.assertEqual(Schedule.objects.count(), len(CATALOG) + 1)
