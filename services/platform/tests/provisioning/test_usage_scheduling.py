"""Hourly scheduling tolerates jitter and retention keeps pace with collection."""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from uuid import uuid4

from django.db.models.query import QuerySet
from django.utils import timezone

from apps.provisioning import virtualmin_usage_service as usage
from apps.provisioning import virtualmin_usage_tasks as tasks
from apps.provisioning.virtualmin_usage_models import NodeUsageSyncState, UsageInterval, UsageReading
from tests.provisioning.test_virtualmin_migration_service import MigrationTestBase


class UsageSchedulingTests(MigrationTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.settings_values["provisioning.usage_sync_enabled"] = True
        self.state = usage.current_state(self.account)
        self.now = timezone.now()
        identity_patch = patch.object(tasks, "transport_identity", return_value="a" * 64)
        enqueue_patch = patch.object(tasks, "async_task")
        self.addCleanup(identity_patch.stop)
        self.addCleanup(enqueue_patch.stop)
        identity_patch.start()
        self.enqueue = enqueue_patch.start()

    def reading(self, taken_at: datetime) -> UsageReading:
        return UsageReading(
            account=self.account,
            owner_scope=self.state.owner_scope,
            sync_token=uuid4(),
            server_id_snapshot=self.server.pk,
            chain_epoch=0,
            taken_at=taken_at,
            period_start=taken_at.replace(day=1),
            period_end=taken_at,
            period_timezone="UTC",
        )

    def test_earlier_jitter_next_hour_does_not_skip_a_poll_and_duplicates_coalesce(self) -> None:
        first = datetime(2026, 10, 30, 10, 10, 5, tzinfo=UTC)
        NodeUsageSyncState.objects.create(server=self.server, next_run=first - timedelta(hours=1))
        NodeUsageSyncState.objects.create(server=self.target, next_run=first + timedelta(days=1))
        with patch.object(tasks.timezone, "now", return_value=first):
            self.assertEqual(tasks.dispatch_usage_sync(), {"queued": 1})
        claim = NodeUsageSyncState.objects.get(server=self.server)
        self.assertEqual(claim.lease_until, first + timedelta(seconds=330))
        claim.token, claim.lease_until = None, None
        claim.save(update_fields=["token", "lease_until"])
        with patch.object(tasks.timezone, "now", return_value=first + timedelta(minutes=20)):
            self.assertEqual(tasks.dispatch_usage_sync(), {"queued": 0})
        earlier_next_hour = first + timedelta(hours=1, seconds=-4)
        with patch.object(tasks.timezone, "now", return_value=earlier_next_hour):
            self.assertEqual(tasks.dispatch_usage_sync(), {"queued": 1})
        self.assertEqual(self.enqueue.call_count, 2)

    def test_cleanup_drains_more_than_one_batch_and_preserves_last_good_and_recent_readings(self) -> None:
        old = self.now - timedelta(days=91)
        records = UsageReading.objects.bulk_create([self.reading(old) for _ in range(4005)])
        recent = self.reading(self.now - timedelta(days=89))
        recent.save()
        boundary = self.reading(self.now - timedelta(days=90))
        boundary.save()
        UsageInterval.objects.bulk_create(
            [
                UsageInterval(
                    account=self.account,
                    owner_scope=self.state.owner_scope,
                    server=self.server,
                    started_at=old - timedelta(days=1),
                    ended_at=old,
                )
                for _ in range(1005)
            ]
        )
        self.state.disk_reading, self.state.bandwidth_reading = records[0], records[1]
        self.state.save(update_fields=["disk_reading", "bandwidth_reading"])
        with patch.object(tasks.timezone, "now", return_value=self.now):
            tasks.dispatch_usage_sync()
        self.assertSetEqual(
            set(UsageReading.objects.values_list("pk", flat=True)),
            {records[0].pk, records[1].pk, recent.pk, boundary.pk},
        )
        self.assertFalse(UsageInterval.objects.filter(ended_at__lt=self.now - timedelta(days=90)).exists())
        self.assertTrue(UsageInterval.objects.filter(account=self.account, ended_at__isnull=True).exists())

    def test_cleanup_budget_expires_between_batches_and_next_dispatch_resumes(self) -> None:
        old = self.now - timedelta(days=91)
        UsageReading.objects.bulk_create([self.reading(old) for _ in range(2005)])
        original_delete = QuerySet.delete
        elapsed = [0.0]

        def delete_and_exhaust_budget(query):
            result = original_delete(query)
            if query.model is UsageReading:
                elapsed[0] = 100.0
            return result

        with (
            patch.object(tasks, "monotonic", side_effect=lambda: elapsed[0], create=True),
            patch.object(QuerySet, "delete", new=delete_and_exhaust_budget),
        ):
            tasks.dispatch_usage_sync()
        self.assertGreater(UsageReading.objects.count(), 0)
        self.assertLess(UsageReading.objects.count(), 2005)
        tasks.dispatch_usage_sync()
        self.assertEqual(UsageReading.objects.count(), 0)

    def test_cleanup_removes_old_interval_totals_without_removing_the_live_interval(self) -> None:
        interval = UsageInterval.objects.get(account=self.account, ended_at__isnull=True)
        old = self.now - timedelta(days=120)
        recent = self.now - timedelta(days=60)
        interval.totals = {
            old.replace(day=1).isoformat(): {"bytes": 10, "through": old.isoformat(), "complete": True},
            recent.replace(day=1).isoformat(): {"bytes": 20, "through": recent.isoformat(), "complete": True},
        }
        interval.save(update_fields=["totals"])
        tasks.dispatch_usage_sync()
        interval.refresh_from_db()
        self.assertEqual(
            interval.totals,
            {recent.replace(day=1).isoformat(): {"bytes": 20, "through": recent.isoformat(), "complete": True}},
        )
