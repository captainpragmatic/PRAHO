"""Durable bounded dispatch stays asynchronous even when the test queue defaults to sync."""

from datetime import timedelta
from unittest.mock import patch

from django.test import TransactionTestCase, override_settings
from django.utils import timezone
from django_q.conf import Conf
from django_q.models import Schedule

from apps.domains import dns_zone_services as service
from apps.domains import dns_zone_tasks as worker
from apps.domains.tasks import setup_domain_scheduled_tasks
from tests.domains.test_dns_zone_import_service import UPLOAD, hosting_fixture


@override_settings(
    DISABLE_AUDIT_SIGNALS=True,
    AUDIT_CHAIN_ENABLED=False,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class ZoneDispatchTests(TransactionTestCase):
    def setUp(self):
        account, _, actor = hosting_fixture()
        patcher = patch.object(service, "_audit")
        patcher.start()
        self.addCleanup(patcher.stop)
        revision = service.preview_zone_import(account, UPLOAD, actor=actor).unwrap()
        self.operation = service.request_crosscheck(revision.zone, revision.number, actor=actor).unwrap()

    def test_schedule_setup_registers_the_real_bounded_dispatcher_idempotently(self):
        setup_domain_scheduled_tasks()
        setup_domain_scheduled_tasks()
        schedule = Schedule.objects.get(name="domains-dns-zones")
        self.assertEqual(schedule.func, "apps.domains.dns_zone_tasks.dispatch_zone_operations")
        self.assertEqual(schedule.minutes, 1)

    def test_dispatch_is_not_inline_even_with_sync_default_and_duplicate_dispatch_deduplicates(self):
        with patch.object(Conf, "SYNC", True), patch.object(worker, "async_task") as enqueue:
            self.assertEqual(worker.dispatch_zone_operations()["queued"], 1)
            self.assertEqual(worker.dispatch_zone_operations()["queued"], 0)
        enqueue.assert_called_once()
        self.assertIs(enqueue.call_args.kwargs["sync"], False)
        self.assertEqual(enqueue.call_args.kwargs["timeout"], worker.JOB_TIMEOUT)

    def test_queue_failure_releases_only_its_unstarted_claim_and_durable_work_remains_retryable(self):
        with patch.object(worker, "async_task", side_effect=OSError("broker offline")):
            self.assertEqual(worker.dispatch_zone_operations()["queued"], 1)
        self.operation.refresh_from_db()
        self.assertIsNone(self.operation.lease_token)
        self.assertEqual(self.operation.status, "waiting")
        self.operation.next_attempt_at = timezone.now() - timedelta(seconds=1)
        self.operation.save(update_fields=["next_attempt_at"])
        with patch.object(worker, "async_task") as enqueue:
            self.assertEqual(worker.dispatch_zone_operations()["queued"], 1)
        enqueue.assert_called_once()
