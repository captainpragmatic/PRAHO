"""PostgreSQL delivery races claim one durable operation and one asynchronous dispatch."""

import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from django.db import close_old_connections, connection
from django.test import TransactionTestCase, override_settings

from apps.domains import dns_zone_services as service
from apps.domains import dns_zone_tasks as worker
from tests.domains.test_dns_zone_import_service import UPLOAD, hosting_fixture


@override_settings(
    DISABLE_AUDIT_SIGNALS=True,
    AUDIT_CHAIN_ENABLED=False,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class ZoneDeliveryPostgresTests(TransactionTestCase):
    def setUp(self):
        if connection.vendor != "postgresql":
            self.skipTest("Delivery row claims require the PostgreSQL CI gate")
        account, _, actor = hosting_fixture()
        with patch.object(service, "_audit"):
            revision = service.preview_zone_import(account, UPLOAD, actor=actor).unwrap()
            self.operation = service.request_crosscheck(revision.zone, revision.number, actor=actor).unwrap()

    def simultaneous(self, callback):
        ready = threading.Barrier(2)

        def run():
            close_old_connections()
            try:
                ready.wait(timeout=10)
                return callback()
            finally:
                connection.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            jobs = [pool.submit(run) for _ in range(2)]
            return [job.result(timeout=30) for job in jobs]

    def test_two_dispatchers_queue_one_operation_with_a_shared_reserved_claim(self):
        with patch.object(worker, "async_task") as enqueue:
            outcomes = self.simultaneous(worker.dispatch_zone_operations)
        self.assertEqual(sum(outcome["queued"] for outcome in outcomes), 1)
        enqueue.assert_called_once()
        self.assertIs(enqueue.call_args.kwargs["sync"], False)

    def test_duplicate_broker_delivery_consumes_a_reserved_lease_once(self):
        token = worker._claim(self.operation.pk, dispatch=True)
        outcomes = self.simultaneous(lambda: worker._claim(self.operation.pk, token))
        self.assertEqual(sum(outcome is not None for outcome in outcomes), 1)
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.lease_token, token)
        self.assertIsNotNone(self.operation.worker_started_at)
