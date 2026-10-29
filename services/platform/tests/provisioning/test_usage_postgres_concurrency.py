"""Real row locks fence terminal mutations against cached usage publication."""

from concurrent.futures import ThreadPoolExecutor
from threading import Event
from unittest.mock import patch
from uuid import uuid4

from django.db import connection, connections
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from apps.provisioning import virtualmin_usage_service as usage
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob
from tests.helpers.task_queue import quiet_task_queue
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase


@override_settings(DISABLE_AUDIT_SIGNALS=True)
class UsagePostgresConcurrencyTests(TransactionTestCase):
    def setUp(self):
        if connection.vendor != "postgresql":
            self.skipTest("Usage publication row-lock acceptance requires PostgreSQL")
        quiet_task_queue(self)
        # These fixture constructors do not depend on TestCase transactions.
        VirtualminTaskTestBase.setUp(self)
        # fsm-bypass: establish the existing active account before its restore.
        type(self.account).objects.filter(pk=self.account.pk).update(status="active")
        self.account.refresh_from_db()

    def test_terminal_restore_commits_before_waiting_publisher_can_accept_cached_scan(self):
        ready, release = Event(), Event()
        with patch("apps.provisioning.virtualmin_usage_service.enabled", return_value=True):
            usage.current_state(self.account)
            captured = usage.capture(self.server)
            self.assertIn(self.account.pk, captured)
            now, token = timezone.now(), uuid4()
            payload = {
                "version": 1,
                "installation": str(uuid4()),
                "observed_at": now.isoformat(),
                "records": [
                    {
                        "domain": self.account.domain,
                        "username": self.account.virtualmin_username,
                        "domain_id": "42",
                        "scan_started_at": now.isoformat(),
                        "scan_finished_at": now.isoformat(),
                        "disk_files_bytes": 1048576,
                        "disk_db_bytes": 0,
                        "databases": 0,
                        "mailboxes": 0,
                        "segments": [],
                    }
                ],
            }
            job = VirtualminProvisioningJob.objects.create(
                server=self.server,
                account=self.account,
                operation="restore_domain",
                status="running",
                execution_token=token,
            )
            original = VirtualminProvisioningJob._invalidate_usage_gauge

            def terminal_boundary(account_id, operation):
                ready.set()
                if not release.wait(15):
                    raise TimeoutError("Usage concurrency test did not release terminal writer")
                original(account_id, operation)

            def finish():
                try:
                    return VirtualminProvisioningJob.finish_execution(job.pk, token, "completed", "Restored")
                finally:
                    connections.close_all()

            def publish():
                try:
                    return usage.publish_snapshot(self.server.pk, payload, captured)
                finally:
                    connections.close_all()

            with (
                patch.object(VirtualminProvisioningJob, "_invalidate_usage_gauge", side_effect=terminal_boundary),
                ThreadPoolExecutor(max_workers=2) as workers,
            ):
                terminal = workers.submit(finish)
                self.assertTrue(ready.wait(15))
                try:
                    publisher = workers.submit(publish)
                finally:
                    release.set()
                self.assertEqual(terminal.result(timeout=15), 1)
                self.assertEqual(publisher.result(timeout=15), 0)
            self.assertIsNone(usage.public_usage(self.service)["disk_usage_gb"])
