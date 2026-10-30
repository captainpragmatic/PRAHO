"""Real row locks fence terminal mutations against cached usage publication."""

from concurrent.futures import Future, ThreadPoolExecutor
from datetime import timedelta
from threading import Event
from time import monotonic
from unittest.mock import patch
from uuid import UUID, uuid4

from django.db import connection, connections, transaction
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from apps.provisioning import virtualmin_usage_service as usage
from apps.provisioning import virtualmin_usage_tasks as usage_tasks
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob
from apps.provisioning.virtualmin_usage_models import UsageInterval
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

    @staticmethod
    def _backend_pid() -> int:
        with connection.cursor() as cursor:
            cursor.execute("SET lock_timeout = '10s'")
            cursor.execute("SET statement_timeout = '15s'")
            cursor.execute("SELECT pg_backend_pid()")
            return cursor.fetchone()[0]

    def _assert_database_wait(
        self,
        worker_pid: int,
        blocker_pid: int,
        pending: Future[int],
        *,
        table: str,
        statement: str,
    ) -> None:
        self.assertNotEqual(worker_pid, blocker_pid)
        deadline = monotonic() + 5
        observed_wait = None
        poll = Event()
        while monotonic() < deadline:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_stat_clear_snapshot()")
                cursor.execute(
                    "SELECT wait_event_type, pg_blocking_pids(pid), query FROM pg_stat_activity WHERE pid = %s",
                    [worker_pid],
                )
                observed_wait = cursor.fetchone()
            if observed_wait and observed_wait[0] == "Lock" and blocker_pid in observed_wait[1]:
                self.assertIn(table, observed_wait[2])
                self.assertRegex(observed_wait[2], statement)
                return
            if pending.done():
                self.fail(f"Worker completed without waiting for {table}: {pending.result()}")
            poll.wait(0.01)
        self.fail(f"Worker never waited on {table}: {observed_wait!r}")

    def _cached_scan(self):
        usage.current_state(self.account)
        captured = usage.capture(self.server)
        self.assertIn(self.account.pk, captured)
        now = timezone.now()
        return captured, {
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

    def test_terminal_restore_commits_before_waiting_publisher_can_accept_cached_scan(self):
        ready, release, publisher_attempting_lock = (Event() for _ in range(3))
        terminal_pids, publisher_pids = [], []
        with patch("apps.provisioning.virtualmin_usage_service.enabled", return_value=True):
            captured, payload = self._cached_scan()
            token = uuid4()
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
                if not release.wait(20):
                    raise TimeoutError("Usage concurrency test did not release terminal writer")
                original(account_id, operation)

            def finish():
                try:
                    terminal_pids.append(self._backend_pid())
                    return VirtualminProvisioningJob.finish_execution(job.pk, token, "completed", "Restored")
                finally:
                    connections.close_all()

            def publish():
                def observe_account_lock(execute, sql, params, many, context):
                    if self.account._meta.db_table in sql and "FOR " in sql:
                        # pg_stat_activity truncates this wide account SELECT
                        # before its lock clause with PostgreSQL's default
                        # track_activity_query_size. Check the complete SQL here;
                        # the database observation below proves its actual wait.
                        self.assertRegex(sql, r"\bFOR (?:NO KEY )?UPDATE\b")
                        publisher_attempting_lock.set()
                    return execute(sql, params, many, context)

                try:
                    publisher_pids.append(self._backend_pid())
                    with connection.execute_wrapper(observe_account_lock):
                        return usage.publish_snapshot(self.server.pk, payload, captured)
                finally:
                    connections.close_all()

            with (
                patch.object(VirtualminProvisioningJob, "_invalidate_usage_gauge", side_effect=terminal_boundary),
                ThreadPoolExecutor(max_workers=2) as workers,
            ):
                terminal = workers.submit(finish)
                try:
                    self.assertTrue(ready.wait(5), "Terminal writer did not reach its invalidation boundary")
                    publisher = workers.submit(publish)
                    self.assertTrue(publisher_attempting_lock.wait(5), "Publisher did not attempt the account row lock")
                    self._assert_database_wait(
                        publisher_pids[0],
                        terminal_pids[0],
                        publisher,
                        table=self.account._meta.db_table,
                        statement=r"^SELECT\b",
                    )
                finally:
                    release.set()
                self.assertEqual(terminal.result(timeout=15), 1)
                self.assertEqual(publisher.result(timeout=15), 0)
            self.assertIsNone(usage.public_usage(self.service)["disk_usage_gb"])

    def test_publisher_account_lock_allows_service_writer_to_commit_foreign_key(self):
        account_locked = Event()
        publisher_pids = []
        with patch("apps.provisioning.virtualmin_usage_service.enabled", return_value=True):
            captured, payload = self._cached_scan()
            owner_pid = self._backend_pid()

            def publish():
                def observe_account_lock(execute, sql, params, many, context):
                    result = execute(sql, params, many, context)
                    if self.account._meta.db_table in sql and "FOR " in sql:
                        account_locked.set()
                    return result

                try:
                    publisher_pids.append(self._backend_pid())
                    with connection.execute_wrapper(observe_account_lock):
                        return usage.publish_snapshot(self.server.pk, payload, captured)
                finally:
                    connections.close_all()

            with ThreadPoolExecutor(max_workers=1) as workers:
                with transaction.atomic():
                    with connection.cursor() as cursor:
                        cursor.execute("SET LOCAL lock_timeout = '3s'")
                    type(self.service).objects.select_for_update().get(pk=self.service.pk)
                    publisher = workers.submit(publish)
                    self.assertTrue(account_locked.wait(5), "Publisher did not acquire the account row lock")
                    self._assert_database_wait(
                        publisher_pids[0],
                        owner_pid,
                        publisher,
                        table=self.service._meta.db_table,
                        statement=r"\bUPDATE\b",
                    )
                    # Commit checks this deferred FK while the publisher still
                    # owns the account row and waits for our Service update lock.
                    job = VirtualminProvisioningJob.objects.create(
                        server=self.server,
                        account=self.account,
                        operation="backup_domain",
                        status="pending",
                    )
                self.assertEqual(publisher.result(timeout=15), 1)
            self.assertTrue(VirtualminProvisioningJob.objects.filter(pk=job.pk).exists())
            self.service.refresh_from_db()
            self.assertEqual(self.service.disk_usage_mb, 1)
            self.assertEqual(usage.public_usage(self.service)["usage_state"], "fresh")

    def test_retention_waits_for_publisher_and_preserves_its_new_month_total(self):
        publisher_ready, release, pruner_ready = Event(), Event(), Event()
        publisher_pids, pruner_pids = [], []
        with patch("apps.provisioning.virtualmin_usage_service.enabled", return_value=True):
            captured, payload = self._cached_scan()
            self.assertEqual(usage.publish_snapshot(self.server.pk, payload, captured), 1)
            interval = UsageInterval.objects.get(account=self.account, ended_at__isnull=True)
            observed = timezone.now()
            start, end = usage.month(observed)
            old_at = observed - timedelta(days=120)
            old_key, current_key = usage.month(old_at)[0].isoformat(), start.isoformat()
            interval.totals = {old_key: {"bytes": 7, "through": old_at.isoformat(), "complete": True}}
            interval.save(update_fields=["totals"])
            records = [
                {
                    "domain_id": interval.domain_id,
                    "segments": [
                        {
                            "id": str(interval.pk),
                            "bytes": 123,
                            "start": max(start, interval.started_at).isoformat(),
                            "end": min(end, observed).isoformat(),
                            "complete": True,
                        }
                    ],
                }
            ]

            def publish():
                def pause_before_totals_write(execute, sql, params, many, context):
                    if sql.startswith("UPDATE") and interval._meta.db_table in sql and '"totals"' in sql:
                        publisher_ready.set()
                        if not release.wait(20):
                            raise TimeoutError("Usage retention test did not release publisher")
                    return execute(sql, params, many, context)

                try:
                    publisher_pids.append(self._backend_pid())
                    with transaction.atomic(), connection.execute_wrapper(pause_before_totals_write):
                        # Exercise the real segment path directly. The gauge
                        # identity UPDATE would otherwise acquire this row lock
                        # even without the segment publisher's explicit lock.
                        usage.publish_segments(
                            self.server.pk,
                            UUID(payload["installation"]),
                            records,
                            observed,
                            uuid4(),
                            captured,
                        )
                    return 1
                finally:
                    connections.close_all()

            def prune():
                try:
                    pruner_pids.append(self._backend_pid())
                    pruner_ready.set()
                    usage_tasks._prune_interval_batch(None, observed - timedelta(days=90), monotonic() + 15)
                    return 1
                finally:
                    connections.close_all()

            with ThreadPoolExecutor(max_workers=2) as workers:
                publisher = workers.submit(publish)
                try:
                    self.assertTrue(publisher_ready.wait(5), "Publisher did not reach the totals UPDATE")
                    pruner = workers.submit(prune)
                    self.assertTrue(pruner_ready.wait(5), "Pruner database connection did not start")
                    self._assert_database_wait(
                        pruner_pids[0],
                        publisher_pids[0],
                        pruner,
                        table=interval._meta.db_table,
                        statement=r"\bFOR UPDATE\b",
                    )
                finally:
                    release.set()
                self.assertEqual(publisher.result(timeout=15), 1)
                self.assertEqual(pruner.result(timeout=15), 1)
            interval.refresh_from_db()
            self.assertEqual(
                interval.totals,
                {
                    current_key: {"bytes": 123, "through": observed.isoformat(), "complete": True},
                },
            )
