"""Real PostgreSQL ordering of public create retry, receipt OFF and restore admission."""

from __future__ import annotations

import json
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from threading import Event
from time import monotonic
from typing import TypeVar
from unittest import skipUnless
from uuid import uuid4

from django.db import close_old_connections, connection, connections, transaction
from django.db.models.signals import post_save
from django.utils.module_loading import import_string
from django_q.models import OrmQ

from apps.common.types import Result
from apps.provisioning.virtualmin_backup_service import RestoreConfig
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob
from apps.provisioning.virtualmin_service import VirtualminBackupManagementService
from tests.provisioning import test_virtualmin_create_retry_policy as fixtures

_T = TypeVar("_T")


@skipUnless(connection.vendor == "postgresql", "Real PostgreSQL blocking and conditional claim updates are required")
class RevokedCreateConcurrencyTests(fixtures.CreateRetryFixture):
    def setUp(self) -> None:
        super().setUp()
        self.locking_queries: dict[int, str] = {}

    def _worker(self, action: Callable[[], _T], ready: Event, pids: list[int]) -> _T:
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SET lock_timeout = '20s'")
                cursor.execute("SET statement_timeout = '30s'")
                cursor.execute("SELECT pg_backend_pid()")
                pid = cursor.fetchone()[0]
                pids.append(pid)
            ready.set()

            def observe(execute, sql, params, many, context):
                if "FOR UPDATE" in sql or "FOR NO KEY UPDATE" in sql:
                    self.locking_queries[pid] = sql
                return execute(sql, params, many, context)

            with connection.execute_wrapper(observe):
                return action()
        finally:
            connections.close_all()

    def _wait_for_account_lock(self, pid: int, owner_pid: int, pending: Future[_T]) -> None:
        deadline, poll = monotonic() + 10, Event()
        sample = None
        while monotonic() < deadline:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_stat_clear_snapshot()")
                cursor.execute(
                    "SELECT wait_event_type, pg_blocking_pids(pid), query FROM pg_stat_activity WHERE pid = %s", [pid]
                )
                sample = cursor.fetchone()
            if sample and sample[0] == "Lock" and owner_pid in sample[1]:
                self.assertIn(connection.ops.quote_name(VirtualminAccount._meta.db_table), self.locking_queries[pid])
                self.assertTrue(sample[2].startswith("SELECT"), sample)
                print(
                    json.dumps(
                        {
                            "account_lock_wait": True,
                            "waiter_pid": pid,
                            "owner_pid": owner_pid,
                            "wait_event_type": sample[0],
                            "blocking_pids": sample[1],
                            "account_table": VirtualminAccount._meta.db_table,
                            "lock_clause": "FOR NO KEY UPDATE"
                            if "FOR NO KEY UPDATE" in self.locking_queries[pid]
                            else "FOR UPDATE",
                        }
                    ),
                    flush=True,
                )
                return
            if pending.done():
                self.fail(f"Public writer finished before the real Account lock wait: {pending.result()!r}")
            poll.wait(0.01)
        self.fail(f"No Account wait: pid={pid}, owner={owner_pid}, last_sample={sample!r}")

    def _take_payload(self, job: VirtualminProvisioningJob) -> tuple[str, str]:
        matches = []
        for row in OrmQ.objects.order_by("pk"):
            task = row.task
            args = task.get("args", ())
            if task.get("func") == fixtures.RETRY and args and str(args[0]) == str(job.pk):
                matches.append((row, task))
        self.assertEqual(len(matches), 1, "Only one normal owned nonce publication may be consumed")
        row, task = matches[0]
        self.assertFalse(task.get("kwargs", {}))
        args = task["args"]
        self.assertEqual(len(args), 2)
        job_id, nonce = args
        assert isinstance(job_id, str) and isinstance(nonce, str), "Normal retry arguments must remain strings"
        row.delete()
        return job_id, nonce

    def _prepare_retry(self) -> tuple[str, str]:
        self._failed_direct_create("provisioning", attach_order=True)
        swept = self._due_sweep()
        self.assertTrue(swept["success"], swept)
        self.assertEqual(swept["results"]["retried_jobs"], 1)
        return self._take_payload(self.job)

    @staticmethod
    def _consume(payload: tuple[str, str]) -> dict[str, object]:
        return import_string(fixtures.RETRY)(*payload)

    def _restore(self) -> Result[VirtualminProvisioningJob, str]:
        return VirtualminBackupManagementService(self.server).create_restore_job(
            self.account, RestoreConfig(backup_id="operator-retained-backup"), initiated_by=self.operator.email
        )

    def _off(self) -> VirtualminProvisioningJob:
        return VirtualminProvisioningJob.objects.get(
            account=self.account, operation="suspend_domain", parameters__revoked_create_job_id=str(self.job.pk)
        )

    def _native_enabled(self) -> bool:
        native = self.gateway.domain_state_of(self.account.domain)
        assert native is not None, "The exact created resource must survive without deletion"
        return native.enabled

    def _assert_one_child(self) -> VirtualminProvisioningJob:
        off = self._off()
        self.job.refresh_from_db()
        self.assertEqual(self.job.status, "attention")
        self.assertIsNone(self.job.next_retry_at)
        receipt = self.job.result["revoked_creation"]
        self.assertEqual(receipt["off_job_id"], str(off.pk))
        self.assertEqual(receipt["source_job_id"], str(self.job.pk))
        self.assertEqual(len(self.gateway.get_calls("create-domain")), 2)  # One rejection, one accepted retry.
        self.assertEqual(len(self.gateway.get_calls("delete-domain")), 0)
        return off

    def test_duplicate_real_source_and_off_nonce_deliveries_accept_each_mutation_once(self) -> None:
        payload = self._prepare_retry()
        accepted, release = Event(), Event()

        def accepted_create() -> None:
            self._cancel_and_run_normal_reconcile()
            accepted.set()
            self.assertTrue(release.wait(20), "Duplicate observer did not release accepted create")

        self.gateway.after_accepted_create = accepted_create
        with ThreadPoolExecutor(max_workers=2) as workers:
            first = workers.submit(self._worker, lambda: self._consume(payload), Event(), [])
            try:
                self.assertTrue(accepted.wait(10))
                duplicate = workers.submit(self._worker, lambda: self._consume(payload), Event(), [])
                self.assertEqual(duplicate.result(15)["action"], "stale_claim_discarded")
            finally:
                release.set()
            self.assertFalse(first.result(20)["success"])
        off = self._assert_one_child()
        off_payload = self._take_payload(off)
        disabling, release_off = Event(), Event()

        def before_disable() -> None:
            self.assertFalse(connection.in_atomic_block)
            disabling.set()
            self.assertTrue(release_off.wait(20), "Duplicate observer did not release OFF")

        self.gateway.before_disable = before_disable
        with ThreadPoolExecutor(max_workers=2) as workers:
            first_off = workers.submit(self._worker, lambda: self._consume(off_payload), Event(), [])
            try:
                self.assertTrue(disabling.wait(10))
                duplicate_off = workers.submit(self._worker, lambda: self._consume(off_payload), Event(), [])
                self.assertEqual(duplicate_off.result(15)["action"], "stale_claim_discarded")
            finally:
                release_off.set()
            self.assertTrue(first_off.result(20)["success"])
        self._assert_one_child()
        self.account.refresh_from_db()
        off.refresh_from_db()
        self.job.refresh_from_db()
        self.assertEqual((self.account.status, off.status), ("suspended", "completed"))
        self.assertEqual(self.job.result["revoked_creation"]["phase"], "disabled")
        self.assertEqual(len(self.gateway.get_calls("disable-domain")), 1)
        self.assertFalse(self._native_enabled())

    def test_public_restore_first_blocks_bookkeeping_then_prevents_off_publication(self) -> None:
        payload = self._prepare_retry()
        accepted, release_create, restored, release_restore = Event(), Event(), Event(), Event()

        def accepted_create() -> None:
            self._cancel_and_run_normal_reconcile()
            accepted.set()
            self.assertTrue(release_create.wait(20))

        def restore_owner() -> Result[VirtualminProvisioningJob, str]:
            # Extend ONLY this public writer's real transaction for observation.
            # Its create_restore_job acquires the Account mutex itself.
            with transaction.atomic():
                result = self._restore()
                self.assertTrue(result.is_ok(), result)
                restored.set()
                self.assertTrue(release_restore.wait(20))
            return result

        self.gateway.after_accepted_create = accepted_create
        with ThreadPoolExecutor(max_workers=2) as workers:
            retry_ready, restore_ready = Event(), Event()
            retry_pids: list[int] = []
            restore_pids: list[int] = []
            creator = workers.submit(self._worker, lambda: self._consume(payload), retry_ready, retry_pids)
            try:
                self.assertTrue(retry_ready.wait(10) and accepted.wait(10))
                restore = workers.submit(self._worker, restore_owner, restore_ready, restore_pids)
                self.assertTrue(restore_ready.wait(10) and restored.wait(10))
                release_create.set()
                self._wait_for_account_lock(retry_pids[0], restore_pids[0], creator)
            finally:
                release_create.set()
                release_restore.set()
            self.assertTrue(restore.result(20).is_ok())
            self.assertFalse(creator.result(20)["success"])
        self.job.refresh_from_db()
        self.assertEqual(self.job.status, "attention")
        self.assertEqual(self.job.result["revoked_creation"]["phase"], "blocked")
        self.assertEqual(
            VirtualminProvisioningJob.objects.filter(account=self.account, operation="restore_domain").count(), 1
        )
        self.assertFalse(
            VirtualminProvisioningJob.objects.filter(account=self.account, operation="suspend_domain").exists()
        )
        self.assertEqual(len(self.gateway.get_calls("disable-domain")), 0)
        self.assertTrue(self._native_enabled())

    def test_off_publication_first_blocks_public_restore_then_refuses_it(self) -> None:
        payload = self._prepare_retry()
        self.gateway.after_accepted_create = self._cancel_and_run_normal_reconcile
        published, release = Event(), Event()
        uid = "receipt-off-race-" + uuid4().hex

        def pause_real_insert(
            sender: type[VirtualminProvisioningJob],
            instance: VirtualminProvisioningJob,
            created: bool,
            **kwargs: object,
        ) -> None:
            if (
                created
                and instance.operation == "suspend_domain"
                and instance.parameters.get("revoked_create_job_id") == str(self.job.pk)
            ):
                self.assertTrue(connection.in_atomic_block)
                published.set()
                self.assertTrue(release.wait(20), "Observer did not release real OFF publication")

        post_save.connect(pause_real_insert, sender=VirtualminProvisioningJob, weak=False, dispatch_uid=uid)
        try:
            with ThreadPoolExecutor(max_workers=2) as workers:
                retry_ready, restore_ready = Event(), Event()
                retry_pids: list[int] = []
                restore_pids: list[int] = []
                creator = workers.submit(self._worker, lambda: self._consume(payload), retry_ready, retry_pids)
                try:
                    self.assertTrue(retry_ready.wait(10) and published.wait(10))
                    restore = workers.submit(self._worker, self._restore, restore_ready, restore_pids)
                    self.assertTrue(restore_ready.wait(10))
                    self._wait_for_account_lock(restore_pids[0], retry_pids[0], restore)
                finally:
                    release.set()
                self.assertFalse(creator.result(20)["success"])
                refused = restore.result(20)
                self.assertTrue(refused.is_err(), refused)
                self.assertIn("active operation", refused.unwrap_err())
        finally:
            release.set()
            post_save.disconnect(sender=VirtualminProvisioningJob, dispatch_uid=uid)
        self._assert_one_child()
        self.assertFalse(
            VirtualminProvisioningJob.objects.filter(account=self.account, operation="restore_domain").exists()
        )
        self.assertTrue(self._deliver_receipt_off()["success"])
        self.account.refresh_from_db()
        self.assertEqual(self.account.status, "suspended")
        self.assertFalse(self._native_enabled())
        self.assertEqual(len(self.gateway.get_calls("disable-domain")), 1)
