"""Combined public retry ownership and landed node-maintenance admission."""

from __future__ import annotations

import json
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import time, timedelta
from threading import Event
from time import monotonic
from typing import TypeVar
from unittest import skipUnless
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.db import close_old_connections, connection, connections, transaction
from django.db.models.signals import post_save
from django.test import Client
from django.urls import reverse
from django.utils import timezone
from django.utils.module_loading import import_string
from django_q.models import OrmQ

from apps.infrastructure.node_maintenance_models import NodeMaintenancePolicy, NodeMaintenanceWindow
from apps.infrastructure.node_maintenance_service import change_window, create_window
from apps.provisioning.virtualmin_migration_models import account_has_active_operation
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob, VirtualminServer
from tests.provisioning.test_virtualmin_create_retry_policy import RETRY, CreateRetryFixture

_T = TypeVar("_T")


class MaintenanceRetryFixture(CreateRetryFixture):
    def _window(self) -> NodeMaintenanceWindow:
        NodeMaintenancePolicy.objects.create(
            node=self.server,
            timezone="Etc/GMT-6" if timezone.now().hour < 12 else "Etc/GMT+6",
            weekdays=list(range(7)),
            starts_time=time(0),
            ends_time=time(23, 59),
            max_defer_minutes=30,
        )
        starts_at = timezone.now() - timedelta(seconds=10)
        return create_window(
            self.server.pk,
            actor=self.operator,
            kind="panel_update",
            execution_mode="manual",
            starts_at=starts_at,
            ends_at=starts_at + timedelta(minutes=30),
            expects_downtime=True,
            expected_downtime_minutes=5,
            customer_note="Hosting software maintenance.",
        )

    def _start(self, window: NodeMaintenanceWindow) -> NodeMaintenanceWindow:
        return change_window(
            window.pk, actor=self.operator, revision=window.revision, action="start", reason="Approved work"
        )


class CreateRetryMaintenanceTests(MaintenanceRetryFixture):
    def test_normal_retry_keeps_its_claim_through_the_shared_native_gate(self) -> None:
        self._failed_public_create()
        observed_claims = []
        owner = self.gateway.get_domain_owner

        def record_claim(domain):
            current = VirtualminProvisioningJob.objects.get(pk=self.job.pk)
            observed_claims.append((current.status, current.claimed_at, current.started_at))
            return owner(domain)

        def accepted() -> None:
            current = VirtualminProvisioningJob.objects.get(pk=self.job.pk)
            observed_claims.append((current.status, current.claimed_at, current.started_at))

        self.gateway.after_accepted_create = accepted
        with patch.object(self.gateway, "get_domain_owner", side_effect=record_claim):
            result = self._retry_through_public_sweep()

        self.job.refresh_from_db()
        self.assertEqual(
            observed_claims[0][2], self.job.started_at, "The shared gate replaced the owned retry's start timestamp"
        )
        self.assertEqual(len(observed_claims), 2, "Actual owner observation and native create must both be reached")
        self.assertEqual(observed_claims[0][0], "running")
        self.assertIsNotNone(observed_claims[0][2])
        self.assertEqual(observed_claims[0], observed_claims[1], "Maintenance admission restarted the owned retry")
        self.assertTrue(result["success"], result)
        self.assertEqual(self.job.status, "completed")
        self.assertEqual(self.job.retry_count, 1)

    def test_a_started_window_refuses_the_real_queued_retry_before_creation(self) -> None:
        self._failed_public_create()
        window = self._start(self._window())

        result = self._retry_through_public_sweep()

        self.assertFalse(result["success"], result)
        self.assertEqual(len(self.gateway.get_calls("create-domain")), 1)
        self.assertIsNone(self.gateway.domain_state_of(self.account.domain))
        window.refresh_from_db()
        self.assertEqual(window.status, "running")

    def test_off_publication_won_first_prevents_the_public_window_start(self) -> None:
        self._failed_direct_create("provisioning", attach_order=True)
        window = self._window()
        self.gateway.after_accepted_create = self._cancel_and_run_normal_reconcile

        result = self._retry_through_public_sweep()

        self.assertFalse(result["success"], result)
        self.assertEqual(
            VirtualminProvisioningJob.objects.filter(account=self.account, operation="suspend_domain").count(), 1
        )
        with self.assertRaisesMessage(ValidationError, "hosting-account operation"):
            self._start(window)
        self.assertTrue(self._deliver_receipt_off()["success"])
        self.assertEqual(len(self.gateway.get_calls("disable-domain")), 1)

    def test_a_window_winning_the_committed_create_gap_parks_an_usable_unissued_review(self) -> None:
        self._failed_direct_create("provisioning", attach_order=True)
        window = self._window()
        observed = []

        def after_settlement(sender, instance, **kwargs) -> None:
            if instance.pk == self.job.pk and instance.status == "completed" and not observed:
                observed.append(instance.pk)
                # This is a real public competing writer AFTER the source commit,
                # before the producer returns to publish its recovery child.
                transaction.on_commit(lambda: self._start(window))

        post_save.connect(after_settlement, sender=VirtualminProvisioningJob, weak=False)
        self.addCleanup(post_save.disconnect, after_settlement, sender=VirtualminProvisioningJob)
        self.gateway.after_accepted_create = self._cancel_and_run_normal_reconcile

        result = self._retry_through_public_sweep()

        self.assertFalse(result["success"], result)
        self.assertEqual(observed, [self.job.pk], "The real source completion boundary was not reached")
        window.refresh_from_db()
        self.assertEqual(window.status, "running")
        self.assertFalse(VirtualminProvisioningJob.objects.filter(account=self.account, operation="suspend_domain"))
        self.job.refresh_from_db()
        self.assertEqual(self.job.status, "attention")
        self.assertIsNone(self.job.next_retry_at)
        self.assertNotIn("revoked_creation", self.job.result)
        review = self.job.result["creation_review"]
        self.assertEqual(review["server_id"], str(self.server.pk))
        self.assertEqual(review["domain"], self.account.domain)
        self.assertEqual(review["owner"], self.account.virtualmin_username)
        self.assertEqual(review["native_outcome"], "created")
        self.assertEqual(review["phase"], "off_not_issued_maintenance")
        self.assertFalse(account_has_active_operation(self.account), "An unissued review is not a global OFF hold")
        self.assertTrue(self.gateway.domain_state_of(self.account.domain).enabled)
        self.assertEqual(len(self.gateway.get_calls("disable-domain")), 0)
        self._acknowledge_unissued_review(review)

    def _acknowledge_unissued_review(self, review: dict[str, object]) -> None:
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.operator)
        status_url = reverse("provisioning:virtualmin_job_status", args=[self.job.pk])
        page = client.get(status_url)
        self.assertEqual(page.status_code, 200)
        self.assertNotContains(page, "The linked disable operation must be settled first")
        token = client.cookies["csrftoken"].value
        resolve_url = reverse("provisioning:virtualmin_job_resolve", args=[self.job.pk])
        self.assertEqual(client.post(resolve_url, {"note": "Investigated recorded target"}).status_code, 403)
        before = len(self.gateway.get_calls())
        response = client.post(
            resolve_url, {"note": "Reviewed actual enabled resource; OFF was not issued"}, HTTP_X_CSRFTOKEN=token
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(len(self.gateway.get_calls()), before, "Acknowledgement must not claim a native verification")
        self.job.refresh_from_db()
        self.assertEqual(self.job.status, "failed")
        self.assertIsNone(self.job.next_retry_at)
        self.assertEqual(self.job.result["creation_review"], review)
        self.assertEqual(self._deliver_owned(RETRY, str(self.job.pk)), [], "Acknowledgement must not replay creation")

        queued_before = set(OrmQ.objects.values_list("pk", flat=True))
        retry_url = reverse("provisioning:virtualmin_job_retry", args=[self.job.pk])
        self.assertEqual(client.post(retry_url, HTTP_X_CSRFTOKEN=token).status_code, 302)
        sweeps = [
            row
            for row in OrmQ.objects.exclude(pk__in=queued_before)
            if row.task["func"] == "apps.provisioning.virtualmin_tasks.process_failed_virtualmin_jobs"
        ]
        self.assertEqual(len(sweeps), 1)
        task = sweeps[0].task
        sweeps[0].delete()
        self.assertTrue(import_string(task["func"])(*task["args"], **task.get("kwargs", {}))["success"])
        delivered = self._deliver_owned(RETRY, str(self.job.pk))
        self.assertEqual(len(delivered), 1)
        self.assertFalse(delivered[0]["success"], delivered)
        self.assertFalse(VirtualminProvisioningJob.objects.filter(account=self.account, operation="suspend_domain"))
        self.assertEqual(len(self.gateway.get_calls("create-domain")), 2)
        self.assertEqual(len(self.gateway.get_calls("disable-domain")), 0)
        self.assertEqual(len(self.gateway.get_calls("enable-domain")), 0)
        self.assertEqual(len(self.gateway.get_calls("delete-domain")), 0)


@skipUnless(connection.vendor == "postgresql", "Actual server-row locks and blocking PIDs require PostgreSQL")
class CreateRetryMaintenanceConcurrencyTests(MaintenanceRetryFixture):
    def setUp(self) -> None:
        super().setUp()
        self.locking_queries: dict[int, str] = {}

    def _worker(self, action: Callable[[], _T], pids: list[int]) -> _T:
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SET lock_timeout = '20s'")
                cursor.execute("SET statement_timeout = '30s'")
                cursor.execute("SELECT pg_backend_pid()")
                pid = cursor.fetchone()[0]
                pids.append(pid)

            def observe(execute, sql, params, many, context):
                if "FOR UPDATE" in sql:
                    self.locking_queries[pid] = sql
                return execute(sql, params, many, context)

            with connection.execute_wrapper(observe):
                return action()
        finally:
            connections.close_all()

    def _wait_for_server_lock(self, pids: list[int], owner: list[int], pending: Future[_T]) -> None:
        deadline, poll = monotonic() + 10, Event()
        sample = None
        while monotonic() < deadline:
            if pids:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_stat_clear_snapshot()")
                    cursor.execute(
                        "SELECT wait_event_type, pg_blocking_pids(pid), query FROM pg_stat_activity WHERE pid = %s",
                        [pids[0]],
                    )
                    sample = cursor.fetchone()
                if sample and sample[0] == "Lock" and owner[0] in sample[1]:
                    full_query = self.locking_queries[pids[0]]
                    self.assertIn(connection.ops.quote_name(VirtualminServer._meta.db_table), full_query)
                    self.assertIn("FOR UPDATE", full_query)
                    print(
                        json.dumps(
                            {
                                "server_lock_wait": True,
                                "waiter_pid": pids[0],
                                "owner_pid": owner[0],
                                "blocking_pids": sample[1],
                            }
                        ),
                        flush=True,
                    )
                    return
            if pending.done():
                self.fail(f"Public operation finished before the actual Server lock wait: {pending.result()!r}")
            poll.wait(0.01)
        self.fail(f"No Server lock wait observed: {sample!r}")

    def _take_retry_payload(self) -> tuple[str, str]:
        rows = [
            row
            for row in OrmQ.objects.all()
            if row.task["func"] == RETRY and str(row.task.get("args", [None])[0]) == str(self.job.pk)
        ]
        self.assertEqual(len(rows), 1)
        task = rows[0].task
        rows[0].delete()
        job_id, nonce = task["args"]
        assert isinstance(job_id, str) and isinstance(nonce, str), (
            "The actual queued nonce arguments must remain strings"
        )
        return job_id, nonce

    def test_window_first_serializes_the_real_retry_at_the_server_mutex(self) -> None:
        self._failed_public_create()
        window = self._window()
        held, release = Event(), Event()
        owner, waiter = [], []

        def window_published(sender, instance, **kwargs) -> None:
            if instance.pk == window.pk and instance.status == "running":
                self.assertTrue(connection.in_atomic_block)
                held.set()
                self.assertTrue(release.wait(15), "The real retry did not release window publication")

        post_save.connect(window_published, sender=NodeMaintenanceWindow, weak=False)
        self.addCleanup(post_save.disconnect, window_published, sender=NodeMaintenanceWindow)
        with ThreadPoolExecutor(max_workers=2) as workers:
            publisher = workers.submit(self._worker, lambda: self._start(window), owner)
            try:
                self.assertTrue(held.wait(10), "Public maintenance start never published its real window")
                self.assertEqual(self._due_sweep()["results"]["retried_jobs"], 1)
                payload = self._take_retry_payload()
                consumer = workers.submit(self._worker, lambda: import_string(RETRY)(*payload), waiter)
                self._wait_for_server_lock(waiter, owner, consumer)
            finally:
                release.set()
            self.assertEqual(publisher.result(15).status, "running")
            self.assertFalse(consumer.result(15)["success"])
        self.assertEqual(len(self.gateway.get_calls("create-domain")), 1)
        self.assertIsNone(self.gateway.domain_state_of(self.account.domain))
        self.job.refresh_from_db()
        self.assertEqual(self.job.retry_count, 1)

    def test_off_publication_first_serializes_the_public_window_at_the_server_mutex(self) -> None:
        self._failed_direct_create("provisioning", attach_order=True)
        window = self._window()
        self.assertEqual(self._due_sweep()["results"]["retried_jobs"], 1)
        payload = self._take_retry_payload()
        self.gateway.after_accepted_create = self._cancel_and_run_normal_reconcile
        held, release = Event(), Event()
        owner, waiter = [], []

        def off_published(sender, instance, created, **kwargs) -> None:
            if created and instance.parameters.get("revoked_create_job_id") == str(self.job.pk):
                self.assertTrue(connection.in_atomic_block)
                held.set()
                self.assertTrue(release.wait(15), "The public window did not release actual OFF publication")

        post_save.connect(off_published, sender=VirtualminProvisioningJob, weak=False)
        self.addCleanup(post_save.disconnect, off_published, sender=VirtualminProvisioningJob)
        with ThreadPoolExecutor(max_workers=2) as workers:
            publisher = workers.submit(self._worker, lambda: import_string(RETRY)(*payload), owner)
            try:
                self.assertTrue(held.wait(10), "Actual public retry never published receipt OFF")
                starter = workers.submit(self._worker, lambda: self._start(window), waiter)
                self._wait_for_server_lock(waiter, owner, starter)
            finally:
                release.set()
            self.assertFalse(publisher.result(15)["success"])
            with self.assertRaisesMessage(ValidationError, "hosting-account operation"):
                starter.result(15)
        window.refresh_from_db()
        self.assertEqual(window.status, "scheduled")
        self.assertFalse(window.executions.exists())
        self.assertEqual(
            VirtualminProvisioningJob.objects.filter(account=self.account, operation="suspend_domain").count(), 1
        )
        self.assertTrue(self._deliver_receipt_off()["success"])
        self.assertEqual(len(self.gateway.get_calls("create-domain")), 2)
        self.assertEqual(len(self.gateway.get_calls("disable-domain")), 1)
