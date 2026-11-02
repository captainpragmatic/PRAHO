"""Original node authority and current hosting intent both fence create recovery."""

from __future__ import annotations

import json
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from typing import Any, Literal
from unittest import skipUnless
from unittest.mock import patch

from django.core.cache import cache
from django.db import close_old_connections, connection, connections
from django.test import Client
from django.urls import reverse
from django.utils.module_loading import import_string
from django_q.models import OrmQ
from django_q.signing import SignedPackage

from apps.common.types import Retriability
from apps.orders.models import Order
from apps.orders.services import OrderService, StatusChangeData
from apps.provisioning.models import Service
from apps.provisioning.virtualmin_gateway import get_virtualmin_timeouts
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from apps.provisioning.virtualmin_node_capability import destination_refusal
from apps.provisioning.virtualmin_security import acknowledge_source, connection_identity, record_inspection
from apps.provisioning.virtualmin_tasks import provision_virtualmin_account
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService
from apps.users.models import User
from tests.provisioning import test_virtualmin_create_retry_policy as fixtures
from tests.provisioning.test_node_security_policy import node_policy_evidence

SWEEP = "apps.provisioning.virtualmin_tasks.process_failed_virtualmin_jobs"
TIMEOUT_SETTING_KEY = "virtualmin.request_timeout_seconds"
Boundary = Literal["node", "timeout_settings"]


class CombinedRetryFixture(fixtures.CreateRetryFixture):
    def _accepted_original(self) -> None:
        self.gateway.first_create_accepted = True
        self.gateway.first_create_retriability = Retriability.UNKNOWN
        outcome = provision_virtualmin_account(
            {
                "service_id": str(self.service.pk),
                "domain": self.service.domain,
                "username": self.service.username,
                "password": None,
                "template": "Default Settings",
                "server_id": str(self.server.pk),
            }
        )
        self.assertFalse(outcome["success"], outcome)
        self.assertEqual(outcome["retriability"], "unknown")
        self.account = VirtualminAccount.objects.get(service=self.service)
        self.job = VirtualminProvisioningJob.objects.get(account=self.account, operation="create_domain")
        self.assertEqual((self.account.status, self.job.status), ("error", "failed"))
        self.assertIsNone(self.job.next_retry_at)
        self.original_secret = bytes(self.account.encrypted_password)
        self.assertIsNotNone(self.gateway.domain_state_of(self.account.domain))

    def _staff_probe(self) -> dict[str, Any]:
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.operator)
        page = client.get(reverse("provisioning:virtualmin_job_status", args=[self.job.pk]))
        self.assertEqual(page.status_code, 200)
        token = client.cookies["csrftoken"].value
        route = reverse("provisioning:virtualmin_job_retry", args=[self.job.pk])
        self.assertEqual(client.post(route).status_code, 403)
        before = set(OrmQ.objects.values_list("pk", flat=True))
        self.assertEqual(client.post(route, {"csrfmiddlewaretoken": token}).status_code, 302)
        rows = [row for row in OrmQ.objects.exclude(pk__in=before) if row.task["func"] == SWEEP]
        self.assertEqual(len(rows), 1)
        task = SignedPackage.loads(rows[0].payload)
        rows[0].delete()
        swept = import_string(SWEEP)(*task.get("args", ()), **task.get("kwargs", {}))
        self.assertTrue(swept["success"], swept)
        delivered = self._deliver_owned(fixtures.RETRY, str(self.job.pk))
        self.assertEqual(len(delivered), 1, delivered)
        return delivered[0]

    def _withdraw_node(self, *, source_only: bool) -> None:
        if source_only:
            actor = User.objects.create_superuser(email="combined-node-operator@example.com", password="fixture-secret")
            evidence = node_policy_evidence()
            evidence["identity"] = connection_identity(self.server)
            review = record_inspection(self.server, evidence)
            acknowledge_source(
                review, evidence, actor, "Retain original mail/DNS/Unix; no new web destination admission"
            )
        else:
            self.server.legacy_security_admission = False
            self.server.save(update_fields=["legacy_security_admission", "updated_at"])
        self.server.refresh_from_db()
        self.assertIsNotNone(destination_refusal(self.server))

    def _assert_single_off(self) -> None:
        outcome = self._deliver_receipt_off()
        self.assertTrue(outcome["success"], outcome)
        self.job.refresh_from_db()
        self.account.refresh_from_db()
        self.assertEqual(self.job.result["revoked_creation"]["phase"], "disabled")
        self.assertEqual(self.account.status, "suspended")
        self.assertEqual(bytes(self.account.encrypted_password), self.original_secret)
        self.assertFalse(self.gateway.domain_state_of(self.account.domain).enabled)
        self.assertEqual(len(self.gateway.get_calls("create-domain")), 1)
        self.assertEqual(len(self.gateway.get_calls("disable-domain")), 1)
        self.assertEqual(len(self.gateway.get_calls("enable-domain")), 0)
        self.assertEqual(len(self.gateway.get_calls("delete-domain")), 0)
        self.assertEqual(
            VirtualminProvisioningJob.objects.filter(
                account=self.account, operation="suspend_domain", parameters__revoked_create_job_id=str(self.job.pk)
            ).count(),
            1,
        )


class CreateRetryNodeCapabilityTests(CombinedRetryFixture):
    def test_original_unknown_cancelled_service_still_disables_once_after_legacy_withdrawal(self) -> None:
        self._accepted_original()
        self._cancel_and_run_normal_reconcile()
        self._withdraw_node(source_only=False)
        self._staff_probe()
        self._assert_single_off()

    def test_original_unknown_cancelled_service_still_disables_once_after_real_source_ack(self) -> None:
        self._accepted_original()
        self._cancel_and_run_normal_reconcile()
        self._withdraw_node(source_only=True)
        self._staff_probe()
        self._assert_single_off()

    def test_unverified_absent_target_never_receives_new_create(self) -> None:
        self._failed_public_create()
        self._withdraw_node(source_only=False)
        outcome = self._retry_through_public_sweep()
        self.assertFalse(outcome["success"], outcome)
        self.assertIsNone(self.gateway.domain_state_of(self.account.domain))
        self.assertEqual(len(self.gateway.get_calls("create-domain")), 1)
        self.assertEqual(len(self.gateway.get_calls("enable-domain")), 0)

    def test_node_admission_withdrawn_during_actual_preflight_read_refuses_create(self) -> None:
        self._failed_public_create()
        actual_read = self.gateway.list_templates
        observed = []

        def read_then_withdraw() -> Any:
            result = actual_read()
            self._withdraw_node(source_only=False)
            observed.append(True)
            return result

        with patch.object(self.gateway, "list_templates", side_effect=read_then_withdraw):
            self._retry_through_public_sweep()
        self.assertEqual(observed, [True])
        self.assertEqual(
            len(self.gateway.get_calls("create-domain")),
            1,
            "A new CREATE ran after the actual destination policy was withdrawn during preflight",
        )
        self.assertIsNone(self.gateway.domain_state_of(self.account.domain))


@skipUnless(connection.vendor == "postgresql", "Real concurrent public revocation needs PostgreSQL")
class CreateRetryFinalBoundaryTests(CombinedRetryFixture):
    @staticmethod
    def _matches_boundary(sql: str, params: Any, boundary: Boundary) -> bool:
        if boundary == "node":
            return "FOR UPDATE" in sql and (f"FROM {connection.ops.quote_name(VirtualminServer._meta.db_table)}" in sql)
        return (
            sql.lstrip().startswith("SELECT")
            and f"FROM {connection.ops.quote_name(SystemSetting._meta.db_table)}" in sql
            and TIMEOUT_SETTING_KEY in (params or ())
        )

    def _run_retry_at_boundary(
        self,
        packet: dict[str, Any],
        preflight_done: Event,
        pause_events: tuple[Event, Event],
        worker_pid: list[int],
        boundary: Boundary,
    ) -> dict[str, Any]:
        boundary_read, release = pause_events
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SET lock_timeout = '10s'")
                cursor.execute("SET statement_timeout = '20s'")
                cursor.execute("SELECT pg_backend_pid()")
                worker_pid.append(cursor.fetchone()[0])
            latched = False

            def observe(execute: Callable[..., Any], sql: str, params: Any, many: bool, context: dict[str, Any]) -> Any:
                nonlocal latched
                result = execute(sql, params, many, context)
                if not latched and preflight_done.is_set() and self._matches_boundary(sql, params, boundary):
                    latched = True
                    self.assertEqual(connection.in_atomic_block, boundary == "node")
                    boundary_read.set()
                    self.assertTrue(
                        release.wait(15), "Public cancellation never committed at the observed SQL boundary"
                    )
                return result

            with connection.execute_wrapper(observe):
                return import_string(fixtures.RETRY)(*packet["args"], **packet.get("kwargs", {}))
        finally:
            connections.close_all()

    def _cancel_order(self, writer_pid: list[int], *, reconcile: bool) -> bool:
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SET lock_timeout = '10s'")
                cursor.execute("SET statement_timeout = '20s'")
                cursor.execute("SELECT pg_backend_pid()")
                writer_pid.append(cursor.fetchone()[0])
            order = Order.objects.get(pk=self.order.pk)
            result = OrderService.update_order_status(order, StatusChangeData("cancelled", changed_by=self.operator))
            self.assertTrue(result.is_ok(), result)
            self.assertEqual(Order.objects.get(pk=order.pk).status, "cancelled")
            self.assertEqual(Service.objects.get(pk=self.service.pk).status, "suspended")
            if reconcile:
                native_calls = len(self.gateway.get_calls())
                outcomes = self._deliver_owned(fixtures.RECONCILE, str(self.service.pk))
                self.assertTrue(outcomes, "Public cancellation did not publish normal reconciliation")
                self.assertTrue(
                    all(outcome.get("action") in {"noop", "operation_active"} for outcome in outcomes), outcomes
                )
                self.assertEqual(len(self.gateway.get_calls()), native_calls)
            return True
        finally:
            connections.close_all()

    def test_real_order_cancellation_at_final_node_sql_is_seen_by_last_dispatch_check(self) -> None:
        self._assert_cancel_at_boundary("node")

    def test_real_cancellation_during_timeout_settings_read_prevents_new_create(self) -> None:
        # Only the service-level budget lookup is covered. Gateway internals and
        # the check-to-RPC network gap still need the existing post-acceptance OFF.
        self._assert_cancel_at_boundary("timeout_settings")

    def _assert_cancel_at_boundary(self, boundary: Boundary) -> None:
        self._failed_public_create()
        original_secret = bytes(self.account.encrypted_password)
        original_identity = self.job.parameters["node_connection_identity"]
        original_count = VirtualminServer.objects.get(pk=self.server.pk).current_domains
        swept = self._due_sweep()
        self.assertTrue(swept["success"], swept)
        packets = [
            row
            for row in OrmQ.objects.all()
            if row.task["func"] == fixtures.RETRY and str(row.task["args"][0]) == str(self.job.pk)
        ]
        self.assertEqual(len(packets), 1)
        packet = SignedPackage.loads(packets[0].payload)
        packets[0].delete()
        preflight_done, boundary_read, release = Event(), Event(), Event()
        worker_pid = []
        writer_pid = []
        actual_templates = self.gateway.list_templates

        def templates() -> Any:
            result = actual_templates()
            if boundary == "timeout_settings":
                # Cool only this real value after native preflight. Preserve the
                # invalidation token, every other cache entry and the actual getter.
                cache.delete(SettingsService._get_cache_key(TIMEOUT_SETTING_KEY), version=SettingsService.CACHE_VERSION)
            preflight_done.set()
            return result

        with (
            patch.object(self.gateway, "list_templates", side_effect=templates),
            ThreadPoolExecutor(max_workers=2) as pool,
        ):
            pending = pool.submit(
                self._run_retry_at_boundary, packet, preflight_done, (boundary_read, release), worker_pid, boundary
            )
            try:
                self.assertTrue(boundary_read.wait(15), f"Did not reach the actual {boundary} SQL boundary")
                self.assertTrue(
                    pool.submit(self._cancel_order, writer_pid, reconcile=boundary == "timeout_settings").result(
                        timeout=15
                    )
                )
                self.assertNotEqual(worker_pid, writer_pid)
                print(
                    json.dumps(
                        {
                            "latch": f"actual_{boundary}_query",
                            "worker_pid": worker_pid[0],
                            "public_order_writer_pid": writer_pid[0],
                            "public_cancel_committed_before_release": True,
                        }
                    )
                )
            finally:
                release.set()
            pending.result(timeout=20)
        self.assertEqual(
            len(self.gateway.get_calls("create-domain")),
            1,
            "Fresh CREATE crossed public cancellation after the last service/account check",
        )
        self.assertIsNone(self.gateway.domain_state_of(self.account.domain))
        if boundary == "timeout_settings":
            self.account.refresh_from_db()
            self.job.refresh_from_db()
            self.assertEqual(self.job.status, "failed")
            self.assertIsNone(self.job.next_retry_at)
            self.assertEqual(self.account.status, "error")
            self.assertEqual(bytes(self.account.encrypted_password), original_secret)
            self.assertEqual(self.job.parameters["node_connection_identity"], original_identity)
            self.assertEqual(VirtualminServer.objects.get(pk=self.server.pk).current_domains, original_count)
            self.assertEqual(len(self.gateway.get_calls("enable-domain")), 0)
            self.assertEqual(len(self.gateway.get_calls("delete-domain")), 0)
            self.assertNotIn("revoked_creation", self.job.result)

    def test_public_retry_preserves_real_provisioning_timeout(self) -> None:
        self._failed_public_create()
        # Exercise the real configuration source, not a mocked timeout getter.
        self.assertEqual(get_virtualmin_timeouts()["PROVISIONING_TIMEOUT"], 180)
        with patch.object(self.gateway, "call", wraps=self.gateway.call) as external_calls:
            result = self._retry_through_public_sweep()
        self.assertTrue(result["success"], result)
        creates = [call for call in external_calls.call_args_list if call.args[0] == "create-domain"]
        self.assertEqual(len(creates), 1)
        self.assertEqual(creates[0].kwargs["timeout_seconds"], 180)
        self.assertEqual(len(self.gateway.get_calls("create-domain")), 2)
