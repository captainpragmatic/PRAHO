"""Round 2 contracts. RED/GREEN docstrings describe the pre-change expectation."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from unittest.mock import patch

from django.db import IntegrityError, transaction
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.common.types import Err, Ok
from apps.infrastructure.models import NodeDeployment
from apps.provisioning.models import Service
from apps.provisioning.virtualmin_drain_service import NodeDrainService
from apps.provisioning.virtualmin_migration_models import NodeDrain, VirtualminMigration
from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from apps.provisioning.virtualmin_service import (
    VirtualminProvisioningService,
    VirtualminServerManagementService,
)
from apps.provisioning.virtualmin_tasks import health_check_virtualmin_servers, run_node_drain
from apps.settings.catalog import CATALOG_BY_KEY
from apps.users.models import User
from tests.provisioning.test_virtualmin_migration_service import MigrationTestBase


class DrainTests(MigrationTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.settings_values["infrastructure.drain_enabled"] = True
        queue_patch = patch(
            "apps.provisioning.virtualmin_drain_service.async_task", return_value="drain-task"
        )
        self.drain_queue = queue_patch.start()
        self.addCleanup(queue_patch.stop)

    def _second(self, status: str = "suspended") -> VirtualminAccount:
        domain = f"second-{status}.example.com"
        # fsm-bypass: establish an existing customer service/account fixture.
        service = Service.objects.create(
            customer=self.customer, service_plan=self.plan, currency=self.currency,
            service_name=domain, domain=domain, username=f"second{status}",
            billing_cycle="monthly", price="10.00", status="active",
        )
        return VirtualminAccount.objects.create(
            service=service, server=self.server, domain=domain,
            virtualmin_username=f"second{status}", status=status, domains=[domain],
            encrypted_password=self.account.encrypted_password,
        )

    def _start_drain(self) -> NodeDrain:
        with self.captureOnCommitCallbacks(execute=True):
            result = NodeDrainService.start_drain(self.server, initiated_by=self.staff)
        self.assertTrue(result.is_ok(), result)
        self.server.refresh_from_db()
        self.assertTrue(self.server.is_draining)
        return result.unwrap()

    def _fake_run(
        self,
        drain: NodeDrain,
        *,
        first_status: str = "completed",
        after_first: Callable[[], object] | None = None,
    ) -> tuple[dict, list]:
        """Mock migration orchestration, while retaining real drain/account persistence."""
        attempted = []

        def start(account, target, *, initiated_by, reason, enqueue):
            self.assertEqual(reason, "drain")
            self.assertFalse(enqueue)
            attempted.append(account.pk)
            return Ok(VirtualminMigration.objects.create(
                account=account, source_server=account.server, target_server=target,
                initiated_by=initiated_by, reason=reason,
            ))

        def execute(migration_id):
            migration = VirtualminMigration.objects.get(pk=migration_id)
            status = first_status if len(attempted) == 1 else "completed"
            if status == "completed":
                account = migration.account
                account.server = migration.target_server
                account.save(update_fields=["server", "updated_at"])
            # fsm-bypass: emulate the terminal result of the mocked migration dependency.
            VirtualminMigration.objects.filter(pk=migration.pk).update(status=status)
            if len(attempted) == 1 and after_first:
                after_first()
            return Ok({
                "action": status, "migration_id": str(migration_id), "lease_acquired": True,
            })

        with (
            patch.object(VirtualminMigrationService, "start_migration", side_effect=start),
            patch.object(VirtualminMigrationService, "run", side_effect=execute),
        ):
            result = run_node_drain(str(drain.pk))
        drain.refresh_from_db()
        self.server.refresh_from_db()
        return result, attempted

    def _fail_health(self, count: int, server: VirtualminServer | None = None):
        server = server or self.server
        VirtualminServer.objects.filter(pk=server.pk).update(consecutive_health_failures=count - 1)
        with patch.object(
            VirtualminProvisioningService, "test_server_connection", return_value=Err("unreachable")
        ):
            result = VirtualminServerManagementService().health_check_server(server)
        server.refresh_from_db()
        self.assertTrue(result.is_err())
        self.assertEqual(result.unwrap_err(), "unreachable")
        return server

    def test_draining_blocks_shared_admission_and_placement(self) -> None:
        """RED: can_host_domain and least-loaded placement admit the draining server."""
        VirtualminServer.objects.filter(pk=self.server.pk).update(is_draining=True, current_domains=0)
        VirtualminServer.objects.filter(pk=self.target.pk).update(current_domains=20)
        self.server.refresh_from_db()
        self.assertTrue(self.server.is_healthy)
        self.assertFalse(self.server.can_host_domain())
        selected = VirtualminProvisioningService()._select_best_server()
        self.assertTrue(selected.is_ok(), selected)
        self.assertEqual(selected.unwrap().pk, self.target.pk)

    def test_migration_targets_exclude_draining_servers(self) -> None:
        """RED: eligible_targets still admits a draining target."""
        VirtualminServer.objects.filter(pk=self.target.pk).update(is_draining=True)
        self.assertEqual(VirtualminMigrationService.eligible_targets(self.account), [])

    def test_creation_preflight_rejects_freshly_draining_target(self) -> None:
        """RED: creation accesses the gateway despite the persisted drain flag."""
        VirtualminServer.objects.filter(pk=self.server.pk).update(is_draining=True)
        service = VirtualminProvisioningService(self.server)
        with patch.object(service, "_get_gateway") as gateway:
            result = service._execute_domain_creation(self.account, self._failed_job())
        self.assertTrue(result.is_err(), result)
        self.assertIn("draining", result.unwrap_err())
        gateway.assert_not_called()

    def test_retry_rejects_draining_before_adoption_or_creation(self) -> None:
        """RED: retry probes/adopts an existing domain or recreates an absent domain."""
        VirtualminServer.objects.filter(pk=self.server.pk).update(is_draining=True)
        service = VirtualminProvisioningService(self.server)
        for owner in (None, self.account.virtualmin_username):
            with self.subTest(owner=owner), transaction.atomic():
                with patch.object(service, "_get_gateway") as gateway:
                    gateway.return_value.get_domain_owner.return_value = Ok(owner)
                    result = service._retry_create_domain(self.account, self._failed_job())
                self.assertTrue(result.is_err(), result)
                self.assertIn("draining", result.unwrap_err())
                gateway.assert_not_called()
                transaction.set_rollback(True)

    def test_happy_path_requires_routing_finalization(self) -> None:
        """RED: drain orchestration, counts, exclusion, and finalization are absent."""
        second = self._second()
        terminated = self._second("terminated")
        drain = self._start_drain()
        self.assertEqual(drain.accounts_total, 2)
        result, attempted = self._fake_run(drain)
        self.assertTrue(result["success"], result)
        self.assertCountEqual(attempted, [self.account.pk, second.pk])
        self.assertNotIn(terminated.pk, attempted)
        self.assertEqual((drain.status, drain.accounts_migrated, drain.accounts_skipped), ("completed", 2, 0))
        self.assertTrue(self.server.is_draining)
        self.assertEqual(self.server.status, "active")
        self.assertFalse(drain.routing_confirmed)
        self.assertFalse(self.server.accounts.filter(status__in=("active", "suspended")).exists())

        finalized = NodeDrainService.finalize_drain(drain, confirmed_by=self.staff)
        self.assertTrue(finalized.is_ok(), finalized)
        drain.refresh_from_db()
        self.server.refresh_from_db()
        self.assertTrue(drain.routing_confirmed)
        self.assertEqual(self.server.status, "disabled")
        self.assertFalse(self.server.is_draining)
        for action in ("started", "completed", "finalized"):
            event = AuditEvent.objects.get(action=f"node_drain_{action}", object_id=str(drain.pk))
            event.full_clean()
        event = AuditEvent.objects.get(action="node_drain_finalized", object_id=str(drain.pk))
        self.assertEqual(event.user_id, self.staff.pk)

    def test_real_migration_accepts_drain_without_enqueuing(self) -> None:
        """RED: start_migration rejects drain and has no synchronous enqueue control."""
        VirtualminServer.objects.filter(pk=self.server.pk).update(is_draining=True)
        with self.captureOnCommitCallbacks(execute=True):
            result = VirtualminMigrationService().start_migration(
                self.account, self.target, initiated_by=self.staff, reason="drain", enqueue=False
            )
        self.assertTrue(result.is_ok(), result)
        self.enqueue.assert_not_called()
        execution = VirtualminMigrationService().run(result.unwrap().pk)
        self.assertTrue(execution.is_ok(), execution)
        self.account.refresh_from_db()
        self.assertEqual(self.account.server_id, self.target.pk)
        self.assertEqual(VirtualminMigration.objects.get(pk=result.unwrap().pk).status, "completed")

    def test_failed_or_review_migration_stops_before_second_account(self) -> None:
        """RED: drain does not pause and count outstanding accounts."""
        self._second()
        for status in ("needs_review", "failed", "rolled_back"):
            with self.subTest(status=status), transaction.atomic():
                drain = self._start_drain()
                result, attempted = self._fake_run(drain, first_status=status)
                self.assertFalse(result["success"])
                self.assertEqual(len(attempted), 1)
                self.assertEqual(drain.status, "paused_needs_review")
                self.assertEqual((drain.accounts_migrated, drain.accounts_skipped), (0, 2))
                self.assertTrue(self.server.is_draining)
                transaction.set_rollback(True)

    def test_source_health_is_rechecked_between_accounts(self) -> None:
        """RED: a second migration proceeds after the source becomes unhealthy."""
        self._second()
        drain = self._start_drain()
        _, attempted = self._fake_run(
            drain,
            after_first=lambda: VirtualminServer.objects.filter(pk=self.server.pk).update(
                health_check_error="unreachable"
            ),
        )
        self.assertEqual(len(attempted), 1)
        self.assertEqual(drain.status, "paused_needs_review")
        self.assertEqual((drain.accounts_migrated, drain.accounts_skipped), (1, 1))
        self.assertTrue(AuditEvent.objects.filter(
            action="node_drain_paused", object_id=str(drain.pk), requires_review=True
        ).exists())

    def test_cancel_waits_for_current_account(self) -> None:
        """RED: cooperative cancellation and admission restoration are absent."""
        self._second()
        drain = self._start_drain()

        def cancel():
            result = NodeDrainService.cancel_drain(drain)
            self.assertTrue(result.is_ok(), result)
            self.server.refresh_from_db()
            self.assertTrue(self.server.is_draining)

        _, attempted = self._fake_run(drain, after_first=cancel)
        self.assertEqual(len(attempted), 1)
        self.assertEqual(drain.status, "cancelled")
        self.assertEqual((drain.accounts_migrated, drain.accounts_skipped), (1, 1))
        self.assertEqual(self.server.status, "active")
        self.assertFalse(self.server.is_draining)
        self.assertTrue(AuditEvent.objects.filter(
            action="node_drain_cancelled", object_id=str(drain.pk)
        ).exists())

    def test_drain_preserves_eligible_target_policy_order(self) -> None:
        """RED: the drain locally re-sorts the policy-ordered target list by load."""
        heavier = VirtualminServer.objects.create(
            name="heavier", hostname="heavier.example.com", api_username="test",
            weight=200, current_domains=50, last_health_check=timezone.now(),
        )
        drain = self._start_drain()
        with patch.object(
            VirtualminMigrationService, "eligible_targets", return_value=[heavier, self.target]
        ):
            self._fake_run(drain)
        self.assertEqual(VirtualminMigration.objects.get(account=self.account).target_server_id, heavier.pk)

    def test_worker_checkpoints_without_overlapping_migrations(self) -> None:
        """RED: no bounded task checkpoint or stale-delivery token exists."""
        drain = self._start_drain()
        old_token = drain.task_token
        with (
            patch("apps.provisioning.virtualmin_drain_service.monotonic", side_effect=[0, 1000]),
            self.captureOnCommitCallbacks(execute=True),
        ):
            result = run_node_drain(str(drain.pk), str(old_token))
        self.assertEqual(result["status"], "pending")
        drain.refresh_from_db()
        self.assertNotEqual(drain.task_token, old_token)
        self.assertFalse(VirtualminMigration.objects.exists())
        self.assertEqual(self.drain_queue.call_count, 2)

        with patch.object(VirtualminMigrationService, "start_migration") as start:
            run_node_drain(str(drain.pk), str(old_token))
        start.assert_not_called()
        result, attempted = self._fake_run(drain)
        self.assertTrue(result["success"])
        self.assertEqual(len(attempted), 1)

    def test_interrupted_worker_requires_review_without_replay(self) -> None:
        """RED: interrupted drains have no review-only recovery."""
        drain = self._start_drain()
        # fsm-bypass: simulate a worker killed beyond its execution budget.
        NodeDrain.objects.filter(pk=drain.pk).update(
            status="running", worker_started_at=timezone.now() - timedelta(hours=6)
        )
        with patch.object(VirtualminMigrationService, "start_migration") as start:
            result = run_node_drain(str(drain.pk), str(drain.task_token))
        self.assertEqual(result["status"], "paused_needs_review")
        start.assert_not_called()

    def test_draining_defers_autofail_and_remains_in_sweep(self) -> None:
        """RED: sixth failure auto-fails draining nodes; selector inclusion itself is GREEN."""
        VirtualminServer.objects.filter(pk=self.server.pk).update(is_draining=True)
        server = self._fail_health(6)
        self.assertEqual(server.status, "active")
        self.assertEqual(server.consecutive_health_failures, 6)
        self.assertEqual(server.health_check_error, "unreachable")
        event = AuditEvent.objects.get(
            action="virtualmin_server_autofail_deferred", object_id=str(server.pk)
        )
        self.assertEqual(event.severity, "high")
        self.assertTrue(event.requires_review)

        with patch.object(VirtualminServerManagementService, "health_check_server", return_value=Ok({})) as check:
            result = health_check_virtualmin_servers()
        self.assertTrue(result["success"])
        self.assertIn(self.server.pk, [call.args[0].pk for call in check.call_args_list])

    def test_unowned_server_still_autofails(self) -> None:
        """GREEN pin: sixth failure retains existing auto-fail behavior."""
        server = self._fail_health(6)
        self.assertEqual(server.status, "failed")
        self.assertTrue(server.failed_by_health_check)

    def test_source_and_target_migrations_defer_until_terminal(self) -> None:
        """RED: non-terminal migrations on either side fail to defer auto-fail."""
        for checked_server in (self.server, self.target):
            with self.subTest(server=checked_server.pk), transaction.atomic():
                migration = VirtualminMigration.objects.create(
                    account=self.account, source_server=self.server, target_server=self.target,
                    status="needs_review",  # fsm-bypass: existing unresolved migration fixture.
                )
                server = self._fail_health(6, checked_server)
                self.assertEqual(server.status, "active")
                # fsm-bypass: emulate explicit resolution of the migration.
                VirtualminMigration.objects.filter(pk=migration.pk).update(status="rolled_back")
                server = self._fail_health(7, checked_server)
                self.assertEqual(server.status, "failed")
                transaction.set_rollback(True)

    def test_auto_drain_at_threshold(self) -> None:
        """RED: enabled auto-drain is never requested at the configured threshold."""
        self.settings_values["infrastructure.auto_drain_enabled"] = True
        with patch.object(NodeDrainService, "start_drain", return_value=Ok(None)) as start:
            self._fail_health(2)
            start.assert_not_called()
            self._fail_health(3)
            start.assert_called_once_with(self.server, initiated_by=None, reason="auto_health")
            self._fail_health(4)
            self.assertEqual(start.call_count, 1)
        self.assertEqual(AuditEvent.objects.filter(
            action="virtualmin_server_health_alert", object_id=str(self.server.pk)
        ).count(), 1)

    def test_default_auto_off_emits_only_alert(self) -> None:
        """RED: alert-only mode currently emits no threshold review audit."""
        with patch.object(NodeDrainService, "start_drain") as start:
            self._fail_health(3)
        start.assert_not_called()
        event = AuditEvent.objects.get(
            action="virtualmin_server_health_alert", object_id=str(self.server.pk)
        )
        self.assertTrue(event.requires_review)
        self.assertEqual(event.severity, "high")
        self.assertFalse(NodeDrain.objects.exists())

    def test_drain_flag_off_prevents_auto_start(self) -> None:
        """RED: coordinated flag gating and threshold alert are absent."""
        self.settings_values.update({
            "infrastructure.auto_drain_enabled": True,
            "infrastructure.drain_enabled": False,
        })
        with patch.object(NodeDrainService, "start_drain") as start:
            self._fail_health(3)
        start.assert_not_called()
        self.assertTrue(AuditEvent.objects.filter(action="virtualmin_server_health_alert").exists())

    def test_auto_start_failure_is_contained_and_audited(self) -> None:
        """RED: no contained auto-drain failure path exists."""
        self.settings_values["infrastructure.auto_drain_enabled"] = True
        with patch.object(NodeDrainService, "start_drain", side_effect=RuntimeError("queue unavailable")):
            self._fail_health(3)
        self.assertTrue(AuditEvent.objects.filter(
            action="virtualmin_server_health_alert", description__contains="queue unavailable"
        ).exists())

    def test_threshold_validation_and_runtime_clamp(self) -> None:
        """RED: missing catalog validation and unsafe threshold handling."""
        definition = CATALOG_BY_KEY["infrastructure.auto_drain_failure_threshold"]
        self.assertEqual(definition.validation, {"min": 1, "max": 5})
        self.settings_values["infrastructure.auto_drain_enabled"] = True
        for configured, effective in ((0, 1), (6, 5), (100, 5)):
            with self.subTest(configured=configured):
                self.settings_values["infrastructure.auto_drain_failure_threshold"] = configured
                with patch.object(NodeDrainService, "start_drain", return_value=Ok(None)) as start:
                    self._fail_health(effective)
                start.assert_called_once()

    def test_partial_unique_constraint_covers_every_nonterminal_state(self) -> None:
        """RED: no database constraint prevents competing drains."""
        for status in ("pending", "running", "paused_needs_review"):
            with self.subTest(status=status), transaction.atomic():
                # fsm-bypass: establish each non-terminal drain fixture.
                NodeDrain.objects.create(server=self.server, status=status)
                with self.assertRaises(IntegrityError), transaction.atomic():
                    NodeDrain.objects.create(server=self.server)
                transaction.set_rollback(True)
        NodeDrain.objects.create(server=self.server, status="completed")
        NodeDrain.objects.create(server=self.server)
        self.assertEqual(NodeDrain.objects.filter(server=self.server).count(), 2)

    def test_preflight_flags_and_managed_node_requirement(self) -> None:
        """RED: drain feature and managed-node preflights are absent."""
        for key in ("provisioning.migration_enabled", "infrastructure.drain_enabled"):
            with self.subTest(key=key):
                self.settings_values[key] = False
                result = NodeDrainService.start_drain(self.server, initiated_by=self.staff)
                self.assertTrue(result.is_err(), result)
                self.settings_values[key] = True
        NodeDeployment.objects.filter(virtualmin_server=self.server).delete()
        result = NodeDrainService.start_drain(self.server, initiated_by=self.staff)
        self.assertTrue(result.is_err(), result)
        self.assertIn("node_deployment", result.unwrap_err())
        self.assertFalse(NodeDrain.objects.exists())
        self.drain_queue.assert_not_called()

    def test_duplicate_start_and_early_finalization_are_rejected(self) -> None:
        """RED: duplicate starts and premature finalization have no guards."""
        drain = self._start_drain()
        self.assertTrue(NodeDrainService.start_drain(self.server, initiated_by=self.staff).is_err())
        self.assertTrue(NodeDrainService.finalize_drain(drain, confirmed_by=self.staff).is_err())
        self.assertEqual(NodeDrain.objects.count(), 1)
        self.server.refresh_from_db()
        self.assertTrue(self.server.is_draining)
        self.assertEqual(self.server.status, "active")

    def test_enqueue_failure_pauses_and_retains_exclusion(self) -> None:
        """RED: failed queue dispatch has no persistent review state."""
        self.drain_queue.side_effect = RuntimeError("broker unavailable")
        drain = self._start_drain()
        drain.refresh_from_db()
        self.assertEqual(drain.status, "paused_needs_review")
        self.assertIn("broker unavailable", drain.error_detail)
        self.assertTrue(self.server.is_draining)

    def test_staff_ui_requires_explicit_routing_confirmation(self) -> None:
        """RED: drain page and routing-confirmation POST gate do not exist."""
        self.client.force_login(self.staff)
        drain = self._start_drain()
        self._fake_run(drain)
        url = reverse("provisioning:node_drain", args=[self.server.pk])
        self.assertEqual(self.client.get(url).status_code, 200)
        payload = {"action": "finalize", "drain_id": str(drain.pk)}
        self.assertEqual(self.client.post(url, payload).status_code, 400)
        drain.refresh_from_db()
        self.assertFalse(drain.routing_confirmed)
        response = self.client.post(url, {**payload, "routing_confirmed": "on"})
        self.assertEqual(response.status_code, 302)
        self.server.refresh_from_db()
        self.assertEqual(self.server.status, "disabled")

    def test_nonstaff_cannot_start_drain(self) -> None:
        """RED: staff-only drain endpoint is absent."""
        user = User.objects.create_user(email="drain-customer@example.com", password="test-password")
        self.client.force_login(user)
        url = reverse("provisioning:node_drain", args=[self.server.pk])
        response = self.client.post(url, {"action": "start"})
        self.assertEqual(response.status_code, 302)
        self.assertFalse(NodeDrain.objects.exists())
