"""Crash and cancellation regressions from the ADR-0061 cutover review."""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

from django.urls import reverse
from django.utils import timezone

from apps.common.types import Ok
from apps.provisioning import virtualmin_tasks
from apps.provisioning.migration_barrier import BarrierStep
from apps.provisioning.virtualmin_migration_models import VirtualminMigration, account_has_active_migration
from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService, migration_task_timeout
from tests.provisioning.test_virtualmin_migration_barrier_wiring import RECORD, TOKEN, BarrierCase


class BarrierReplayRegressionTests(BarrierCase):
    def test_compensation_defers_while_native_target_operations_are_busy(self) -> None:
        migration, token = self._held("compensating", contract="cutover", restore_issued=True)
        with patch(
            "apps.provisioning.virtualmin_migration_service.run_barrier",
            return_value=Ok(BarrierStep("busy", "operation_running")),
        ):
            VirtualminMigrationService().execute(migration, token)
        migration.refresh_from_db()
        self.assertEqual(migration.status, "compensating")
        self.assertEqual(migration.parked_phase, "")
        self.assertIsNotNone(migration.resume_after)
        self.assertNotIn("delete-domain", self._programs("target"))

    def test_mail_enabled_domains_are_refused_before_the_source_is_fenced(self) -> None:
        state = self.source_gateway.domain_state_of(self.account.domain)
        assert state is not None
        state.features = ["unix", "dir", "web", "ssl", "mail", "mysql"]
        result = VirtualminMigrationService().start_migration(self.account, self.target, initiated_by=self.staff)
        self.assertTrue(result.is_err(), result)
        self.assertIn("mail", result.unwrap_err().lower())
        self.assertNotIn("disable-domain", self._programs("source"))
        self.assertNotIn("backup-domain", self._programs("source"))

    def test_replayed_quiesce_keeps_the_original_record_and_process_fence(self) -> None:
        migration, token = self._cutover()
        original = {"record": RECORD, "token": TOKEN}
        VirtualminMigration.objects.filter(pk=migration.pk).update(barrier_state=original)
        migration.refresh_from_db()
        actions: list[str] = []

        def node(_server, variables):
            action = variables["barrier_action"]
            actions.append(action)
            self.assertNotEqual(action, "record", "a replay must not replace the pre-fence record")
            if action == "verify":
                self.assertEqual(variables["barrier_killed_at"], "123")
            return Ok(BarrierStep("ok", action, {"killed_at": 123}))

        with patch("apps.provisioning.virtualmin_migration_service.run_barrier", side_effect=node):
            VirtualminMigrationService()._quiesce(migration, token)

        migration.refresh_from_db()
        self.assertEqual(actions, ["apply", "verify"])
        self.assertEqual(migration.status, "backing_up")
        self.assertEqual(migration.barrier_state["record"], RECORD)
        self.assertEqual(migration.barrier_state["token"], TOKEN)

    def test_rollback_does_not_cascade_enable_after_exact_barrier_release(self) -> None:
        migration, token = self._cutover()
        VirtualminMigration.objects.filter(pk=migration.pk).update(
            source_disabled_at=timezone.now(), barrier_state={"record": RECORD, "token": TOKEN}
        )
        migration.refresh_from_db()

        with patch(
            "apps.provisioning.virtualmin_migration_service.run_barrier",
            return_value=Ok(BarrierStep("ok", "released")),
        ):
            VirtualminMigrationService()._rollback(migration, token, target_delete_allowed=False)

        migration.refresh_from_db()
        self.assertEqual(migration.status, "rolled_back", migration.error_detail)
        self.assertNotIn("enable-domain", self._programs("source"))


class CancellationCompensationRegressionTests(BarrierCase):
    def _restored(self):
        migration, token = self._cutover("verifying")
        snapshot = migration.pre_migration_snapshot
        snapshot["domain"] = self.account.domain
        snapshot["remote"].update(domain=self.account.domain, username=self.account.virtualmin_username)
        self.target_gateway.seed_domain(self.account.domain, username=self.account.virtualmin_username, enabled=False)
        VirtualminMigration.objects.filter(pk=migration.pk).update(
            restore_issued=True,
            cancel_requested=True,
            barrier_state={"record": RECORD, "token": TOKEN},
            pre_migration_snapshot=snapshot,
        )
        migration.refresh_from_db()
        self.assertIsNotNone(self.target_gateway.domain_state_of(self.account.domain))
        return migration, token

    def test_cancel_after_restore_removes_the_target_before_releasing_the_source(self) -> None:
        migration, token = self._restored()
        actions: list[tuple[str, str]] = []

        def node(server, variables):
            side = "source" if server.pk == self.server.pk else "target"
            action = variables["barrier_action"]
            actions.append((side, action))
            if action == "release":
                self.assertIsNone(self.target_gateway.domain_state_of(self.account.domain))
                self.assertEqual(variables["barrier_saved_token"], TOKEN)
            return Ok(BarrierStep("ok", action))

        with patch("apps.provisioning.virtualmin_migration_service.run_barrier", side_effect=node):
            VirtualminMigrationService().execute(migration, token)

        migration.refresh_from_db()
        self.assertEqual(migration.status, "rolled_back", migration.error_detail)
        self.assertIsNone(self.target_gateway.domain_state_of(self.account.domain))
        self.assertEqual(actions, [("target", "idle"), ("source", "release")])

    def test_a_busy_target_defers_compensation_without_releasing_the_source(self) -> None:
        migration, token = self._restored()

        def node(_server, variables):
            self.assertEqual(variables["barrier_action"], "idle")
            return Ok(BarrierStep("busy", "operation_running"))

        with patch("apps.provisioning.virtualmin_migration_service.run_barrier", side_effect=node):
            VirtualminMigrationService().execute(migration, token)

        migration.refresh_from_db()
        self.assertEqual((migration.status, migration.parked_phase), ("compensating", ""))
        self.assertIsNotNone(migration.resume_after)
        self.assertIsNotNone(self.target_gateway.domain_state_of(self.account.domain))
        self.assertTrue(account_has_active_migration(self.account))
        self.assertNotIn("delete-domain", self._programs("target"))

    def test_a_target_owned_by_someone_else_is_never_deleted(self) -> None:
        migration, token = self._restored()
        self.target_gateway.domain_state_of(self.account.domain).username = "another-owner"
        with patch(
            "apps.provisioning.virtualmin_migration_service.run_barrier",
            return_value=Ok(BarrierStep("ok", "idle")),
        ):
            VirtualminMigrationService().execute(migration, token)
        migration.refresh_from_db()
        self.assertEqual(migration.parked_phase, "compensating")
        self.assertNotIn("delete-domain", self._programs("target"))

    def test_a_successful_noop_delete_keeps_the_compensation_parked(self) -> None:
        migration, token = self._restored()
        self.effects[("target", "delete-domain")] = lambda: self.original_calls["target"]("info", {})
        with patch(
            "apps.provisioning.virtualmin_migration_service.run_barrier",
            return_value=Ok(BarrierStep("ok", "idle")),
        ):
            VirtualminMigrationService().execute(migration, token)
        migration.refresh_from_db()
        self.assertEqual(migration.parked_phase, "compensating")
        self.assertIsNotNone(self.target_gateway.domain_state_of(self.account.domain))
        self.assertTrue(account_has_active_migration(self.account))

    def test_compensation_resumes_after_a_worker_crash(self) -> None:
        migration, _ = self._restored()
        VirtualminMigration.objects.filter(pk=migration.pk).update(
            status="compensating", lease_token=None, worker_lease_expires_at=None
        )

        with patch(
            "apps.provisioning.virtualmin_migration_service.run_barrier",
            return_value=Ok(BarrierStep("ok", "confirmed")),
        ):
            VirtualminMigrationService().run(migration.pk)

        migration.refresh_from_db()
        self.assertEqual(migration.status, "rolled_back")
        self.assertIsNone(self.target_gateway.domain_state_of(self.account.domain))

    def test_staff_can_retry_a_parked_compensation_without_unlocking_it(self) -> None:
        migration, _ = self._restored()
        VirtualminMigration.objects.filter(pk=migration.pk).update(
            status="compensating", parked_phase="compensating", lease_token=None, worker_lease_expires_at=None
        )
        self.client.force_login(self.staff)

        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                reverse("provisioning:virtualmin_migration_resolve", args=[self.account.pk]),
                {"migration_id": str(migration.pk), "note": "Earlier node operation has stopped"},
            )

        self.assertEqual(response.status_code, 302)
        migration.refresh_from_db()
        self.assertEqual((migration.status, migration.parked_phase), ("compensating", ""))
        self.assertTrue(account_has_active_migration(self.account))
        self.enqueue.assert_called()


class WakeBudgetRegressionTests(BarrierCase):
    def test_scheduled_wake_retains_the_full_migration_budget(self) -> None:
        migration = self._start()
        with patch.object(virtualmin_tasks, "schedule") as scheduled:
            self.assertTrue(
                virtualmin_tasks.schedule_migration_wake(migration.pk, timezone.now() + timedelta(minutes=1))
            )
        self.assertEqual(scheduled.call_args.kwargs.get("q_options"), {"timeout": migration_task_timeout()})
