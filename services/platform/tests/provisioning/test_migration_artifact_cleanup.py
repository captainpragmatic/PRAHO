"""Terminal moves retire only their UUID-owned temporary transport artifacts."""

from __future__ import annotations

import importlib
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from django.utils import timezone

from apps.common.types import Err, Ok
from apps.infrastructure.ansible_service import AnsibleResult
from apps.provisioning.virtualmin_migration_models import SpoolReservation, VirtualminMigration
from tests.provisioning.test_virtualmin_migration_service import MigrationTestBase


class MigrationArtifactCleanupTests(MigrationTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.cleanup = importlib.import_module("apps.provisioning.migration_artifact_cleanup")
        self.remote: dict[object, set[str]] = {self.server.pk: set(), self.target.pk: set()}
        self.failed_node: object | None = None
        self.calls: list[tuple[object, str]] = []
        runner = patch("apps.provisioning.migration_artifact_cleanup.AnsibleService")
        self.runner = runner.start()
        self.addCleanup(runner.stop)
        self.runner.return_value.run_playbook.side_effect = self._remove_remote

    def migration(self, status: str = "completed", **fields: object) -> VirtualminMigration:
        return VirtualminMigration.objects.create(
            account=self.account,
            source_server=self.server,
            target_server=self.target,
            status=status,
            contract="legacy",
            **fields,
        )

    def stage(self, migration: VirtualminMigration) -> None:
        for suffix in ("", ".dom", ".info"):
            name = migration.archive_name + suffix
            (Path(self.spool.name) / name).write_text("archive or private sidecar")
            for files in self.remote.values():
                files.add(name)
        SpoolReservation.objects.create(
            archive_name=migration.archive_name,
            expected_bytes=128,
            owner=f"migration:{migration.pk}",
            expires_at=timezone.now() + timedelta(hours=1),
        )

    def _remove_remote(self, deployment, playbook, variables, *, timeout_seconds):
        self.assertEqual(playbook, "virtualmin_remote_cleanup.yml")
        self.assertGreater(timeout_seconds, 0)
        self.assertEqual(set(variables), {"archive_name"})
        node, name = deployment.virtualmin_server_id, variables["archive_name"]
        self.calls.append((node, name))
        if node == self.failed_node:
            return Err("node unavailable")
        self.remote[node].difference_update(name + suffix for suffix in ("", ".dom", ".info"))
        return Ok(AnsibleResult(success=True, playbook=playbook, stdout="", stderr="", return_code=0))

    def force_due(self, migration: VirtualminMigration) -> None:
        migration.refresh_from_db()
        state = migration.barrier_state
        state["artifact_cleanup"]["next_run"] = (timezone.now() - timedelta(seconds=1)).isoformat()
        VirtualminMigration.objects.filter(pk=migration.pk).update(barrier_state=state)

    def test_each_determinate_terminal_exit_removes_archive_sidecars_and_reservation_everywhere(self) -> None:
        untouched = "virtualmin_backup_" + uuid4().hex + ".tar.gz"
        (Path(self.spool.name) / untouched).write_text("later account backup")
        for files in self.remote.values():
            files.add(untouched)
        for status in ("completed", "failed", "rolled_back"):
            with self.subTest(status=status):
                migration = self.migration(status)
                self.stage(migration)
                self.assertEqual(self.cleanup.cleanup_migration_artifacts(str(migration.pk))["action"], "cleaned")
                migration.refresh_from_db()
                self.assertTrue(migration.barrier_state["artifact_cleanup"]["done"])
                self.assertIsNone(migration.lease_token)
                self.assertEqual(migration.status, status)
                for suffix in ("", ".dom", ".info"):
                    name = migration.archive_name + suffix
                    self.assertFalse((Path(self.spool.name) / name).exists())
                    self.assertTrue(all(name not in files for files in self.remote.values()))
                self.assertFalse(SpoolReservation.objects.filter(archive_name=migration.archive_name).exists())
                self.assertEqual(self.cleanup.cleanup_migration_artifacts(str(migration.pk))["action"], "cleaned")
        self.assertEqual(len(self.calls), 6, "a completed cleanup does not contact nodes again")
        self.assertTrue((Path(self.spool.name) / untouched).exists())
        self.assertTrue(all(untouched in files for files in self.remote.values()))

    def test_active_and_ambiguous_operations_are_never_cleaned(self) -> None:
        for status in ("needs_review", "restoring", "pending"):
            migration = self.migration(status)
            self.stage(migration)
            self.assertEqual(self.cleanup.cleanup_migration_artifacts(str(migration.pk))["action"], "excluded")
            self.assertTrue((Path(self.spool.name) / migration.archive_name).exists())
            migration.delete()
        self.assertEqual(self.calls, [])

    def test_completed_cutover_retires_held_and_activation_data_on_target(self) -> None:
        migration = self.migration(
            barrier_state={"target_domain_id": "42", "held_archives": [{"archive_name": "held"}]}
        )
        self.stage(migration)
        with (
            patch("apps.provisioning.migration_target_hold.cleanup_held_target") as held,
            patch(
                "apps.provisioning.migration_bridge_service.retire_target_activation_data", return_value=Ok("retired")
            ) as activation,
        ):
            self.assertEqual(self.cleanup.cleanup_migration_artifacts(str(migration.pk))["action"], "cleaned")
        held.assert_called_once()
        activation.assert_called_once()
        self.assertEqual(held.call_args.args[0].target_server_id, self.target.pk)
        migration.refresh_from_db()
        self.assertTrue(migration.barrier_state["artifact_cleanup"]["target_hold"])
        self.assertTrue(migration.barrier_state["artifact_cleanup"]["target_activation"])

    def test_activation_retirement_failure_remains_retryable_without_repeating_other_cleanup(self) -> None:
        migration = self.migration(
            barrier_state={"target_domain_id": "42", "held_archives": [{"archive_name": "held"}]}
        )
        self.stage(migration)
        with (
            patch("apps.provisioning.migration_target_hold.cleanup_held_target") as held,
            patch(
                "apps.provisioning.migration_bridge_service.retire_target_activation_data",
                return_value=Err("node unavailable"),
            ),
        ):
            self.assertEqual(self.cleanup.cleanup_migration_artifacts(str(migration.pk))["action"], "retrying")
        held.assert_called_once()
        self.force_due(migration)
        with (
            patch("apps.provisioning.migration_target_hold.cleanup_held_target") as held,
            patch(
                "apps.provisioning.migration_bridge_service.retire_target_activation_data", return_value=Ok("retired")
            ) as activation,
        ):
            self.assertEqual(self.cleanup.cleanup_migration_artifacts(str(migration.pk))["action"], "cleaned")
        held.assert_not_called()
        activation.assert_called_once()
        self.assertEqual(len(self.calls), 2)

    def test_later_account_operation_keeps_its_own_uuid_artifacts(self) -> None:
        previous, current = self.migration(), self.migration("restoring")
        self.stage(previous)
        self.stage(current)
        self.assertEqual(self.cleanup.cleanup_migration_artifacts(str(previous.pk))["action"], "cleaned")
        for suffix in ("", ".dom", ".info"):
            name = current.archive_name + suffix
            self.assertTrue((Path(self.spool.name) / name).exists())
            self.assertTrue(all(name in files for files in self.remote.values()))
        self.assertTrue(SpoolReservation.objects.filter(archive_name=current.archive_name).exists())

    def test_recovery_archives_are_excluded_by_both_contract_and_reason(self) -> None:
        for field in ("contract", "reason"):
            migration = self.migration()
            VirtualminMigration.objects.filter(pk=migration.pk).update(**{field: "recovery"})
            self.stage(migration)
            self.assertEqual(self.cleanup.cleanup_migration_artifacts(str(migration.pk))["action"], "excluded")
            self.assertTrue((Path(self.spool.name) / migration.archive_name).exists())
        self.assertEqual(self.calls, [])

    def test_an_unavailable_source_does_not_prevent_target_cleanup_and_retry_resumes_only_missing_work(self) -> None:
        migration = self.migration()
        self.stage(migration)
        self.failed_node = self.server.pk
        self.assertEqual(self.cleanup.cleanup_migration_artifacts(str(migration.pk))["action"], "retrying")
        migration.refresh_from_db()
        state = migration.barrier_state["artifact_cleanup"]
        self.assertTrue(state["spool"])
        self.assertTrue(state["target"])
        self.assertFalse(state.get("source", False))
        self.failed_node = None
        self.force_due(migration)
        self.assertEqual(self.cleanup.cleanup_migration_artifacts(str(migration.pk))["action"], "cleaned")
        self.assertEqual([node for node, _ in self.calls], [self.server.pk, self.target.pk, self.server.pk])

    def test_a_live_migration_lease_blocks_cleanup_and_an_expired_one_can_be_reclaimed(self) -> None:
        migration = self.migration()
        self.stage(migration)
        VirtualminMigration.objects.filter(pk=migration.pk).update(
            lease_token=uuid4(),
            worker_lease_expires_at=timezone.now() + timedelta(minutes=5),
        )
        self.assertEqual(self.cleanup.cleanup_migration_artifacts(str(migration.pk))["action"], "busy")
        self.assertTrue((Path(self.spool.name) / migration.archive_name).exists())
        VirtualminMigration.objects.filter(pk=migration.pk).update(
            worker_lease_expires_at=timezone.now() - timedelta(seconds=1)
        )
        self.assertEqual(self.cleanup.cleanup_migration_artifacts(str(migration.pk))["action"], "cleaned")

    def test_lease_loss_after_one_remote_command_cannot_checkpoint_or_contact_the_other_node(self) -> None:
        migration = self.migration()
        self.stage(migration)
        replacement = uuid4()

        def steal(*args, **kwargs):
            result = self._remove_remote(*args, **kwargs)
            VirtualminMigration.objects.filter(pk=migration.pk).update(
                lease_token=replacement,
                worker_lease_expires_at=timezone.now() + timedelta(minutes=5),
            )
            return result

        self.runner.return_value.run_playbook.side_effect = steal
        self.assertEqual(self.cleanup.cleanup_migration_artifacts(str(migration.pk))["action"], "busy")
        migration.refresh_from_db()
        self.assertEqual(migration.lease_token, replacement)
        self.assertFalse(migration.barrier_state["artifact_cleanup"].get("source", False))
        self.assertEqual(len(self.calls), 1)

    def test_archive_names_from_another_operation_are_never_used(self) -> None:
        migration = self.migration()
        self.stage(migration)
        original = migration.archive_name
        VirtualminMigration.objects.filter(pk=migration.pk).update(archive_name="migration_" + str(uuid4()) + ".tar.gz")
        self.assertEqual(self.cleanup.cleanup_migration_artifacts(str(migration.pk))["action"], "retrying")
        self.assertTrue((Path(self.spool.name) / original).exists())
        self.assertEqual(self.calls, [])

    def test_spool_symlinks_never_delete_their_target(self) -> None:
        migration = self.migration()
        target = Path(self.spool.name) / "customer-content"
        target.write_text("owned by account")
        (Path(self.spool.name) / migration.archive_name).symlink_to(target)
        self.assertEqual(self.cleanup.cleanup_migration_artifacts(str(migration.pk))["action"], "retrying")
        self.assertEqual(target.read_text(), "owned by account")
        migration.refresh_from_db()
        self.assertFalse(migration.barrier_state["artifact_cleanup"].get("spool", False))

    def test_due_retry_sweep_ignores_finished_future_and_leased_cleanup_rows(self) -> None:
        due = self.migration()
        finished, future, leased = self.migration(), self.migration(), self.migration()
        VirtualminMigration.objects.filter(pk=finished.pk).update(barrier_state={"artifact_cleanup": {"done": True}})
        VirtualminMigration.objects.filter(pk=future.pk).update(
            barrier_state={
                "artifact_cleanup": {"next_run": (timezone.now() + timedelta(hours=1)).isoformat()},
            }
        )
        VirtualminMigration.objects.filter(pk=leased.pk).update(
            lease_token=uuid4(),
            worker_lease_expires_at=timezone.now() + timedelta(minutes=5),
        )
        with patch("apps.provisioning.migration_artifact_cleanup.async_task") as dispatch:
            self.assertEqual(self.cleanup.reclaim_migration_artifacts(), 1)
        self.assertEqual(dispatch.call_args.args[1], str(due.pk))

    def test_failed_dispatch_is_recovered_by_the_bounded_terminal_sweep(self) -> None:
        migrations = [self.migration() for _ in range(7)]
        self.migration("needs_review")
        excluded = self.migration()
        VirtualminMigration.objects.filter(pk=excluded.pk).update(contract="recovery")
        with patch("apps.provisioning.migration_artifact_cleanup.async_task", side_effect=OSError("queue down")):
            self.assertFalse(self.cleanup.schedule_artifact_cleanup(migrations[0].pk))
        with patch("apps.provisioning.migration_artifact_cleanup.async_task") as dispatch:
            self.assertEqual(self.cleanup.reclaim_migration_artifacts(), 5)
        self.assertEqual(dispatch.call_count, 5)
        self.assertNotIn(str(excluded.pk), [call.args[1] for call in dispatch.call_args_list])
