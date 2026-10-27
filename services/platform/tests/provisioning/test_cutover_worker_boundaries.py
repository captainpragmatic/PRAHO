"""Managed cutovers yield between expensive phases and hold targets before committing."""

from datetime import timedelta
from unittest.mock import patch

from django.utils import timezone

from apps.common.types import Ok
from apps.provisioning.migration_barrier import BarrierStep
from apps.provisioning.virtualmin_migration_service import (
    MigrationDeferredError,
    VirtualminMigrationService,
    migration_task_timeout,
)
from tests.provisioning.test_virtualmin_migration_barrier_wiring import BarrierCase


class CutoverWorkerTests(BarrierCase):
    def test_an_absent_target_does_not_release_exclusion_before_its_held_runner_is_cancelled(self):
        migration, token = self._held(
            "compensating",
            contract="cutover",
            restore_issued=True,
            barrier_state={"target_domain_id": "42", "held_archives": []},
        )
        service = VirtualminMigrationService()
        with (
            patch(
                "apps.provisioning.virtualmin_migration_service.run_barrier", return_value=Ok(BarrierStep("ok", "idle"))
            ),
            patch.object(
                service,
                "_release_target_hold",
                side_effect=MigrationDeferredError(timezone.now() + timedelta(seconds=60), "Node runner busy"),
            ),
            patch("apps.provisioning.virtualmin_tasks.schedule_migration_wake"),
        ):
            service.execute(migration, token)
        migration.refresh_from_db()
        self.assertEqual(migration.status, "compensating")
        self.assertIsNotNone(migration.resume_after)

    def test_small_transfer_settings_cannot_shorten_the_worker_below_bridge_rpc_budget(self):
        self.settings_values.update(
            {"provisioning.migration_backup_timeout_seconds": 60, "provisioning.migration_transfer_timeout_seconds": 60}
        )
        self.assertGreaterEqual(migration_task_timeout(), 10800)

    def test_completed_backup_yields_before_a_fresh_transfer_is_dispatched(self):
        migration, token = self._held("backing_up", contract="cutover")
        service = VirtualminMigrationService()

        def backup(row, owner):
            service._move(row, owner, "fetching")

        with (
            patch.object(service, "_backup", side_effect=backup),
            patch.object(service, "_transfer", side_effect=AssertionError("Transfer belongs to the next worker")),
            patch("apps.provisioning.virtualmin_tasks.schedule_migration_wake"),
        ):
            service.execute(migration, token)
        migration.refresh_from_db()
        self.assertEqual(migration.status, "fetching")
        self.assertIsNotNone(migration.resume_after)

    def test_cutover_restore_uses_the_shared_held_target_primitive(self):
        migration, token = self._held("restoring", contract="cutover", archive_sha256="a" * 64)
        with patch("apps.provisioning.migration_target_hold.restore_held_target") as restore:
            VirtualminMigrationService()._restore(migration, token)
        restore.assert_called_once()
        self.assertEqual(
            restore.call_args.args[3], [{"archive_name": migration.archive_name, "checksum_sha256": "a" * 64}]
        )
        self.assertNotIn("restore-domain", self._programs("target"))

    def test_final_recovery_transfer_yields_before_starting_the_held_restore(self):
        migration, token = self._held("fetching", contract="recovery")
        service = VirtualminMigrationService()

        def transfer(row, owner):
            service._move(row, owner, "pushing")
            service._move(row, owner, "restoring")

        with (
            patch.object(service, "_transfer", side_effect=transfer),
            patch.object(service, "_restore", side_effect=AssertionError("Restore belongs to the next worker")),
            patch("apps.provisioning.virtualmin_tasks.schedule_migration_wake"),
        ):
            service.execute(migration, token)
        migration.refresh_from_db()
        self.assertEqual(migration.status, "restoring")
        self.assertIsNotNone(migration.resume_after)
