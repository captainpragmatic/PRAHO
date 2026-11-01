"""Terminal imported cleanup retires transport staging without deleting retained services."""

import importlib
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from django.utils import timezone

from apps.infrastructure.ansible_service import AnsibleService
from apps.provisioning.component_migration_transport import source_operation_variables
from apps.provisioning.component_target_transport import target_operation_variables
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from tests.provisioning.test_component_migration_admission import ComponentAdmissionTestBase


class ComponentArtifactCleanupTests(ComponentAdmissionTestBase):
    def setUp(self):
        super().setUp()
        self.cleanup = importlib.import_module("apps.provisioning.migration_artifact_cleanup")
        self.migration = self.start(self.approve(self.review()))
        self.source = self.enterContext(patch("apps.provisioning.component_artifact_cleanup.run_source_operation"))
        self.target_cleanup = self.enterContext(
            patch("apps.provisioning.component_artifact_cleanup.run_target_operation")
        )
        self.generic = self.enterContext(patch("apps.provisioning.migration_artifact_cleanup._remove_remote"))
        self.archive = Path(self.spool.name) / self.migration.archive_name
        self.archive.write_bytes(b"private selected archive")

    def terminal(self, status="rolled_back", *, restore=False, **state):
        # fsm-bypass: model the durable outcome of an independent native compensation worker.
        VirtualminMigration.objects.filter(pk=self.migration.pk).update(
            status=status, restore_issued=restore, barrier_state=state
        )
        self.migration.refresh_from_db()

    def clean(self):
        return self.cleanup.cleanup_migration_artifacts(str(self.migration.pk))["action"]

    def test_cancelled_before_hold_removes_only_controller_archive_without_ssh(self):
        self.terminal("failed")
        self.assertEqual(self.clean(), "cleaned")
        self.assertFalse(self.archive.exists())
        self.source.assert_not_called()
        self.target_cleanup.assert_not_called()
        self.generic.assert_not_called()

    def test_lost_export_response_still_retires_released_source_and_removed_target_staging(self):
        self.terminal(
            restore=True,
            component_source_hold_issued=True,
            component_source_released=True,
            component_target_archive_issued=True,
            component_target_removed=True,
        )
        self.assertNotIn("component_export", self.migration.barrier_state)
        self.assertEqual(self.clean(), "cleaned")
        self.assertEqual(self.source.call_args.args[2], "source_retire_artifacts")
        self.assertEqual(self.target_cleanup.call_args.args[2], "target_retire_artifacts")
        self.assertEqual(self.source.call_args.args[1], self.target_cleanup.call_args.args[1])
        self.assertFalse(self.archive.exists())
        self.assertEqual(self.clean(), "cleaned")
        self.assertEqual(self.source.call_count, 1)
        self.assertEqual(self.target_cleanup.call_count, 1)
        self.generic.assert_not_called()

    def test_pushed_archive_before_prepare_uses_exact_never_prepared_target_scope(self):
        self.terminal(component_target_archive_issued=True)
        self.assertEqual(self.clean(), "cleaned")
        self.assertEqual(self.target_cleanup.call_args.args[2], "target_retire_unprepared_archive")
        self.source.assert_not_called()
        self.generic.assert_not_called()

    def test_unreleased_source_and_unremoved_prepared_target_preserve_their_private_evidence(self):
        self.terminal(restore=True, component_source_hold_issued=True, component_target_archive_issued=True)
        self.assertEqual(self.clean(), "retrying")
        self.assertFalse(self.archive.exists(), "controller cleanup remains independent of unavailable remote proof")
        self.source.assert_not_called()
        self.target_cleanup.assert_not_called()
        self.migration.refresh_from_db()
        self.assertNotIn("done", self.migration.barrier_state["artifact_cleanup"])

    def test_source_failure_does_not_block_target_and_retry_contacts_only_missing_location(self):
        self.terminal(
            component_source_hold_issued=True, component_source_released=True, component_target_archive_issued=True
        )
        self.source.side_effect = RuntimeError("source unavailable")
        self.assertEqual(self.clean(), "retrying")
        self.assertEqual(self.target_cleanup.call_count, 1)
        self.migration.refresh_from_db()
        state = self.migration.barrier_state
        state["artifact_cleanup"]["next_run"] = (timezone.now() - timedelta(seconds=1)).isoformat()
        VirtualminMigration.objects.filter(pk=self.migration.pk).update(barrier_state=state)
        self.source.side_effect = None
        self.assertEqual(self.clean(), "cleaned")
        self.assertEqual(self.source.call_count, 2)
        self.assertEqual(self.target_cleanup.call_count, 1)

    def test_completed_and_sealed_outcomes_cannot_enter_terminal_component_cleanup(self):
        self.terminal("completed")
        self.assertEqual(self.clean(), "excluded")
        self.terminal(component_source_seal_intent=True)
        self.assertEqual(self.clean(), "retrying")
        self.assertTrue(self.archive.exists())
        self.source.assert_not_called()
        self.target_cleanup.assert_not_called()

    def test_current_cleanup_lease_is_required_between_remote_commands(self):
        self.terminal(
            component_source_hold_issued=True, component_source_released=True, component_target_archive_issued=True
        )

        def steal(*_args):
            VirtualminMigration.objects.filter(pk=self.migration.pk).update(lease_token=uuid4())

        self.source.side_effect = steal
        self.assertEqual(self.clean(), "busy")
        self.target_cleanup.assert_not_called()

    def test_malformed_native_intent_is_never_reinterpreted_as_no_remote_artifacts(self):
        for key in ("component_source_hold_issued", "component_target_archive_issued", "component_source_seal_intent"):
            with self.subTest(key=key):
                self.terminal(**{key: "true"})
                self.assertEqual(self.clean(), "retrying")
                self.source.assert_not_called()
                self.target_cleanup.assert_not_called()
                self.migration.refresh_from_db()
                self.assertNotIn("done", self.migration.barrier_state["artifact_cleanup"])

    def test_terminal_reclaim_discovers_imported_rollback_after_lost_dispatch(self):
        self.terminal()
        with patch("apps.provisioning.migration_artifact_cleanup.async_task") as enqueue:
            self.assertEqual(self.cleanup.reclaim_migration_artifacts(), 1)
        self.assertEqual(enqueue.call_args.args[1], str(self.migration.pk))


class ComponentArtifactTransportTests(ComponentAdmissionTestBase):
    def setUp(self):
        super().setUp()
        self.migration = self.start(self.approve(self.review()))
        self.token = uuid4()
        # fsm-bypass: the shared terminal artifact scheduler owns this isolated cleanup lease.
        VirtualminMigration.objects.filter(pk=self.migration.pk).update(
            status="rolled_back",
            archive_sha256="a" * 64,
            lease_token=self.token,
            worker_lease_expires_at=timezone.now() + timedelta(minutes=5),
            barrier_state={
                "component_source_hold_issued": True,
                "component_source_released": True,
                "component_target_archive_issued": True,
            },
        )
        self.migration.refresh_from_db()

    def refusal(self, action):
        source = action.startswith("source_")
        values = (source_operation_variables if source else target_operation_variables)(
            self.migration, self.token, action
        )
        return AnsibleService._server_playbook_authority(
            self.server if source else self.target, "virtualmin_component.yml", values, None
        )

    def test_terminal_scheduler_can_retire_released_source_and_never_prepared_target(self):
        for action in ("source_retire_artifacts", "target_retire_unprepared_archive"):
            with self.subTest(action=action):
                self.assertTrue(self.refusal(action).is_ok())
        self.assertTrue(self.refusal("target_retire_artifacts").is_err())

    def test_prepared_target_requires_independently_removed_native_receipt(self):
        VirtualminMigration.objects.filter(pk=self.migration.pk).update(restore_issued=True)
        self.migration.refresh_from_db()
        self.assertTrue(self.refusal("target_retire_unprepared_archive").is_err())
        self.assertTrue(self.refusal("target_retire_artifacts").is_err())
        state = {**self.migration.barrier_state, "component_target_removed": True}
        VirtualminMigration.objects.filter(pk=self.migration.pk).update(barrier_state=state)
        self.migration.refresh_from_db()
        self.assertTrue(self.refusal("target_retire_artifacts").is_ok())

    def test_uncertain_seal_or_stolen_lease_prevents_both_artifact_transports(self):
        for change in (
            {"barrier_state": {**self.migration.barrier_state, "component_source_seal_intent": True}},
            {"lease_token": uuid4()},
        ):
            VirtualminMigration.objects.filter(pk=self.migration.pk).update(**change)
            self.migration.refresh_from_db()
            for action in ("source_retire_artifacts", "target_retire_unprepared_archive"):
                self.assertTrue(self.refusal(action).is_err())
