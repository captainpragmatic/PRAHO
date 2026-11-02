"""Typed historical terminal receipts distinguish native holds from private archive debt."""

from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.common.types import Err
from apps.provisioning.migration_artifact_cleanup import cleanup_migration_artifacts
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from tests.infrastructure.maintenance_component_fixtures import MaintenanceComponentFixture


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    Q_CLUSTER={"name": "maintenance-component-receipts", "orm": "default", "retry": 100000},
)
class NodeMaintenanceComponentReceiptTests(MaintenanceComponentFixture, TestCase):
    def terminal(self, evidence, *, restored=False, release_lease=True):
        migration = self.component_start()
        token = uuid4()
        self.assertTrue(migration.acquire_lease(token, timedelta(minutes=5)))
        # Persist the historical receipt being classified through the actual lease
        # and transition CAS. This is controller admission proof, not native proof.
        self.assertTrue(
            migration.transition(token, "pending", "quiescing", barrier_state=evidence, restore_issued=restored)
        )
        values = {"lease_token": None, "worker_lease_expires_at": None} if release_lease else {}
        self.assertTrue(migration.transition(token, "quiescing", "rolled_back", **values))
        migration.refresh_from_db()
        self.assertEqual(migration.status, "rolled_back")
        return migration

    def test_unreleased_terminal_source_hold_refuses_source_maintenance(self):
        self.terminal({"component_source_hold_issued": True})
        with self.assertRaisesMessage(ValidationError, "component"):
            self.window()

    def test_removed_target_receipt_must_be_true_before_target_maintenance(self):
        migration = self.terminal({"component_target_removed": "true"}, restored=True)
        from apps.infrastructure.node_maintenance_service import create_window  # noqa: PLC0415

        starts_at = timezone.now() - timedelta(seconds=10)
        with self.assertRaisesMessage(ValidationError, "component"):
            create_window(
                self.target.pk,
                actor=self.actor,
                kind="panel_update",
                execution_mode="manual",
                starts_at=starts_at,
                ends_at=starts_at + timedelta(minutes=30),
                expects_downtime=True,
                expected_downtime_minutes=5,
                customer_note="Hosting maintenance",
            )
        self.assertTrue(VirtualminMigration.objects.get(pk=migration.pk).restore_issued)

    def test_unknown_hold_marker_is_not_equivalent_to_never_issued(self):
        self.terminal({"component_source_hold_issued": "unknown", "component_source_released": True})
        with self.assertRaisesMessage(ValidationError, "component"):
            self.window()

    def test_live_terminal_cleanup_lease_still_owns_the_endpoints_after_native_release(self):
        migration = self.terminal(
            {"component_source_hold_issued": True, "component_source_released": True},
            release_lease=False,
        )
        self.assertIsNotNone(migration.lease_token)
        with self.assertRaisesMessage(ValidationError, "component"):
            self.window()

    def test_released_native_holds_with_only_private_archive_debt_allow_source_maintenance(self):
        self.terminal(
            {
                "component_source_hold_issued": True,
                "component_source_released": True,
                "component_target_removed": True,
                "artifact_cleanup": {"done": False},
            },
            restored=True,
        )
        self.assertEqual(self.start(self.window()).status, "running")

    def test_running_maintenance_defers_terminal_artifact_cleanup_before_any_remote_dispatch(self):
        migration = self.terminal(
            {
                "component_source_hold_issued": True,
                "component_source_released": True,
                "component_target_removed": True,
                "artifact_cleanup": {"done": False},
            },
            restored=True,
        )
        evidence = migration.barrier_state
        self.start(self.window())
        with patch(
            "apps.infrastructure.ansible_service.AnsibleService.run_server_playbook",
            return_value=Err("A running maintenance window must prevent this remote dispatch"),
        ) as remote:
            result = cleanup_migration_artifacts(str(migration.pk))
        self.assertEqual(result, {"action": "waiting"}, f"remote dispatches={remote.call_count}")
        remote.assert_not_called()
        migration.refresh_from_db()
        self.assertIsNone(migration.lease_token)
        self.assertEqual(migration.barrier_state, evidence)
