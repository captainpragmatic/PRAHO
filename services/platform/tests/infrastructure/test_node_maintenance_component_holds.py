"""Terminal controller status does not release live bridge or native ownership."""

from datetime import timedelta
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from apps.common.types import Ok
from apps.infrastructure.deployment_service import NodeDeploymentService
from apps.infrastructure.node_maintenance_models import NodeMaintenanceExecution
from apps.infrastructure.node_maintenance_service import create_window
from apps.infrastructure.provider_config import ProviderCommandResult
from apps.provisioning.virtualmin_migration_models import MigrationBridge
from tests.infrastructure.maintenance_retained_fixtures import RetainedMaintenanceFixture


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    Q_CLUSTER={"name": "maintenance-component-holds", "orm": "default", "retry": 100000},
)
class NodeMaintenanceComponentHoldTests(RetainedMaintenanceFixture, TransactionTestCase):
    def window_on(self, node):
        starts_at = timezone.now() - timedelta(seconds=10)
        return create_window(
            node.pk,
            actor=self.actor,
            kind="panel_update",
            execution_mode="manual",
            starts_at=starts_at,
            ends_at=starts_at + timedelta(minutes=30),
            expects_downtime=True,
            expected_downtime_minutes=5,
            customer_note="Hosting functions may be interrupted",
        )

    def test_completed_migration_with_active_bridge_still_fences_both_nodes(self):
        self.publish_retained_website(cleanup=False)
        bridge = MigrationBridge.objects.get(migration=self.migration)
        self.assertEqual((self.migration.status, bridge.status), ("completed", "active"))
        self.assertEqual(self.account.server_id, self.target.pk)
        for node in (self.node, self.target):
            with self.subTest(node=node.pk), self.assertRaisesMessage(ValidationError, "migration"):
                self.window_on(node)

    def test_failed_bridge_is_not_proof_that_native_source_or_target_was_retired(self):
        self.publish_retained_website(cleanup=False)
        bridge = MigrationBridge.objects.get(migration=self.migration)
        bridge.fail()
        bridge.save()
        for node in (self.node, self.target):
            with self.subTest(node=node.pk), self.assertRaisesMessage(ValidationError, "migration"):
                self.window_on(node)

    def test_active_terminal_bridge_refuses_direct_target_reboot_before_provider(self):
        self.publish_retained_website(cleanup=False)
        with patch("apps.infrastructure.deployment_service.run_provider_command", return_value=Ok(
            ProviderCommandResult(True, "", "", 0, "fixture")
        )) as provider:
            result = NodeDeploymentService().reboot_node(self.deployment, {}, user=self.actor)
        self.assertTrue(result.is_err(), result)
        self.assertIn("migration", result.unwrap_err())
        provider.assert_not_called()
        self.assertFalse(NodeMaintenanceExecution.objects.exists())

    def test_actual_retirement_allows_manual_source_work_while_retained_duty_remains(self):
        self.publish_retained_website()
        self.assertFalse(hasattr(self.obligation, "release"))
        self.assertEqual(MigrationBridge.objects.get(migration=self.migration).status, "torn_down")
        window = self.window_on(self.node)
        self.assertEqual(self.start(window).status, "running")

    def test_actual_terminal_retirement_allows_target_reboot_without_component_policy_replay(self):
        self.publish_retained_website()
        with (
            patch(
                "apps.infrastructure.deployment_service.run_provider_command",
                return_value=Ok(ProviderCommandResult(True, "", "", 0, "fixture")),
            ) as provider,
            patch("apps.provisioning.component_target_transport.run_target_operation") as component,
        ):
            result = NodeDeploymentService().reboot_node(self.deployment, {}, user=self.actor)
        self.assertTrue(result.is_ok(), result)
        provider.assert_called_once()
        component.assert_not_called()
        self.assertEqual(NodeMaintenanceExecution.objects.get(deployment=self.deployment).phase, "awaiting_recovery")
