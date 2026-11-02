"""A migration/recovery names both servers, including a currently empty incoming target."""

from datetime import timedelta

from django.utils import timezone

from apps.infrastructure.models import NodeDeployment
from apps.infrastructure.node_maintenance_models import NodeMaintenancePolicy
from apps.infrastructure.node_maintenance_service import change_window, create_window
from apps.provisioning.account_hostname_models import AccountHostname
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.provisioning.virtualmin_recovery_service import VirtualminRecoveryService
from tests.infrastructure.maintenance_policy_fixtures import maintenance_policy_times
from tests.provisioning.test_virtualmin_migration_service import MigrationTestBase


class NodeMaintenanceMigrationAdmissionTests(MigrationTestBase):
    def setUp(self) -> None:
        super().setUp()
        # The shared migration transport fixture has live accounts but leaves deployment rows pending.
        # Establish completed managed nodes through their actual model transition contract.
        for deployment in NodeDeployment.objects.filter(virtualmin_server__in=(self.server, self.target)):
            for status in (
                "provisioning_node",
                "configuring_dns",
                "installing_panel",
                "configuring_backups",
                "validating",
                "registering",
                "completed",
            ):
                deployment.transition_to(status)

    def running_window(self, node: VirtualminServer) -> None:
        starts_time, ends_time = maintenance_policy_times()
        NodeMaintenancePolicy.objects.create(
            node=node,
            timezone="UTC",
            weekdays=list(range(7)),
            starts_time=starts_time,
            ends_time=ends_time,
            max_defer_minutes=30,
        )
        starts_at = timezone.now() - timedelta(seconds=10)
        window = create_window(
            node.pk,
            actor=self.staff,
            kind="panel_update",
            execution_mode="manual",
            starts_at=starts_at,
            ends_at=starts_at + timedelta(minutes=30),
            expects_downtime=True,
            expected_downtime_minutes=5,
            customer_note="Hosting software maintenance.",
        )
        change_window(window.pk, actor=self.staff, revision=1, action="start", reason="Approved window")

    def test_public_migration_refuses_an_empty_target_with_running_maintenance(self) -> None:
        self.assertFalse(self.target.accounts.exists())
        self.running_window(self.target)
        self.events.clear()

        result = VirtualminMigrationService().start_migration(
            self.account, self.target, initiated_by=self.staff, enqueue=False
        )

        self.assertTrue(result.is_err())
        self.assertIn("Maintenance", result.unwrap_err())
        self.assertFalse(VirtualminMigration.objects.exists())
        self.assertEqual(self.events, [])

    def test_public_migration_refuses_running_maintenance_on_the_source(self) -> None:
        self.running_window(self.server)
        self.events.clear()

        result = VirtualminMigrationService().start_migration(
            self.account, self.target, initiated_by=self.staff, enqueue=False
        )

        self.assertTrue(result.is_err())
        self.assertIn("Maintenance", result.unwrap_err())
        self.assertFalse(VirtualminMigration.objects.exists())
        self.assertEqual(self.events, [])

    def test_public_recovery_refuses_running_maintenance_on_its_actual_target(self) -> None:
        self.running_window(self.target)
        AccountHostname.objects.get_or_create(
            account=self.account,
            defaults={"target_server": self.server, "label": "ab1234cd", "zone": "accounts.example.test"},
        )
        self.events.clear()

        result = VirtualminRecoveryService().start_recovery(
            self.account,
            self.target,
            backup_ids=["b" * 32],
            source_fenced="Old source is confirmed powered off",
            initiated_by=self.staff,
            enqueue=False,
        )

        self.assertTrue(result.is_err())
        self.assertIn("Maintenance", result.unwrap_err())
        self.assertFalse(VirtualminMigration.objects.exists())
        self.assertEqual(self.events, [])
