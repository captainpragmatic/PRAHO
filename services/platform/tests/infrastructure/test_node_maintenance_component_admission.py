"""Both endpoints share component admission with the real node maintenance claim."""

from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings

from apps.infrastructure.node_maintenance_service import create_window
from apps.provisioning.component_migration_models import SourceServiceObligation
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from tests.infrastructure.maintenance_component_fixtures import MaintenanceComponentFixture


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    Q_CLUSTER={"name": "maintenance-component", "orm": "default", "retry": 100000},
)
class NodeMaintenanceComponentAdmissionTests(MaintenanceComponentFixture, TestCase):
    def target_window(self):
        source = self.window()
        return create_window(
            self.target.pk,
            actor=self.actor,
            kind=source.kind,
            execution_mode="manual",
            starts_at=source.starts_at,
            ends_at=source.ends_at,
            expects_downtime=True,
            expected_downtime_minutes=5,
            customer_note="Hosting maintenance",
        )

    def test_without_maintenance_public_component_start_publishes_obligation_and_reservation(self):
        migration = self.component_start()
        self.assertEqual(migration.status, "pending")
        self.assertEqual(migration.component_source_obligation.source_server_id, self.node.pk)
        self.assertEqual(VirtualminMigration.active_reservations(self.target), 1)

    def test_source_window_refuses_component_start_before_any_publication(self):
        self.start(self.window())
        with self.assertRaisesMessage(ValidationError, "Maintenance"):
            self.component_start()
        self.assertFalse(VirtualminMigration.objects.exists())
        self.assertFalse(SourceServiceObligation.objects.exists())

    def test_target_window_refuses_component_start_before_any_publication(self):
        self.start(self.target_window())
        with self.assertRaisesMessage(ValidationError, "Maintenance"):
            self.component_start()
        self.assertFalse(VirtualminMigration.objects.exists())
        self.assertFalse(SourceServiceObligation.objects.exists())

    def test_admitted_component_work_refuses_source_window_start(self):
        window = self.window()
        migration = self.component_start()
        with self.assertRaisesMessage(ValidationError, "migration"):
            self.start(window)
        self.assertEqual(VirtualminMigration.objects.get(pk=migration.pk).status, "pending")
        self.assertFalse(window.executions.exists())

    def test_admitted_component_work_refuses_empty_target_window_start(self):
        window = self.target_window()
        self.component_start()
        with self.assertRaisesMessage(ValidationError, "migration"):
            self.start(window)
        self.assertFalse(window.executions.exists())
