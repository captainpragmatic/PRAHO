"""Real component publication/cleanup; native and DNS observations stay external."""

import base64
import json
from datetime import datetime, timedelta
from importlib import import_module
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch
from uuid import uuid4

from django.apps import apps
from django.db import connection
from django.utils import timezone
from django_q.models import Schedule

from apps.common.types import Ok
from apps.infrastructure.ansible_service import AnsibleResult
from apps.infrastructure.node_maintenance_models import NodeMaintenanceWindow
from apps.infrastructure.node_maintenance_service import create_window
from apps.provisioning.component_cutover import commit_component_cutover
from apps.provisioning.component_migration_service import release_source_obligation
from apps.provisioning.component_migration_worker import ComponentMigrationWorker
from apps.provisioning.migration_bridge_cleanup import cleanup_bridge, schedule_bridge_cleanup
from apps.provisioning.virtualmin_migration_models import MigrationBridge, VirtualminMigration
from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService
from tests.infrastructure.maintenance_component_fixtures import MaintenanceComponentFixture


class RetainedMaintenanceFixture(MaintenanceComponentFixture):
    def setUp(self) -> None:
        super().setUp()
        self.customer.primary_email = "retained-maintenance@example.test"
        self.customer.save(update_fields=["primary_email"])
        import_module("apps.infrastructure.migrations.0008_node_maintenance_templates").seed_templates(
            apps, SimpleNamespace(connection=connection)
        )
        import_module("apps.infrastructure.migrations.0012_maintenance_hosting_dependency_copy").seed_neutral_templates(
            apps, SimpleNamespace(connection=connection)
        )

    def publish_retained_website(self, *, cleanup: bool = True) -> None:
        self.migration = self.component_start()
        token = uuid4()
        self.assertTrue(self.migration.acquire_lease(token, timedelta(minutes=5)))
        # fsm-bypass: prior independent native export/restore/TLS observations.
        # This fixture proves the actual publication and forward cleanup, not SSH.
        VirtualminMigration.objects.filter(pk=self.migration.pk).update(
            status="verifying",
            archive_sha256="a" * 64,
            barrier_state={
                "target_domain_id": "987654321",
                "component_target_receipt_sha256": "b" * 64,
                "component_bridge_verified": True,
                "component_bridge_origin_certificate": "external native certificate observation",
            },
        )
        self.migration.refresh_from_db()
        with (
            patch("apps.provisioning.component_cutover.run_source_operation", return_value={"phase": "committed"}),
            patch(
                "apps.provisioning.component_cutover.run_target_operation",
                return_value={"target_receipt_sha256": "b" * 64},
            ),
        ):
            commit_component_cutover(ComponentMigrationWorker(), self.migration, token)
        self.migration.refresh_from_db()
        self.assertTrue(
            self.migration.transition(token, "activating", "activating", lease_token=None, worker_lease_expires_at=None)
        )
        with (
            patch("apps.provisioning.component_migration_worker.run_target_operation", return_value={}),
            patch("apps.provisioning.component_migration_worker.run_source_operation", return_value={}),
            patch("apps.provisioning.component_migration_worker.run_bridge_operation", return_value={}),
            patch("apps.provisioning.component_migration_worker.observe_frontends", return_value=({}, [])),
        ):
            outcome = VirtualminMigrationService().run(self.migration.pk)
        self.assertTrue(outcome.is_ok(), outcome)
        self.migration.refresh_from_db()
        self.assertEqual(self.migration.status, "completed", self.migration.error_detail)
        self.assertIsNone(self.migration.lease_token)
        self.assertIsNone(self.migration.worker_lease_expires_at)
        schedule_prefix = f"bridge-cleanup-{self.migration.pk}-"
        if not Schedule.objects.filter(name__startswith=schedule_prefix).exists():
            self.assertTrue(schedule_bridge_cleanup(self.migration.pk))
        self.assertTrue(Schedule.objects.filter(name__startswith=schedule_prefix).exists())
        bridge = MigrationBridge.objects.get(migration=self.migration)
        self.assertIn("expires_at", bridge.evidence)
        self.account.refresh_from_db()
        self.assertEqual(self.account.server_id, self.target.pk)
        self.obligation = self.migration.component_source_obligation
        self.assertFalse(hasattr(self.obligation, "release"))
        if not cleanup:
            return
        deadline = datetime.fromisoformat(bridge.evidence["expires_at"]) + timedelta(seconds=1)

        def retired(_server, _playbook, values: dict[str, Any], **_kwargs) -> Ok[AnsibleResult]:
            action = values["component_action"]
            receipt = {
                "operation_id": str(self.migration.pk),
                "action": action,
                "phase": "retired" if action == "source_retire" else "artifacts_retired",
            }
            if action == "target_retire_artifacts":
                receipt["target_domain_id"] = "987654321"
            encoded = base64.b64encode(json.dumps(receipt).encode()).decode()
            return Ok(AnsibleResult(True, "virtualmin_component.yml", "PRAHO_COMPONENT_RESULT=" + encoded, "", 0))

        with (
            patch("apps.provisioning.migration_bridge_cleanup.timezone.now", return_value=deadline),
            patch("apps.provisioning.component_bridge_cleanup.run_bridge_operation", return_value={}),
            patch("apps.provisioning.migration_routing.observe_frontends", return_value=({}, [])),
            patch("apps.infrastructure.ansible_service.AnsibleService.run_server_playbook", side_effect=retired),
        ):
            self.assertEqual(cleanup_bridge(str(self.migration.pk)), {"action": "torn_down"})
        bridge.refresh_from_db()
        self.assertEqual(bridge.status, "torn_down")
        self.account.refresh_from_db()
        self.assertEqual(self.account.server_id, self.target.pk)
        self.obligation = self.migration.component_source_obligation
        self.assertFalse(hasattr(self.obligation, "release"))

    def schedule_source(self, *, due: bool = False) -> NodeMaintenanceWindow:
        starts_at = timezone.now() + timedelta(seconds=-10 if due else 600)
        return create_window(
            self.node.pk,
            actor=self.actor,
            kind="reboot",
            execution_mode="manual",
            starts_at=starts_at,
            ends_at=starts_at + timedelta(minutes=30),
            expects_downtime=True,
            expected_downtime_minutes=5,
            customer_note="Mail and DNS maintenance; the website remains on its current server.",
        )

    def release_retained_source(self) -> None:
        self.native_source._domains.pop(self.account.domain)
        release_source_obligation(
            self.obligation, self.actor, "Native retained services removed and backups handed off"
        )
