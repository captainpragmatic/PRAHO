"""Coverage additions for migration listing, admission and recovery outcomes."""

from __future__ import annotations

from datetime import timedelta
from typing import cast
from urllib.parse import urlsplit
from uuid import uuid4

from django.utils import timezone
from requests import Response

from apps.audit.models import AuditEvent
from apps.infrastructure.models import CloudProvider, NodeDeployment, NodeRegion, NodeSize, PanelType
from apps.provisioning.virtualmin_gateway import VirtualminConfig, VirtualminGateway
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from apps.provisioning.virtualmin_migration_service import (
    VirtualminMigrationService,
    list_migration_domains,
    resolve_migration,
)
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.settings.services import SettingsService
from tests.provisioning.test_cov_virtualmin_views_servers import VirtualminViewsFixture


class ProvisioningSupportMigrationFixture(VirtualminViewsFixture):
    def setUp(self) -> None:
        super().setUp()
        self.target = VirtualminServer.objects.create(
            name="Support migration target", hostname="support-target.example.com", api_username="praho-acl"
        )
        self.target.set_api_password("support-target-password")
        self.target.save(update_fields=["encrypted_api_password"])
        self.gateway = VirtualminGateway(VirtualminConfig(server=self.server, use_credential_vault=False))

    def migration(self, status: str) -> VirtualminMigration:
        return VirtualminMigration.objects.create(
            account=self.account, source_server=self.server, target_server=self.target, status=status
        )


class ProvisioningSupportMigrationTests(ProvisioningSupportMigrationFixture):
    def test_listing_preserves_multiline_attributes_and_unknown_enabled_state(self) -> None:
        values: dict[str, object] = {"Username": [" tenant "], "Status": ["Unknown"], "Disk quota": ["100 MB"]}
        self.payload["data"] = [{"name": "tenant.example.com", "values": values}]
        result = list_migration_domains(self.gateway)
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(
            result.unwrap(),
            [{"domain": "tenant.example.com", "username": "tenant", "enabled": None, "attributes": values}],
        )

    def test_listing_strict_refuses_malformed_rows_while_sync_retains_valid_rows(self) -> None:
        self.payload["data"] = [
            {"separator": "---"},
            {"name": "tenant.example.com", "values": {"Username": "tenant", "Status": "Disabled"}},
        ]
        strict = list_migration_domains(self.gateway)
        self.assertTrue(strict.is_err())
        self.assertEqual(strict.unwrap_err(), "Incomplete Virtualmin multiline domain listing")
        permissive = list_migration_domains(self.gateway, strict=False)
        self.assertTrue(permissive.is_ok(), permissive)
        rows = permissive.unwrap()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["domain"], "tenant.example.com")
        self.assertFalse(rows[0]["enabled"])

    def test_listing_refuses_duplicates_invalid_shape_and_transport_denial(self) -> None:
        row = {"name": "tenant.example.com", "values": {"Username": "tenant", "Status": "Enabled"}}
        self.payload["data"] = [row, row]
        duplicate = list_migration_domains(self.gateway)
        self.assertTrue(duplicate.is_err())
        self.assertEqual(duplicate.unwrap_err(), "Duplicate domains in Virtualmin listing")
        self.payload["data"] = {"unexpected": "shape"}
        invalid = list_migration_domains(self.gateway)
        self.assertTrue(invalid.is_err())
        self.assertEqual(invalid.unwrap_err(), "Unrecognized or failed Virtualmin domain listing")
        self.http_status = 403
        denied = list_migration_domains(self.gateway)
        self.assertTrue(denied.is_err())
        self.assertIn("Access forbidden", denied.unwrap_err())

    def test_disabled_migration_refuses_admission_without_rows_or_http(self) -> None:
        updated = SettingsService.update_setting("provisioning.migration_enabled", False)
        self.assertTrue(updated.is_ok(), updated)
        result = VirtualminMigrationService().start_migration(self.account, self.target, initiated_by=self.admin)
        self.assertTrue(result.is_err())
        self.assertEqual(result.unwrap_err(), "Virtualmin migration is disabled")
        self.assertFalse(VirtualminMigration.objects.exists())
        self.assertEqual(self.requests, [])

    def test_admission_refuses_same_server_invalid_status_multi_domain_and_unmanaged_nodes(self) -> None:
        updated = SettingsService.update_setting("provisioning.migration_enabled", True)
        self.assertTrue(updated.is_ok(), updated)
        service = VirtualminMigrationService()
        cases = (
            (self.server, "active", [], "Source and target must differ"),
            (self.target, "error", [], "Only active or suspended accounts can migrate"),
            (self.target, "active", ["alias.example.com"], "Migration requires exactly one domain"),
            (self.target, "active", [], "manual registration has no managed node_deployment"),
        )
        for target, status, domains, error in cases:
            self.account.status = status
            self.account.domains = cast("list[str]", domains)
            self.account.save(update_fields=["status", "domains"])
            result = service.start_migration(self.account, target, initiated_by=self.admin)
            with self.subTest(error=error):
                self.assertTrue(result.is_err())
                self.assertIn(error, result.unwrap_err())
                self.assertFalse(VirtualminMigration.objects.exists())
                self.assertEqual(self.requests, [])

    def test_interrupted_backup_is_parked_for_review_with_audit_and_capacity_reservation(self) -> None:
        migration = self.migration("backing_up")
        result = VirtualminMigrationService().run(migration.pk)
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(
            result.unwrap(), {"action": "needs_review", "migration_id": str(migration.pk), "lease_acquired": True}
        )
        migration.refresh_from_db()
        self.assertEqual(migration.status, "needs_review")
        self.assertEqual(migration.error_detail, "Interrupted phase: backing_up")
        self.assertIsNone(migration.lease_token)
        self.assertIsNone(migration.worker_lease_expires_at)
        self.assertEqual(VirtualminMigration.active_reservations(self.target), 1)
        event = AuditEvent.objects.get(action="virtualmin_migration_needs_review", object_id=str(migration.pk))
        self.assertTrue(event.metadata["requires_review"])
        self.assertEqual(event.new_values["status"], "needs_review")
        self.assertEqual(self.requests, [])

    def test_worker_owned_migration_refuses_manual_resolution_without_changing_state(self) -> None:
        migration = self.migration("needs_review")
        owner = uuid4()
        self.assertTrue(migration.acquire_lease(owner, timedelta(minutes=5)))
        result = resolve_migration(migration, resolved_by=self.admin, note="Repair verified")
        self.assertTrue(result.is_err())
        self.assertIn("currently owned by a worker", result.unwrap_err())
        migration.refresh_from_db()
        self.assertEqual(migration.status, "needs_review")
        self.assertEqual(migration.lease_token, owner)
        self.assertEqual(VirtualminMigration.active_reservations(self.target), 1)

    def test_manual_resolution_requires_review_and_releases_the_rejected_lease(self) -> None:
        migration = self.migration("pending")
        result = resolve_migration(migration, resolved_by=self.admin, note="Repair verified")
        self.assertTrue(result.is_err())
        self.assertEqual(result.unwrap_err(), "Only a needs_review migration can be resolved manually")
        migration.refresh_from_db()
        self.assertEqual(migration.status, "pending")
        self.assertIsNone(migration.lease_token)
        self.assertIsNone(migration.worker_lease_expires_at)
        self.assertFalse(
            AuditEvent.objects.filter(action="virtualmin_migration_failed", object_id=str(migration.pk)).exists()
        )


class ProvisioningManagedMigrationTests(ProvisioningSupportMigrationFixture):
    def setUp(self) -> None:
        super().setUp()
        result = SettingsService.update_setting("provisioning.migration_enabled", True)
        self.assertTrue(result.is_ok(), result)
        provider = CloudProvider.objects.create(
            name="Support migration provider",
            provider_type="hetzner",
            code="het",
            credential_identifier="support-migration",
        )
        region = NodeRegion.objects.create(
            provider=provider,
            name="Falkenstein",
            provider_region_id="fsn1",
            normalized_code="fsn1",
            country_code="de",
            city="Falkenstein",
        )
        size = NodeSize.objects.create(
            provider=provider,
            name="Support small",
            display_name="Small",
            provider_type_id="cpx21",
            vcpus=2,
            memory_gb=4,
            disk_gb=40,
            hourly_cost_eur="0.01",
            monthly_cost_eur="5.00",
        )
        panel = PanelType.objects.create(
            name="Support Virtualmin", panel_type="virtualmin", ansible_playbook="virtualmin.yml"
        )
        for number, server in enumerate((self.server, self.target), start=1):
            NodeDeployment.objects.create(
                provider=provider,
                node_size=size,
                region=region,
                panel_type=panel,
                hostname=f"prd-sha-het-de-fsn1-{number:03}",
                node_number=number,
                ipv4_address=f"203.0.113.{number}",
                virtualmin_server=server,
            )
            server.last_health_check = timezone.now()
            server.save(update_fields=["last_health_check"])
        self.remote_source: list[dict[str, object]] = [
            {
                "name": self.account.domain,
                "values": {"Username": [self.account.virtualmin_username], "Status": ["Enabled"]},
            }
        ]
        self.remote_target: list[dict[str, object]] = []

    def respond(self, method: str, url: str, **kwargs: object) -> Response:
        self.payload["data"] = (
            self.remote_source if urlsplit(url).hostname == self.server.hostname else self.remote_target
        )
        return super().respond(method, url, **kwargs)

    def test_admission_persists_remote_snapshot_without_dispatch_when_enqueue_is_false(self) -> None:
        result = VirtualminMigrationService().start_migration(
            self.account, self.target, initiated_by=self.admin, enqueue=False
        )
        self.assertTrue(result.is_ok(), result)
        migration = result.unwrap()
        migration.refresh_from_db()
        self.assertEqual(migration.status, "pending")
        self.assertEqual(migration.pre_migration_snapshot["domain"], self.account.domain)
        self.assertEqual(migration.pre_migration_snapshot["status"], "active")
        self.assertTrue(migration.pre_migration_snapshot["remote"]["enabled"])
        self.assertEqual(migration.pre_migration_snapshot["remote"]["username"], self.account.virtualmin_username)
        self.assertIsNone(migration.lease_token)
        self.assertIsNone(migration.worker_lease_expires_at)
        self.assertEqual(VirtualminMigration.active_reservations(self.target), 1)
        event = AuditEvent.objects.get(action="virtualmin_migration_started", object_id=str(migration.pk))
        self.assertEqual(event.user_id, self.admin.pk)

    def test_invalid_reason_refuses_admission_without_remote_listing(self) -> None:
        result = VirtualminMigrationService().start_migration(
            self.account, self.target, initiated_by=self.admin, reason="invalid", enqueue=False
        )
        self.assertTrue(result.is_err())
        self.assertEqual(result.unwrap_err(), "Invalid migration reason")
        self.assertFalse(VirtualminMigration.objects.exists())
        self.assertEqual(self.requests, [])

    def test_full_target_and_insufficient_broker_budget_refuse_admission(self) -> None:
        self.target.current_domains = self.target.max_domains
        self.target.save(update_fields=["current_domains"])
        service = VirtualminMigrationService()
        full = service.start_migration(self.account, self.target, initiated_by=self.admin, enqueue=False)
        self.assertTrue(full.is_err())
        self.assertEqual(full.unwrap_err(), "Target is unhealthy or full")
        self.target.current_domains = 0
        self.target.save(update_fields=["current_domains"])
        with self.settings(Q_CLUSTER={"retry": service.task_timeout + 60}):
            budget = service.start_migration(self.account, self.target, initiated_by=self.admin, enqueue=False)
        self.assertTrue(budget.is_err())
        self.assertIn("budget must fit below", budget.unwrap_err())
        self.assertFalse(VirtualminMigration.objects.exists())
        self.assertEqual(self.requests, [])

    def test_target_collision_persists_failed_migration_and_releases_capacity(self) -> None:
        self.remote_target = list(self.remote_source)
        result = VirtualminMigrationService().start_migration(
            self.account, self.target, initiated_by=self.admin, enqueue=False
        )
        self.assertTrue(result.is_err())
        self.assertEqual(result.unwrap_err(), "Domain already exists on target")
        migration = VirtualminMigration.objects.get(account=self.account)
        self.assertEqual(migration.status, "failed")
        self.assertEqual(migration.error_detail, "Domain already exists on target")
        self.assertEqual(VirtualminMigration.active_reservations(self.target), 0)
        self.account.refresh_from_db()
        self.assertEqual(self.account.server_id, self.server.pk)
        event = AuditEvent.objects.get(action="virtualmin_migration_failed", object_id=str(migration.pk))
        self.assertEqual(event.new_values["status"], "failed")

    def test_source_snapshot_mismatch_is_recorded_as_failed_without_moving_the_account(self) -> None:
        self.remote_source[0]["values"] = {"Username": [self.account.virtualmin_username], "Status": ["Disabled"]}
        result = VirtualminMigrationService().start_migration(
            self.account, self.target, initiated_by=self.admin, enqueue=False
        )
        self.assertTrue(result.is_err())
        self.assertEqual(result.unwrap_err(), "Source enabled state disagrees with the account snapshot")
        migration = VirtualminMigration.objects.get(account=self.account)
        self.assertEqual(migration.status, "failed")
        self.assertEqual(migration.error_detail, result.unwrap_err())
        self.account.refresh_from_db()
        self.assertEqual(self.account.server_id, self.server.pk)
        self.assertEqual(VirtualminMigration.active_reservations(self.target), 0)
