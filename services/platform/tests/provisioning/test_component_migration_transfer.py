"""Imported component transfers reserve selected bytes and never depend on a managed source node."""

import hashlib
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from apps.common.types import Ok
from apps.provisioning.virtualmin_migration_models import SpoolReservation, VirtualminMigration
from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService
from tests.provisioning.test_component_migration_admission import ComponentAdmissionTestBase


class ComponentTransferTests(ComponentAdmissionTestBase):
    def setUp(self):
        super().setUp()
        self.migration = self.start(self.approve(self.review()))
        self.token = uuid4()
        self.assertTrue(self.migration.acquire_lease(self.token, timedelta(minutes=5)))
        self.content = b"immutable private selected archive"
        self.checksum = hashlib.sha256(self.content).hexdigest()
        # fsm-bypass: source export completed independently before this transfer worker resumed.
        VirtualminMigration.objects.filter(pk=self.migration.pk).update(
            status="fetching",
            archive_sha256=self.checksum,
            barrier_state={
                "component_export": {
                    "path": f"/var/lib/praho-transfer/components/{self.migration.pk}/{self.migration.archive_name}",
                    "sha256": self.checksum,
                    "bytes": len(self.content),
                    "files": 1,
                    "databases": ["customer_web"],
                }
            },
        )
        self.migration.refresh_from_db()
        self.engine = VirtualminMigrationService()
        # macOS tempfile may return /var/... through the /var -> /private/var
        # compatibility symlink; the production transfer requires canonical roots.
        self.engine.spool = self.engine.spool.resolve()
        self.source_proof = self.enterContext(
            patch("apps.provisioning.component_migration_transfer.run_source_operation")
        )
        self.ansible.return_value.run_server_playbook.side_effect = self.transfer
        self.enterContext(
            patch("apps.infrastructure.ansible_service.AnsibleService", return_value=self.ansible.return_value)
        )
        self.events = []

    def transfer(self, server, playbook, variables, **_options):
        self.events.append((server.pk, playbook, variables))
        if playbook == "virtualmin_migrate_push.yml":
            current = VirtualminMigration.objects.get(pk=self.migration.pk)
            self.assertIs(current.barrier_state.get("component_target_archive_issued"), True)
        if playbook == "virtualmin_migrate_fetch.yml":
            reservation = SpoolReservation.objects.get(archive_name=self.migration.archive_name)
            self.assertEqual(reservation.expected_bytes, len(self.content))
            (self.engine.spool / self.migration.archive_name).write_bytes(self.content)
        return Ok(SimpleNamespace(success=True, stdout="MIGRATE_SHA256=" + self.checksum))

    def test_selected_fetch_and_push_use_enrolled_servers_exact_bytes_and_private_archive(self):
        from apps.provisioning.component_migration_transfer import transfer_selected_archive  # noqa: PLC0415

        transfer_selected_archive(self.engine, self.migration, self.token)
        self.assertEqual(self.migration.status, "pushing")
        self.assertEqual(self.events[0][0], self.server.pk)
        self.assertEqual(
            self.events[0][2]["remote_archive_dir"], f"/var/lib/praho-transfer/components/{self.migration.pk}"
        )
        archive = self.engine.spool / self.migration.archive_name
        self.assertEqual(archive.stat().st_mode & 0o777, 0o600)
        self.assertFalse(SpoolReservation.objects.exists())
        transfer_selected_archive(self.engine, self.migration, self.token)
        self.assertEqual(self.migration.status, "restoring")
        self.assertEqual(self.events[-1][0], self.target.pk)
        self.ansible.return_value.run_playbook.assert_not_called()

    def test_changed_existing_archive_and_expired_lease_refuse_before_remote_transfer(self):
        from apps.provisioning.component_migration_transfer import transfer_selected_archive  # noqa: PLC0415

        archive = self.engine.spool / self.migration.archive_name
        archive.write_bytes(b"foreign/corrupt existing archive")
        with self.assertRaisesRegex(ValueError, "archive"):
            transfer_selected_archive(self.engine, self.migration, self.token)
        self.assertEqual(archive.read_bytes(), b"foreign/corrupt existing archive")
        self.assertEqual(self.events, [])
        with self.assertRaises(ValueError):
            transfer_selected_archive(self.engine, self.migration, uuid4())
        self.assertEqual(self.events, [])
