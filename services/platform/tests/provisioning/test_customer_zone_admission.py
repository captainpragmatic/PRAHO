"""Account moves wait for provider mutation intents, including uncertain outcomes."""

from django.db import transaction

from apps.domains.dns_zone_models import HostedZone, HostedZoneImportRevision, HostedZoneOperation
from apps.provisioning.account_hostname_models import AccountHostname
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService
from apps.provisioning.virtualmin_recovery_service import VirtualminRecoveryService
from tests.provisioning.test_virtualmin_migration_service import MigrationTestBase


class CustomerZoneAdmissionTests(MigrationTestBase):
    def setUp(self):
        super().setUp()
        self.hostname = AccountHostname.objects.create(
            account=self.account, target_server=self.server, label="a1b2c3d4", zone="accounts.example.net"
        )
        self.zone = HostedZone.objects.create(
            customer=self.account.service.customer,
            service=self.account.service,
            account=self.account,
            account_hostname=self.hostname,
            name=self.account.domain,
        )
        self.revision = HostedZoneImportRevision.objects.create(
            zone=self.zone,
            number=1,
            raw_upload=b"",
            raw_digest="a" * 64,
            inventory_digest="b" * 64,
            manifest_digest="c" * 64,
        )

    def test_migration_refuses_live_or_uncertain_customer_zone_writes_before_remote_calls(self):
        for kind in ("apply", "edit", "switch", "delete"):
            for status in ("pending", "running", "waiting", "parked"):
                with self.subTest(kind=kind, status=status), transaction.atomic():
                    operation = HostedZoneOperation.objects.create(
                        zone=self.zone, revision=self.revision, kind=kind, status=status
                    )
                    self.events.clear()
                    result = VirtualminMigrationService().start_migration(
                        self.account, self.target, initiated_by=self.staff, enqueue=False
                    )
                    self.assertTrue(result.is_err(), result)
                    self.assertIn("DNS", result.unwrap_err())
                    self.assertFalse(VirtualminMigration.objects.exists())
                    self.assertEqual(self.events, [])
                    operation.delete()

    def test_recovery_refuses_uncertain_zone_write_before_fencing_the_source(self):
        HostedZoneOperation.objects.create(zone=self.zone, revision=self.revision, kind="edit", status="parked")
        self.events.clear()
        result = VirtualminRecoveryService().start_recovery(
            self.account,
            self.target,
            backup_ids=["b" * 32],
            source_fenced="provider power-off confirmed",
            initiated_by=self.staff,
            enqueue=False,
        )
        self.assertTrue(result.is_err(), result)
        self.assertIn("DNS", result.unwrap_err())
        self.assertFalse(VirtualminMigration.objects.exists())
        self.server.refresh_from_db()
        self.assertEqual(self.server.status, "active")
        self.assertEqual(self.events, [])

    def test_read_only_activation_poll_does_not_block_a_move(self):
        self._read_only_operation("activate")

    def test_read_only_import_crosscheck_does_not_block_a_move(self):
        self._read_only_operation("crosscheck")

    def _read_only_operation(self, kind):
        HostedZoneOperation.objects.create(zone=self.zone, revision=self.revision, kind=kind, status="waiting")
        result = VirtualminMigrationService().start_migration(
            self.account, self.target, initiated_by=self.staff, enqueue=False
        )
        self.assertTrue(result.is_ok(), result)
