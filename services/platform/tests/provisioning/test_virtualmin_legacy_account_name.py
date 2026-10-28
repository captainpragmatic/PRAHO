"""An unpublished name follows legacy ownership without being published during the move."""

from unittest.mock import patch

from django.utils import timezone

from apps.common.types import Ok
from apps.provisioning import account_hostname_service as names
from apps.provisioning.account_hostname_models import AccountHostname
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService
from apps.provisioning.virtualmin_models import VirtualminServer
from tests.helpers.fake_dns_gateway import FakeDnsGateway
from tests.provisioning.test_virtualmin_migration_barrier_wiring import BarrierCase

ZONE = "praho-sites.net"
ZONE_ID = "0123456789abcdef0123456789abcdef"


class LegacyAccountNameTests(BarrierCase):
    def setUp(self):
        super().setUp()
        self.account.provisioned_at = timezone.now()
        self.account.save(update_fields=["provisioned_at"])
        self.server.ipv4_address = "203.0.113.10"
        self.server.save(update_fields=["ipv4_address"])
        self.target.ipv4_address = "203.0.113.20"
        self.target.save(update_fields=["ipv4_address"])
        self.name = AccountHostname.objects.create(
            account=self.account, label="abcd1234", zone=ZONE, target_server=self.server
        )
        self.settings_values.update(
            {
                "dns.account_hostname_zone": ZONE,
                "dns.account_hostname_zone_id": ZONE_ID,
                "dns.account_zone_api_token": "test-token",
            }
        )
        FakeDnsGateway.reset({ZONE_ID: ZONE})
        self.enterContext(patch.object(names, "_dns_gateway", return_value=FakeDnsGateway("test-token")))
        self.neutral = self.enterContext(patch.object(names, "ensure_account_name_neutral", return_value=Ok("a" * 64)))

    def test_an_unpublished_uncertified_name_still_uses_legacy(self):
        migration = self._start()
        self.assertEqual(migration.contract, VirtualminMigration.Contract.LEGACY)
        self.neutral.assert_not_called()
        self.assertEqual(FakeDnsGateway.calls, [])

    def test_legacy_completion_moves_the_unpublished_name_atomically_with_the_account(self):
        migration, token = self._held("repointing")
        self.source_gateway._domains[self.account.domain].enabled = False
        VirtualminMigrationService()._repoint(migration, token)
        self.account.refresh_from_db()
        self.name.refresh_from_db()
        self.assertEqual(self.account.server_id, self.target.pk)
        self.assertEqual(self.name.target_server_id, self.target.pk)
        self.assertEqual(self.name.records, {})
        self.assertEqual(FakeDnsGateway.calls, [])
        with patch.object(names, "certificate_ready_on", return_value=True):
            self.assertTrue(names.sync_account_hostname(self.name).is_ok())
        self.assertEqual(FakeDnsGateway.published(self.name.fqdn)["A"], self.target.ipv4_address)

    def test_an_unplaced_name_can_follow_a_legacy_move(self):
        self.name.target_server = None
        self.name.save(update_fields=["target_server"])
        migration, token = self._held("repointing")
        self.source_gateway._domains[self.account.domain].enabled = False
        VirtualminMigrationService()._repoint(migration, token)
        self.name.refresh_from_db()
        self.assertEqual(self.name.target_server_id, self.target.pk)

    def test_active_legacy_excludes_publication_before_recording_intent_or_provider_io(self):
        migration = self._start()
        self.assertEqual(migration.contract, VirtualminMigration.Contract.LEGACY)
        with patch.object(names, "certificate_ready_on", return_value=True):
            result = names.sync_account_hostname(self.name)
        self.assertEqual(result, Ok("skipped:migration_locked"))
        self.name.refresh_from_db()
        self.assertEqual(self.name.records, {})
        self.assertEqual(FakeDnsGateway.calls, [])
        self.neutral.assert_not_called()

    def test_a_preupgrade_blank_contract_also_holds_publication(self):
        migration = self._start()
        VirtualminMigration.objects.filter(pk=migration.pk).update(contract="")
        with patch.object(names, "certificate_ready_on", return_value=True):
            self.assertEqual(names.sync_account_hostname(self.name), Ok("skipped:migration_locked"))
        self.name.refresh_from_db()
        self.assertEqual(self.name.records, {})
        self.assertEqual(FakeDnsGateway.calls, [])

    def test_published_preupgrade_state_refuses_before_target_activation(self):
        migration, token = self._held("activating")
        self.target_gateway.seed_domain(self.account.domain, username=self.account.virtualmin_username, enabled=False)
        self.name.records = {"A": {"intended": self.server.ipv4_address, "ttl": 300}}
        self.name.save(update_fields=["records"])
        with self.assertRaisesRegex(ValueError, "published"):
            VirtualminMigrationService()._activate(migration, token)
        self.assertNotIn("enable-domain", self._programs("target"))
        self.assertFalse(self.target_gateway._domains[self.account.domain].enabled)

    def test_published_preupgrade_state_refuses_before_ownership_commit(self):
        migration, token = self._held("repointing")
        self.source_gateway._domains[self.account.domain].enabled = False
        self.name.records = {"A": {"intended": self.server.ipv4_address, "ttl": 300}}
        self.name.save(update_fields=["records"])
        with self.assertRaisesRegex(ValueError, "published"):
            VirtualminMigrationService()._repoint(migration, token)
        self.account.refresh_from_db()
        self.assertEqual(self.account.server_id, self.server.pk)

    def test_a_retired_name_refuses_admission_without_node_reads(self):
        AccountHostname.objects.filter(pk=self.name.pk).update(retired_at=timezone.now())
        result = VirtualminMigrationService().start_migration(
            self.account, self.target, initiated_by=self.staff, enqueue=False
        )
        self.assertTrue(result.is_err(), result)
        self.assertEqual(self.events, [])
        self.assertFalse(VirtualminMigration.objects.exists())

    def test_a_foreign_target_name_refuses_admission_without_node_reads(self):
        foreign = VirtualminServer.objects.create(name="Foreign", hostname="foreign.example.com")
        AccountHostname.objects.filter(pk=self.name.pk).update(target_server=foreign)
        result = VirtualminMigrationService().start_migration(
            self.account, self.target, initiated_by=self.staff, enqueue=False
        )
        self.assertTrue(result.is_err(), result)
        self.assertEqual(self.events, [])
        self.assertFalse(VirtualminMigration.objects.exists())
