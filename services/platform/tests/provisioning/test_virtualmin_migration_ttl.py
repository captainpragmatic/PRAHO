"""The cutover's TTL step in the migration state machine (ADR-0061 P2.3, contract step 1).

A migration whose account has a published name is a cutover: pending lowers the name's TTL and waits
for the provider to confirm it before quiescing. A legacy migration with nothing published goes
straight to quiescing. Cancellation, a deadline, and any later pre-commit failure restore the TTL.
"""

from __future__ import annotations

import dataclasses
from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from django.utils import timezone

from apps.common.types import Ok
from apps.infrastructure.dns_gateway import _DNS_PROVIDER_REGISTRY, register_dns_gateway
from apps.provisioning import account_hostname_service as hostname_service
from apps.provisioning import virtualmin_tasks
from apps.provisioning.account_hostname_models import AccountHostname
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from apps.provisioning.virtualmin_migration_service import (
    DefiniteMigrationFailureError,
    MigrationDeferredError,
    VirtualminMigrationService,
)
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from tests.helpers.fake_dns_gateway import FakeDnsGateway
from tests.provisioning.test_virtualmin_migration_service import MigrationTestBase

ZONE = "praho-sites.net"
ZONE_ID = "0123456789abcdef0123456789abcdef"
ORIGINAL_TTL = 900


_ORIGINAL_RECONCILE = FakeDnsGateway.reconcile_records


def _stale_ttl(gateway: FakeDnsGateway, zone_id: str, specs: list, owner_tag: str):
    """A provider that accepts the change but still reports the old TTL on every record."""
    outcome = _ORIGINAL_RECONCILE(gateway, zone_id, specs, owner_tag)
    outcome.applied = [dataclasses.replace(record, ttl=ORIGINAL_TTL) for record in outcome.applied]
    return outcome


class MigrationTtlCase(MigrationTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.settings_values.update(
            {
                "dns.account_hostname_zone": ZONE,
                "dns.account_hostname_zone_id": ZONE_ID,
                "dns.account_zone_api_token": "token-value",
                "dns.account_record_ttl_seconds": ORIGINAL_TTL,
            }
        )
        previous = _DNS_PROVIDER_REGISTRY.get(hostname_service.DNS_PROVIDER)
        register_dns_gateway(hostname_service.DNS_PROVIDER, FakeDnsGateway)
        self.addCleanup(
            lambda: register_dns_gateway(hostname_service.DNS_PROVIDER, previous) if previous else None
        )
        FakeDnsGateway.reset({ZONE_ID: ZONE})
        VirtualminServer.objects.filter(pk=self.server.pk).update(
            ipv4_address="95.217.0.10", ipv6_address="2a01:4f8::1"
        )
        self.server.refresh_from_db()
        ready = patch.object(hostname_service, "certificate_ready_on", return_value=True)
        ready.start()
        self.addCleanup(ready.stop)

    def _published_name(self) -> AccountHostname:
        VirtualminAccount.objects.filter(pk=self.account.pk).update(provisioned_at=timezone.now())
        self.account.refresh_from_db()
        hostname = hostname_service.allocate_account_hostname(self.account)
        AccountHostname.objects.filter(pk=hostname.pk).update(target_server=self.server)
        hostname.refresh_from_db()
        self.assertEqual(hostname_service.sync_account_hostname(hostname), Ok("published"))
        hostname.refresh_from_db()
        self.assertEqual(hostname.records["A"]["applied_ttl"], ORIGINAL_TTL)
        return hostname

    def _lowered(self, hostname: AccountHostname) -> None:
        self.assertEqual(hostname_service.lower_account_hostname_ttl(hostname), Ok("converged"))
        hostname.refresh_from_db()

    def _held(self, status: str, **fields: object) -> tuple[VirtualminMigration, object]:
        migration = self._start()
        token = uuid4()
        VirtualminMigration.objects.filter(pk=migration.pk).update(
            status=status, lease_token=token, worker_lease_expires_at=timezone.now() + timedelta(hours=1), **fields
        )
        migration.refresh_from_db()
        return migration, token

    def _provider_ttls(self, hostname: AccountHostname) -> dict[str, int]:
        return {r["type"]: r["ttl"] for r in FakeDnsGateway.records.values() if r["name"] == hostname.fqdn}



class ContractTests(MigrationTtlCase):
    def test_a_published_name_makes_the_migration_a_cutover(self) -> None:
        self._published_name()

        migration = self._start()

        self.assertEqual(migration.contract, "cutover")

    def test_a_migration_with_nothing_published_is_legacy(self) -> None:
        migration = self._start()

        self.assertEqual(migration.contract, "legacy")


class LoweringStepTests(MigrationTtlCase):
    def _stop_after_quiescing(self, seen: dict[str, int]) -> object:
        hostname = AccountHostname.objects.filter(account=self.account).first()

        def quiesce(_service: VirtualminMigrationService, _row: VirtualminMigration, _token: object) -> None:
            if hostname is not None:
                hostname.refresh_from_db()
                seen.update(self._provider_ttls(hostname))
            raise MigrationDeferredError(timezone.now() + timedelta(minutes=5), "stop after quiescing")

        return quiesce

    def test_the_pending_step_lowers_the_ttl_before_quiescing(self) -> None:
        self._published_name()
        migration, token = self._held("pending")
        seen: dict[str, int] = {}

        with (
            patch.object(VirtualminMigrationService, "_quiesce", self._stop_after_quiescing(seen)),
            patch.object(virtualmin_tasks, "schedule"),
        ):
            VirtualminMigrationService().execute(migration, token)

        self.assertEqual(seen, {"A": hostname_service.CUTOVER_TTL_SECONDS, "AAAA": hostname_service.CUTOVER_TTL_SECONDS})
        migration.refresh_from_db()
        self.assertEqual(migration.status, "quiescing")

    def test_a_legacy_migration_never_lowers_a_ttl(self) -> None:
        migration, token = self._held("pending")
        seen: dict[str, int] = {}

        with (
            patch.object(hostname_service, "lower_account_hostname_ttl", side_effect=AssertionError("lowered")),
            patch.object(VirtualminMigrationService, "_quiesce", self._stop_after_quiescing(seen)),
            patch.object(virtualmin_tasks, "schedule"),
        ):
            VirtualminMigrationService().execute(migration, token)

        migration.refresh_from_db()
        self.assertEqual(migration.status, "quiescing")


class CompensationTests(MigrationTtlCase):
    def test_a_cancel_while_waiting_restores_the_ttl(self) -> None:
        hostname = self._published_name()
        self._lowered(hostname)
        migration, token = self._held("lowering_ttl", cancel_requested=True)

        VirtualminMigrationService().execute(migration, token)

        migration.refresh_from_db()
        self.assertEqual(migration.status, "rolled_back")
        hostname.refresh_from_db()
        self.assertIsNone(hostname.previous_ttl)
        self.assertEqual(self._provider_ttls(hostname), {"A": ORIGINAL_TTL, "AAAA": ORIGINAL_TTL})

    def test_a_ttl_that_never_confirms_rolls_back_and_restores(self) -> None:
        hostname = self._published_name()
        self._lowered(hostname)
        AccountHostname.objects.filter(pk=hostname.pk).update(
            ttl_lowered_at=timezone.now() - hostname_service.TTL_LOWER_DEADLINE - timedelta(seconds=1)
        )
        migration, token = self._held("lowering_ttl")

        with patch.object(FakeDnsGateway, "reconcile_records", _stale_ttl):
            VirtualminMigrationService().execute(migration, token)

        migration.refresh_from_db()
        self.assertEqual(migration.status, "rolled_back")
        self.assertEqual(self._provider_ttls(hostname), {"A": ORIGINAL_TTL, "AAAA": ORIGINAL_TTL})

    def test_a_pre_cutover_failure_after_lowering_restores_the_ttl(self) -> None:
        hostname = self._published_name()
        self._lowered(hostname)
        migration, token = self._held("backing_up")

        with patch.object(
            VirtualminMigrationService, "_command", side_effect=DefiniteMigrationFailureError("backup failed")
        ):
            VirtualminMigrationService().execute(migration, token)

        migration.refresh_from_db()
        self.assertEqual(migration.status, "rolled_back")
        hostname.refresh_from_db()
        self.assertIsNone(hostname.previous_ttl)
        self.assertEqual(self._provider_ttls(hostname), {"A": ORIGINAL_TTL, "AAAA": ORIGINAL_TTL})

    def test_a_legacy_rollback_never_touches_dns(self) -> None:
        migration, token = self._held("backing_up")

        with patch.object(
            VirtualminMigrationService, "_command", side_effect=DefiniteMigrationFailureError("backup failed")
        ):
            VirtualminMigrationService().execute(migration, token)

        migration.refresh_from_db()
        self.assertEqual(migration.status, "rolled_back")
        self.assertEqual(FakeDnsGateway.calls, [])
