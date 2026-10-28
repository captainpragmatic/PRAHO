"""Real PostgreSQL publication locks select the contract before external mutation."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.db import close_old_connections, connection
from django.test import override_settings
from django.utils import timezone

from apps.infrastructure.models import CloudProvider, NodeDeployment, NodeRegion, NodeSize, PanelType
from apps.provisioning import account_hostname_service as names
from apps.provisioning.account_hostname_models import AccountHostname
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from apps.settings.services import SettingsService
from tests.helpers.fake_dns_gateway import FakeDnsGateway
from tests.mocks.virtualmin_mock import MockVirtualminGateway
from tests.provisioning.test_account_hostname_service import AccountNameTransactionCase

_SECONDS = 15


@override_settings(
    DISABLE_AUDIT_SIGNALS=True,
    AUDIT_CHAIN_ENABLED=False,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    Q_CLUSTER={"retry": 14400, "orm": "default"},
)
class LegacyAccountNamePostgresRaceTests(AccountNameTransactionCase):
    def setUp(self):
        if connection.vendor != "postgresql":
            self.skipTest("Publication/admission races require PostgreSQL row locks")
        self.enterContext(patch("apps.provisioning.virtualmin_tasks.reconcile_virtualmin_service_state_async"))
        super().setUp()
        self.name = self.hostname
        self.name.target_server = self.server
        self.name.save(update_fields=["target_server"])
        self.server.last_health_check = timezone.now()
        self.server.save(update_fields=["last_health_check"])
        self.target = VirtualminServer.objects.create(
            name="Legacy race target",
            hostname="legacy-target.example.com",
            api_username="praho-acl",
            ipv4_address="203.0.113.20",
            last_health_check=timezone.now(),
        )
        provider = CloudProvider.objects.create(
            name="Legacy race provider", provider_type="hetzner", code="het", credential_identifier="legacy-race"
        )
        region = NodeRegion.objects.create(
            provider=provider,
            name="Legacy race region",
            provider_region_id="fsn1",
            normalized_code="fsn1",
            country_code="de",
            city="Falkenstein",
        )
        size = NodeSize.objects.create(
            provider=provider,
            name="Legacy race size",
            display_name="Small",
            provider_type_id="cpx21",
            vcpus=2,
            memory_gb=4,
            disk_gb=40,
            hourly_cost_eur="0.01",
            monthly_cost_eur="5.00",
        )
        panel = PanelType.objects.create(
            name="Legacy race Virtualmin", panel_type="virtualmin", ansible_playbook="virtualmin.yml"
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
        spool = self.enterContext(TemporaryDirectory())
        for key, value in (("provisioning.migration_enabled", True), ("provisioning.migration_spool_dir", spool)):
            self.assertTrue(SettingsService.update_setting(key, value).is_ok())
        self.source_gateway = MockVirtualminGateway(server_hostname=self.server.hostname)
        source = self.source_gateway.seed_domain(
            self.account.domain, username=self.account.virtualmin_username, enabled=True
        )
        source.features = ["unix", "dir", "web", "ssl", "logrotate", "mysql", "webmin"]
        self.target_gateway = MockVirtualminGateway(server_hostname=self.target.hostname)
        self.enterContext(
            patch(
                "apps.provisioning.virtualmin_migration_service.VirtualminGateway",
                side_effect=lambda config: (
                    self.source_gateway if config.server.pk == self.server.pk else self.target_gateway
                ),
            )
        )
        self.enterContext(patch.object(names, "certificate_ready_on", return_value=True))
        self.node_mutation = self.enterContext(
            patch(
                "apps.infrastructure.ansible_service.AnsibleService.run_playbook",
                side_effect=AssertionError("No native mutation belongs to admission/publication"),
            )
        )
        self.enqueue = self.enterContext(patch("django_q.tasks.async_task", side_effect=AssertionError("No dispatch")))

    def _publish(self):
        return names.sync_account_hostname(AccountHostname.objects.get(pk=self.name.pk))

    def _admit(self):
        return VirtualminMigrationService().start_migration(
            VirtualminAccount.objects.get(pk=self.account.pk), self.target, initiated_by=None, enqueue=False
        )

    def _thread(self, action, ready, done, pids):
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SET lock_timeout = '15s'")
                cursor.execute("SET statement_timeout = '15s'")
                cursor.execute("SELECT pg_backend_pid()")
                pids.append(cursor.fetchone()[0])
            ready.set()
            return action()
        finally:
            done.set()
            connection.close()

    def _waits_on(self, waiter, holder, done):
        deadline = time.monotonic() + _SECONDS
        while time.monotonic() < deadline and not done.is_set():
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT wait_event_type, pg_blocking_pids(pid), query FROM pg_stat_activity WHERE pid = %s",
                    [waiter],
                )
                row = cursor.fetchone()
            if row and row[0] == "Lock" and holder in row[1] and "provisioning_account_hostnames" in row[2]:
                return True
            done.wait(0.01)
        return False

    def _ordered_race(self, first, second, external_boundary):
        reached, release = threading.Event(), threading.Event()
        ready1, ready2, done1, done2 = (threading.Event() for _ in range(4))
        pids1, pids2 = [], []
        original = external_boundary[0]

        def pause(*args, **kwargs):
            reached.set()
            if not release.wait(_SECONDS):
                raise AssertionError("The external-I/O boundary was not released")
            return original(*args, **kwargs)

        with (
            patch.object(external_boundary[1], external_boundary[2], autospec=True, side_effect=pause),
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            winner = executor.submit(self._thread, first, ready1, done1, pids1)
            try:
                self.assertTrue(reached.wait(_SECONDS), "The first service never reached its external boundary")
                follower = executor.submit(self._thread, second, ready2, done2, pids2)
                self.assertTrue(ready2.wait(_SECONDS), "The second SQL connection never became ready")
                self.assertNotEqual(pids1[0], pids2[0])
                blocked = self._waits_on(pids2[0], pids1[0], done2)
            finally:
                release.set()
            first_result = winner.result(timeout=_SECONDS)
            second_result = follower.result(timeout=_SECONDS)
        self.assertTrue(blocked, "The second public service did not wait on the first service's publication lock")
        self.node_mutation.assert_not_called()
        self.enqueue.assert_not_called()
        return first_result, second_result

    def test_publisher_first_selects_cutover_after_waiting_for_the_real_provider_boundary(self):
        original = FakeDnsGateway.reconcile_records
        published, admitted = self._ordered_race(
            self._publish, self._admit, (original, FakeDnsGateway, "reconcile_records")
        )
        self.assertTrue(published.is_ok(), published)
        self.assertTrue(admitted.is_ok(), admitted)
        self.assertEqual(admitted.unwrap().contract, VirtualminMigration.Contract.CUTOVER)
        self.assertEqual(FakeDnsGateway.published(self.name.fqdn)["A"], self.server.ipv4_address)

    def test_admission_first_selects_legacy_and_blocks_all_publication_intent_and_provider_writes(self):
        original = self.target_gateway.call
        admitted, published = self._ordered_race(self._admit, self._publish, (original, self.target_gateway, "call"))
        self.assertTrue(admitted.is_ok(), admitted)
        self.assertEqual(admitted.unwrap().contract, VirtualminMigration.Contract.LEGACY)
        self.assertEqual(published.unwrap(), "skipped:migration_locked")
        self.name.refresh_from_db()
        self.assertEqual(self.name.records, {})
        self.assertEqual(FakeDnsGateway.calls, [])
