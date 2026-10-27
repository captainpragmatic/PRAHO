"""Real PostgreSQL account locks serialize owner mail intent and migration admission."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from tempfile import TemporaryDirectory
from unittest.mock import patch
from uuid import uuid4

from django.db import close_old_connections, connection, transaction
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from apps.infrastructure.models import CloudProvider, NodeDeployment, NodeRegion, NodeSize, PanelType
from apps.provisioning.virtualmin_mail_enrollment import prepare_mail_enrollment, request_mail_enrollment
from apps.provisioning.virtualmin_mail_models import VirtualminMailOperation
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService
from apps.provisioning.virtualmin_models import VirtualminAccount
from apps.settings.services import SettingsService
from apps.users.models import CustomerMembership, User
from tests.mocks.virtualmin_mock import MockVirtualminGateway
from tests.provisioning.test_account_hostname_models import _make_server
from tests.provisioning.test_virtualmin_mail_models import MailModelFixture

_RACE_SECONDS = 15


@override_settings(
    DISABLE_AUDIT_SIGNALS=True,
    AUDIT_CHAIN_ENABLED=False,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    Q_CLUSTER={"retry": 14400, "orm": "default"},
)
class MailEnrollmentPostgresRaceTests(MailModelFixture, TransactionTestCase):
    """Observe the second connection waiting on the first, then verify fresh admission outcomes."""

    def setUp(self):
        if connection.vendor != "postgresql":
            self.skipTest("Mail enrollment admission races require PostgreSQL row locks")
        # Fixture Service creation queues reconciliation in autocommit; no worker belongs to these races.
        self.enterContext(patch("apps.provisioning.virtualmin_tasks.reconcile_virtualmin_service_state_async"))
        super().setUp()
        self.owner = User.objects.create_user(email="mail-race-owner@example.test", password="Owner-test123!")
        CustomerMembership.objects.create(user=self.owner, customer=self.account.service.customer, role="owner")
        self.proposal = prepare_mail_enrollment(
            self.account,
            actor=self.owner,
            intent="enable",
            plan={"version": 1, "records": [{"name": self.account.domain, "type": "MX", "value": self.name.fqdn}]},
        ).unwrap()
        self.target = _make_server()
        self.server.last_health_check = timezone.now()
        self.server.save(update_fields=["last_health_check"])
        self.target.last_health_check = timezone.now()
        self.target.save(update_fields=["last_health_check"])
        self._managed_nodes()
        self.spool = self.enterContext(TemporaryDirectory())
        for key, value in (
            ("provisioning.migration_enabled", True),
            ("provisioning.migration_spool_dir", self.spool),
        ):
            result = SettingsService.update_setting(key, value, reason="Isolated admission race fixture")
            self.assertTrue(result.is_ok(), result)
        self.source_gateway = MockVirtualminGateway(server_hostname=self.server.hostname)
        source = self.source_gateway.seed_domain(
            self.account.domain, username=self.account.virtualmin_username, enabled=True
        )
        source.features = ["unix", "dir", "web", "ssl", "logrotate", "mysql", "webmin"]
        self.target_gateway = MockVirtualminGateway(server_hostname=self.target.hostname)
        self.gateway_factory = self.enterContext(
            patch(
                "apps.provisioning.virtualmin_migration_service.VirtualminGateway",
                side_effect=lambda config: (
                    self.source_gateway if config.server.pk == self.server.pk else self.target_gateway
                ),
            )
        )
        self.playbook = self.enterContext(
            patch(
                "apps.infrastructure.ansible_service.AnsibleService.run_playbook",
                side_effect=AssertionError("No node mutation"),
            )
        )
        self.enqueue = self.enterContext(
            patch("django_q.tasks.async_task", side_effect=AssertionError("No queue dispatch"))
        )
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_backend_pid()")
            self.main_pid = cursor.fetchone()[0]

    def _managed_nodes(self):
        provider = CloudProvider.objects.create(
            name="Mail race provider", provider_type="hetzner", code="het", credential_identifier="mail-race-fixture"
        )
        region = NodeRegion.objects.create(
            provider=provider,
            name="Mail race region",
            provider_region_id="fsn1",
            normalized_code="fsn1",
            country_code="de",
            city="Falkenstein",
        )
        size = NodeSize.objects.create(
            provider=provider,
            name="Mail race size",
            display_name="Mail race size",
            provider_type_id="cpx21",
            vcpus=2,
            memory_gb=4,
            disk_gb=40,
            hourly_cost_eur="0.01",
            monthly_cost_eur="5.00",
        )
        panel = PanelType.objects.create(
            name="Mail race Virtualmin", panel_type="virtualmin", ansible_playbook="virtualmin.yml"
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

    def _confirm(self, submission):
        return request_mail_enrollment(
            VirtualminAccount.objects.get(pk=self.account.pk),
            actor=User.objects.get(pk=self.owner.pk),
            intent="enable",
            proposal_id=self.proposal["proposal_id"],
            consent_digest=self.proposal["consent_digest"],
            submission_id=submission,
        )

    def _migrate(self):
        return VirtualminMigrationService().start_migration(
            VirtualminAccount.objects.get(pk=self.account.pk),
            self.target,
            initiated_by=User.objects.get(pk=self.owner.pk),
            enqueue=False,
        )

    def _thread(self, action, pids, ready, done):
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

    def _waits_for_account(self, pid, done):
        deadline = time.monotonic() + _RACE_SECONDS
        while time.monotonic() < deadline and not done.is_set():
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT wait_event_type, pg_blocking_pids(pid) FROM pg_stat_activity WHERE pid = %s", [pid]
                )
                row = cursor.fetchone()
            if row and row[0] == "Lock" and self.main_pid in row[1]:
                return True
            done.wait(0.01)
        return False

    def _race(self, first, second):
        pids, ready, done = [], threading.Event(), threading.Event()
        with ThreadPoolExecutor(max_workers=1) as executor:
            with transaction.atomic():
                VirtualminAccount.objects.select_for_update(no_key=True).get(pk=self.account.pk)
                pending = executor.submit(self._thread, second, pids, ready, done)
                self.assertTrue(ready.wait(_RACE_SECONDS), "The independent database connection never became ready")
                self.assertNotEqual(pids[0], self.main_pid)
                self.assertTrue(
                    self._waits_for_account(pids[0], done), "Admission did not wait on the account's SQL lock"
                )
                winner = first()
            follower = pending.result(timeout=_RACE_SECONDS)
        return winner, follower

    def test_concurrent_exact_submission_confirms_return_the_same_durable_operation(self):
        submission = uuid4()
        first, second = self._race(lambda: self._confirm(submission), lambda: self._confirm(submission))
        self.assertTrue(first.is_ok(), first)
        self.assertTrue(second.is_ok(), second)
        self.assertEqual(first.unwrap().pk, second.unwrap().pk)
        self.assertEqual(VirtualminMailOperation.objects.count(), 1)
        self.gateway_factory.assert_not_called()
        self.playbook.assert_not_called()
        self.enqueue.assert_not_called()

    def test_concurrent_distinct_submissions_admit_exactly_one_open_operation(self):
        first, second = self._race(lambda: self._confirm(uuid4()), lambda: self._confirm(uuid4()))
        self.assertTrue(first.is_ok(), first)
        self.assertEqual(second.unwrap_err(), "mail_operation_active")
        self.assertEqual(VirtualminMailOperation.objects.filter(status="queued").count(), 1)
        self.assertEqual(VirtualminMigration.objects.count(), 0)
        self.gateway_factory.assert_not_called()
        self.playbook.assert_not_called()
        self.enqueue.assert_not_called()

    def test_mail_admission_winning_blocks_the_waiting_public_migration_before_backend_reads(self):
        mail, migration = self._race(lambda: self._confirm(uuid4()), self._migrate)
        self.assertTrue(mail.is_ok(), mail)
        self.assertTrue(migration.is_err(), migration)
        self.assertIn("active", migration.unwrap_err())
        self.assertEqual(VirtualminMailOperation.objects.filter(status="queued").count(), 1)
        self.assertEqual(VirtualminMigration.objects.count(), 0)
        self.gateway_factory.assert_not_called()
        self.assertEqual(self.source_gateway.get_calls(), [])
        self.assertEqual(self.target_gateway.get_calls(), [])
        self.playbook.assert_not_called()
        self.enqueue.assert_not_called()

    def test_migration_admission_winning_blocks_the_waiting_mail_confirmation(self):
        migration, mail = self._race(self._migrate, lambda: self._confirm(uuid4()))
        self.assertTrue(migration.is_ok(), migration)
        self.assertEqual(mail.unwrap_err(), "mail_operation_active")
        self.assertEqual(VirtualminMigration.objects.filter(status="pending").count(), 1)
        self.assertEqual(VirtualminMailOperation.objects.count(), 0)
        self.assertEqual([call.program for call in self.source_gateway.get_calls()], ["list-domains"])
        self.assertEqual([call.program for call in self.target_gateway.get_calls()], ["list-domains"])
        self.playbook.assert_not_called()
        self.enqueue.assert_not_called()
