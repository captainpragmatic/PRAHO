"""Account-name dispatchers never spend a worker or request budget on a batch of node RPCs."""

from unittest.mock import patch

from django.conf import settings
from django.utils import timezone
from django_q.conf import Conf
from django_q.models import OrmQ
from django_q.signing import SignedPackage

from apps.common.types import Ok
from apps.provisioning import account_hostname_lifecycle as lifecycle
from apps.provisioning import account_hostname_service as service
from apps.provisioning import account_name_certificates as certificates
from apps.provisioning.account_hostname_models import AccountHostname
from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService
from apps.provisioning.virtualmin_models import VirtualminAccount
from tests.helpers.fake_dns_gateway import FakeDnsGateway
from tests.provisioning.test_account_hostname_service import AccountNameTestCase
from tests.provisioning.test_virtualmin_migration_service import MigrationTestBase


class BoundedDispatcherTests(AccountNameTestCase):
    def _due(self):
        AccountHostname.objects.filter(pk=self.hostname.pk).update(
            target_server=self.server,
            last_reconciled_at=timezone.now() - timezone.timedelta(days=2),
            records={"A": {"intended": self.server.ipv4_address, "ttl": 300}},
        )
        self.hostname.refresh_from_db()

    def test_the_scheduled_sweep_does_not_run_a_single_guard_that_can_exceed_its_entire_budget(self):
        self._due()
        elapsed = []

        def node_call(*args, **kwargs):
            # An allowed successful guard RPC (180s SSH wait +180s playbook)
            # already exceeds this schedule's inherited 300s worker timeout.
            elapsed.append(310)
            return Ok("a" * 64)

        with (
            patch.object(service, "certificate_ready_on", return_value=True),
            patch.object(service, "ensure_account_name_neutral", side_effect=node_call),
            patch("django_q.tasks.async_task") as enqueue,
        ):
            result = lifecycle.reconcile_account_names()
        self.assertLess(sum(elapsed), settings.Q_CLUSTER["timeout"])
        self.assertEqual(FakeDnsGateway.calls, [])
        self.assertEqual(result["enqueued"], 1)
        enqueue.assert_called_once_with(
            "apps.provisioning.account_hostname_lifecycle.sync_account_name",
            str(self.hostname.pk),
            timeout=lifecycle.ACCOUNT_NAME_TASK_TIMEOUT_SECONDS,
            sync=False,
        )

    def test_pending_private_retirements_are_dispatched_without_node_or_provider_io(self):
        self._due()
        VirtualminAccount.objects.filter(pk=self.account.pk).update(status="terminated")
        with patch("django_q.tasks.async_task") as enqueue:
            result = lifecycle.reconcile_account_names()
        self.assertEqual(self.node.calls, [])
        self.assertEqual(FakeDnsGateway.calls, [])
        self.assertEqual(result["enqueued"], 1)
        enqueue.assert_called_once_with(
            "apps.provisioning.account_hostname_lifecycle.retire_account_name",
            str(self.hostname.pk),
            timeout=lifecycle.ACCOUNT_NAME_TASK_TIMEOUT_SECONDS,
            sync=False,
        )

    def test_ensure_hands_dns_to_a_distinct_budget_after_its_four_guard_node_step(self):
        with patch("django_q.tasks.async_task") as enqueue:
            result = lifecycle.ensure_account_name(str(self.account.pk))
        self.assertEqual(result, {"outcome": "sync_queued"})
        self.assertEqual(self.prepare_neutral.call_count, 1)
        self.assertEqual(self.neutral.call_count, 1)  # The fake certificate boundary adds no guards.
        self.assertEqual(FakeDnsGateway.calls, [])
        enqueue.assert_called_once_with(
            "apps.provisioning.account_hostname_lifecycle.sync_account_name",
            str(self.hostname.pk),
            timeout=lifecycle.ACCOUNT_NAME_TASK_TIMEOUT_SECONDS,
            sync=False,
        )

    def test_staff_repair_remains_a_real_queue_dispatch_when_global_sync_is_enabled(self):
        with patch.object(Conf, "SYNC", True), self.captureOnCommitCallbacks(execute=True):
            self.assertTrue(lifecycle.queue_repair(self.account))
        self.assertEqual(self.node.calls, [])
        self.assertEqual(FakeDnsGateway.calls, [])
        tasks = [
            task
            for row in OrmQ.objects.all()
            if (task := SignedPackage.loads(row.payload))["func"] == lifecycle.ENSURE_TASK
        ]
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0]["func"], lifecycle.ENSURE_TASK)
        self.assertFalse(tasks[0]["sync"])
        self.assertEqual(tasks[0]["timeout"], lifecycle.ACCOUNT_NAME_TASK_TIMEOUT_SECONDS)

    def test_certificate_dispatch_never_executes_a_native_install_in_its_caller(self):
        with (
            patch.object(Conf, "SYNC", True),
            patch.object(certificates, "install_account_name_certificate", return_value={"outcome": "installed"}) as worker,
        ):
            certificates._dispatch(certificates.INSTALL_TASK, "row-id")
        worker.assert_not_called()
        tasks = [
            task
            for row in OrmQ.objects.all()
            if (task := SignedPackage.loads(row.payload))["func"] == certificates.INSTALL_TASK
        ]
        self.assertEqual(len(tasks), 1)
        self.assertFalse(tasks[0]["sync"])
        self.assertEqual(tasks[0]["timeout"], lifecycle.ACCOUNT_NAME_TASK_TIMEOUT_SECONDS)

    def test_duplicate_sweeps_do_not_redispatch_or_extend_the_retry_cooldown(self):
        self._due()
        with (
            patch.object(service, "certificate_ready_on", return_value=True),
            patch("django_q.tasks.async_task") as enqueue,
        ):
            lifecycle.reconcile_account_names()
            self.hostname.refresh_from_db()
            claimed = self.hostname.last_swept_at
            lifecycle.reconcile_account_names()
            self.hostname.refresh_from_db()
            self.assertEqual(self.hostname.last_swept_at, claimed)
            self.assertEqual(enqueue.call_count, 1)
            AccountHostname.objects.filter(pk=self.hostname.pk).update(
                last_swept_at=timezone.now() - lifecycle.NODE_STEP_BACKOFF - timezone.timedelta(seconds=1)
            )
            lifecycle.reconcile_account_names()
            self.assertEqual(enqueue.call_count, 2)

    def test_the_publication_worker_requires_a_new_guard_after_successful_placement(self):
        with patch("django_q.tasks.async_task"):
            self.assertEqual(lifecycle.ensure_account_name(str(self.account.pk)), {"outcome": "sync_queued"})
        self.neutral.reset_mock()
        self.neutral.side_effect = None
        self.neutral.return_value = service.Err("fresh guard unproved")
        with patch.object(service, "certificate_ready_on", return_value=True):
            self.assertEqual(lifecycle.sync_account_name(str(self.hostname.pk)), {"outcome": "dns_failed"})
        self.neutral.assert_called_once()
        self.assertFalse(any(call.startswith("reconcile ") for call in FakeDnsGateway.calls))

    def test_termination_callback_queues_private_cleanup_instead_of_running_it_in_the_caller(self):
        self._due()
        with patch("django_q.tasks.async_task") as enqueue, self.captureOnCommitCallbacks(execute=True):
            lifecycle.on_account_terminated(self.account)
        self.assertEqual(self.node.calls, [])
        self.assertEqual(FakeDnsGateway.calls, [])
        enqueue.assert_called_once_with(
            "apps.provisioning.account_hostname_lifecycle.retire_account_name",
            str(self.hostname.pk),
            timeout=lifecycle.ACCOUNT_NAME_TASK_TIMEOUT_SECONDS,
            sync=False,
        )


class QueuedPublicationAdmissionTests(MigrationTestBase):
    def test_real_migration_admission_between_placement_and_publication_prevents_all_sync_io(self):
        self.settings_values.update(
            {
                "dns.account_hostname_zone": "praho-sites.net",
                "dns.account_hostname_zone_id": "0123456789abcdef0123456789abcdef",
                "dns.account_zone_api_token": "test-token",
            }
        )
        with (
            patch.object(service, "ensure_node_account_name", return_value=Ok(None)),
            patch("django_q.tasks.async_task") as enqueue,
        ):
            self.assertEqual(lifecycle.ensure_account_name(str(self.account.pk)), {"outcome": "sync_queued"})
        hostname = AccountHostname.objects.get(account=self.account)
        self.assertEqual(hostname.records, {})
        enqueue.assert_called_once_with(
            lifecycle.SYNC_TASK, str(hostname.pk), timeout=lifecycle.ACCOUNT_NAME_TASK_TIMEOUT_SECONDS, sync=False
        )
        admitted = VirtualminMigrationService().start_migration(
            self.account, self.target, initiated_by=self.staff, enqueue=False
        )
        self.assertTrue(admitted.is_ok(), admitted)
        self.assertEqual(admitted.unwrap().contract, "legacy")
        with (
            patch.object(service, "_dns_gateway", side_effect=AssertionError("No provider reads or writes")),
            patch.object(service, "ensure_account_name_neutral", side_effect=AssertionError("No native action")),
        ):
            self.assertEqual(lifecycle.sync_account_name(str(hostname.pk)), {"outcome": "migration_locked"})
