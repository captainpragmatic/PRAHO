"""
Tests for the Virtualmin task enqueue contract and the failed-job retry sweep.

#325 follow-through: this module previously had zero coverage while every one
of its retry mechanisms was broken — the enqueue wrapper leaked an invalid
`retry=` kwarg into task kwargs (TypeError on every dequeue), and the sweeper
re-dispatched create_domain with an obsolete signature that stranded jobs in
'pending' forever.
"""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch

from django.db import transaction
from django.test import TestCase, override_settings
from django.utils import timezone
from django_q.models import Schedule

from apps.billing.models import Currency
from apps.common.types import Err, Ok, Retriability
from apps.customers.models import Customer
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.signals import handle_service_virtualmin_reconciliation
from apps.provisioning.tasks import queue_service_provisioning
from apps.provisioning.virtualmin_gateway import VirtualminConfig, VirtualminGateway
from apps.provisioning.virtualmin_models import (
    VirtualminAccount,
    VirtualminDriftRecord,
    VirtualminProvisioningJob,
    VirtualminServer,
)
from apps.provisioning.virtualmin_service import (
    VirtualminAccountCreationData,
    VirtualminProvisioningService,
    VirtualminServerManagementService,
)
from apps.provisioning.virtualmin_tasks import (
    health_check_virtualmin_servers,
    process_failed_virtualmin_jobs,
    provision_virtualmin_account_async,
    reconcile_divergent_services_task,
    reconcile_virtualmin_service_state,
    retry_virtualmin_job,
    setup_virtualmin_scheduled_tasks,
)
from tests.helpers.fsm_helpers import force_status
from tests.mocks.virtualmin_mock import MockVirtualminGateway


class _BoomError(Exception):
    pass


class VirtualminTaskTestBase(TestCase):
    """Shared fixtures: customer -> plan -> service -> server -> account -> job."""

    def setUp(self) -> None:
        self.customer = Customer.objects.create(
            name="Test SRL",
            customer_type="company",
            status="active",
            primary_email="test@example.com",
            company_name="Test SRL",
        )
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.plan = ServicePlan.objects.create(
            name="Shared Hosting",
            plan_type="shared_hosting",
            price_monthly=Decimal("10.00"),
        )
        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name="test.example.com",
            domain="test.example.com",
            username="testuser",
            billing_cycle="monthly",
            price=Decimal("10.00"),
            status="active",
        )
        self.server = VirtualminServer.objects.create(
            name="vm-test-1",
            hostname="vm1.example.com",
            api_username="praho-acl",
            api_port=10000,
            status="active",
            max_domains=1000,
            current_domains=10,
        )
        self.server.set_api_password("test_password")
        self.server.save()
        self.account = VirtualminAccount.objects.create(
            domain="test.example.com",
            service=self.service,
            server=self.server,
            virtualmin_username="testexample",
            template_name="Default",
            status="error",
            praho_customer_id=self.customer.id,
            praho_service_id=self.service.id,
        )
        self.account.set_password("account_password")
        self.account.save()

    def _failed_job(self, operation: str = "create_domain", **kwargs) -> VirtualminProvisioningJob:
        defaults = {
            "operation": operation,
            "server": self.server,
            "account": self.account,
            "correlation_id": f"{operation}_{self.account.id}",
            "status": "failed",
            "retry_count": 0,
            "next_retry_at": timezone.now() - timedelta(minutes=1),
        }
        defaults.update(kwargs)
        return VirtualminProvisioningJob.objects.create(**defaults)


class TestEnqueueContract(VirtualminTaskTestBase):
    """The wrapper must never leak non-option kwargs into task kwargs."""

    @patch("apps.provisioning.virtualmin_tasks.async_task", return_value="task-123")
    def test_provision_wrapper_does_not_leak_retry_kwarg(self, mock_async):
        """django-q2 1.9.0 has no `retry` option — it would land in the task
        kwargs and make every dequeue call provision_virtualmin_account(params,
        retry=3) -> TypeError."""
        params = {"service_id": str(self.service.id), "domain": "test.example.com"}

        provision_virtualmin_account_async(params)

        mock_async.assert_called_once()
        _, kwargs = mock_async.call_args
        self.assertNotIn("retry", kwargs)
        self.assertIn("timeout", kwargs)


class TestFailedJobSweep(VirtualminTaskTestBase):
    """The sweep must claim jobs safely and dispatch a job-aware retry."""

    @patch("apps.provisioning.virtualmin_tasks.async_task", return_value="task-123")
    def test_create_domain_retry_dispatches_job_aware_task(self, mock_async):
        """The old re-dispatch called provision_virtualmin_account with an
        obsolete 3-positional signature; a fresh create is also a structural
        no-op because the error-status account row still exists. The sweep must
        dispatch the job-aware retry task with the job id."""
        job = self._failed_job()

        result = process_failed_virtualmin_jobs()

        self.assertTrue(result["success"])
        self.assertEqual(result["results"]["retried_jobs"], 1)
        mock_async.assert_called_once()
        args, kwargs = mock_async.call_args
        self.assertEqual(args[0], "apps.provisioning.virtualmin_tasks.retry_virtualmin_job")
        self.assertEqual(args[1], str(job.id))
        self.assertNotIn("retry", kwargs)

        job.refresh_from_db()
        self.assertEqual(job.status, "pending")
        self.assertEqual(job.retry_count, 1)  # attempt consumed at claim time
        self.assertIsNotNone(job.claimed_at)

    @patch("apps.provisioning.virtualmin_tasks.async_task", return_value="task-123")
    def test_second_sweep_does_not_double_claim(self, mock_async):
        self._failed_job()

        process_failed_virtualmin_jobs()
        process_failed_virtualmin_jobs()

        self.assertEqual(mock_async.call_count, 1)

    @patch("apps.provisioning.virtualmin_tasks.async_task", side_effect=RuntimeError("broker down"))
    def test_enqueue_failure_restores_job_to_failed_with_backoff(self, mock_async):
        job = self._failed_job()

        result = process_failed_virtualmin_jobs()

        self.assertTrue(result["success"])
        job.refresh_from_db()
        self.assertEqual(job.status, "failed")
        self.assertIsNotNone(job.next_retry_at)
        self.assertGreater(job.next_retry_at, timezone.now())

    @patch("apps.provisioning.virtualmin_tasks.async_task", return_value="task-123")
    def test_expired_pending_claim_recovered(self, mock_async):
        """Process death after claim but before/after enqueue must not strand
        the job in 'pending' outside the failed-job filter forever."""
        job = self._failed_job(
            status="pending",
            retry_count=1,
            claimed_at=timezone.now() - timedelta(minutes=31),  # past the 30-min lease
        )

        process_failed_virtualmin_jobs()

        job.refresh_from_db()
        self.assertEqual(job.status, "failed")
        self.assertIsNotNone(job.next_retry_at)

    @patch("apps.provisioning.virtualmin_tasks.async_task", return_value="task-123")
    def test_exhausted_job_is_terminal(self, mock_async):
        job = self._failed_job(retry_count=3, max_retries=3)

        result = process_failed_virtualmin_jobs()

        self.assertTrue(result["success"])
        mock_async.assert_not_called()
        job.refresh_from_db()
        self.assertEqual(job.status, "failed")
        # Terminalized: opted out of every future sweep, not just this one
        self.assertIsNone(job.next_retry_at)

    @patch("apps.provisioning.virtualmin_tasks.async_task", return_value="task-123")
    def test_missing_account_job_is_terminal_not_retried(self, mock_async):
        job = self._failed_job(account=None)

        result = process_failed_virtualmin_jobs()

        mock_async.assert_not_called()
        job.refresh_from_db()
        self.assertNotEqual(job.status, "pending")
        self.assertIsNone(job.next_retry_at)  # opted out of future sweeps
        self.assertEqual(result["results"]["retried_jobs"], 0)


class TestRetryJobExecution(VirtualminTaskTestBase):
    """retry_virtualmin_job must recover on the EXISTING account+job rows."""

    def _run_retry(self, job: VirtualminProvisioningJob) -> dict:
        return retry_virtualmin_job(str(job.id))

    def test_create_retry_converges_remote_success(self):
        """End-to-end revert-detector for the timed-out-but-remotely-successful
        create: the retry must finalize the EXISTING error-status account and
        complete the SAME job — never early-exit on 'account already exists',
        never re-create, never strand pending."""
        mock_gateway = MockVirtualminGateway()
        # Remote create DID succeed — seeded with OUR username (ownership probe)
        mock_gateway.seed_domain(self.account.domain, username=self.account.virtualmin_username)
        job = self._failed_job(status="pending", retry_count=1, claimed_at=timezone.now())
        domains_before = self.server.current_domains

        with patch(
            "apps.provisioning.virtualmin_service.VirtualminGateway",
            return_value=mock_gateway,
        ):
            result = self._run_retry(job)

        self.assertTrue(result["success"], result)
        job.refresh_from_db()
        self.account.refresh_from_db()
        self.server.refresh_from_db()
        self.assertEqual(job.status, "completed")
        self.assertEqual(self.account.status, "active")
        # Exactly-once increment, and no second create-domain call was issued
        self.assertEqual(self.server.current_domains, domains_before + 1)
        self.assertEqual(len(mock_gateway.get_calls("create-domain")), 0)

    def test_suspend_retry_reuses_existing_job_no_fanout(self):
        """Retrying a suspend must not mint a second job row (exponential
        fan-out: each account method creates its own job today)."""
        self.account.status = "active"
        self.account.save(update_fields=["status"])
        force_status(self.service, "suspended")  # the suspend intent is still current
        mock_gateway = MockVirtualminGateway()
        mock_gateway.seed_domain(self.account.domain, username=self.account.virtualmin_username)
        job = self._failed_job(
            operation="suspend_domain", status="pending", retry_count=1, claimed_at=timezone.now()
        )

        with patch(
            "apps.provisioning.virtualmin_service.VirtualminGateway",
            return_value=mock_gateway,
        ):
            result = self._run_retry(job)

        self.assertTrue(result["success"], result)
        self.assertEqual(
            VirtualminProvisioningJob.objects.filter(operation="suspend_domain").count(),
            1,
        )
        job.refresh_from_db()
        self.assertEqual(job.status, "completed")
        self.account.refresh_from_db()
        self.assertEqual(self.account.status, "suspended")


class TestCreateAccountPreflight(VirtualminTaskTestBase):
    """create_virtualmin_account pre-flight: #325 defect 2 — every creation
    failed at 'self.health_check_server' (wrong class) and the conflict/
    template checks read response keys the parser never produces."""

    def _creation_data(self, domain: str = "new.example.com", template: str = "Default"):
        service2 = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name=domain,
            domain=domain,
            username="newuser",
            billing_cycle="monthly",
            price=Decimal("10.00"),
            status="active",
        )
        return VirtualminAccountCreationData(
            service=service2, domain=domain, template=template, server=self.server
        )

    def _create(self, mock_gateway, **kwargs):
        with patch(
            "apps.provisioning.virtualmin_service.VirtualminGateway",
            return_value=mock_gateway,
        ):
            service = VirtualminProvisioningService(self.server)
            return service.create_virtualmin_account(self._creation_data(**kwargs))

    def test_create_account_happy_path(self):
        """First-ever test of the create path: it must actually create."""
        mock_gateway = MockVirtualminGateway()

        result = self._create(mock_gateway)

        self.assertTrue(result.is_ok(), result)
        account = result.unwrap()
        self.assertEqual(account.status, "active")
        self.assertEqual(len(mock_gateway.get_calls("create-domain")), 1)
        job = VirtualminProvisioningJob.objects.get(account=account, operation="create_domain")
        self.assertEqual(job.status, "completed")

    def test_create_blocked_when_connection_fails(self):
        """A failed connection must block BEFORE any mutating call."""
        mock_gateway = MockVirtualminGateway(fail_operations={"info": "Connection refused"})

        result = self._create(mock_gateway)

        self.assertTrue(result.is_err())
        self.assertEqual(len(mock_gateway.get_calls("create-domain")), 0)

    def test_create_blocked_on_remote_domain_conflict(self):
        """A domain already on the server is a conflict, not a silent overwrite."""
        mock_gateway = MockVirtualminGateway()
        mock_gateway.seed_domain("new.example.com")

        result = self._create(mock_gateway)

        self.assertTrue(result.is_err())
        self.assertIn("already exists on server", result.unwrap_err())
        self.assertEqual(len(mock_gateway.get_calls("create-domain")), 0)

    def test_create_blocked_on_missing_template(self):
        mock_gateway = MockVirtualminGateway()

        result = self._create(mock_gateway, template="NoSuchTemplate")

        self.assertTrue(result.is_err())
        self.assertIn("not found on server", result.unwrap_err())
        self.assertEqual(len(mock_gateway.get_calls("create-domain")), 0)


class TestDriftRecords(VirtualminTaskTestBase):
    """#325 defect 5: drift writes used nonexistent model fields and crashed
    with TypeError exactly when drift existed."""

    def setUp(self) -> None:
        super().setUp()
        self.account.status = "suspended"  # PRAHO says suspended...
        self.account.save(update_fields=["status"])

    def _sync(self, mock_gateway):
        with patch(
            "apps.provisioning.virtualmin_service.VirtualminGateway",
            return_value=mock_gateway,
        ):
            service = VirtualminProvisioningService(self.server)
            return service.sync_account_from_virtualmin(self.account)

    def test_status_mismatch_persists_valid_drift_record(self):
        mock_gateway = MockVirtualminGateway()
        mock_gateway.seed_domain(self.account.domain, enabled=True)  # ...Virtualmin says active

        result = self._sync(mock_gateway)

        self.assertTrue(result.is_ok(), result)
        record = VirtualminDriftRecord.objects.get(domain=self.account.domain)
        self.assertEqual(record.server, self.server)
        self.assertIn(
            record.drift_type,
            [choice[0] for choice in VirtualminDriftRecord.DRIFT_TYPE_CHOICES],
        )
        self.assertEqual(record.resolution_status, "pending")
        self.assertTrue(record.description)

    def test_enforce_praho_state_persists_valid_drift_record(self):
        mock_gateway = MockVirtualminGateway()
        mock_gateway.seed_domain(self.account.domain, enabled=True)

        with patch(
            "apps.provisioning.virtualmin_service.VirtualminGateway",
            return_value=mock_gateway,
        ):
            service = VirtualminProvisioningService(self.server)
            result = service.enforce_praho_state(self.account, force=True)

        self.assertTrue(result.is_ok(), result)
        record = VirtualminDriftRecord.objects.filter(domain=self.account.domain).latest("detected_at")
        self.assertIn(
            record.drift_type,
            [choice[0] for choice in VirtualminDriftRecord.DRIFT_TYPE_CHOICES],
        )
        # PRAHO won: Virtualmin was forced to match, drift auto-fixed
        self.assertEqual(record.resolution_status, "auto_fixed")
        self.assertFalse(mock_gateway.domain_state_of(self.account.domain).enabled)


class TestServerHealthModel(VirtualminTaskTestBase):
    """#325 defect 6: hourly checks vs 600s freshness starved placement
    ~50 min/hour, and a single failed check permanently evicted a server."""

    def setUp(self) -> None:
        super().setUp()
        self.mgmt = VirtualminServerManagementService()

    def _check(self, mock_gateway):
        with patch(
            "apps.provisioning.virtualmin_service.VirtualminGateway",
            return_value=mock_gateway,
        ):
            return self.mgmt.health_check_server(self.server)

    def test_server_checked_20_minutes_ago_is_placeable(self):
        """The freshness window must cover the sweep cadence."""
        self.server.last_health_check = timezone.now() - timedelta(minutes=20)
        self.server.save(update_fields=["last_health_check"])
        self.assertTrue(self.server.is_healthy)

    def test_server_checked_26_minutes_ago_is_stale(self):
        self.server.last_health_check = timezone.now() - timedelta(minutes=26)
        self.server.save(update_fields=["last_health_check"])
        self.assertFalse(self.server.is_healthy)

    def test_single_failure_does_not_evict_but_blocks_placement(self):
        """One transient failure: server stays active (still swept, can
        recover) but is immediately non-placeable via the live error."""
        self.server.last_health_check = timezone.now()
        self.server.save(update_fields=["last_health_check"])

        result = self._check(MockVirtualminGateway(fail_operations={"info": "Connection refused"}))

        self.assertTrue(result.is_err())
        self.server.refresh_from_db()
        self.assertEqual(self.server.status, "active")  # not evicted
        self.assertEqual(self.server.consecutive_health_failures, 1)
        self.assertFalse(self.server.is_healthy)  # but not placeable
        # last_health_check means "last VERIFIED" — failure must not stamp it
        self.assertLess(
            self.server.last_health_check, timezone.now() - timedelta(seconds=0)
        )

    def test_sustained_failures_auto_fail_at_threshold(self):
        failing = MockVirtualminGateway(fail_operations={"info": "Connection refused"})
        for _ in range(5):
            self._check(failing)
        self.server.refresh_from_db()
        self.assertEqual(self.server.status, "active")  # 5th failure: not yet

        self._check(failing)
        self.server.refresh_from_db()
        self.assertEqual(self.server.status, "failed")  # 6th: auto-failed
        self.assertTrue(self.server.failed_by_health_check)

    def test_auto_failed_server_recovers_on_success(self):
        self.server.status = "failed"
        self.server.failed_by_health_check = True
        self.server.consecutive_health_failures = 6
        self.server.save(update_fields=["status", "failed_by_health_check", "consecutive_health_failures"])

        result = self._check(MockVirtualminGateway())

        self.assertTrue(result.is_ok())
        self.server.refresh_from_db()
        self.assertEqual(self.server.status, "active")
        self.assertFalse(self.server.failed_by_health_check)
        self.assertEqual(self.server.consecutive_health_failures, 0)
        self.assertTrue(self.server.is_healthy)

    def test_operator_failed_server_is_never_swept_or_recovered(self):
        self.server.status = "failed"  # operator-set: flag stays False
        self.server.save(update_fields=["status"])

        with patch(
            "apps.provisioning.virtualmin_service.VirtualminServerManagementService.health_check_server"
        ) as mock_check:
            health_check_virtualmin_servers()

        mock_check.assert_not_called()
        self.server.refresh_from_db()
        self.assertEqual(self.server.status, "failed")

    def test_schedule_upgrade_replaces_deployed_hourly_row(self):
        """Deployed installations kept the old hourly Schedule row forever —
        setup must UPSERT, not skip-if-exists."""
        Schedule.objects.update_or_create(
            name="virtualmin-health-check",
            defaults={
                "func": "apps.provisioning.virtualmin_tasks.health_check_virtualmin_servers",
                "schedule_type": "H",
                "cluster": "praho-cluster",
            },
        )

        setup_virtualmin_scheduled_tasks()

        row = Schedule.objects.get(name="virtualmin-health-check")
        self.assertEqual(row.schedule_type, "I")
        self.assertEqual(row.minutes, 10)


class TestServiceReconciliation(VirtualminTaskTestBase):
    """#325 defects 4+7: Service lifecycle now converges Virtualmin state via
    an idempotent reconcile task queued on_commit from a dedicated handler."""

    def setUp(self) -> None:
        super().setUp()
        self.account.status = "active"
        self.account.save(update_fields=["status"])

    def _reconcile(self, mock_gateway):
        with patch(
            "apps.provisioning.virtualmin_service.VirtualminGateway",
            return_value=mock_gateway,
        ):
            return reconcile_virtualmin_service_state(str(self.service.id))

    @patch("apps.provisioning.virtualmin_tasks.reconcile_virtualmin_service_state_async", return_value="t-1")
    def test_suspension_enqueues_reconcile_on_commit(self, mock_reconcile):
        """The dunning/suspend path finally reaches Virtualmin — via on_commit,
        so a rolled-back suspension never dispatches."""
        with self.captureOnCommitCallbacks(execute=True):
            self.service.suspend(reason="payment_overdue")
            self.service.save(update_fields=["status", "suspended_at", "suspension_reason", "updated_at"])

        mock_reconcile.assert_called_once_with(str(self.service.id))

    @patch("apps.provisioning.virtualmin_tasks.reconcile_virtualmin_service_state_async", return_value="t-1")
    def test_rollback_produces_no_enqueue(self, mock_reconcile):

        with self.assertRaises(_BoomError), self.captureOnCommitCallbacks(execute=True), transaction.atomic():
            self.service.suspend(reason="payment_overdue")
            self.service.save(update_fields=["status", "suspended_at", "suspension_reason", "updated_at"])
            raise _BoomError

        mock_reconcile.assert_not_called()

    @patch("apps.provisioning.virtualmin_tasks.reconcile_virtualmin_service_state_async", return_value="t-1")
    def test_fires_with_audit_signals_disabled(self, mock_reconcile):
        """Business propagation must not be silenced by the audit kill flag
        (the old trigger lived inside the audit handler and was)."""
        with override_settings(DISABLE_AUDIT_SIGNALS=True), self.captureOnCommitCallbacks(execute=True):
            self.service.suspend(reason="payment_overdue")
            self.service.save(update_fields=["status", "suspended_at", "suspension_reason", "updated_at"])

        mock_reconcile.assert_called_once()

    def test_reconcile_suspends_account_for_suspended_service(self):
        force_status(self.service, "suspended")
        mock_gateway = MockVirtualminGateway()
        mock_gateway.seed_domain(self.account.domain)

        result = self._reconcile(mock_gateway)

        self.assertEqual(result["action"], "suspended")
        self.account.refresh_from_db()
        self.assertEqual(self.account.status, "suspended")

    def test_reconcile_unsuspends_account_for_active_service(self):
        """Dunning recovery used to be silently absorbed by the provisioning
        trigger's existing-account early-exit."""
        self.account.status = "suspended"
        self.account.save(update_fields=["status"])
        mock_gateway = MockVirtualminGateway()
        mock_gateway.seed_domain(self.account.domain, enabled=False)

        result = self._reconcile(mock_gateway)

        self.assertEqual(result["action"], "unsuspended")
        self.account.refresh_from_db()
        self.assertEqual(self.account.status, "active")

    def test_reconcile_terminated_service_suspends_never_deletes(self):
        force_status(self.service, "terminated")
        mock_gateway = MockVirtualminGateway()
        mock_gateway.seed_domain(self.account.domain)

        result = self._reconcile(mock_gateway)

        self.assertEqual(result["action"], "suspended")
        self.assertEqual(len(mock_gateway.get_calls("delete-domain")), 0)
        self.account.refresh_from_db()
        self.assertEqual(self.account.status, "suspended")

    def test_reconcile_noop_when_states_match(self):
        result = self._reconcile(MockVirtualminGateway())
        self.assertEqual(result["action"], "noop")

    @patch("apps.provisioning.signals._trigger_automatic_virtualmin_provisioning")
    def test_kill_switch_gates_auto_provisioning(self, mock_trigger):
        self.account.delete()

        with override_settings(VIRTUALMIN_AUTO_PROVISIONING_ENABLED=False):
            result = self._reconcile(MockVirtualminGateway())
        self.assertEqual(result["action"], "kill_switch_disabled")
        mock_trigger.assert_not_called()

        result = self._reconcile(MockVirtualminGateway())
        self.assertEqual(result["action"], "provisioning_triggered")
        mock_trigger.assert_called_once()


class TestReviewHardening325(VirtualminTaskTestBase):
    """Regression tests for the adversarial-review findings on this branch."""

    def test_create_retry_never_adopts_foreign_domain(self):
        """Same name, different owner: terminal conflict, no adoption."""
        mock_gateway = MockVirtualminGateway()
        mock_gateway.seed_domain(self.account.domain, username="someoneelse")
        job = self._failed_job(status="pending", retry_count=1, claimed_at=timezone.now())

        with patch("apps.provisioning.virtualmin_service.VirtualminGateway", return_value=mock_gateway):
            result = retry_virtualmin_job(str(job.id))

        self.assertFalse(result["success"])
        self.assertIn("owned by another account", result["error"])
        job.refresh_from_db()
        self.account.refresh_from_db()
        self.assertIsNone(job.next_retry_at)  # terminal
        self.assertNotEqual(self.account.status, "active")

    def test_create_retry_probe_error_is_not_absence(self):
        """An unreachable probe must not fall through to create-domain."""
        mock_gateway = MockVirtualminGateway(fail_operations={"list-domains": "connection timeout"})
        job = self._failed_job(status="pending", retry_count=1, claimed_at=timezone.now())

        with patch("apps.provisioning.virtualmin_service.VirtualminGateway", return_value=mock_gateway):
            result = retry_virtualmin_job(str(job.id))

        self.assertFalse(result["success"])
        self.assertEqual(len(mock_gateway.get_calls("create-domain")), 0)

    def test_duplicate_retry_delivery_is_discarded(self):
        """Only the claim owner executes; a re-delivered task self-discards."""
        job = self._failed_job(status="running", retry_count=1, claimed_at=timezone.now())

        result = retry_virtualmin_job(str(job.id))

        self.assertEqual(result.get("action"), "stale_claim_discarded")

    def test_running_job_with_expired_lease_is_recovered(self):
        """A worker death after mark_started must not strand 'running' forever."""
        job = self._failed_job(status="running", retry_count=1, claimed_at=timezone.now() - timedelta(minutes=31))

        with patch("apps.provisioning.virtualmin_tasks.async_task", return_value="t-1"):
            process_failed_virtualmin_jobs()

        job.refresh_from_db()
        self.assertEqual(job.status, "failed")

    def test_stranded_initial_create_recovers_and_retry_converges_end_to_end(self):
        """Full first-attempt recovery: a worker death after mark_started()
        (running, claimed_at=NULL) leaves the account at 'provisioning' while
        the remote domain already exists. The sweep must recover the job, and
        the job-aware retry must converge the existing remote domain to active
        — proving the fix closes the stranding, not just flips the job row."""
        mock_gateway = MockVirtualminGateway()
        mock_gateway.seed_domain(self.account.domain, username=self.account.virtualmin_username)
        self.account.status = "provisioning"
        self.account.save(update_fields=["status"])
        domains_before = self.server.current_domains
        job = self._failed_job(
            status="running",
            claimed_at=None,
            started_at=timezone.now() - timedelta(minutes=31),
        )

        # 1. Sweep recovers the stranded first-attempt job by started_at.
        VirtualminProvisioningJob.recover_expired_claims(
            timezone.now() - timedelta(minutes=30), timezone.now() - timedelta(minutes=1)
        )
        # 2. The sweep then claims it for retry (failed -> pending).
        self.assertTrue(VirtualminProvisioningJob.claim_for_retry(job.pk, timezone.now()))

        # 3. The job-aware retry converges the existing remote domain.
        with patch(
            "apps.provisioning.virtualmin_service.VirtualminGateway",
            return_value=mock_gateway,
        ):
            result = retry_virtualmin_job(str(job.id))

        self.assertTrue(result["success"], result)
        job.refresh_from_db()
        self.account.refresh_from_db()
        self.server.refresh_from_db()
        self.assertEqual(job.status, "completed")
        self.assertEqual(self.account.status, "active")
        self.assertEqual(self.server.current_domains, domains_before + 1)
        self.assertEqual(len(mock_gateway.get_calls("create-domain")), 0)

    def test_running_initial_execution_with_no_claim_is_recovered(self):
        """A worker death during the INITIAL execution strands the job as
        status='running' with claimed_at=NULL (mark_started never claims). The
        sweep must still recover it — by started_at — or it strands forever,
        the exact class this PR set out to eliminate."""
        job = self._failed_job(
            status="running",
            claimed_at=None,
            started_at=timezone.now() - timedelta(minutes=31),
        )

        with patch("apps.provisioning.virtualmin_tasks.async_task", return_value="t-1"):
            process_failed_virtualmin_jobs()

        job.refresh_from_db()
        self.assertEqual(job.status, "failed")

    def test_exhausted_job_opts_out_of_future_sweeps(self):
        job = self._failed_job(retry_count=3, max_retries=3)

        with patch("apps.provisioning.virtualmin_tasks.async_task", return_value="t-1"):
            process_failed_virtualmin_jobs()

        job.refresh_from_db()
        self.assertIsNone(job.next_retry_at)

    def test_sweep_persists_dispatched_task_id(self):
        job = self._failed_job()

        with patch("apps.provisioning.virtualmin_tasks.async_task", return_value="task-xyz"):
            process_failed_virtualmin_jobs()

        job.refresh_from_db()
        self.assertEqual(job.task_id, "task-xyz")

    def test_lifecycle_retry_arms_next_retry_on_retriable_failure(self):
        """A RETRIABLE gateway failure DURING a retry must keep next_retry_at
        armed. mark_failed() defaulted to UNKNOWN, which disarms it — stranding
        a job whose retry_count is still below max after a transient failure."""
        self.account.status = "active"
        self.account.save(update_fields=["status"])
        force_status(self.service, "suspended")  # suspend is still the desired state
        job = self._failed_job(
            operation="suspend_domain", status="pending", retry_count=1, claimed_at=timezone.now()
        )
        gateway = MagicMock()
        gateway.call.return_value = Err("gateway temporarily unavailable", retriability=Retriability.RETRIABLE)

        with patch("apps.provisioning.virtualmin_service.VirtualminGateway", return_value=gateway):
            result = retry_virtualmin_job(str(job.id))

        self.assertFalse(result["success"])
        job.refresh_from_db()
        self.assertEqual(job.status, "failed")
        self.assertIsNotNone(job.next_retry_at)

    def test_stale_unsuspend_job_is_superseded_by_current_state(self):
        """An old unsuspend retry must not re-enable hosting for a since-suspended service."""
        self.account.status = "suspended"
        self.account.save(update_fields=["status"])
        force_status(self.service, "suspended")  # current desired state: suspended
        job = self._failed_job(
            operation="unsuspend_domain", status="pending", retry_count=1, claimed_at=timezone.now()
        )

        with (
            patch("apps.provisioning.virtualmin_service.VirtualminGateway", return_value=MockVirtualminGateway()),
            patch(
                "apps.provisioning.virtualmin_tasks.reconcile_virtualmin_service_state_async", return_value="t-1"
            ) as mock_reconcile,
        ):
            result = retry_virtualmin_job(str(job.id))

        self.assertFalse(result["success"])
        self.assertIn("superseded by current service state", result["error"])
        job.refresh_from_db()
        self.assertIsNone(job.next_retry_at)
        mock_reconcile.assert_called_once()
        self.account.refresh_from_db()
        self.assertEqual(self.account.status, "suspended")  # hosting stayed off

    def test_idempotency_cache_does_not_absorb_flip_flop(self):
        """suspend -> unsuspend -> suspend within the TTL must execute for real."""
        self.account.status = "active"
        self.account.save(update_fields=["status"])
        mock_gateway = MockVirtualminGateway()
        mock_gateway.seed_domain(self.account.domain, username=self.account.virtualmin_username)

        with patch("apps.provisioning.virtualmin_service.VirtualminGateway", return_value=mock_gateway):
            service = VirtualminProvisioningService(self.server)
            self.assertTrue(service.suspend_account(self.account, "payment_overdue").is_ok())
            self.assertTrue(service.unsuspend_account(self.account).is_ok())
            disable_calls_before = len(mock_gateway.get_calls("disable-domain"))
            self.assertTrue(service.suspend_account(self.account, "payment_overdue").is_ok())

        self.account.refresh_from_db()
        self.assertEqual(self.account.status, "suspended")
        self.assertEqual(len(mock_gateway.get_calls("disable-domain")), disable_calls_before + 1)

    def test_unhealthy_payload_counts_as_failed_check(self):
        """HTTP 200 + healthy:False must not reset the failure streak."""
        with patch(
            "apps.provisioning.virtualmin_service.VirtualminProvisioningService.test_server_connection",
            return_value=Ok({"healthy": False, "server": "x"}),
        ):
            result = VirtualminServerManagementService().health_check_server(self.server)

        self.assertTrue(result.is_err())
        self.server.refresh_from_db()
        self.assertEqual(self.server.consecutive_health_failures, 1)

    def test_gateway_allows_probe_of_auto_failed_server(self):
        """Auto-recovery is reachable: the gateway accepts auto-failed servers."""
        self.server.status = "failed"
        self.server.failed_by_health_check = True
        self.server.save(update_fields=["status", "failed_by_health_check"])
        gateway = VirtualminGateway(VirtualminConfig(server=self.server))
        # Health probe allowed; mutating programs stay blocked until recovery
        self.assertTrue(gateway._validate_server_health("info").is_ok())
        self.assertTrue(gateway._validate_server_health("create-domain").is_err())

        self.server.failed_by_health_check = False
        self.server.save(update_fields=["failed_by_health_check"])
        gateway = VirtualminGateway(VirtualminConfig(server=self.server))
        self.assertTrue(gateway._validate_server_health("info").is_err())

    def test_preflight_blocks_username_conflict(self):
        """The repaired conflict check sees owner usernames."""
        mock_gateway = MockVirtualminGateway()
        mock_gateway.seed_domain("other.example.com", username="newuser")
        service2 = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name="second.example.com",
            domain="second.example.com",
            username="newuser2",
            billing_cycle="monthly",
            price=Decimal("10.00"),
            status="active",
        )
        creation = VirtualminAccountCreationData(
            service=service2, domain="second.example.com", username="newuser", server=self.server
        )

        with patch("apps.provisioning.virtualmin_service.VirtualminGateway", return_value=mock_gateway):
            result = VirtualminProvisioningService(self.server).create_virtualmin_account(creation)

        self.assertTrue(result.is_err())
        self.assertIn("already exists on server", result.unwrap_err())
        self.assertEqual(len(mock_gateway.get_calls("create-domain")), 0)


class TestPrReviewFixes331(VirtualminTaskTestBase):
    """Regression tests for the PR #331 review comments."""

    def test_preflight_blocks_unhealthy_connection_payload(self):
        """An Ok({'healthy': False}) info response is a failed precondition —
        provisioning must not proceed to conflict checks or create-domain."""
        mock_gateway = MockVirtualminGateway()
        service2 = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name="unhealthy.example.com",
            domain="unhealthy.example.com",
            username="unhealthyu",
            billing_cycle="monthly",
            price=Decimal("10.00"),
            status="active",
        )
        creation = VirtualminAccountCreationData(
            service=service2, domain="unhealthy.example.com", server=self.server
        )

        with (
            patch("apps.provisioning.virtualmin_service.VirtualminGateway", return_value=mock_gateway),
            patch.object(mock_gateway, "test_connection", return_value=Ok({"healthy": False, "server": "x"})),
        ):
            result = VirtualminProvisioningService(self.server).create_virtualmin_account(creation)

        self.assertTrue(result.is_err())
        self.assertEqual(len(mock_gateway.get_calls("create-domain")), 0)

    @patch("apps.provisioning.virtualmin_tasks.reconcile_virtualmin_service_state_async", return_value="t-1")
    def test_bare_save_status_change_still_reconciles(self, mock_reconcile):
        """A save() without update_fields (common Django) must not silently
        skip reconciliation after a status transition."""
        self.account.status = "active"
        self.account.save(update_fields=["status"])

        with self.captureOnCommitCallbacks(execute=True):
            self.service.suspend(reason="payment_overdue")
            self.service.save()  # no update_fields

        mock_reconcile.assert_called_once_with(str(self.service.id))

    def test_claim_and_recovery_maintain_operational_timestamps(self):
        """QuerySet.update() paths must bump updated_at and clear claimed_at on recovery."""
        job = self._failed_job()
        before = job.updated_at

        VirtualminProvisioningJob.claim_for_retry(job.pk, timezone.now())
        job.refresh_from_db()
        self.assertGreater(job.updated_at, before)
        self.assertIsNotNone(job.claimed_at)

        VirtualminProvisioningJob.recover_expired_claims(
            timezone.now() + timedelta(minutes=1), timezone.now() + timedelta(minutes=5)
        )
        job.refresh_from_db()
        self.assertEqual(job.status, "failed")
        self.assertIsNone(job.claimed_at)  # recovered jobs no longer look claimed


class TestAtoZReviewFixes(VirtualminTaskTestBase):
    """Regression tests for the full-PR review findings."""

    @patch("apps.provisioning.virtualmin_tasks.reconcile_virtualmin_service_state_async", return_value="t-1")
    def test_lifecycle_retry_requeues_reconcile_when_service_moved_mid_call(self, mock_reconcile):
        """TOCTOU: Service transitions while the gateway call is in flight —
        the retry records the real remote result and re-queues convergence."""
        self.account.status = "active"
        self.account.save(update_fields=["status"])
        force_status(self.service, "suspended")
        mock_gateway = MockVirtualminGateway()
        mock_gateway.seed_domain(self.account.domain, username=self.account.virtualmin_username)
        job = self._failed_job(
            operation="suspend_domain", status="pending", retry_count=1, claimed_at=timezone.now()
        )
        nonce = job.claimed_at.isoformat()

        original_call = mock_gateway.call

        def call_and_flip(program, params=None, **kw):
            result = original_call(program, params, **kw)
            if program == "disable-domain":
                force_status(self.service, "active")  # moved mid-flight
            return result

        with (
            patch("apps.provisioning.virtualmin_service.VirtualminGateway", return_value=mock_gateway),
            patch.object(mock_gateway, "call", side_effect=call_and_flip),
        ):
            result = retry_virtualmin_job(str(job.id), nonce)

        self.assertTrue(result["success"], result)
        self.account.refresh_from_db()
        self.assertEqual(self.account.status, "suspended")  # real remote result recorded
        mock_reconcile.assert_called_once_with(str(self.service.id))  # convergence queued

    @patch("apps.provisioning.tasks.async_task", return_value="task-123")
    def test_service_provisioning_wrapper_does_not_leak_retry_kwarg(self, mock_async):
        """The second wrapper (apps.provisioning.tasks) carried the same
        invalid retry= leak, previously absorbed only by **kwargs."""
        queue_service_provisioning(self.service)

        mock_async.assert_called_once()
        _, kwargs = mock_async.call_args
        self.assertNotIn("retry", kwargs)

    @patch("apps.provisioning.virtualmin_tasks.reconcile_virtualmin_service_state_async", return_value="t-1")
    def test_divergence_backstop_requeues_lost_reconciles(self, mock_reconcile):
        """A lost on_commit enqueue self-heals via the periodic backstop."""
        self.account.status = "active"
        self.account.save(update_fields=["status"])
        force_status(self.service, "suspended")  # divergent: suspended service, live hosting

        result = reconcile_divergent_services_task()

        self.assertEqual(result["queued"], 1)
        mock_reconcile.assert_called_once_with(str(self.service.id))

    @patch("apps.provisioning.virtualmin_tasks.reconcile_virtualmin_service_state_async", return_value="t-1")
    def test_raw_fixture_load_does_not_trigger_reconciliation(self, mock_reconcile):
        """loaddata (post_save raw=True) must never enqueue real provisioning."""
        with self.captureOnCommitCallbacks(execute=True):
            handle_service_virtualmin_reconciliation(
                sender=Service, instance=self.service, created=False, raw=True, update_fields=None
            )

        mock_reconcile.assert_not_called()

    def test_stale_nonce_delivery_discarded_after_reclaim(self):
        """A delivery carrying an old claim nonce cannot steal a new claim."""
        job = self._failed_job(status="pending", retry_count=1, claimed_at=timezone.now())
        old_nonce = (timezone.now() - timedelta(minutes=45)).isoformat()

        result = retry_virtualmin_job(str(job.id), old_nonce)

        self.assertEqual(result.get("action"), "stale_claim_discarded")
        job.refresh_from_db()
        self.assertEqual(job.status, "pending")  # the rightful claim untouched
