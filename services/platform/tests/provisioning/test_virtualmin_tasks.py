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
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_models import (
    VirtualminAccount,
    VirtualminProvisioningJob,
    VirtualminServer,
)
from apps.provisioning.virtualmin_service import VirtualminAccountCreationData, VirtualminProvisioningService
from apps.provisioning.virtualmin_tasks import (
    process_failed_virtualmin_jobs,
    provision_virtualmin_account_async,
    retry_virtualmin_job,
)
from tests.mocks.virtualmin_mock import MockVirtualminGateway


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
            claimed_at=timezone.now() - timedelta(minutes=20),
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
        mock_gateway.seed_domain(self.account.domain)  # remote create DID succeed
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
        mock_gateway = MockVirtualminGateway()
        mock_gateway.seed_domain(self.account.domain)
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
