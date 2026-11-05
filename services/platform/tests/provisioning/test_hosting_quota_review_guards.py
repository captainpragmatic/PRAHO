"""Public quota admission and bounded outbox delivery retain all unresolved owners."""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import MagicMock, patch
from uuid import uuid4

from django.core.cache import cache
from django.db import connection
from django.utils import timezone

from apps.common.types import Ok
from apps.infrastructure.node_maintenance_gate import begin_account_job
from apps.provisioning.hosting_limit_execution import admit_application, apply_hosting_limits
from apps.provisioning.hosting_limit_execution_models import HostingLimitExecution
from apps.provisioning.hosting_limit_models import HostingLimitApplication, ServiceHostingLimits
from apps.provisioning.hosting_limit_tasks import current_application, dispatch_hosting_limits
from apps.provisioning.models import Service
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob
from apps.provisioning.virtualmin_service import VirtualminProvisioningService
from tests.common.postgres_locking import backend_pid
from tests.helpers.task_queue import quiet_task_queue
from tests.provisioning.test_hosting_limit_execution import HostingLimitWorkerFixture
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase


class QuotaAccountAdmissionReviewTests(HostingLimitWorkerFixture, VirtualminTaskTestBase):
    def setUp(self) -> None:
        self.queue = quiet_task_queue(self)
        super().setUp()
        self.setup_native_fixture()
        self.account.status = "active"
        self.account.save(update_fields=["status", "updated_at"])
        cache.clear()

    def _assert_standalone_public_refusal(self) -> None:
        execution = admit_application(self.application.pk)
        self.assertIsNotNone(execution)
        assert execution is not None
        self.assertEqual(execution.job.parameters["quota_parent"], {})
        gateway = MagicMock()
        gateway.call.return_value = Ok(MagicMock(success=True, data={}))

        with patch.object(VirtualminProvisioningService, "_get_gateway", return_value=gateway):
            result = VirtualminProvisioningService().suspend_account(self.account, "Unrelated lifecycle request")

        self.assertTrue(result.is_err(), "A standalone quota claim must retain the native account lane")
        gateway.call.assert_not_called()
        self.account.refresh_from_db()
        execution.refresh_from_db()
        self.assertEqual((self.account.status, execution.phase), ("active", "prepared"))
        self.assertFalse(
            VirtualminProvisioningJob.objects.filter(account=self.account, operation="suspend_domain").exists()
        )

    def test_public_suspend_refuses_real_standalone_quota_claim_with_empty_parent(self) -> None:
        self._assert_standalone_public_refusal()

    def test_postgres_missing_json_parent_retains_public_lifecycle_barrier(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL JSON-path SQL NULL semantics")
        self.assertGreater(backend_pid(), 0)
        self._assert_standalone_public_refusal()

    def test_missing_null_partial_and_foreign_parent_keys_retain_attention_barrier(self) -> None:
        execution = admit_application(self.application.pk)
        self.assertIsNotNone(execution)
        assert execution is not None
        execution.job.mark_attention("Native outcome needs permanent fencing")
        for shape in ("empty", "null", "token_only", "job_only", "json_null", "foreign"):
            candidate = VirtualminProvisioningJob(
                account=self.account, server=self.server, operation="suspend_domain", execution_token=uuid4()
            )
            parent = {
                "empty": {},
                "null": None,
                "token_only": {"token": ""},
                "job_only": {"job_id": str(candidate.pk)},
                "json_null": {"job_id": None, "token": None},
                "foreign": {"job_id": str(uuid4()), "token": str(uuid4())},
            }[shape]
            with self.subTest(parent=shape):
                execution.job.parameters = {**execution.job.parameters, "quota_parent": parent}
                execution.job.save(update_fields=["parameters", "updated_at"])
                self.assertIsNotNone(begin_account_job(self.account, candidate))
                self.assertTrue(candidate._state.adding, "A refused admission must not publish the lifecycle job")

    def test_exact_admitted_parent_child_still_rechecks_its_owned_lane(self) -> None:
        parent = VirtualminProvisioningJob(
            account=self.account,
            server=self.server,
            operation="create_domain",
            claimed_at=timezone.now(),
            execution_token=uuid4(),
            execution_deadline=timezone.now() + timedelta(minutes=15),
        )
        self.assertIsNone(begin_account_job(self.account, parent))
        scope = {
            "job_id": str(parent.pk),
            "token": str(parent.execution_token),
            "account_server_id": str(self.server.pk),
            "native_server_id": str(self.server.pk),
        }
        child = admit_application(self.application.pk, parent=scope)
        self.assertIsNotNone(child)
        self.assertIsNone(begin_account_job(self.account, parent, preserve_claim=True))
        assert child is not None
        child.job.parameters = {**child.job.parameters, "quota_parent": {**scope, "token": str(uuid4())}}
        child.job.save(update_fields=["parameters", "updated_at"])
        self.assertIsNotNone(begin_account_job(self.account, parent, preserve_claim=True))


class QuotaOutboxSweepReviewTests(HostingLimitWorkerFixture, VirtualminTaskTestBase):
    def setUp(self) -> None:
        self.queue = quiet_task_queue(self)
        super().setUp()
        self.setup_native_fixture()
        # These are independently managed accounts; the initial fixture service
        # remains in error and does not enter the sweep's active-account scope.
        self.plan.disk_space_gb = 5
        self.plan.bandwidth_gb = 20
        self.plan.save(update_fields=["disk_space_gb", "bandwidth_gb", "updated_at"])

    def cohort(self, count: int) -> list[Service]:
        services = Service.objects.bulk_create(
            [
                Service(
                    customer=self.customer,
                    service_plan=self.plan,
                    currency=self.currency,
                    service_name=f"sweep-{index}.example.test",
                    domain=f"sweep-{index}.example.test",
                    username=f"sweep{index}",
                    price=10,
                    status="active",
                )
                for index in range(count)
            ]
        )
        VirtualminAccount.objects.bulk_create(
            [
                VirtualminAccount(
                    service=service,
                    server=self.server,
                    domain=service.domain,
                    virtualmin_username=service.username,
                    encrypted_password=b"synthetic-unused",
                    status="active",
                    quota_managed=True,
                )
                for service in services
            ]
        )
        started = timezone.now() - timedelta(days=2)
        for index, service in enumerate(services):
            ServiceHostingLimits.objects.filter(service=service).update(updated_at=started + timedelta(seconds=index))
        return services

    def delivered(self) -> list[str]:
        return [str(item[1]) for item in self.queue.queued() if item[0].endswith(".apply_hosting_limits")]

    def test_managed_historical_applications_never_duplicate_a_service_delivery(self) -> None:
        services = self.cohort(2)
        for revision in (2, 3):
            HostingLimitApplication.objects.create(
                service=services[0],
                revision=revision,
                submission_id=uuid4(),
                expected_plan_id=self.plan.pk,
                target_plan_id=self.plan.pk,
                disk_allowance_mib=5120,
                bandwidth_allowance_mib=20480,
                reason="Previously accepted resource revision",
                authority={"kind": "native_policy_reconciliation", "customer_id": self.customer.pk},
            )
        ServiceHostingLimits.objects.filter(service=services[0]).update(revision=3)

        result = dispatch_hosting_limits()

        self.assertEqual(result["queued"], 2)
        self.assertEqual(len(self.delivered()), 2)
        self.assertEqual(set(self.delivered()), {str(current_application(service.pk).pk) for service in services})

    def test_one_hundred_refused_accounts_cannot_starve_later_broker_redelivery(self) -> None:
        services = self.cohort(101)
        accounts = {account.service_id: account for account in VirtualminAccount.objects.filter(service__in=services)}
        VirtualminProvisioningJob.objects.bulk_create(
            [
                VirtualminProvisioningJob(
                    account=accounts[service.pk], server=self.server, operation="backup_domain", status="running"
                )
                for service in services[:100]
            ]
        )
        blocked = current_application(services[0].pk)
        healthy = current_application(services[-1].pk)
        with patch("apps.provisioning.hosting_limit_transport.probe_account_quota") as probe:
            self.assertEqual(apply_hosting_limits(blocked.pk), "pending")
            probe.assert_not_called()
        for _ in range(2):
            before = len(self.delivered())
            outcome = dispatch_hosting_limits()
            batch = self.delivered()[before:]
            self.assertLessEqual(outcome["queued"], 100)
            self.assertEqual(len(batch), len(set(batch)), "One service receives at most one delivery per sweep")

        self.assertTrue(
            str(healthy.pk) in self.delivered(), "A later durable application must escape refused oldest rows"
        )
        self.assertIsNotNone(admit_application(healthy.pk))
        self.assertEqual(
            VirtualminProvisioningJob.objects.filter(operation="backup_domain", status="running").count(), 100
        )

    def test_attention_issued_and_parent_owned_quota_are_not_redispatched_by_the_sweep(self) -> None:
        services = self.cohort(4)
        for service, phase in zip(services[:2], ("attention", "issued"), strict=True):
            execution = admit_application(current_application(service.pk).pk)
            self.assertIsNotNone(execution)
            assert execution is not None
            HostingLimitExecution.objects.filter(pk=execution.pk).update(phase=phase)
            if phase == "attention":
                execution.job.mark_attention("Retain uncertain native authority")
        account = VirtualminAccount.objects.get(service=services[2])
        parent = VirtualminProvisioningJob(
            account=account, server=self.server, operation="create_domain", execution_token=uuid4()
        )
        self.assertIsNone(begin_account_job(account, parent))
        child = admit_application(
            current_application(services[2].pk).pk,
            parent={
                "job_id": str(parent.pk),
                "token": str(parent.execution_token),
                "account_server_id": str(self.server.pk),
                "native_server_id": str(self.server.pk),
            },
        )
        self.assertIsNotNone(child)

        outcome = dispatch_hosting_limits()

        self.assertEqual(outcome["queued"], 1)
        self.assertEqual(self.delivered(), [str(current_application(services[-1].pk).pk)])
        self.assertEqual(
            set(HostingLimitExecution.objects.values_list("phase", flat=True)), {"attention", "issued", "prepared"}
        )
        parent.refresh_from_db()
        self.assertEqual(parent.status, "running")

    def test_safe_prepared_standalone_execution_is_redelivered_without_a_new_epoch(self) -> None:
        service = self.cohort(1)[0]
        application = current_application(service.pk)
        execution = admit_application(application.pk)
        self.assertIsNotNone(execution)
        assert execution is not None

        outcome = dispatch_hosting_limits()

        self.assertEqual(outcome["queued"], 1)
        self.assertEqual(self.delivered(), [str(application.pk)])
        repeated = admit_application(application.pk)
        self.assertIsNotNone(repeated)
        assert repeated is not None
        self.assertEqual((repeated.pk, repeated.account_epoch), (execution.pk, execution.account_epoch))
