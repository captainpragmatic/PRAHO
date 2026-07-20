"""#295 follow-through: a failed backup job must keep its failure reason permanently.

mark_failed() arms next_retry_at only for explicitly retriable failures, and the periodic
sweeper (process_failed_virtualmin_jobs) picks up any failed job whose next_retry_at has
passed — but its dispatcher has no backup/restore branch. Even a genuinely retriable backup
must therefore opt out, or it is flipped back to "pending", its status_message wiped, and
nothing ever dispatched: a forever-stuck job that lost the failure reason #295 preserves.
"""

from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase

from apps.billing.models import Currency
from apps.common.types import Err, Retriability
from apps.customers.models import Customer
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from apps.provisioning.virtualmin_service import VirtualminBackupManagementService


class BackupJobFailureStateTests(TestCase):
    """Failure reason persists and the job opts out of the retry sweep."""

    def setUp(self) -> None:
        self.customer = Customer.objects.create(
            name="Backup TZ SRL", customer_type="company", status="active",
            primary_email="backup-tz@test.ro", company_name="Backup TZ SRL",
        )
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.plan = ServicePlan.objects.create(
            name="Backup Plan", plan_type="shared_hosting", price_monthly=Decimal("29.99"),
        )
        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name="backup-svc.example.com",
            domain="backup-svc.example.com",
            username="backupuser",
            billing_cycle="monthly",
            price=Decimal("29.99"),
            status="active",
        )
        self.vm_server = VirtualminServer.objects.create(
            name="Backup VM", hostname="backup-vm.example.com", api_username="api_user",
            api_port=10000, status="active", max_domains=1000,
        )
        self.vm_server.set_api_password("test_password")
        self.vm_server.save()
        self.account = VirtualminAccount.objects.create(
            domain="backup-svc.example.com",
            service=self.service,
            server=self.vm_server,
            virtualmin_username="backupuser",
            template_name="Default",
            status="active",
            praho_customer_id=self.customer.id,
            praho_service_id=self.service.id,
        )

    @patch("apps.provisioning.virtualmin_backup_service.VirtualminBackupService")
    def test_failed_backup_keeps_reason_and_opts_out_of_retry_sweep(self, mock_service_cls) -> None:
        mock_service_cls.return_value.backup_domain.return_value = Err(
            "disk full — backup aborted", retriability=Retriability.RETRIABLE
        )

        result = VirtualminBackupManagementService(self.vm_server).create_backup_job(self.account)

        self.assertTrue(result.is_err())
        job = VirtualminProvisioningJob.objects.get(operation="backup_domain", account=self.account)
        self.assertEqual(job.status, "failed")
        # The whole point of #295: the reason lands in the REAL field.
        self.assertIn("disk full", job.status_message)
        # And the sweeper must never pick it up: it would flip the job to "pending",
        # wipe status_message, and dispatch nothing (no backup branch exists).
        self.assertIsNone(job.next_retry_at)
