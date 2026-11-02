"""Real public account admission and node claims serialize on the same server."""

from datetime import timedelta
from decimal import Decimal

from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.currency_models import Currency
from apps.customers.models import Customer
from apps.infrastructure.node_maintenance_models import NodeMaintenancePolicy, NodeMaintenanceWindow
from apps.infrastructure.node_maintenance_service import change_window, create_window
from apps.provisioning.service_models import Service, ServicePlan
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from apps.provisioning.virtualmin_service import VirtualminBackupManagementService
from apps.users.models import User
from tests.infrastructure.maintenance_policy_fixtures import maintenance_policy_times


class MaintenanceAdmissionFixture:
    def setUp(self) -> None:
        self.actor = User.objects.create_superuser(email="admission-operator@example.test", password=None)
        self.node = VirtualminServer.objects.create(name="Admission node", hostname="admission.example.test")
        starts_time, ends_time = maintenance_policy_times()
        NodeMaintenancePolicy.objects.create(
            node=self.node,
            timezone="UTC",
            weekdays=list(range(7)),
            starts_time=starts_time,
            ends_time=ends_time,
            max_defer_minutes=30,
        )
        self.customer = Customer.objects.create(name="Admission customer")
        Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.plan = ServicePlan.objects.create(name="Admission plan", price_monthly=Decimal("10"))
        self.account = self.account_on_node("admission-one.example.test")

    def account_on_node(self, domain: str) -> VirtualminAccount:
        service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency_id="RON",
            service_name="Hosting",
            domain=domain,
            username=domain.partition(".")[0],
            price=Decimal("10"),
            status="active",
        )
        return VirtualminAccount.objects.create(
            service=service,
            server=self.node,
            domain=domain,
            virtualmin_username=service.username,
            status="active",
        )

    def window(self, *, future: bool = False) -> NodeMaintenanceWindow:
        starts_at = timezone.now() + (timedelta(days=3) if future else -timedelta(seconds=10))
        return create_window(
            self.node.pk,
            actor=self.actor,
            kind="panel_update",
            execution_mode="manual",
            starts_at=starts_at,
            ends_at=starts_at + timedelta(minutes=30),
            expects_downtime=True,
            expected_downtime_minutes=5,
            customer_note="Hosting software maintenance.",
        )

    def start(self, window: NodeMaintenanceWindow) -> NodeMaintenanceWindow:
        return change_window(
            window.pk, actor=self.actor, revision=window.revision, action="start", reason="Approved work"
        )


@override_settings(Q_CLUSTER={"name": "maintenance-admission", "orm": "default", "retry": 100000})
class NodeMaintenanceAdmissionTests(MaintenanceAdmissionFixture, TestCase):
    def test_a_running_window_refuses_public_backup_admission_before_any_job_is_published(self) -> None:
        self.start(self.window())

        result = VirtualminBackupManagementService(self.node).create_backup_job(self.account)

        self.assertTrue(result.is_err(), "Public backup admission crossed a running node-wide maintenance claim")
        self.assertIn("Maintenance", result.unwrap_err())
        self.assertFalse(VirtualminProvisioningJob.objects.exists())

    def test_a_future_scheduled_window_does_not_reserve_the_node(self) -> None:
        self.window(future=True)

        result = VirtualminBackupManagementService(self.node).create_backup_job(self.account)

        self.assertTrue(result.is_ok(), result)
        self.assertEqual(result.unwrap().status, "pending")

    def test_an_already_admitted_backup_prevents_the_window_starting(self) -> None:
        window = self.window()
        backup = VirtualminBackupManagementService(self.node).create_backup_job(self.account)
        self.assertTrue(backup.is_ok(), backup)

        with self.assertRaisesMessage(ValidationError, "hosting-account operation"):
            self.start(window)

        self.assertEqual(NodeMaintenanceWindow.objects.get(pk=window.pk).status, "scheduled")
        self.assertFalse(window.executions.exists())

    def test_independent_account_jobs_still_coexist(self) -> None:
        other = self.account_on_node("admission-two.example.test")
        for account in (self.account, other):
            result = VirtualminBackupManagementService(self.node).create_backup_job(account)
            self.assertTrue(result.is_ok(), result)
        self.assertEqual(VirtualminProvisioningJob.objects.filter(status="pending").count(), 2)
