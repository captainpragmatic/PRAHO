"""Native account writers cannot bypass a running window through direct service calls."""

from datetime import timedelta

from django.utils import timezone

from apps.infrastructure.node_maintenance_models import NodeMaintenancePolicy
from apps.infrastructure.node_maintenance_service import change_window, create_window
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob
from apps.users.models import User
from tests.infrastructure.maintenance_policy_fixtures import maintenance_policy_times
from tests.provisioning.test_cov_provisioning_services_creation import VirtualminServiceCoverageCase


class NodeMaintenanceAccountMutationTests(VirtualminServiceCoverageCase):
    def running_window(self) -> None:
        actor = User.objects.create_superuser(email="mutation-operator@example.test", password=None)
        starts_time, ends_time = maintenance_policy_times()
        NodeMaintenancePolicy.objects.create(
            node=self.server,
            timezone="UTC",
            weekdays=list(range(7)),
            starts_time=starts_time,
            ends_time=ends_time,
            max_defer_minutes=30,
        )
        starts_at = timezone.now() - timedelta(seconds=10)
        window = create_window(
            self.server.pk,
            actor=actor,
            kind="panel_update",
            execution_mode="manual",
            starts_at=starts_at,
            ends_at=starts_at + timedelta(minutes=30),
            expects_downtime=True,
            expected_downtime_minutes=5,
            customer_note="Hosting software updates.",
        )
        change_window(window.pk, actor=actor, revision=1, action="start", reason="Approved native work")

    def test_new_account_creation_is_refused_before_a_row_or_native_request(self) -> None:
        self.running_window()
        result = self.provisioning.create_virtualmin_account(self._creation())
        self.assertTrue(result.is_err())
        self.assertIn("Maintenance", result.unwrap_err())
        self.assertFalse(VirtualminAccount.objects.exists())
        self.assertFalse(VirtualminProvisioningJob.objects.exists())
        self.assertEqual(self.requests, [])

    def test_direct_suspension_is_refused_before_native_io(self) -> None:
        account = self._account("active")
        self.running_window()
        result = self.provisioning.suspend_account(account)
        self.assertTrue(result.is_err())
        self.assertIn("Maintenance", result.unwrap_err())
        self.assertEqual(self.requests, [])
        self.assertFalse(VirtualminProvisioningJob.objects.exists())

    def test_direct_unsuspension_is_refused_before_native_io(self) -> None:
        account = self._account("suspended")
        self.running_window()
        result = self.provisioning.unsuspend_account(account)
        self.assertTrue(result.is_err())
        self.assertIn("Maintenance", result.unwrap_err())
        self.assertEqual(self.requests, [])
        self.assertFalse(VirtualminProvisioningJob.objects.exists())

    def test_direct_deletion_is_refused_before_native_io(self) -> None:
        account = self._account("error")
        self.running_window()
        result = self.provisioning.delete_account(account)
        self.assertTrue(result.is_err())
        self.assertIn("Maintenance", result.unwrap_err())
        self.assertEqual(self.requests, [])
        self.assertFalse(VirtualminProvisioningJob.objects.exists())

    def test_direct_reprovisioning_is_refused_before_password_or_native_mutation(self) -> None:
        account = self._account("error")
        password = account.encrypted_password
        self.running_window()
        result = self.provisioning.reprovision_virtualmin_account(account)
        self.assertTrue(result.is_err())
        self.assertIn("Maintenance", result.unwrap_err())
        account.refresh_from_db()
        self.assertEqual(account.encrypted_password, password)
        self.assertEqual(self.requests, [])
        self.assertFalse(VirtualminProvisioningJob.objects.exists())
