"""Real create/archive parents retain reviewed base while an accepted R expires."""

from datetime import timedelta
from unittest.mock import patch

from django.test import TransactionTestCase
from django.utils import timezone

from apps.common.types import Ok
from apps.provisioning.hosting_limit_execution_models import HostingLimitExecution
from apps.provisioning.hosting_limit_models import ServiceHostingLimits
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob
from apps.provisioning.virtualmin_service import VirtualminProvisioningService
from apps.settings.services import SettingsService
from apps.tickets.models import Ticket
from apps.users.models import User
from tests.helpers.task_queue import quiet_task_queue
from tests.mocks.virtualmin_mock import MockVirtualminGateway
from tests.provisioning import test_hosting_raises as raise_fixtures
from tests.provisioning.test_managed_single_restore_limits import ManagedSingleRestoreFixture


class HostingParentRaiseExpiryTests(ManagedSingleRestoreFixture, TransactionTestCase):
    observe = raise_fixtures.HostingRaiseTests.observe
    grant = raise_fixtures.HostingRaiseTests.grant

    def receipt(self, cap, request=None, available=100 * 1024**3):
        return {
            **ManagedSingleRestoreFixture.receipt(self, cap, request),
            "quota_protocol": 2,
            "available_bytes": available,
        }

    def setUp(self):
        quiet_task_queue(self)
        super().setUp()
        self.staff = User.objects.get(email="restore-adoption@example.com")
        self.ticket = Ticket.objects.filter(customer=self.customer).first()
        self.service.refresh_from_db()
        self.assertTrue(SettingsService.update_setting("provisioning.hosting_raises_enabled", True).is_ok())
        self.application = self.grant(expires_at=timezone.now() + timedelta(minutes=2))
        self.apply()
        self.account.refresh_from_db()
        self.clock = [timezone.now()]

    def node_restore(self, server, variables, **kwargs):
        outcome = super().node_restore(server, variables, **kwargs)
        self.clock[0] = self.application.overlay_expires_at + timedelta(seconds=1)
        return outcome

    def test_public_managed_restore_repairs_reviewed_base_after_overlay_expiry_during_archive_io(self):
        with patch("apps.provisioning.hosting_raise_service.timezone.now", side_effect=lambda: self.clock[0]):
            job, result = self.execute_restore()
        self.assertEqual(
            result["status"],
            "completed",
            {
                **result,
                "quota_claims": list(
                    HostingLimitExecution.objects.values(
                        "phase", "reserved_bytes", "job__status", "job__status_message"
                    )
                ),
            },
        )
        self.assertEqual(job.status, "completed")
        self.assertEqual(self.quota_requests[0]["disk_limit_kib"], 5632 * 1024)
        self.assertEqual(job.hosting_limit_application_id, self.application.pk)
        self.assertEqual(job.parameters["hosting_limits"]["disk_cap_mib"], 6912)
        self.assertEqual(ServiceHostingLimits.objects.get(service=self.service).applied_overlay_revision, 2)
        self.assertNotIn("enable-domain", self.api_calls)

    def test_public_recreate_repairs_reviewed_base_after_overlay_expiry_during_create_io(self):
        gateway = MockVirtualminGateway(server_hostname=self.server.hostname)
        gateway.available_templates.append("Default")
        original = gateway.call
        requests = []

        def call(program, params=None, **kwargs):
            result = original(program, params, **kwargs)
            if program == "create-domain":
                gateway.seed_domain(self.account.domain, username=self.account.virtualmin_username, domain_id="12345")
                self.clock[0] = self.application.overlay_expires_at + timedelta(seconds=1)
            return result

        def native(server, action, request):
            self.assertEqual(action, "apply")
            requests.append(request)
            return self.fresh_receipt(request["disk_limit_kib"] // 1024, request)

        with (
            patch("apps.provisioning.hosting_raise_service.timezone.now", side_effect=lambda: self.clock[0]),
            patch("apps.provisioning.virtualmin_service.VirtualminGateway", return_value=gateway),
            patch.object(gateway, "call", side_effect=call),
            patch.object(
                gateway,
                "test_connection",
                return_value=Ok({"healthy": True, "data": {"available_disk_mb": 100 * 1024}}),
            ),
            patch(
                "apps.provisioning.hosting_limit_transport.probe_account_quota",
                side_effect=lambda execution: self.fresh_receipt(1024),
            ),
            patch("apps.provisioning.hosting_limit_transport.run_quota_operation", side_effect=native),
        ):
            result = VirtualminProvisioningService(self.server).reprovision_virtualmin_account(
                self.account, self.server
            )
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(gateway.get_calls("create-domain")[0].params["quota"], str(6912 * 1024))
        self.assertEqual(requests[0]["disk_limit_kib"], 5632 * 1024)
        job = VirtualminProvisioningJob.objects.get(account=self.account, operation="create_domain")
        self.assertEqual(job.hosting_limit_application_id, self.application.pk)
        self.assertEqual(job.parameters["hosting_limits"]["disk_cap_mib"], 6912)
