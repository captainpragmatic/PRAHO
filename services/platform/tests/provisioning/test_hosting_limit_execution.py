"""Native quota execution owns the same durable account lane as restores and moves."""

from datetime import timedelta
from threading import Event
from unittest.mock import patch
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.db import connection, transaction
from django.test import TransactionTestCase
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.common.types import Ok
from apps.provisioning.hosting_limit_assignments import request_service_plan_change
from apps.provisioning.hosting_limit_execution import (
    admit_application,
    apply_hosting_limits,
    ensure_managed_limits,
    freeze_migration_limits,
    recover_quota_executions,
    reserve_managed_creation,
    reserve_managed_migration,
    resolve_quota_job,
)
from apps.provisioning.hosting_limit_execution_models import HostingLimitExecution
from apps.provisioning.hosting_limit_models import ServiceHostingLimits
from apps.provisioning.hosting_limit_override_service import grant_resource_override
from apps.provisioning.hosting_limit_tasks import current_application, dispatch_hosting_limits
from apps.provisioning.hosting_limit_transport import probe_account_quota
from apps.provisioning.hosting_node_policy_models import NodeHostingPolicy
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_backup_service import VirtualminBackupService
from apps.provisioning.virtualmin_gateway import VirtualminResponse
from apps.provisioning.virtualmin_migration_models import (
    VirtualminMigration,
    account_blocks_reconcile,
    account_has_active_operation,
)
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from apps.provisioning.virtualmin_security import connection_identities, connection_identity
from apps.provisioning.virtualmin_tasks import retry_virtualmin_job
from apps.provisioning.virtualmin_usage_models import AccountUsageState, UsageReading
from apps.settings.services import SettingsService
from apps.tickets.models import Ticket
from apps.users.models import User
from tests.common.postgres_locking import backend_pid, database_worker, wait_for_blocker
from tests.mocks.virtualmin_mock import MockVirtualminGateway
from tests.provisioning.test_hosting_node_policy import quota_evidence
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase


class HostingLimitAdmissionTests(VirtualminTaskTestBase):
    def test_uncertain_quota_application_blocks_lifecycle_admission_and_reconcile(self) -> None:
        job = VirtualminProvisioningJob.objects.create(
            operation="apply_hosting_limits",
            account=self.account,
            server=self.server,
            status="attention",
            correlation_id="quota-uncertain",
        )
        self.assertTrue(account_has_active_operation(self.account))
        self.assertTrue(account_blocks_reconcile(self.account))
        self.assertFalse(account_has_active_operation(self.account, ignore_job_id=job.pk))

    def test_completed_quota_application_releases_account_without_reenabling(self) -> None:
        VirtualminProvisioningJob.objects.create(
            operation="apply_hosting_limits",
            account=self.account,
            server=self.server,
            status="completed",
            correlation_id="quota-completed",
        )
        self.assertFalse(account_has_active_operation(self.account))
        self.assertFalse(account_blocks_reconcile(self.account))
        self.account.refresh_from_db()
        self.assertEqual(self.account.status, "error")

    def test_quota_attention_prevents_service_and_account_ownership_rebinding(self) -> None:
        VirtualminProvisioningJob.objects.create(
            operation="apply_hosting_limits",
            account=self.account,
            server=self.server,
            status="attention",
            correlation_id="quota-owner-fence",
        )
        with self.assertRaises(ValidationError):
            Service.objects.filter(pk=self.service.pk).update(customer_id=self.customer.pk + 1)


class HostingLimitWorkerFixture:
    def setup_native_fixture(self) -> None:
        evidence = quota_evidence()
        evidence["identity"] = connection_identity(self.server)
        self.policy = NodeHostingPolicy.objects.create(
            server=self.server,
            connection_identity=evidence["identity"],
            quota_adopted=True,
            quota_verified_at=timezone.now(),
            quota_evidence=evidence,
        )
        self.native_identity = {key: evidence[key] for key in ("installation", "filesystem_uuid", "boot_id")}
        self.native_identity.update(domain_id="12345", domain=self.account.domain, uid=1001, gid=1001)
        replacement = ServicePlan.objects.create(
            name="Larger quota",
            plan_type="shared_hosting",
            price_monthly=20,
            disk_space_gb=5,
            bandwidth_gb=20,
        )
        self.staff = User.objects.create_user(
            email="quota-admin@example.com", is_staff=True, is_superuser=True, staff_role="admin"
        )
        self.ticket = Ticket.objects.create(
            customer=self.customer, title="Native quota adoption", description="Customer-approved adoption"
        )
        self.application = grant_resource_override(
            user=self.staff,
            service=self.service,
            target_plan_id=replacement.pk,
            ticket_id=self.ticket.pk,
            reason="Approved native quota regression",
            expected_revision=1,
            submission_id=uuid4(),
            billing_unchanged=True,
            adopt_existing_native_limits=True,
        )

    def receipt(self, *, cap=1024, request=None, available=10 * 1024**3):
        result = {
            "schema": 1,
            "identity": self.native_identity,
            "observed_at": timezone.now().isoformat(),
            "filesystem": "ext4",
            "storage_qualified": True,
            "uid_enforced": True,
            "gid_enforced": True,
            "uid_soft_kib": cap * 1024,
            "uid_hard_kib": cap * 1024,
            "gid_soft_kib": cap * 1024,
            "gid_hard_kib": cap * 1024,
            "uid_used_bytes": 2048,
            "gid_used_bytes": 4096,
            "available_bytes": available,
            "configured_quota_kib": cap * 1024,
            "configured_uquota_kib": cap * 1024,
            "configured_bandwidth_bytes": 20 * 1024**3,
            "bandwidth_actions_safe": True,
            "observation": {"files_bytes": 4096, "database_bytes": 4096, "total_bytes": 8192},
        }
        if request:
            result.update(token=request["token"], generation=request["generation"])
        return result


class HostingLimitWorkerTests(HostingLimitWorkerFixture, VirtualminTaskTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.setup_native_fixture()

    def test_verified_application_updates_operational_state_once_without_unsuspending(self) -> None:
        def native(server, action, request):
            self.assertEqual(action, "apply")
            return self.receipt(cap=request["disk_limit_kib"] // 1024, request=request)

        with (
            patch("apps.provisioning.hosting_limit_transport.probe_account_quota", return_value=self.receipt()),
            patch(
                "apps.provisioning.hosting_limit_transport.run_quota_operation",
                side_effect=native,
            ) as transport,
        ):
            self.assertEqual(apply_hosting_limits(self.application.pk), "completed")
            self.assertEqual(apply_hosting_limits(self.application.pk), "completed")
        self.assertEqual(transport.call_count, 1)
        self.assertEqual(HostingLimitExecution.objects.count(), 1)
        execution = HostingLimitExecution.objects.get()
        self.assertEqual(execution.reserved_bytes, (5632 - 1024) * 1024**2)
        self.assertIsNotNone(execution.reservation_released_at)
        limits = ServiceHostingLimits.objects.get(service=self.service)
        self.assertEqual((limits.applied_revision, limits.operational_revision), (2, 2))
        self.assertEqual(limits.operational_disk_allowance_mib, 5120)
        self.assertEqual(limits.verified_receipt["token"], str(execution.job.execution_token))
        self.account.refresh_from_db()
        self.assertEqual(self.account.status, "error")
        self.assertEqual(self.account.effective_disk_quota_mb, 5632)
        self.assertTrue(self.account.quota_managed)
        audit = AuditEvent.objects.filter(
            action="virtualmin_account_updated",
            object_id=str(self.account.pk),
            new_values__quota_managed=True,
        ).latest("timestamp")
        self.assertFalse(audit.old_values["quota_managed"])
        self.assertEqual(audit.new_values["hosting_limit_authority"]["application_id"], str(self.application.pk))
        self.assertEqual(audit.new_values["hosting_limit_authority"]["authority"]["ticket_id"], str(self.ticket.pk))

    def test_explicit_adoption_repairs_known_uid_gid_quota_disagreement(self) -> None:
        probe = self.receipt()
        probe.update(uid_soft_kib=0, uid_hard_kib=0, configured_uquota_kib=0, bandwidth_actions_safe=False)

        def native(server, action, request):
            return self.receipt(cap=request["disk_limit_kib"] // 1024, request=request)

        with (
            patch("apps.provisioning.hosting_limit_transport.probe_account_quota", return_value=probe),
            patch(
                "apps.provisioning.hosting_limit_transport.run_quota_operation",
                side_effect=native,
            ),
        ):
            self.assertEqual(apply_hosting_limits(self.application.pk), "completed")
        receipt = ServiceHostingLimits.objects.get(service=self.service).verified_receipt
        self.assertEqual(receipt["uid_hard_kib"], 5632 * 1024)
        self.assertEqual(receipt["gid_hard_kib"], 5632 * 1024)

    def test_native_bandwidth_action_uncertainty_never_publishes_managed_limits(self) -> None:
        def native(server, action, request):
            receipt = self.receipt(cap=request["disk_limit_kib"] // 1024, request=request)
            receipt.pop("bandwidth_actions_safe", None)
            return receipt

        with (
            patch("apps.provisioning.hosting_limit_transport.probe_account_quota", return_value=self.receipt()),
            patch("apps.provisioning.hosting_limit_transport.run_quota_operation", side_effect=native),
        ):
            self.assertEqual(apply_hosting_limits(self.application.pk), "attention")
        self.account.refresh_from_db()
        self.assertFalse(self.account.quota_managed)
        self.assertIsNone(ServiceHostingLimits.objects.get(service=self.service).verified_at)
        self.assertTrue(account_has_active_operation(self.account))

    def test_native_probe_refuses_a_foreign_unix_owner_before_issuing_any_quota_command(self) -> None:
        execution = admit_application(self.application.pk)
        response = VirtualminResponse(
            success=True,
            data={"data": [{"name": self.account.domain, "values": {"ID": ["12345"], "Username": ["foreign"]}}]},
            raw_response="{}",
            http_status=200,
            execution_time=0,
            program="list-domains",
            server_hostname=self.server.hostname,
        )
        with (
            patch("apps.provisioning.virtualmin_gateway.VirtualminGateway.call", return_value=Ok(response)),
            patch(
                "apps.provisioning.hosting_node_transport.run_quota_operation",
            ) as native,
            self.assertRaisesMessage(ValueError, "another Unix owner"),
        ):
            probe_account_quota(execution)
        native.assert_not_called()

    def test_observed_create_retry_cannot_activate_before_current_kernel_quota_verification(self) -> None:
        gateway = MockVirtualminGateway()
        gateway.seed_domain(self.account.domain, username=self.account.virtualmin_username)
        job = self._failed_job(status="pending", claimed_at=timezone.now(), retry_count=1)
        with (
            patch("apps.provisioning.virtualmin_service.VirtualminGateway", return_value=gateway),
            patch(
                "apps.provisioning.hosting_limit_transport.probe_account_quota",
                return_value=self.receipt(),
            ),
            patch(
                "apps.provisioning.hosting_limit_transport.run_quota_operation",
                side_effect=RuntimeError("native response lost"),
            ),
        ):
            result = retry_virtualmin_job(str(job.pk))
        self.assertFalse(result["success"])
        self.account.refresh_from_db()
        job.refresh_from_db()
        self.assertNotEqual(self.account.status, "active")
        self.assertEqual(job.status, "attention")
        self.assertIsNone(ServiceHostingLimits.objects.get(service=self.service).applied_revision)

    def test_lost_response_retains_reservation_and_requires_fence_before_new_generation(self) -> None:
        with (
            patch("apps.provisioning.hosting_limit_transport.probe_account_quota", return_value=self.receipt()),
            patch(
                "apps.provisioning.hosting_limit_transport.run_quota_operation",
                side_effect=RuntimeError("response lost"),
            ),
        ):
            self.assertEqual(apply_hosting_limits(self.application.pk), "attention")
            self.assertEqual(apply_hosting_limits(self.application.pk), "attention")
        execution = HostingLimitExecution.objects.get()
        self.assertIsNone(execution.reservation_released_at)
        self.assertTrue(account_blocks_reconcile(self.account))
        self.assertIsNone(ServiceHostingLimits.objects.get(service=self.service).applied_revision)
        execution.job.refresh_from_db()
        with patch("apps.provisioning.hosting_limit_transport.run_quota_operation", side_effect=RuntimeError("busy")):
            self.assertTrue(resolve_quota_job(execution.job, resolved_by="staff", note="Investigated").is_err())
        execution.refresh_from_db()
        self.assertIsNone(execution.reservation_released_at)
        fence = {"outcome": "fenced", "token": execution.request["token"], "generation": execution.account_epoch}
        with patch("apps.provisioning.hosting_limit_transport.run_quota_operation", return_value=fence) as native:
            self.assertTrue(resolve_quota_job(execution.job, resolved_by="staff", note="Investigated").is_ok())
        self.assertEqual(native.call_args.args[1], "fence")
        execution.refresh_from_db()
        self.assertIsNotNone(execution.reservation_released_at)
        replacement = admit_application(self.application.pk)
        self.assertEqual(replacement.account_epoch, execution.account_epoch + 1)

    def test_insufficient_capacity_never_issues_or_changes_operational_state(self) -> None:
        with (
            patch(
                "apps.provisioning.hosting_limit_transport.probe_account_quota",
                return_value=self.receipt(available=1024),
            ),
            patch(
                "apps.provisioning.hosting_limit_transport.run_quota_operation",
            ) as native,
        ):
            self.assertEqual(apply_hosting_limits(self.application.pk), "pending")
        native.assert_not_called()
        execution = HostingLimitExecution.objects.get()
        self.assertIsNone(execution.issued_at)
        self.assertIsNotNone(execution.reservation_released_at)
        self.assertIsNone(ServiceHostingLimits.objects.get(service=self.service).applied_revision)

    def test_failed_readonly_admission_has_bounded_retries_then_attention(self) -> None:
        with (
            patch(
                "apps.provisioning.hosting_limit_transport.probe_account_quota", side_effect=RuntimeError("unavailable")
            ),
            patch(
                "apps.provisioning.hosting_limit_transport.run_quota_operation",
            ) as native,
        ):
            for _attempt in range(3):
                self.assertEqual(apply_hosting_limits(self.application.pk), "pending")
                VirtualminProvisioningJob.objects.filter(operation="apply_hosting_limits").update(
                    next_retry_at=timezone.now() - timedelta(seconds=1),
                )
            self.assertEqual(apply_hosting_limits(self.application.pk), "attention")
        self.assertEqual(HostingLimitExecution.objects.count(), 3)
        native.assert_not_called()

    def test_expired_issued_execution_never_releases_native_hold_or_capacity(self) -> None:
        execution = admit_application(self.application.pk)
        HostingLimitExecution.objects.filter(pk=execution.pk).update(
            phase="issued",
            issued_at=timezone.now(),
            reserved_bytes=123,
        )
        VirtualminProvisioningJob.objects.filter(pk=execution.job_id).update(
            execution_deadline=timezone.now() - timedelta(seconds=1),
        )
        self.assertEqual(recover_quota_executions(), 1)
        execution.refresh_from_db()
        self.assertEqual(execution.phase, "attention")
        self.assertIsNone(execution.reservation_released_at)
        self.assertEqual(execution.reserved_bytes, 123)
        self.assertTrue(account_has_active_operation(self.account))

    def test_restore_verification_repairs_archived_caps_before_reporting_success(self) -> None:
        response = VirtualminResponse(
            success=True,
            data={"data": [{"name": self.account.domain, "values": {"Username": [self.account.virtualmin_username]}}]},
            raw_response="{}",
            http_status=200,
            execution_time=0,
            program="list-domains",
            server_hostname=self.server.hostname,
        )

        def native(server, action, request):
            return self.receipt(cap=request["disk_limit_kib"] // 1024, request=request)

        with (
            patch("apps.provisioning.virtualmin_gateway.VirtualminGateway.call", return_value=Ok(response)),
            patch(
                "apps.provisioning.hosting_limit_transport.probe_account_quota",
                return_value=self.receipt(),
            ),
            patch("apps.provisioning.hosting_limit_transport.run_quota_operation", side_effect=native),
        ):
            result = VirtualminBackupService(self.server)._verify_restored_domain(self.server, self.account)
        self.assertTrue(result.is_ok(), str(result))
        limits = ServiceHostingLimits.objects.get(service=self.service)
        self.assertEqual(limits.applied_revision, 2)
        self.assertEqual(limits.verified_receipt["uid_hard_kib"], 5632 * 1024)

    def test_batch_connection_identity_is_exact_and_has_one_credential_query(self) -> None:
        # The current row is deliberately reloaded, even if the caller holds stale endpoint data.
        expected = connection_identity(self.server)
        self.server.hostname = "stale.example.com"
        # Servers/deployments + credentials + one uncached global CIDR setting.
        with self.assertNumQueries(3):
            observed = connection_identities([self.server, self.server])
        self.assertEqual(observed, {self.server.pk: expected})

    def test_missing_canonical_disk_evidence_never_falls_back_to_kernel_totals(self) -> None:
        probe = self.receipt()
        probe.pop("observation")

        def native(server, action, request):
            return self.receipt(cap=request["disk_limit_kib"] // 1024, request=request)

        with (
            patch("apps.provisioning.hosting_limit_transport.probe_account_quota", return_value=probe),
            patch(
                "apps.provisioning.hosting_limit_transport.run_quota_operation",
                side_effect=native,
            ) as native,
        ):
            self.assertEqual(apply_hosting_limits(self.application.pk), "pending")
        native.assert_not_called()

    def accepted_reading(self, *, owner_id, age_hours):
        now = timezone.now()
        observed = now - timedelta(hours=age_hours)
        state = AccountUsageState.objects.create(
            account=self.account,
            service_id_snapshot=self.service.pk,
            customer_id_snapshot=owner_id,
            server_id_snapshot=self.server.pk,
            chain_epoch_snapshot=self.account.chain_epoch,
            domain_id="12345",
            installation=self.native_identity["installation"],
            gauge_not_before=now - timedelta(hours=4),
            owner_started_at=now - timedelta(hours=4),
        )
        state.disk_reading = UsageReading.objects.create(
            account=self.account,
            owner_scope=state.owner_scope,
            sync_token=uuid4(),
            server_id_snapshot=self.server.pk,
            chain_epoch=self.account.chain_epoch,
            taken_at=observed,
            scan_started_at=observed,
            disk_files_bytes=4096,
            disk_db_bytes=4096,
            disk_total_bytes=8192,
            period_start=now - timedelta(days=1),
            period_end=now + timedelta(days=1),
            period_timezone="UTC",
        )
        state.save(update_fields=["disk_reading"])

    def test_fresh_wrong_owner_reading_cannot_replace_a_missing_native_observation(self) -> None:
        self.accepted_reading(owner_id=self.customer.pk + 1, age_hours=0)
        self.test_missing_canonical_disk_evidence_never_falls_back_to_kernel_totals()

    def test_stale_correct_owner_reading_cannot_replace_a_missing_native_observation(self) -> None:
        self.accepted_reading(owner_id=self.customer.pk, age_hours=3)
        self.test_missing_canonical_disk_evidence_never_falls_back_to_kernel_totals()

    def test_fresh_exact_owner_reading_is_a_valid_canonical_observation_control(self) -> None:
        self.accepted_reading(owner_id=self.customer.pk, age_hours=0)
        probe = self.receipt()
        probe.pop("observation")

        def native(server, action, request):
            return self.receipt(cap=request["disk_limit_kib"] // 1024, request=request)

        with (
            patch("apps.provisioning.hosting_limit_transport.probe_account_quota", return_value=probe),
            patch(
                "apps.provisioning.hosting_limit_transport.run_quota_operation",
                side_effect=native,
            ),
        ):
            self.assertEqual(apply_hosting_limits(self.application.pk), "completed")
        self.assertEqual(ServiceHostingLimits.objects.get(service=self.service).applied_revision, 2)

    def apply_with_probe(self, probe):
        def native(server, action, request):
            return self.receipt(cap=request["disk_limit_kib"] // 1024, request=request)

        with (
            patch("apps.provisioning.hosting_limit_transport.probe_account_quota", return_value=probe),
            patch("apps.provisioning.hosting_limit_transport.run_quota_operation", side_effect=native),
        ):
            return apply_hosting_limits(self.application.pk)

    def test_databases_above_the_file_cap_do_not_block_the_cap(self) -> None:
        # Databases are outside the kernel cap (ADR-0075), so only what the cap governs has to fit under it.
        gib = 1024**3
        probe = self.receipt()
        probe["observation"] = {"files_bytes": gib, "database_bytes": 60 * gib, "total_bytes": 61 * gib}
        self.assertEqual(self.apply_with_probe(probe), "completed")

    def test_files_above_the_cap_still_block_it(self) -> None:
        gib = 1024**3
        probe = self.receipt()
        probe["observation"] = {"files_bytes": 60 * gib, "database_bytes": gib, "total_bytes": 61 * gib}
        self.assertEqual(self.apply_with_probe(probe), "pending")

    def test_kernel_usage_above_the_cap_still_blocks_it_whatever_the_observation_says(self) -> None:
        probe = self.receipt()
        probe["uid_used_bytes"] = 60 * 1024**3
        self.assertEqual(self.apply_with_probe(probe), "pending")

    def test_an_accepted_reading_compares_files_rather_than_total_with_the_cap(self) -> None:
        self.accepted_reading(owner_id=self.customer.pk, age_hours=0)
        UsageReading.objects.filter(account=self.account).update(
            disk_files_bytes=4096, disk_db_bytes=60 * 1024**3, disk_total_bytes=4096 + 60 * 1024**3
        )
        probe = self.receipt()
        probe.pop("observation")
        self.assertEqual(self.apply_with_probe(probe), "completed")

    def test_stale_or_wrong_owner_canonical_reading_cannot_authorize_fit(self) -> None:
        now = timezone.now()
        state = AccountUsageState.objects.create(
            account=self.account,
            service_id_snapshot=self.service.pk,
            customer_id_snapshot=self.customer.pk + 1,
            server_id_snapshot=self.server.pk,
            chain_epoch_snapshot=self.account.chain_epoch,
            domain_id="12345",
            installation=self.native_identity["installation"],
            gauge_not_before=now - timedelta(hours=3),
        )
        reading = UsageReading.objects.create(
            account=self.account,
            owner_scope=state.owner_scope,
            sync_token=uuid4(),
            server_id_snapshot=self.server.pk,
            chain_epoch=self.account.chain_epoch,
            taken_at=now - timedelta(hours=3),
            scan_started_at=now - timedelta(hours=3),
            disk_files_bytes=4096,
            disk_db_bytes=4096,
            disk_total_bytes=8192,
            period_start=now - timedelta(days=1),
            period_end=now + timedelta(days=1),
            period_timezone="UTC",
        )
        state.disk_reading = reading
        state.save(update_fields=["disk_reading"])
        probe = self.receipt()
        probe.pop("observation")
        with (
            patch("apps.provisioning.hosting_limit_transport.probe_account_quota", return_value=probe),
            patch(
                "apps.provisioning.hosting_limit_transport.run_quota_operation",
            ) as native,
        ):
            self.assertEqual(apply_hosting_limits(self.application.pk), "pending")
        native.assert_not_called()

    def test_full_create_reservation_survives_parent_uncertainty_and_elapsed_child_lease(self) -> None:
        parent = VirtualminProvisioningJob.objects.create(
            account=self.account,
            server=self.server,
            operation="create_domain",
            status="running",
            correlation_id="native-create",
        )
        self.assertTrue(reserve_managed_creation(self.account, parent, 10 * 1024**3).is_ok())
        execution = HostingLimitExecution.objects.get()
        self.assertEqual(execution.reserved_bytes, 5632 * 1024**2)
        VirtualminProvisioningJob.objects.filter(pk=parent.pk).update(status="attention")
        VirtualminProvisioningJob.objects.filter(pk=execution.job_id).update(
            execution_deadline=timezone.now() - timedelta(days=1)
        )
        self.assertEqual(recover_quota_executions(), 0)
        execution.refresh_from_db()
        self.assertIsNone(execution.reservation_released_at)
        # A standalone sweep cannot steal a parent's prepared native child.
        with patch("apps.provisioning.hosting_limit_transport.run_quota_operation") as transport:
            self.assertEqual(apply_hosting_limits(self.application.pk), "pending")
        transport.assert_not_called()

    def test_unknown_create_capacity_never_publishes_a_claim(self) -> None:
        parent = VirtualminProvisioningJob.objects.create(
            account=self.account,
            server=self.server,
            operation="create_domain",
            status="running",
            correlation_id="no-space-proof",
        )
        self.assertTrue(reserve_managed_creation(self.account, parent, None).is_err())
        self.assertFalse(HostingLimitExecution.objects.exists())

    def test_stored_node_reserve_controls_positive_delta_application(self) -> None:
        self.assertTrue(SettingsService.update_setting("virtualmin.disk_free_reserve_mb", 1393).is_ok())

        def native(server, action, request):
            return self.receipt(cap=request["disk_limit_kib"] // 1024, request=request)

        with (
            patch(
                "apps.provisioning.hosting_limit_transport.probe_account_quota",
                return_value=self.receipt(available=6000 * 1024**2),
            ),
            patch(
                "apps.provisioning.hosting_limit_transport.run_quota_operation",
                side_effect=native,
            ) as transport,
        ):
            self.assertEqual(apply_hosting_limits(self.application.pk), "pending")
            transport.assert_not_called()
            self.assertTrue(SettingsService.update_setting("virtualmin.disk_free_reserve_mb", 1392).is_ok())
            VirtualminProvisioningJob.objects.filter(operation="apply_hosting_limits").update(
                next_retry_at=timezone.now() - timedelta(seconds=1)
            )
            self.assertEqual(apply_hosting_limits(self.application.pk), "completed")
        self.assertEqual(ServiceHostingLimits.objects.get(service=self.service).applied_revision, 2)

    def test_stored_node_reserve_controls_full_create_cap_admission(self) -> None:
        parent = VirtualminProvisioningJob.objects.create(
            account=self.account,
            server=self.server,
            operation="create_domain",
            status="running",
            correlation_id="reserve-setting",
        )
        self.assertTrue(SettingsService.update_setting("virtualmin.disk_free_reserve_mb", 1001).is_ok())
        self.assertTrue(reserve_managed_creation(self.account, parent, 6632 * 1024**2).is_err())
        self.assertTrue(SettingsService.update_setting("virtualmin.disk_free_reserve_mb", 1000).is_ok())
        self.assertTrue(reserve_managed_creation(self.account, parent, 6632 * 1024**2).is_ok())
        claim = HostingLimitExecution.objects.get(phase="prepared")
        self.assertEqual(claim.reserved_bytes, 5632 * 1024**2)
        self.assertIsNone(claim.issued_at)

    def test_stored_node_reserve_controls_full_migration_cap_admission(self) -> None:
        source = VirtualminServer.objects.create(
            name="reserve-source", hostname="reserve-source.example.com", api_username="root"
        )
        migration = VirtualminMigration.objects.create(
            account=self.account,
            source_server=source,
            target_server=self.server,
            status="restoring",
            lease_token=uuid4(),
            worker_lease_expires_at=timezone.now() + timedelta(hours=1),
            pre_migration_snapshot={"hosting_limits": freeze_migration_limits(self.account)},
        )
        with patch(
            "apps.provisioning.virtualmin_gateway.VirtualminGateway.test_connection",
            return_value=Ok({"healthy": True, "data": {"available_disk_mb": 6632}}),
        ):
            self.assertTrue(SettingsService.update_setting("virtualmin.disk_free_reserve_mb", 1001).is_ok())
            self.assertTrue(reserve_managed_migration(migration).is_err())
            self.assertTrue(SettingsService.update_setting("virtualmin.disk_free_reserve_mb", 1000).is_ok())
            self.assertTrue(reserve_managed_migration(migration).is_ok())
        claim = HostingLimitExecution.objects.get(phase="prepared")
        self.assertEqual(claim.reserved_bytes, 5632 * 1024**2)
        self.assertIsNone(claim.issued_at)

    def test_broker_outage_keeps_assignment_durable_and_sweep_recovers_delivery(self) -> None:
        with (
            patch(
                "apps.provisioning.hosting_limit_tasks.async_task", side_effect=OSError("broker unavailable")
            ) as broker,
            self.captureOnCommitCallbacks(execute=True),
            transaction.atomic(),
        ):
            another = grant_resource_override(
                user=self.staff,
                service=Service.objects.get(pk=self.service.pk),
                target_plan_id=self.application.target_plan_id,
                ticket_id=self.ticket.pk,
                expected_revision=2,
                submission_id=uuid4(),
                reason="Broker outage assignment",
                billing_unchanged=True,
                adopt_existing_native_limits=True,
            )
            broker.assert_not_called()
        self.assertEqual(ServiceHostingLimits.objects.get(service=self.service).revision, 3)
        self.account.status = "active"
        self.account.save(update_fields=["status", "updated_at"])
        with patch("apps.provisioning.hosting_limit_tasks.async_task") as broker:
            self.assertEqual(dispatch_hosting_limits()["queued"], 1)
        self.assertEqual(broker.call_args.args[1], str(another.pk))

    def test_node_adoption_and_discovery_alone_never_apply_a_legacy_account_cap(self) -> None:
        legacy = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name="imported.example.com",
            domain="imported.example.com",
            username="imported",
            price=10,
            status="active",
        )
        account = VirtualminAccount.objects.create(
            service=legacy,
            server=self.server,
            domain="imported.example.com",
            virtualmin_username="imported",
            encrypted_password=b"unused",
            status="active",
        )
        application = current_application(legacy.pk)
        with patch("apps.provisioning.hosting_limit_tasks.async_task") as broker:
            self.assertEqual(dispatch_hosting_limits()["queued"], 0)
        broker.assert_not_called()
        self.assertIsNone(admit_application(application.pk))
        self.assertFalse(HostingLimitExecution.objects.filter(job__account=account).exists())

    def test_migration_preserves_reviewed_ceiling_then_reconciles_new_paid_target_after_release(self) -> None:
        source = VirtualminServer.objects.create(
            name="old-source",
            hostname="old-source.example.com",
            api_username="root",
            status="disabled",
        )
        frozen = freeze_migration_limits(self.account)
        migration = VirtualminMigration.objects.create(
            account=self.account,
            source_server=source,
            target_server=self.server,
            status="activating",
            lease_token=uuid4(),
            worker_lease_expires_at=timezone.now() + timedelta(hours=1),
            cutover_committed_at=timezone.now(),
            pre_migration_snapshot={"hosting_limits": frozen},
        )
        larger = ServicePlan.objects.create(
            name="Later paid larger", plan_type="shared_hosting", price_monthly=40, disk_space_gb=20, bandwidth_gb=40
        )
        with transaction.atomic():
            later = request_service_plan_change(
                service=Service.objects.get(pk=self.service.pk),
                target_plan_id=larger.pk,
                expected_revision=2,
                submission_id=uuid4(),
                reason="Paid upgrade while native move is held",
                authority={"kind": "commercial_plan_change"},
            )
        requests = []

        def native(server, action, request):
            requests.append(request)
            result = self.receipt(cap=request["disk_limit_kib"] // 1024, request=request)
            result["configured_bandwidth_bytes"] = request["bandwidth_limit_bytes"]
            return result

        with (
            patch(
                "apps.provisioning.hosting_limit_transport.probe_account_quota",
                return_value=self.receipt(available=100 * 1024**3),
            ),
            patch(
                "apps.provisioning.hosting_limit_transport.run_quota_operation",
                side_effect=native,
            ),
        ):
            self.assertTrue(ensure_managed_limits(self.account, migration=migration, native_server=self.server).is_ok())
            limits = ServiceHostingLimits.objects.get(service=self.service)
            self.assertEqual((limits.revision, limits.applied_revision, limits.operational_revision), (3, 2, 2))
            self.assertEqual(requests[-1]["disk_limit_kib"], 5632 * 1024)
            self.assertEqual(apply_hosting_limits(later.pk), "pending")
            VirtualminMigration.objects.filter(pk=migration.pk).update(status="completed")
            self.assertEqual(apply_hosting_limits(later.pk), "completed")
        self.assertEqual(requests[-1]["disk_limit_kib"], 22528 * 1024)
        migration.refresh_from_db()
        self.assertEqual(migration.pre_migration_snapshot["hosting_limits"], frozen)


class HostingLimitExecutionConcurrencyTests(HostingLimitWorkerFixture, TransactionTestCase):
    def setUp(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("Native quota admission needs PostgreSQL READ COMMITTED")
        queue = patch("apps.provisioning.hosting_limit_tasks.async_task")
        queue.start()
        self.addCleanup(queue.stop)
        VirtualminTaskTestBase.setUp(self)
        self.setup_native_fixture()

    def test_waited_account_admission_uses_fresh_canonical_target(self) -> None:
        target = VirtualminServer.objects.create(
            name="new-canonical", hostname="new.example.com", api_username="root", status="active"
        )
        evidence = quota_evidence()
        evidence["identity"] = connection_identity(target)
        NodeHostingPolicy.objects.create(
            server=target,
            quota_adopted=True,
            connection_identity=evidence["identity"],
            quota_verified_at=timezone.now(),
            quota_evidence=evidence,
        )
        start = Event()

        def admit():
            if not start.wait(10):
                raise AssertionError("Canonical node writer never acquired the account")
            execution = admit_application(self.application.pk)
            return execution.job.server_id

        writer = backend_pid()
        with database_worker(admit) as (pid, pending):
            with transaction.atomic():
                account = VirtualminAccount.objects.select_for_update(of=("self",)).get(pk=self.account.pk)
                account.server = target
                account.save(update_fields=["server", "updated_at"])
                start.set()
                wait_for_blocker(pid, writer, pending, table="provisioning_virtualmin_accounts")
            self.assertEqual(pending.result(timeout=10), target.pk)

    def test_waited_server_capacity_counts_other_committed_full_cap_reservation(self) -> None:
        other_service = Service.objects.create(
            customer=self.customer,
            service_plan_id=self.application.target_plan_id,
            currency=self.currency,
            service_name="other.example.com",
            domain="other.example.com",
            username="other",
            price=20,
            status="active",
        )
        other = VirtualminAccount.objects.create(
            service=other_service,
            server=self.server,
            domain="other.example.com",
            virtualmin_username="other",
            encrypted_password=b"unused",
            status="provisioning",
        )
        parent = VirtualminProvisioningJob.objects.create(
            account=other,
            server=self.server,
            operation="create_domain",
            status="running",
            correlation_id="other-full-cap",
        )
        start = Event()

        def apply():
            if not start.wait(10):
                raise AssertionError("Competing capacity writer never reached its reservation")
            return apply_hosting_limits(self.application.pk)

        writer = backend_pid()
        with (
            patch("apps.provisioning.hosting_limit_transport.probe_account_quota", return_value=self.receipt()),
            patch(
                "apps.provisioning.hosting_limit_transport.run_quota_operation",
            ) as native,
            database_worker(apply) as (pid, pending),
        ):
            with transaction.atomic():
                reserved = reserve_managed_creation(other, parent, 10 * 1024**3)
                self.assertTrue(reserved.is_ok(), str(reserved))
                start.set()
                wait_for_blocker(pid, writer, pending, table="provisioning_virtualmin_servers")
            self.assertEqual(pending.result(timeout=10), "pending")
        native.assert_not_called()
        rejected = HostingLimitExecution.objects.get(job__hosting_limit_application=self.application)
        self.assertIsNone(rejected.issued_at)
        self.assertIsNotNone(rejected.reservation_released_at)
