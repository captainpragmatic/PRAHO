"""An issued archive repair retains its admitted resource authority."""

from copy import deepcopy
from datetime import timedelta
from threading import Event
from unittest.mock import patch
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.db import DatabaseError, connection, transaction
from django.db.models.signals import post_save
from django.test import TransactionTestCase
from django.utils import timezone

from apps.common.types import Ok, Retriability
from apps.infrastructure.node_maintenance_gate import begin_account_job
from apps.provisioning.hosting_limit_execution import admit_application, apply_hosting_limits
from apps.provisioning.hosting_limit_models import ServiceHostingLimits
from apps.provisioning.hosting_limit_override_service import grant_resource_override
from apps.provisioning.hosting_parent_limits import (
    BINDING_KEY,
    ISSUED_KEY,
    SNAPSHOT_KEY,
    held_parent_application_matches,
    held_parent_cap_repair_issued,
    mark_parent_limits_issued,
)
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_backup_service import RestoreConfig, VirtualminBackupService
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob
from apps.provisioning.virtualmin_service import (
    VirtualminAccountCreationData,
    VirtualminBackupManagementService,
    VirtualminProvisioningService,
)
from apps.tickets.models import Ticket
from apps.users.models import User
from tests.common.postgres_locking import backend_pid, database_worker, wait_for_blocker
from tests.helpers.task_queue import quiet_task_queue
from tests.mocks.virtualmin_mock import MockVirtualminGateway
from tests.provisioning.test_managed_single_restore_limits import ManagedSingleRestoreFixture


class HostingParentRestoreLimitsTests(ManagedSingleRestoreFixture, TransactionTestCase):
    def setUp(self):
        quiet_task_queue(self)
        super().setUp()
        self.later = None

    def fresh_receipt(self, cap, request=None):
        value = {**super().fresh_receipt(cap, request), "available_bytes": 100 * 1024**3}
        if request:
            value["configured_bandwidth_bytes"] = request["bandwidth_limit_bytes"]
        return value

    def node_restore(self, server, variables, **kwargs):
        result = super().node_restore(server, variables, **kwargs)
        self.assertFalse(connection.in_atomic_block, "Native restore must not hold financial/database locks")
        parent = VirtualminProvisioningJob.objects.get(
            account=self.account, operation="restore_domain", status="running"
        )
        scope = {
            "job_id": str(parent.pk),
            "token": str(parent.execution_token),
            "account_server_id": str(self.server.pk),
            "native_server_id": str(self.server.pk),
        }
        self.assertTrue(held_parent_cap_repair_issued(self.application, scope))
        target = ServicePlan.objects.create(
            name="Later twenty", plan_type="shared_hosting", price_monthly=40, disk_space_gb=20, bandwidth_gb=40
        )
        self.later = grant_resource_override(
            user=User.objects.get(email="restore-adoption@example.com"),
            service=Service.objects.get(pk=self.service.pk),
            target_plan_id=target.pk,
            expected_revision=2,
            submission_id=uuid4(),
            reason="Explicit resource assignment accepted while archive writer is issued",
            ticket_id=Ticket.objects.filter(customer=self.customer).first().pk,
            billing_unchanged=True,
        )
        self.assertFalse(held_parent_cap_repair_issued(self.later, scope))
        self.assertIsNone(
            admit_application(self.later.pk, parent=scope),
            "A held parent must not authorize a different current application",
        )
        return result

    def test_real_restore_retains_admitted_cap_then_applies_later_assignment_after_release(self):
        job, outcome = self.execute_restore()
        self.assertEqual(outcome["status"], "completed", outcome)
        self.assertEqual(job.status, "completed")
        self.assertEqual(self.quota_requests[0]["disk_limit_kib"], 5632 * 1024)
        limits = ServiceHostingLimits.objects.get(service=self.service)
        self.assertEqual((limits.revision, limits.applied_revision, limits.operational_revision), (3, 2, 2))
        self.assertEqual(self.service.price, 10)
        self.assertIsNotNone(self.later)
        with (
            patch(
                "apps.provisioning.hosting_limit_transport.probe_account_quota", return_value=self.fresh_receipt(5632)
            ),
            patch(
                "apps.provisioning.hosting_limit_transport.run_quota_operation",
                side_effect=lambda server, action, request: self.fresh_receipt(
                    request["disk_limit_kib"] // 1024, request
                ),
            ),
        ):
            self.assertEqual(apply_hosting_limits(self.later.pk), "completed")
        limits.refresh_from_db()
        self.assertEqual((limits.revision, limits.applied_revision), (3, 3))
        self.assertNotIn("enable-domain", self.api_calls)


class HostingParentCreateLimitsTests(ManagedSingleRestoreFixture, TransactionTestCase):
    def setUp(self):
        quiet_task_queue(self)
        super().setUp()

    def create_with_competing_assignment(self, *, recreate=False, after_admission=False):
        service = (
            self.service
            if recreate
            else Service.objects.create(
                customer=self.customer,
                service_plan=ServicePlan.objects.get(pk=self.application.target_plan_id),
                currency=self.currency,
                service_name="new-parent.example.test",
                domain="new-parent.example.test",
                username="newparent",
                price=10,
                status="active",
            )
        )
        service.refresh_from_db()
        original_revision = ServiceHostingLimits.objects.get(service=service).revision
        gateway = MockVirtualminGateway(server_hostname=self.server.hostname)
        gateway.available_templates.append("Default")
        original_call = gateway.call
        requests = []
        assigned = []

        def assign():
            self.assertFalse(connection.in_atomic_block)
            target = ServicePlan.objects.create(
                name="New parent target twenty",
                plan_type="shared_hosting",
                price_monthly=40,
                disk_space_gb=20,
                bandwidth_gb=40,
            )
            assigned.append(
                grant_resource_override(
                    user=User.objects.get(email="restore-adoption@example.com"),
                    service=Service.objects.get(pk=service.pk),
                    target_plan_id=target.pk,
                    expected_revision=original_revision,
                    submission_id=uuid4(),
                    reason="Accepted resources after native parent admission",
                    ticket_id=Ticket.objects.filter(customer=self.customer).first().pk,
                    billing_unchanged=True,
                )
            )

        def admitted(sender, instance, created, **kwargs):
            if created and instance.operation == "create_domain" and instance.account.service_id == service.pk:
                transaction.on_commit(assign)

        def call(program, params=None, **kwargs):
            result = original_call(program, params, **kwargs)
            if program == "create-domain":
                self.assertFalse(connection.in_atomic_block)
                gateway.seed_domain(service.domain, username=service.username, domain_id="12345")
                if not after_admission:
                    assign()
            return result

        def probe(execution):
            result = self.fresh_receipt(1024)
            result["available_bytes"] = 100 * 1024**3
            result["identity"] = {**self.identity, "domain": service.domain, "uid": 1002, "gid": 1002}
            return result

        def native(server, action, request):
            requests.append(request)
            result = self.fresh_receipt(request["disk_limit_kib"] // 1024, request)
            result["identity"] = request["identity"]
            result["configured_bandwidth_bytes"] = request["bandwidth_limit_bytes"]
            return result

        if after_admission:
            post_save.connect(admitted, sender=VirtualminProvisioningJob, weak=False)
        try:
            with (
                patch("apps.provisioning.virtualmin_service.VirtualminGateway", return_value=gateway),
                patch.object(gateway, "call", side_effect=call),
                patch.object(
                    gateway,
                    "test_connection",
                    return_value=Ok({"healthy": True, "data": {"available_disk_mb": 100 * 1024}}),
                ),
                patch("apps.provisioning.hosting_limit_transport.probe_account_quota", side_effect=probe),
                patch("apps.provisioning.hosting_limit_transport.run_quota_operation", side_effect=native),
            ):
                provisioner = VirtualminProvisioningService(self.server)
                outcome = (
                    provisioner.reprovision_virtualmin_account(self.account, self.server)
                    if recreate
                    else provisioner.create_virtualmin_account(
                        VirtualminAccountCreationData(
                            service=service,
                            domain=service.domain,
                            username=service.username,
                            template="Default",
                            server=self.server,
                        )
                    )
                )
        finally:
            if after_admission:
                post_save.disconnect(admitted, sender=VirtualminProvisioningJob)
        self.assertTrue(outcome.is_ok(), outcome)
        self.assertEqual(len(assigned), 1)
        self.assertEqual(gateway.get_calls("create-domain")[0].params["quota"], str(5632 * 1024))
        self.assertEqual(requests[0]["disk_limit_kib"], 5632 * 1024)
        limits = ServiceHostingLimits.objects.get(service=service)
        self.assertEqual((limits.revision, limits.applied_revision), (original_revision + 1, original_revision))

    def test_public_create_repairs_admitted_cap_after_mid_create_assignment(self):
        self.create_with_competing_assignment()

    def test_public_recreate_repairs_admitted_cap_after_mid_create_assignment(self):
        self.create_with_competing_assignment(recreate=True)

    def test_assignment_committed_after_admission_cannot_change_native_create_parameters(self):
        self.create_with_competing_assignment(after_admission=True)


class HostingParentAuthorityTests(ManagedSingleRestoreFixture, TransactionTestCase):
    def setUp(self):
        quiet_task_queue(self)
        super().setUp()

    def admit(self):
        with patch.object(VirtualminBackupService, "read_manifest", return_value=Ok(dict(self.manifest))):
            result = VirtualminBackupManagementService(self.server).create_restore_job(
                self.account, RestoreConfig("old-single", force_restore=True), initiated_by="staff"
            )
        self.assertTrue(result.is_ok(), result)
        return result.unwrap()

    def test_positional_conflict_upsert_cannot_replace_an_admitted_parent(self):
        job = self.admit()
        replacement = VirtualminProvisioningJob(
            pk=job.pk, account=self.account, server=self.server, operation="backup_domain", parameters={}
        )
        with self.assertRaises(ValidationError):
            VirtualminProvisioningJob.objects.bulk_create(
                [replacement], None, False, True, ["operation", "parameters", "hosting_limit_application"], ["id"]
            )

    def test_accepted_snapshot_and_binding_are_immutable_across_orm_writers(self):
        job = self.admit()
        accepted = deepcopy(job.parameters)
        changed = deepcopy(job.parameters)
        changed[SNAPSHOT_KEY]["disk_cap_mib"] += 1
        with self.assertRaises(ValidationError):
            VirtualminProvisioningJob.objects.filter(pk=job.pk).update(parameters=changed)
        job.parameters = changed
        with self.assertRaises(ValidationError):
            job.save(update_fields=["parameters"])
        with self.assertRaises(ValidationError):
            VirtualminProvisioningJob.objects.bulk_update([job], ["parameters"])
        with self.assertRaises(ValidationError):
            VirtualminProvisioningJob(
                pk=job.pk, account=self.account, server=self.server, operation="backup_domain"
            ).save()
        with self.assertRaises(ValidationError):
            VirtualminProvisioningJob.objects.filter(pk=job.pk).update(id=uuid4())
        with self.assertRaises(ValidationError):
            VirtualminProvisioningJob.objects.filter(pk=job.pk).update(
                parameters={**accepted, ISSUED_KEY: {"invented": True}}
            )
        job.refresh_from_db()
        self.assertEqual(job.parameters[BINDING_KEY]["job_id"], str(job.pk))
        self.assertNotIn(ISSUED_KEY, job.parameters)

    def test_issued_witness_requires_actual_dispatch_claim_and_refuses_rotated_nonce(self):
        job = self.admit()
        token = uuid4()
        self.assertEqual(
            VirtualminProvisioningJob.claim_execution(job.pk, token, timezone.now() + timedelta(minutes=5)), 1
        )
        job.refresh_from_db()
        scope = {
            "job_id": str(job.pk),
            "token": str(token),
            "account_server_id": str(self.server.pk),
            "native_server_id": str(self.server.pk),
        }
        self.assertTrue(held_parent_application_matches(self.application, scope))
        self.assertFalse(held_parent_cap_repair_issued(self.application, scope))
        self.assertTrue(mark_parent_limits_issued(job))
        self.assertTrue(held_parent_cap_repair_issued(self.application, scope))
        job.refresh_from_db()
        accepted = deepcopy(job.parameters)
        changed = deepcopy(accepted)
        changed[ISSUED_KEY][-1]["token"] = str(uuid4())
        with self.assertRaises(ValidationError):
            VirtualminProvisioningJob.objects.filter(pk=job.pk).update(parameters=changed)
        replacement = uuid4()
        VirtualminProvisioningJob.objects.filter(pk=job.pk).update(execution_token=replacement)
        self.assertFalse(held_parent_cap_repair_issued(self.application, scope))
        job.refresh_from_db()
        self.assertFalse(mark_parent_limits_issued(job))
        self.assertEqual(job.parameters, accepted)

    def test_create_repair_witness_requires_current_claim_and_keeps_prior_dispatch_history(self):
        job = VirtualminProvisioningJob.objects.create(
            account=self.account, server=self.server, operation="create_domain"
        )
        self.assertIsNone(begin_account_job(self.account, job))
        self.assertIsNone(job.execution_token)
        scope = {
            "job_id": str(job.pk),
            "token": "",
            "account_server_id": str(self.server.pk),
            "native_server_id": str(self.server.pk),
        }
        self.assertTrue(mark_parent_limits_issued(job))
        self.assertTrue(held_parent_cap_repair_issued(self.application, scope))
        first = deepcopy(job.parameters)
        stale = VirtualminProvisioningJob.objects.get(pk=job.pk)
        job.mark_failed("A bounded create retry is due", retriability=Retriability.RETRIABLE)
        VirtualminProvisioningJob.objects.filter(pk=job.pk).update(next_retry_at=timezone.now())
        claimed_at = timezone.now()
        self.assertTrue(VirtualminProvisioningJob.claim_for_retry(job.pk, claimed_at))
        self.assertTrue(VirtualminProvisioningJob.start_claimed(job.pk, timezone.now(), claimed_at.isoformat()))
        job.refresh_from_db()
        self.assertIsNone(job.execution_token)
        self.assertFalse(
            held_parent_cap_repair_issued(self.application, scope),
            "The earlier empty-token create witness must not authorize a new claim generation",
        )
        self.assertFalse(mark_parent_limits_issued(stale), "A stale delivery cannot append new dispatch authority")
        self.assertTrue(mark_parent_limits_issued(job))
        self.assertTrue(held_parent_cap_repair_issued(self.application, scope))
        self.assertEqual(job.parameters[SNAPSHOT_KEY], first[SNAPSHOT_KEY])
        self.assertEqual(job.parameters[ISSUED_KEY][:-1], first[ISSUED_KEY])
        self.assertEqual(len(job.parameters[ISSUED_KEY]), 2)
        self.assertNotEqual(job.parameters[ISSUED_KEY][0]["started_at"], job.parameters[ISSUED_KEY][1]["started_at"])
        self.assertEqual(job.parameters[ISSUED_KEY][1]["claimed_at"], claimed_at.isoformat())
        accepted = deepcopy(job.parameters)
        self.assertTrue(mark_parent_limits_issued(job))
        self.assertEqual(job.parameters, accepted, "Repeated dispatch publication on one claim is idempotent")
        changed = deepcopy(accepted)
        changed[ISSUED_KEY][0]["token"] = "invented"
        with self.assertRaises(ValidationError):
            VirtualminProvisioningJob.objects.filter(pk=job.pk).update(parameters=changed)
        for history in (accepted[ISSUED_KEY][1:], [*accepted[ISSUED_KEY], accepted[ISSUED_KEY][-1]]):
            with self.assertRaises(ValidationError):
                VirtualminProvisioningJob.objects.filter(pk=job.pk).update(parameters={**accepted, ISSUED_KEY: history})

    def stale_progress_write(self, *, model_save):
        if connection.vendor != "postgresql":
            self.skipTest("Exact waited metadata mutation proof requires PostgreSQL")
        job = self.admit()
        token = uuid4()
        VirtualminProvisioningJob.claim_execution(job.pk, token, timezone.now() + timedelta(minutes=5))
        job.refresh_from_db()
        start, writer = Event(), backend_pid()

        def progress():
            assert start.wait(10)
            stale = VirtualminProvisioningJob.objects.get(pk=job.pk)
            values = {**stale.parameters, "progress": "old callback"}
            if not model_save:
                return VirtualminProvisioningJob.objects.filter(pk=job.pk, execution_token=token).update(
                    parameters=values
                )
            stale.parameters = values
            try:
                stale.save(update_fields=["parameters"])
            except DatabaseError:
                return 0
            return 1

        with database_worker(progress) as (pid, pending):
            with transaction.atomic():
                self.assertTrue(mark_parent_limits_issued(job))
                start.set()
                wait_for_blocker(pid, writer, pending, table="provisioning_virtualmin_jobs", operation="UPDATE")
            self.assertEqual(pending.result(timeout=30), 0)
        job.refresh_from_db()
        self.assertIn(ISSUED_KEY, job.parameters)
        self.assertNotIn("progress", job.parameters)

    def test_waited_queryset_progress_write_cannot_erase_new_dispatch_evidence(self):
        self.stale_progress_write(model_save=False)

    def test_waited_model_progress_save_cannot_erase_new_dispatch_evidence(self):
        self.stale_progress_write(model_save=True)
