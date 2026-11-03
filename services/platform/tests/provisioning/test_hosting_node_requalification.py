"""Fresh native reboot observations revoke current proof before dispatch refusal."""

from copy import deepcopy
from datetime import timedelta
from decimal import Decimal
from threading import Event
from unittest.mock import patch
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.db import transaction
from django.test import TransactionTestCase
from django.utils import timezone

from apps.common.types import Err, Ok
from apps.provisioning.hosting_limit_execution import (
    _fail_unissued,
    _prepare_dispatch,
    admit_application,
    ensure_managed_limits,
    freeze_migration_limits,
    quota_transport_refusal,
    reserve_managed_creation,
    resolve_quota_job,
)
from apps.provisioning.hosting_limit_execution_models import HostingLimitExecution
from apps.provisioning.hosting_limit_models import ServiceHostingLimits
from apps.provisioning.hosting_limit_policy import effective_disk_limit
from apps.provisioning.hosting_limit_transport import probe_account_quota
from apps.provisioning.hosting_node_execution import (
    claim_hosting_operation,
    hosting_transport_allowed,
    record_hosting_inspection,
)
from apps.provisioning.hosting_node_policy import managed_quota_refusal
from apps.provisioning.hosting_node_policy_models import NodeHostingPolicy
from apps.provisioning.hosting_node_tasks import review_node_hosting
from apps.provisioning.service_models import Service, ServicePlan
from apps.provisioning.virtualmin_gateway import VirtualminResponse
from apps.provisioning.virtualmin_migration_models import MigrationBridge, VirtualminMigration
from apps.provisioning.virtualmin_migration_service import resolve_migration
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from apps.provisioning.virtualmin_pair_restore import PairStepResult, hold_half_restored, resolve_pair_job
from tests.common.postgres_locking import backend_pid, database_worker, wait_for_blocker
from tests.provisioning.test_hosting_limit_execution import HostingLimitWorkerFixture
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase


class HostingNodeDispatchRequalificationTests(HostingLimitWorkerFixture, TransactionTestCase):
    def setUp(self):
        queue = patch("apps.provisioning.hosting_limit_tasks.async_task")
        queue.start()
        self.addCleanup(queue.stop)
        VirtualminTaskTestBase.setUp(self)
        self.setup_native_fixture()

    def test_dispatch_rejects_new_boot_and_commits_invalidation_before_raising(self):
        execution = admit_application(self.application.pk)
        self.assertIsNotNone(execution)
        ServiceHostingLimits.objects.filter(service=self.service).update(verified_at=timezone.now())
        historical = deepcopy(self.policy.quota_evidence)
        receipt = self.receipt()
        receipt["identity"] = {**self.native_identity, "boot_id": str(uuid4())}
        with self.assertRaises(ValidationError):
            _prepare_dispatch(execution.pk, receipt)
        self.assertIsNone(NodeHostingPolicy.objects.get(pk=self.policy.pk).quota_verified_at)
        self.assertIsNone(ServiceHostingLimits.objects.get(service=self.service).verified_at)
        self.assertEqual(NodeHostingPolicy.objects.get(pk=self.policy.pk).quota_evidence, historical)
        execution.refresh_from_db()
        self.assertEqual(execution.phase, "prepared")
        self.assertEqual(execution.request, {})

    def test_public_parent_resolution_keeps_restore_held_then_releases_child_capacity_for_readoption(self):
        parent = VirtualminProvisioningJob.objects.create(
            operation="restore_domain",
            server=self.server,
            account=self.account,
            status="running",
            execution_token=uuid4(),
            parameters={
                "managed_single_restore": True,
                "pair_node_step": "quota_verification",
                "pair_token": str(uuid4()),
                "virtualmin_domain_id": "12345",
            },
        )
        parent_scope = {
            "job_id": str(parent.pk),
            "token": str(parent.execution_token),
            "account_server_id": str(self.server.pk),
            "native_server_id": str(self.server.pk),
        }
        child = admit_application(self.application.pk, parent=parent_scope)
        self.assertIsNotNone(child)
        child.reserved_bytes = 5632 * 1024**2
        child.save(update_fields=["reserved_bytes", "updated_at"])
        fresh = self.receipt()
        fresh["identity"] = {**self.native_identity, "boot_id": str(uuid4())}
        with self.assertRaises(ValidationError):
            _prepare_dispatch(child.pk, fresh)
        _fail_unissued(child.pk, "Node rebooted during restore")
        parent.mark_attention("Quota verification requires node requalification")
        hold_half_restored(self.account, parent.parameters)
        inventory = {
            "identity": self.policy.connection_identity,
            "quota": {
                **self.policy.quota_evidence,
                "boot_id": fresh["identity"]["boot_id"],
                "requalification_required": True,
            },
        }
        review = record_hosting_inspection(self.server, inventory)
        with self.assertRaises(ValidationError):
            claim_hosting_operation(review, inventory, self.staff, "adopt_quota", "Requalify reboot")
        child.job.refresh_from_db()
        self.assertTrue(resolve_quota_job(child.job, resolved_by="staff", note="Parent still held").is_err())
        with (
            patch("apps.provisioning.virtualmin_pair_restore.run_pair_step", return_value=Err("unreachable")),
            patch("apps.provisioning.virtualmin_tasks.reconcile_virtualmin_service_state_async") as enable,
        ):
            self.assertTrue(resolve_pair_job(parent, resolved_by="staff", note="Fence parent").is_err())
            parent.refresh_from_db()
            self.assertEqual(parent.status, "attention")
            enable.assert_not_called()
        with (
            patch(
                "apps.provisioning.virtualmin_pair_restore.run_pair_step",
                return_value=Ok(
                    PairStepResult(outcome="released", reason="barrier_removed", ran=False, checkpoints=())
                ),
            ) as release,
            patch("apps.provisioning.virtualmin_tasks.reconcile_virtualmin_service_state_async") as enable,
        ):
            self.assertTrue(resolve_pair_job(parent, resolved_by="staff", note="Permanently fence parent").is_ok())
            self.assertEqual(release.call_args.args[1]["pair_action"], "release")
            enable.assert_not_called()
        self.account.refresh_from_db()
        self.assertEqual(self.account.restore_hold, "half_restored")
        self.assertTrue(resolve_quota_job(child.job, resolved_by="staff", note="Parent safely held").is_ok())
        child.refresh_from_db()
        self.assertIsNotNone(child.reservation_released_at)
        run = claim_hosting_operation(review, inventory, self.staff, "adopt_quota", "Requalify held node")
        self.assertIsNotNone(run.pk)
        self.account.refresh_from_db()
        self.assertEqual(self.account.restore_hold, "half_restored")

    def test_public_readonly_probe_observes_changed_boot_without_relaxing_mutation_identity(self):
        execution = admit_application(self.application.pk)
        self.assertIsNotNone(execution)
        response = VirtualminResponse(
            success=True,
            data={
                "data": [
                    {
                        "name": self.account.domain,
                        "values": {"ID": ["12345"], "Username": [self.account.virtualmin_username]},
                    }
                ]
            },
            raw_response="{}",
            http_status=200,
            execution_time=0,
            program="list-domains",
            server_hostname=self.server.hostname,
        )
        fresh = self.receipt()
        fresh["identity"] = {**self.native_identity, "boot_id": str(uuid4())}

        def native(server, action, request):
            self.assertEqual(action, "probe")
            self.assertNotIn("boot_id", request["identity"])
            self.assertEqual(request["identity"]["installation"], self.native_identity["installation"])
            self.assertEqual(request["identity"]["filesystem_uuid"], self.native_identity["filesystem_uuid"])
            self.assertIsNone(quota_transport_refusal(server, {"quota_action": action, "quota_request": request}))
            self.assertIsNotNone(quota_transport_refusal(server, {"quota_action": "apply", "quota_request": request}))
            return fresh

        with (
            patch("apps.provisioning.virtualmin_gateway.VirtualminGateway.call", return_value=Ok(response)),
            patch("apps.provisioning.hosting_node_transport.run_quota_operation", side_effect=native),
        ):
            observed = probe_account_quota(execution)
        self.assertEqual(observed["identity"]["boot_id"], fresh["identity"]["boot_id"])
        with self.assertRaises(ValidationError):
            _prepare_dispatch(execution.pk, observed)
        self.assertIsNone(NodeHostingPolicy.objects.get(pk=self.policy.pk).quota_verified_at)

    def _qualified_paused_migration(self):
        source = VirtualminServer.objects.create(hostname="old-source.example.test")
        token = uuid4()
        migration = VirtualminMigration.objects.create(
            account=self.account,
            source_server=source,
            target_server=self.server,
            status="activating",
            contract="cutover",
            cutover_committed_at=timezone.now(),
            lease_token=token,
            worker_lease_expires_at=timezone.now() + timedelta(minutes=5),
            pre_migration_snapshot={"hosting_limits": freeze_migration_limits(self.account)},
        )
        bridge = MigrationBridge.objects.create(
            migration=migration,
            source_server=source,
            target_server=self.server,
            domain=self.account.domain,
            status="failed",
        )
        parent = {
            "migration_id": str(migration.pk),
            "token": str(token),
            "account_server_id": str(source.pk),
            "native_server_id": str(self.server.pk),
            "approved_application_id": str(self.application.pk),
            "frozen_application_id": str(self.application.pk),
        }
        child = admit_application(self.application.pk, parent=parent)
        self.assertIsNotNone(child)
        child.reserved_bytes = 5632 * 1024**2
        child.save(update_fields=["reserved_bytes", "updated_at"])
        fresh = self.receipt()
        fresh["identity"] = {**self.native_identity, "boot_id": str(uuid4())}
        with self.assertRaises(ValidationError):
            _prepare_dispatch(child.pk, fresh)
        _fail_unissued(child.pk, "Native target rebooted after cutover")
        self.assertTrue(
            migration.transition(
                token,
                "activating",
                "needs_review",
                parked_phase="activating",
                lease_token=None,
                worker_lease_expires_at=None,
            )
        )
        inventory = {
            "identity": self.policy.connection_identity,
            "quota": {
                **self.policy.quota_evidence,
                "boot_id": fresh["identity"]["boot_id"],
                "requalification_required": True,
            },
        }
        review = record_hosting_inspection(self.server, inventory)
        with self.assertRaises(ValidationError):
            claim_hosting_operation(review, inventory, self.staff, "adopt_quota", "Normal adoption stays excluded")

        def native(server, action, request):
            if action == "inspect":
                return inventory
            self.assertEqual(action, "requalify")
            self.assertTrue(hosting_transport_allowed(server, {"hosting_action": action, "hosting_request": request}))
            self.assertFalse(
                hosting_transport_allowed(server, {"hosting_action": "quota_policy", "hosting_request": request})
            )
            return {
                **inventory,
                "quota": {**inventory["quota"], "requalification_required": False, "qualification_id": str(uuid4())},
                "fenced_token": request["token"],
            }

        with patch("apps.provisioning.hosting_node_tasks.run_node_operation", side_effect=native):
            result = review_node_hosting(
                str(self.server.pk),
                str(self.staff.pk),
                "requalify_quota",
                {"review_id": str(review.pk), "reason": "Only isolated same-node reboot qualification"},
            )
        self.assertEqual(result["outcome"], "verified", result)
        self.assertIsNone(managed_quota_refusal(self.server))
        migration.refresh_from_db()
        bridge.refresh_from_db()
        child.refresh_from_db()
        self.assertEqual(migration.status, "needs_review")
        self.assertIsNotNone(migration.cutover_committed_at)
        self.assertEqual(bridge.status, "failed")
        self.assertEqual(child.phase, "attention")
        self.assertEqual(child.reserved_bytes, 5632 * 1024**2)
        self.assertIsNone(child.reservation_released_at)
        self.assertIsNone(ServiceHostingLimits.objects.get(service=self.service).verified_at)
        return migration, bridge, child, fresh

    def _transfer_with_competing_capacity(self, migration, child):
        plan = ServicePlan.objects.create(name="Competing create", price_monthly=10, disk_space_gb=1, bandwidth_gb=2)
        service = Service.objects.create(
            customer=self.customer,
            service_plan=plan,
            currency=self.currency,
            service_name="Competing create",
            domain="competing.example.test",
            username="competing",
            price=Decimal(10),
        )
        account = VirtualminAccount.objects.create(
            service=service,
            server=self.server,
            domain=service.domain,
            virtualmin_username="competing",
            status="provisioning",
        )
        job = VirtualminProvisioningJob.objects.create(
            account=account, server=self.server, operation="create_domain", status="running", execution_token=uuid4()
        )
        cap = effective_disk_limit(ServiceHostingLimits.objects.get(service=service).disk_allowance_mib)
        self.assertIsNotNone(cap)
        available = child.reserved_bytes + (1024 + cap) * 1024**2 - 1
        start = Event()

        def competing():
            assert start.wait(10)
            return reserve_managed_creation(account, job, available)

        parent = {**child.job.parameters["quota_parent"], "token": str(migration.lease_token)}
        writer = backend_pid()
        with database_worker(competing) as (pid, pending):
            with transaction.atomic():
                replacement = admit_application(self.application.pk, parent=parent)
                self.assertIsNotNone(replacement)
                self.assertNotEqual(replacement.pk, child.pk)
                self.assertEqual(replacement.reserved_bytes, child.reserved_bytes)
                start.set()
                wait_for_blocker(pid, writer, pending, table="provisioning_virtualmin_servers")
            result = pending.result(timeout=30)
        self.assertTrue(result.is_err(), "Competing creation consumed a transferred capacity claim")
        self.assertIn("capacity", result.unwrap_err().lower())

    def _resume_migration(self, migration):
        with patch("apps.provisioning.virtualmin_migration_service.VirtualminMigrationService._enqueue"):
            resumed = resolve_migration(
                migration, resolved_by=self.staff, note="Isolated reboot qualification verified"
            )
        self.assertTrue(resumed.is_ok(), resumed)
        migration.refresh_from_db()
        self.assertEqual(migration.status, "activating")
        self.assertTrue(migration.acquire_lease(uuid4(), timedelta(minutes=5)))
        migration.refresh_from_db()

    def test_issued_unknown_retargeted_and_overlay_attempts_never_transfer_capacity(self):
        migration, _bridge, child, _fresh = self._qualified_paused_migration()
        self._resume_migration(migration)
        parent = {**child.job.parameters["quota_parent"], "token": str(migration.lease_token)}
        for change in (
            {"issued_at": timezone.now()},
            {"request": {"unknown": True}},
            {"receipt": {"unknown": True}},
            {"overlay_revision": 1},
            {"identity": {**child.identity, "filesystem_uuid": str(uuid4())}},
            {"phase": "issued"},
        ):
            with self.subTest(change=change):
                HostingLimitExecution.objects.filter(pk=child.pk).update(**change)
                self.assertIsNone(admit_application(self.application.pk, parent=parent))
                self.assertEqual(HostingLimitExecution.objects.count(), 1)
                current = HostingLimitExecution.objects.get(pk=child.pk)
                self.assertIsNone(current.reservation_released_at)
                self.assertEqual(current.reserved_bytes, child.reserved_bytes)
                HostingLimitExecution.objects.filter(pk=child.pk).update(
                    issued_at=None,
                    request={},
                    receipt={},
                    overlay_revision=0,
                    identity=child.identity,
                    phase="attention",
                )
        replacement = admit_application(self.application.pk, parent=parent)
        self.assertIsNotNone(replacement)
        self.assertNotEqual(replacement.pk, child.pk)

    def test_paused_committed_migration_can_requalify_node_without_releasing_parent_or_child_holds(self):
        migration, _bridge, child, fresh = self._qualified_paused_migration()
        self._resume_migration(migration)
        self._transfer_with_competing_capacity(migration, child)
        dispatches = []

        def apply(server, action, request):
            self.assertEqual(action, "apply")
            self.assertGreater(request["generation"], child.account_epoch)
            dispatches.append(request)
            child.refresh_from_db()
            self.assertEqual(child.phase, "superseded")
            current = HostingLimitExecution.objects.filter(job__account_id=self.account.pk).exclude(pk=child.pk).get()
            self.assertEqual(current.reserved_bytes, child.reserved_bytes)
            self.assertIsNone(current.reservation_released_at)
            self.assertIsNotNone(child.reservation_released_at)
            self.assertEqual(current.job.parameters["quota_reservation_from"], str(child.pk))
            result = self.receipt(cap=request["disk_limit_kib"] // 1024, request=request)
            result["identity"] = fresh["identity"]
            return result

        with (
            patch("apps.provisioning.hosting_limit_transport.probe_account_quota", return_value=fresh),
            patch("apps.provisioning.hosting_limit_transport.run_quota_operation", side_effect=apply),
        ):
            result = ensure_managed_limits(self.account, migration=migration)
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(len(dispatches), 1)
        self.assertIsNone(
            _prepare_dispatch(child.pk, fresh), "Delayed old read-only probe issued after reservation handoff"
        )
        migration.refresh_from_db()
        self.assertEqual(migration.status, "activating")
