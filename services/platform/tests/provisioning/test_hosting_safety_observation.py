"""Fresh safety is a durable read-only job, independent of old applied receipts."""

from copy import deepcopy
from datetime import timedelta
from threading import Event
from unittest import skipUnless
from unittest.mock import patch
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.db import connection, transaction
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from apps.billing.plan_change_safety import current_safety_used_bytes
from apps.common.types import Ok
from apps.customers.models import Customer
from apps.infrastructure.node_maintenance_gate import begin_account_job
from apps.provisioning.hosting_limit_execution import admit_application, apply_hosting_limits, quota_transport_refusal
from apps.provisioning.hosting_limit_execution_models import HostingLimitExecution
from apps.provisioning.hosting_limit_models import ServiceHostingLimits
from apps.provisioning.hosting_limit_override_service import grant_resource_override
from apps.provisioning.hosting_node_policy_models import NodeHostingPolicy
from apps.provisioning.hosting_safety_observation import (
    _claim,
    dispatch_hosting_safety_observations,
    request_safety_refresh,
    run_hosting_safety_observation,
)
from apps.provisioning.service_models import ServicePlan
from apps.provisioning.virtualmin_gateway import VirtualminResponse
from apps.provisioning.virtualmin_migration_models import account_has_active_operation
from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from apps.provisioning.virtualmin_recovery_service import VirtualminRecoveryService
from apps.provisioning.virtualmin_security import connection_identity
from apps.provisioning.virtualmin_service import VirtualminBackupManagementService, VirtualminProvisioningService
from apps.provisioning.virtualmin_usage_service import capture, current_state, publish_snapshot
from apps.tickets.models import Ticket
from apps.users.models import CustomerMembership, User
from tests.common.postgres_locking import backend_pid, database_worker, wait_for_blocker
from tests.provisioning.test_hosting_node_policy import quota_evidence
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase


class HostingSafetyObservationFixture:
    def setUp(self):
        VirtualminTaskTestBase.setUp(self)
        self.account.status = "active"
        self.account.save(update_fields=["status"])
        self.actor = User.objects.create_user(email="safety-owner@example.test", password=None)
        CustomerMembership.objects.create(user=self.actor, customer=self.customer, role="owner", is_active=True)
        evidence = quota_evidence()
        evidence["identity"] = connection_identity(self.server)
        self.policy = NodeHostingPolicy.objects.create(
            server=self.server,
            connection_identity=evidence["identity"],
            quota_adopted=True,
            quota_verified_at=timezone.now(),
            quota_evidence=evidence,
        )
        self.identity = {key: evidence[key] for key in ("installation", "filesystem_uuid", "boot_id")}
        self.identity.update(domain_id="12345", domain=self.account.domain, uid=1001, gid=1001)
        current_state(self.account)

    def publish_canonical(self, total=32000):
        now = timezone.now()
        payload = {
            "version": 1,
            "installation": self.identity["installation"],
            "observed_at": now.isoformat(),
            "records": [
                {
                    "domain": self.account.domain,
                    "username": self.account.virtualmin_username,
                    "domain_id": "12345",
                    "scan_started_at": now.isoformat(),
                    "scan_finished_at": now.isoformat(),
                    "disk_files_bytes": total - 1000,
                    "disk_db_bytes": 1000,
                    "databases": 1,
                    "mailboxes": 0,
                    "segments": [],
                }
            ],
        }
        self.assertEqual(publish_snapshot(self.server.pk, payload, capture(self.server)), 1)

    def probe(self):
        return {
            "schema": 1,
            "identity": self.identity,
            "observed_at": timezone.now().isoformat(),
            "filesystem": "ext4",
            "storage_qualified": True,
            "uid_enforced": True,
            "gid_enforced": True,
            "uid_soft_kib": 1024,
            "uid_hard_kib": 1024,
            "gid_soft_kib": 1024,
            "gid_hard_kib": 1024,
            "uid_used_bytes": 9000,
            "gid_used_bytes": 12000,
            "available_bytes": 10 * 1024**3,
            "configured_quota_kib": 1024,
            "configured_uquota_kib": 1024,
            "configured_bandwidth_bytes": 1024**3,
            "bandwidth_actions_safe": True,
        }

    def request(self):
        with patch("apps.provisioning.hosting_safety_observation.async_task"):
            return request_safety_refresh(self.service.pk, self.customer.pk, self.actor.pk)

    def run_observer(self, job, probe=None, effect=None):
        listing = VirtualminResponse(
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

        def native(server, action, request):
            self.assertFalse(connection.in_atomic_block)
            self.assertEqual(action, "probe")
            self.assertEqual(request["disk_limit_kib"], 0)
            self.assertEqual(request["bandwidth_limit_bytes"], 0)
            self.assertIsNone(quota_transport_refusal(server, {"quota_action": action, "quota_request": request}))
            self.assertIsNotNone(quota_transport_refusal(server, {"quota_action": "apply", "quota_request": request}))
            if effect is not None:
                effect()
            return self.probe() if probe is None else probe

        with (
            patch("apps.provisioning.virtualmin_gateway.VirtualminGateway.call", return_value=Ok(listing)),
            patch("apps.provisioning.hosting_node_transport.run_quota_operation", side_effect=native) as transport,
        ):
            outcome = run_hosting_safety_observation(str(job.pk), str(job.execution_token))
        return outcome, transport.call_count


class HostingSafetyObservationTests(HostingSafetyObservationFixture, TransactionTestCase):
    def test_real_canonical_publication_and_readonly_job_produce_exact_current_safety(self):
        self.publish_canonical()
        self.assertIsNone(current_safety_used_bytes(self.service))
        epoch = self.account.quota_generation
        job = self.request()
        self.assertEqual(job.operation, "observe_hosting_limits")
        self.assertEqual(job.status, "pending")
        self.assertEqual(self.run_observer(job), ("completed", 1))
        job.refresh_from_db()
        self.assertEqual(job.result["components"], {"uid_bytes": 9000, "gid_bytes": 12000, "canonical_bytes": 32000})
        self.assertEqual(current_safety_used_bytes(self.service), 32000)
        self.account.refresh_from_db()
        self.assertEqual(self.account.quota_generation, epoch)
        self.assertEqual(self.account.status, "active")
        self.assertFalse(self.account.quota_managed)
        self.assertEqual(self.run_observer(job), ("completed", 0))

    def test_missing_canonical_evidence_never_falls_back_to_kernel_usage_or_old_receipts(self):
        job = self.request()
        outcome, calls = self.run_observer(job)
        self.assertEqual((outcome, calls), ("failed", 1))
        self.assertIsNone(current_safety_used_bytes(self.service))
        job.refresh_from_db()
        self.assertEqual(job.result, {})

    def test_successful_old_quota_receipt_is_not_current_canonical_safety(self):
        staff = User.objects.create_superuser(email="safety-staff@example.test", password=None)
        plan = ServicePlan.objects.create(
            name="Approved limits", plan_type=self.plan.plan_type, price_monthly=20, disk_space_gb=5, bandwidth_gb=20
        )
        ticket = Ticket.objects.create(customer=self.customer, title="Adopt native limits", description="Approved")
        with patch("apps.provisioning.hosting_limit_tasks.async_task"):
            application = grant_resource_override(
                user=staff,
                service=self.service,
                target_plan_id=plan.pk,
                ticket_id=ticket.pk,
                reason="Explicitly adopt the existing native account",
                expected_revision=1,
                submission_id=uuid4(),
                billing_unchanged=True,
                adopt_existing_native_limits=True,
            )
        before = {**self.probe(), "observation": {"files_bytes": 40000, "database_bytes": 10000, "total_bytes": 50000}}

        def applied(server, action, request):
            self.assertEqual(action, "apply")
            receipt = {
                **before,
                "observed_at": timezone.now().isoformat(),
                "token": request["token"],
                "generation": request["generation"],
                "configured_bandwidth_bytes": request["bandwidth_limit_bytes"],
            }
            receipt.update(
                dict.fromkeys(
                    (
                        "uid_soft_kib",
                        "uid_hard_kib",
                        "gid_soft_kib",
                        "gid_hard_kib",
                        "configured_quota_kib",
                        "configured_uquota_kib",
                    ),
                    request["disk_limit_kib"],
                )
            )
            return receipt

        with (
            patch("apps.provisioning.hosting_limit_transport.probe_account_quota", return_value=before),
            patch("apps.provisioning.hosting_limit_transport.run_quota_operation", side_effect=applied),
        ):
            self.assertEqual(apply_hosting_limits(application.pk), "completed")
        limits = ServiceHostingLimits.objects.get(service=self.service)
        self.assertIsNotNone(limits.verified_at)
        self.assertEqual(limits.verified_receipt["observation"]["total_bytes"], 50000)
        job = self.request()
        self.assertEqual(self.run_observer(job), ("failed", 1))
        self.assertIsNone(current_safety_used_bytes(self.service))

    def test_result_is_immutable_and_scope_and_strict_time_are_rechecked(self):
        self.publish_canonical()
        job = self.request()
        self.assertEqual(self.run_observer(job), ("completed", 1))
        with self.assertRaises(ValidationError):
            VirtualminProvisioningJob.objects.filter(pk=job.pk).update(result={})
        with patch("apps.billing.plan_change_safety.timezone.now", return_value=timezone.now() + timedelta(minutes=6)):
            self.assertIsNone(current_safety_used_bytes(self.service))
        self.server.api_port += 1
        self.server.save(update_fields=["api_port"])
        self.assertIsNone(current_safety_used_bytes(self.service))

    def test_new_failed_refresh_never_revives_older_snapshot(self):
        self.publish_canonical()
        first = self.request()
        self.assertEqual(self.run_observer(first), ("completed", 1))
        latest = self.request()
        self.assertNotEqual(first.pk, latest.pk)
        self.assertIsNone(current_safety_used_bytes(self.service))
        invalid = self.probe()
        invalid["storage_qualified"] = False
        self.assertEqual(self.run_observer(latest, invalid), ("failed", 1))
        self.assertIsNone(current_safety_used_bytes(self.service))

    def test_native_probe_canonical_is_a_distinct_fresh_numerator(self):
        job = self.request()
        probe = self.probe()
        probe.update(
            uid_used_bytes=80000,
            gid_used_bytes=120000,
            observation={"files_bytes": 9000, "database_bytes": 1000, "total_bytes": 10000},
        )
        self.assertEqual(self.run_observer(job, probe), ("completed", 1))
        self.assertEqual(current_safety_used_bytes(self.service), 120000)
        job.refresh_from_db()
        self.assertEqual(job.result["components"]["canonical_bytes"], 10000)

    def test_stale_future_and_malformed_raw_observations_fail_closed(self):
        self.publish_canonical()
        for change in (
            {"observed_at": (timezone.now() - timedelta(seconds=61)).isoformat()},
            {"observed_at": (timezone.now() + timedelta(seconds=3)).isoformat()},
            {"uid_used_bytes": True},
            {"gid_used_bytes": -1},
            {"observation": {"files_bytes": 1000, "database_bytes": 1000, "total_bytes": 0}},
        ):
            with self.subTest(change=change):
                job = self.request()
                self.assertEqual(self.run_observer(job, {**self.probe(), **change}), ("failed", 1))
                self.assertIsNone(current_safety_used_bytes(self.service))

    def test_actor_revocation_and_owner_retarget_during_io_cannot_publish(self):
        self.publish_canonical()
        job = self.request()

        def revoke():
            CustomerMembership.objects.filter(user=self.actor, customer=self.customer).update(is_active=False)

        self.assertEqual(self.run_observer(job, effect=revoke), ("failed", 1))
        CustomerMembership.objects.filter(user=self.actor, customer=self.customer).update(is_active=True)
        job = self.request()
        other = Customer.objects.create(name="New observation owner", status="active")

        def retarget():
            self.service.customer = other
            self.service.save(update_fields=["customer"])

        self.assertEqual(self.run_observer(job, effect=retarget), ("failed", 1))
        self.assertIsNone(current_safety_used_bytes(self.service))

    def test_epoch_change_and_expired_running_lease_discard_late_probe(self):
        self.publish_canonical()
        job = self.request()
        before = self.account.quota_generation

        def change_epoch():
            self.account.quota_generation += 1
            self.account.save(update_fields=["quota_generation"])

        self.assertEqual(self.run_observer(job, effect=change_epoch), ("failed", 1))
        self.account.refresh_from_db()
        self.assertEqual(self.account.quota_generation, before + 1)
        job = self.request()

        def expire():
            with patch(
                "apps.provisioning.hosting_safety_observation.timezone.now",
                return_value=timezone.now() + timedelta(minutes=5),
            ):
                dispatch_hosting_safety_observations()

        self.assertEqual(self.run_observer(job, effect=expire), ("superseded", 1))
        self.assertEqual(self.run_observer(job), ("failed", 0))
        self.assertIsNone(current_safety_used_bytes(self.service))

    def test_pending_coalescing_nonce_replay_and_queue_failure_preserve_durable_job(self):
        with patch(
            "apps.provisioning.hosting_safety_observation.async_task", side_effect=RuntimeError("broker unavailable")
        ):
            first = request_safety_refresh(self.service.pk, self.customer.pk, self.actor.pk)
        self.assertEqual(self.request().pk, first.pk)
        self.assertEqual(run_hosting_safety_observation(str(first.pk), str(uuid4())), "superseded")
        with patch("apps.provisioning.hosting_safety_observation.async_task") as queue:
            self.assertEqual(dispatch_hosting_safety_observations(), 1)
            self.assertEqual(queue.call_count, 1)
        first.refresh_from_db()
        self.assertEqual(first.status, "pending")

    def test_refresh_never_enters_a_financial_transaction_or_unauthorized_tenant(self):
        with transaction.atomic(), self.assertRaises(RuntimeError):
            self.request()
        outsider = User.objects.create_user(email="safety-outsider@example.test", password=None)
        with self.assertRaises(ValidationError):
            request_safety_refresh(self.service.pk, self.customer.pk, outsider.pk)
        self.assertFalse(VirtualminProvisioningJob.objects.exists())

    def test_completed_job_scope_cannot_change_via_save_bulk_or_constructed_overwrite(self):
        self.publish_canonical()
        job = self.request()
        self.assertEqual(self.run_observer(job), ("completed", 1))
        job.refresh_from_db()
        accepted = deepcopy(job.result)
        job.operation = "backup_domain"
        with self.assertRaises(ValidationError):
            job.save(update_fields=["operation"])
        with self.assertRaises(ValidationError):
            VirtualminProvisioningJob.objects.bulk_update([job], ["operation"])
        with self.assertRaises(ValidationError):
            VirtualminProvisioningJob(
                pk=job.pk, operation="backup_domain", server=self.server, account=self.account, result={}
            ).save()
        self.assertEqual(VirtualminProvisioningJob.objects.get(pk=job.pk).result, accepted)

    def test_conflict_upsert_cannot_replace_completed_observation_with_another_operation(self):
        self.publish_canonical()
        job = self.request()
        self.assertEqual(self.run_observer(job), ("completed", 1))
        replacement = VirtualminProvisioningJob(
            pk=job.pk, operation="backup_domain", server=self.server, account=self.account, result={}
        )
        with self.assertRaises(ValidationError):
            VirtualminProvisioningJob.objects.bulk_create(
                [replacement], update_conflicts=True, update_fields=["operation", "result"], unique_fields=["id"]
            )

    def test_completed_observation_primary_key_cannot_be_moved(self):
        self.publish_canonical()
        job = self.request()
        self.assertEqual(self.run_observer(job), ("completed", 1))
        with self.assertRaises(ValidationError):
            VirtualminProvisioningJob.objects.filter(pk=job.pk).update(id=uuid4())

    @skipUnless(connection.vendor == "postgresql", "Requires PostgreSQL row locks and observed blocker PIDs")
    def test_waited_claim_rechecks_epoch_before_any_native_read(self):
        self.publish_canonical()
        job = self.request()
        writer, start = backend_pid(), Event()

        def observe():
            assert start.wait(10)
            return self.run_observer(job)

        with database_worker(observe) as (pid, pending):
            with transaction.atomic():
                locked = VirtualminAccount.objects.select_for_update(of=("self",)).get(pk=self.account.pk)
                locked.quota_generation += 1
                locked.save(update_fields=["quota_generation"])
                start.set()
                wait_for_blocker(pid, writer, pending, table="provisioning_virtualmin_accounts")
            self.assertEqual(pending.result(timeout=30), ("failed", 0))
        self.assertIsNone(current_safety_used_bytes(self.service))

    @skipUnless(connection.vendor == "postgresql", "Requires PostgreSQL row locks and observed blocker PIDs")
    def test_waited_publication_rechecks_changed_epoch_after_real_probe(self):
        self.publish_canonical()
        job = self.request()
        writer, probing, finish = backend_pid(), Event(), Event()

        def paused_probe():
            probing.set()
            assert finish.wait(10)

        with database_worker(lambda: self.run_observer(job, effect=paused_probe)) as (pid, pending):
            self.assertTrue(probing.wait(10))
            with transaction.atomic():
                account = VirtualminAccount.objects.select_for_update(of=("self",)).get(pk=self.account.pk)
                account.quota_generation += 1
                account.save(update_fields=["quota_generation"])
                finish.set()
                wait_for_blocker(pid, writer, pending, table="provisioning_virtualmin_accounts")
            self.assertEqual(pending.result(timeout=30), ("failed", 1))
        job.refresh_from_db()
        self.assertEqual(job.result, {})
        self.assertIsNone(current_safety_used_bytes(self.service))

    def test_selector_performs_only_reads_inside_financial_transaction_and_rechecks_base_revision(self):
        self.publish_canonical()
        job = self.request()
        self.assertEqual(self.run_observer(job), ("completed", 1))
        with (
            transaction.atomic(),
            patch("apps.provisioning.hosting_node_transport.run_quota_operation") as network,
            patch("apps.provisioning.virtualmin_gateway.VirtualminGateway.call") as api,
        ):
            self.assertEqual(current_safety_used_bytes(self.service), 32000)
            network.assert_not_called()
            api.assert_not_called()
        limits = ServiceHostingLimits.objects.get(service=self.service)
        limits.revision += 1
        limits.save(update_fields=["revision"])
        self.assertIsNone(current_safety_used_bytes(self.service))

    def test_customer_privacy_reboot_and_foreign_native_owner_fail_closed(self):
        self.publish_canonical()
        job = self.request()
        probe = self.probe()
        probe["identity"] = {**self.identity, "boot_id": str(uuid4())}
        self.assertEqual(self.run_observer(job, probe), ("failed", 1))
        self.policy.refresh_from_db()
        self.assertIsNone(self.policy.quota_verified_at)
        self.assertIsNone(current_safety_used_bytes(self.service))
        self.policy.quota_verified_at = timezone.now()
        self.policy.save(update_fields=["quota_verified_at"])
        job = self.request()
        probe = self.probe()
        probe["identity"] = {**self.identity, "installation": str(uuid4())}
        self.assertEqual(self.run_observer(job, probe), ("failed", 1))
        job = self.request()

        def erase():
            Customer.all_objects.filter(pk=self.customer.pk).update(anonymized_at=timezone.now())

        self.assertEqual(self.run_observer(job, effect=erase), ("failed", 1))
        self.assertIsNone(current_safety_used_bytes(self.service))

    def test_strict_future_selector_time_is_not_a_current_measurement(self):
        self.publish_canonical()
        job = self.request()
        self.assertEqual(self.run_observer(job), ("completed", 1))
        with patch("apps.billing.plan_change_safety.timezone.now", return_value=timezone.now() - timedelta(minutes=1)):
            self.assertIsNone(current_safety_used_bytes(self.service))


class StaleCanonicalSafetyTests(HostingSafetyObservationFixture, TransactionTestCase):
    def setUp(self):
        old = timezone.now() - timedelta(hours=3)
        with (
            patch("apps.provisioning.virtualmin_usage_service.timezone.now", return_value=old),
            patch("django.utils.timezone.datetime") as wall_clock,
        ):
            wall_clock.now.return_value = old
            super().setUp()
            self.publish_canonical()

    def test_genuinely_old_published_canonical_reading_cannot_be_replaced_by_kernel_only(self):
        state = current_state(self.account)
        self.assertLess(state.disk_reading.taken_at, timezone.now() - timedelta(hours=2))
        self.assertGreaterEqual(state.disk_reading.scan_started_at, state.owner_started_at)
        job = self.request()
        self.assertGreater(job.execution_deadline, timezone.now())
        self.assertEqual(self.run_observer(job), ("failed", 1))
        self.assertIsNone(current_safety_used_bytes(self.service))


@override_settings(Q_CLUSTER={"name": "safety-native-admission", "orm": "default", "retry": 100000})
class HostingSafetyNativeAdmissionTests(HostingSafetyObservationFixture, TransactionTestCase):
    def setUp(self):
        super().setUp()
        self.publish_canonical()

    def test_public_backup_yields_to_running_read_then_admits_after_publication(self):
        observation = self.request()

        def admit_backup():
            self.assertFalse(account_has_active_operation(self.account))
            result = VirtualminBackupManagementService(self.server).create_backup_job(self.account)
            self.assertTrue(result.is_err(), result)
            self.assertIn("safety observation", result.unwrap_err())
            self.assertFalse(VirtualminProvisioningJob.objects.filter(operation="backup_domain").exists())

        self.assertEqual(self.run_observer(observation, effect=admit_backup), ("completed", 1))
        with patch("django_q.tasks.async_task"):
            result = VirtualminBackupManagementService(self.server).create_backup_job(self.account)
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(result.unwrap().status, "pending")

    def test_shared_native_lifecycle_gate_yields_without_creating_a_job(self):
        observation = self.request()
        mutation = VirtualminProvisioningJob(operation="suspend_domain", account=self.account, server=self.server)

        def start_native_writer():
            refusal = begin_account_job(self.account, mutation)
            self.assertIsNotNone(refusal)
            self.assertIn("safety observation", refusal)
            self.assertTrue(mutation._state.adding)

        self.assertEqual(self.run_observer(observation, effect=start_native_writer), ("completed", 1))
        self.assertIsNone(begin_account_job(self.account, mutation))
        self.assertEqual(mutation.status, "running")

    def test_quota_admission_yields_without_advancing_epoch_or_claiming_capacity(self):
        actor = User.objects.create_superuser(email="safety-quota-admin@example.test", password=None)
        target = ServicePlan.objects.create(
            name="Reviewed quota target",
            plan_type=self.plan.plan_type,
            price_monthly=20,
            disk_space_gb=5,
            bandwidth_gb=20,
        )
        ticket = Ticket.objects.create(customer=self.customer, title="Review quotas", description="Approved adoption")
        with patch("apps.provisioning.hosting_limit_tasks.async_task"):
            application = grant_resource_override(
                user=actor,
                service=self.service,
                target_plan_id=target.pk,
                ticket_id=ticket.pk,
                reason="Explicit existing-account adoption",
                expected_revision=1,
                submission_id=uuid4(),
                billing_unchanged=True,
                adopt_existing_native_limits=True,
            )
        observation = self.request()
        generation = self.account.quota_generation

        def admit_quota():
            self.assertIsNone(admit_application(application.pk))
            self.account.refresh_from_db()
            self.assertEqual(self.account.quota_generation, generation)
            self.assertFalse(HostingLimitExecution.objects.exists())

        self.assertEqual(self.run_observer(observation, effect=admit_quota), ("completed", 1))
        self.assertIsNotNone(admit_application(application.pk))

    def test_public_move_and_recovery_yield_before_any_native_listing(self):
        target = VirtualminServer.objects.create(
            name="safety-target", hostname="safety-target.example.test", status="active"
        )
        observation = self.request()

        def start_moves():
            move, recovery = VirtualminMigrationService(), VirtualminRecoveryService()
            move.enabled = recovery.enabled = True
            with patch.object(move, "_listing") as move_native, patch.object(recovery, "_listing") as recovery_native:
                result = move.start_migration(self.account, target, initiated_by=None, enqueue=False)
                self.assertTrue(result.is_err(), result)
                self.assertIn("safety observation", result.unwrap_err())
                result = recovery.start_recovery(
                    self.account, target, backup_ids=["a" * 32], source_fenced="Owned fenced replacement", enqueue=False
                )
                self.assertTrue(result.is_err(), result)
                self.assertIn("safety observation", result.unwrap_err())
                move_native.assert_not_called()
                recovery_native.assert_not_called()

        self.assertEqual(self.run_observer(observation, effect=start_moves), ("completed", 1))

    def test_pending_read_yields_to_already_admitted_public_backup(self):
        observation = self.request()
        with patch("django_q.tasks.async_task"):
            backup = VirtualminBackupManagementService(self.server).create_backup_job(self.account)
        self.assertTrue(backup.is_ok(), backup)
        self.assertEqual(self.run_observer(observation), ("failed", 0))
        self.assertEqual(backup.unwrap().status, "pending")

    def test_delete_after_lifecycle_change_yields_to_still_running_read(self):
        self.account.protected_from_deletion = False
        self.account.save(update_fields=["protected_from_deletion"])
        observation = self.request()

        def delete():
            self.account.status = "error"
            self.account.save(update_fields=["status"])
            with patch("apps.provisioning.virtualmin_gateway.VirtualminGateway.call") as native:
                result = VirtualminProvisioningService(self.server).delete_account(self.account)
                self.assertTrue(result.is_err(), result)
                self.assertIn("safety observation", result.unwrap_err())
                native.assert_not_called()
            self.assertFalse(VirtualminProvisioningJob.objects.filter(operation="delete_domain").exists())

        self.assertEqual(self.run_observer(observation, effect=delete), ("failed", 1))

    @skipUnless(connection.vendor == "postgresql", "Requires PostgreSQL row locks and observed blocker PIDs")
    def test_waited_public_backup_sees_committed_running_read_under_account_mutex(self):
        observation = self.request()
        writer, start = backend_pid(), Event()

        def backup():
            assert start.wait(10)
            return VirtualminBackupManagementService(self.server).create_backup_job(self.account)

        with database_worker(backup) as (pid, pending):
            with transaction.atomic():
                claimed, outcome = _claim(observation.pk, observation.execution_token)
                self.assertEqual(outcome, "running")
                self.assertIsNotNone(claimed)
                start.set()
                wait_for_blocker(pid, writer, pending, table="provisioning_virtualmin_accounts")
            result = pending.result(timeout=30)
        self.assertTrue(result.is_err(), result)
        self.assertIn("safety observation", result.unwrap_err())
        self.assertFalse(VirtualminProvisioningJob.objects.filter(operation="backup_domain").exists())

    @skipUnless(connection.vendor == "postgresql", "Requires PostgreSQL row locks and observed blocker PIDs")
    def test_waited_public_read_yields_to_committed_backup_under_account_mutex(self):
        writer, start = backend_pid(), Event()

        def observe():
            assert start.wait(10)
            try:
                self.request()
            except ValidationError as error:
                return str(error)
            return None

        with database_worker(observe) as (pid, pending):
            with transaction.atomic(), patch("django_q.tasks.async_task"):
                backup = VirtualminBackupManagementService(self.server).create_backup_job(self.account)
                self.assertTrue(backup.is_ok(), backup)
                start.set()
                wait_for_blocker(pid, writer, pending, table="provisioning_virtualmin_accounts")
            self.assertIsNotNone(pending.result(timeout=30))
        self.assertFalse(VirtualminProvisioningJob.objects.filter(operation="observe_hosting_limits").exists())
