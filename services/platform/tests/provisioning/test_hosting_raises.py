"""An independent overlay must reach the real quota lane without changing billing."""

from datetime import timedelta
from threading import Event
from unittest.mock import patch
from uuid import uuid4

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import connection, transaction
from django.test import TransactionTestCase
from django.utils import timezone

from apps.billing.plan_change_safety import current_safety_used_bytes
from apps.common.types import Ok
from apps.customers.models import Customer
from apps.provisioning import hosting_raise_service as presentation
from apps.provisioning.hosting_limit_assignments import request_service_plan_change
from apps.provisioning.hosting_limit_execution import (
    _prepare_dispatch,
    admit_application,
    apply_hosting_limits,
    ensure_managed_limits,
    freeze_migration_limits,
    reserve_managed_creation,
    reserve_managed_migration,
)
from apps.provisioning.hosting_limit_execution_models import HostingLimitExecution
from apps.provisioning.hosting_limit_models import HostingLimitApplication, ServiceHostingLimits
from apps.provisioning.hosting_limit_selectors import prime_current_verification
from apps.provisioning.hosting_limit_tasks import current_application
from apps.provisioning.hosting_raise_models import ServiceHostingRaise
from apps.provisioning.hosting_raise_service import expire_hosting_raise, grant_hosting_raise, raise_public_state
from apps.provisioning.hosting_safety_observation import request_safety_refresh, run_hosting_safety_observation
from apps.provisioning.virtualmin_gateway import VirtualminResponse
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob, VirtualminServer
from apps.settings.services import SettingsService
from apps.tickets.models import Ticket
from apps.users.models import User
from tests.common.postgres_locking import database_worker
from tests.provisioning import test_hosting_node_requalification as requalification
from tests.provisioning.test_hosting_limit_execution import HostingLimitWorkerFixture
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase


class HostingRaiseFixture(HostingLimitWorkerFixture):
    def receipt(self, **kwargs):
        return {**HostingLimitWorkerFixture.receipt(self, **kwargs), "quota_protocol": 2}

    def setUp(self):
        VirtualminTaskTestBase.setUp(self)
        self.account.status = "active"
        self.account.save(update_fields=["status"])
        with patch("apps.provisioning.hosting_limit_tasks.async_task"):
            self.setup_native_fixture()
        self.apply(self.application)
        self.service.refresh_from_db()
        self.assertTrue(SettingsService.update_setting("provisioning.hosting_raises_enabled", True).is_ok())

    def apply(self, application, *, used=8192, available=10 * 1024**3):
        before = self.receipt(cap=self.account.effective_disk_quota_mb or 1024, available=available)
        before["uid_used_bytes"] = used
        before["gid_used_bytes"] = used

        def native(server, action, request):
            self.assertEqual(action, "apply")
            return self.receipt(cap=request["disk_limit_kib"] // 1024, request=request, available=available)

        with (
            patch("apps.provisioning.hosting_limit_transport.probe_account_quota", return_value=before),
            patch("apps.provisioning.hosting_limit_transport.run_quota_operation", side_effect=native),
        ):
            result = apply_hosting_limits(application.pk)
        self.account.refresh_from_db()
        return result

    def observe(self, *, available=10 * 1024**3, protocol=2):
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
        with patch("apps.provisioning.hosting_safety_observation.async_task"):
            job = request_safety_refresh(self.service.pk, self.customer.pk, self.staff.pk)
        with (
            patch("apps.provisioning.virtualmin_gateway.VirtualminGateway.call", return_value=Ok(listing)),
            patch(
                "apps.provisioning.hosting_node_transport.run_quota_operation",
                return_value={
                    **self.receipt(cap=self.account.effective_disk_quota_mb, available=available),
                    "quota_protocol": protocol,
                },
            ),
        ):
            self.assertEqual(run_hosting_safety_observation(str(job.pk), str(job.execution_token)), "completed")

    def grant(self, *, observe=True, **changes):
        if observe:
            self.observe()
        limits = ServiceHostingLimits.objects.get(service=self.service)
        current = ServiceHostingRaise.objects.filter(service=self.service).first()
        arguments = {
            "user": self.staff,
            "service": self.service,
            "extra_mib": 1280,
            "ticket_id": self.ticket.pk,
            "reason": "Temporary incident relief",
            "expected_base_revision": limits.revision,
            "expected_overlay_revision": current.revision if current else 0,
            "submission_id": uuid4(),
        }
        arguments.update(changes)
        with patch("apps.provisioning.hosting_limit_tasks.async_task"):
            return grant_hosting_raise(**arguments)


class HostingRaiseTests(HostingRaiseFixture, TransactionTestCase):
    def test_grant_reaches_composed_native_cap_without_changing_base_or_price(self):
        limits = ServiceHostingLimits.objects.get(service=self.service)
        original = (limits.revision, limits.disk_allowance_mib, self.service.price, self.service.service_plan_id)
        application = self.grant()
        self.assertEqual(
            (application.revision, application.overlay_revision, application.overlay_extra_mib), (original[0], 1, 1280)
        )
        self.assertEqual(self.apply(application), "completed")
        self.assertEqual(self.account.effective_disk_quota_mb, 5632 + 1280)
        limits.refresh_from_db()
        self.service.refresh_from_db()
        self.assertEqual(
            (limits.revision, limits.disk_allowance_mib, self.service.price, self.service.service_plan_id), original
        )
        self.assertEqual(limits.applied_overlay_revision, 1)
        self.assertEqual(
            HostingLimitExecution.objects.get(job__hosting_limit_application=application).reserved_bytes, 1280 * 1024**2
        )
        self.assertEqual(current_application(self.service.pk).pk, application.pk)

    def test_active_extension_changes_expiry_only_and_preserves_original_seven_day_bound(self):
        first = self.grant()
        self.assertEqual(self.apply(first), "completed")
        row = ServiceHostingRaise.objects.get(service=self.service)
        extended = self.grant(expires_at=row.first_granted_at + timedelta(days=6))
        self.assertEqual(extended.overlay_extra_mib, first.overlay_extra_mib)
        self.assertEqual(extended.overlay_revision, 2)
        with self.assertRaises(ValidationError):
            self.grant(extra_mib=1024)
        with self.assertRaises(ValidationError):
            self.grant(expires_at=row.first_granted_at + timedelta(days=7, seconds=1))

    def test_missing_fresh_safety_cannot_create_raise_or_application(self):
        count = HostingLimitApplication.objects.count()
        limits = ServiceHostingLimits.objects.get(service=self.service)
        with self.assertRaises(ValidationError):
            grant_hosting_raise(
                user=self.staff,
                service=self.service,
                extra_mib=1280,
                ticket_id=self.ticket.pk,
                reason="No fresh safety",
                expected_base_revision=limits.revision,
                expected_overlay_revision=0,
                submission_id=uuid4(),
            )
        self.assertFalse(ServiceHostingRaise.objects.exists())
        self.assertEqual(HostingLimitApplication.objects.count(), count)

    def test_accepted_overlay_invalidates_previous_zero_overlay_safety_immediately(self):
        self.grant()
        self.assertIsNone(current_safety_used_bytes(self.service))

    def test_expiry_applies_current_base_even_over_usage_without_reenabling_account(self):
        raised = self.grant()
        self.assertEqual(self.apply(raised), "completed")
        self.account.status = "suspended"
        self.account.save(update_fields=["status"])
        row = ServiceHostingRaise.objects.get(service=self.service)
        with patch(
            "apps.provisioning.hosting_raise_service.timezone.now", return_value=row.expires_at + timedelta(seconds=1)
        ):
            with patch("apps.provisioning.hosting_limit_tasks.async_task"):
                expired = expire_hosting_raise(self.service.pk)
            self.assertIsNotNone(expired)
            self.assertEqual(expired.overlay_revision, 2)
            self.assertEqual(expired.overlay_extra_mib, 0)
            self.assertEqual(self.apply(expired, used=6000 * 1024**2), "completed")
        self.assertEqual(self.account.effective_disk_quota_mb, 5632)
        self.assertEqual(self.account.status, "suspended")
        self.assertEqual(ServiceHostingRaise.objects.get(service=self.service).revision, 2)

    def test_assignment_keeps_fixed_raise_on_upgrade_and_clamps_on_smaller_base(self):
        raised = self.grant()
        self.assertEqual(self.apply(raised), "completed")
        target = type(self.plan).objects.create(
            name="Ten GiB", plan_type=self.plan.plan_type, disk_space_gb=10, bandwidth_gb=20, price_monthly=30
        )
        with transaction.atomic(), patch("apps.provisioning.hosting_limit_tasks.async_task"):
            larger = request_service_plan_change(
                service=self.service,
                target_plan_id=target.pk,
                expected_revision=2,
                submission_id=uuid4(),
                reason="Accepted larger base",
                authority={"kind": "test_accepted_assignment"},
            )
        self.assertEqual((larger.overlay_revision, larger.overlay_extra_mib), (1, 1280))
        self.assertEqual(self.apply(larger), "completed")
        self.assertEqual(self.account.effective_disk_quota_mb, 11264 + 1280)
        self.service.refresh_from_db()
        smaller = type(self.plan).objects.create(
            name="Two GiB", plan_type=self.plan.plan_type, disk_space_gb=2, bandwidth_gb=20, price_monthly=8
        )
        with transaction.atomic(), patch("apps.provisioning.hosting_limit_tasks.async_task"):
            clamped = request_service_plan_change(
                service=self.service,
                target_plan_id=smaller.pk,
                expected_revision=3,
                submission_id=uuid4(),
                reason="Accepted smaller base",
                authority={"kind": "test_accepted_assignment"},
            )
        self.assertEqual((clamped.overlay_revision, clamped.overlay_extra_mib), (2, 512))
        self.assertEqual(self.apply(clamped), "completed")
        self.assertEqual(self.account.effective_disk_quota_mb, 2253 + 512)

    def test_new_grants_require_explicit_rollout(self):
        self.assertTrue(SettingsService.update_setting("provisioning.hosting_raises_enabled", False).is_ok())
        with self.assertRaises(ValidationError):
            self.grant()
        self.assertFalse(ServiceHostingRaise.objects.exists())

    def test_new_grants_require_current_helpers(self):
        self.observe(protocol=1)
        with self.assertRaises(ValidationError):
            self.grant(observe=False)
        self.assertFalse(ServiceHostingRaise.objects.exists())

    def test_new_grants_require_fresh_unreserved_capacity(self):
        self.observe(available=1)
        with self.assertRaises(ValidationError):
            self.grant(observe=False)
        self.assertFalse(ServiceHostingRaise.objects.exists())

    def test_expired_but_not_removed_raise_is_attention_even_with_old_matching_receipt(self):
        application = self.grant()
        self.assertEqual(self.apply(application), "completed")
        self.assertEqual(raise_public_state(self.service.pk).state, "verified")
        row = ServiceHostingRaise.objects.get(service=self.service)
        with patch(
            "apps.provisioning.hosting_raise_service.timezone.now", return_value=row.expires_at + timedelta(seconds=1)
        ):
            self.assertEqual(raise_public_state(self.service.pk).state, "expired_attention")

    def test_batched_raise_presentation_reuses_primed_verification_and_never_queries_per_service(self):
        raised = self.grant()
        self.assertEqual(self.apply(raised), "completed")
        service = type(self.service).objects.select_related("hosting_limits").get(pk=self.service.pk)
        account = type(self.account).objects.select_related("server__hosting_policy").get(pk=self.account.pk)
        now = timezone.now()
        prime_current_verification([service], {service.pk: account}, at=now)
        with self.assertNumQueries(0):
            presentation.prime_hosting_raises([service], at=now)
            state = presentation.service_raise_public_state(service, at=now)
            self.assertEqual(state.state, "verified")
            self.assertEqual(state.extra_mib, 1280)
            self.assertEqual(state.revision, raised.overlay_revision)
            expired = presentation.raise_public_state_for(
                service, service.__dict__["_hosting_raise_row"], at=raised.overlay_expires_at + timedelta(seconds=1)
            )
            self.assertEqual(expired.state, "expired_attention")
        others = [
            type(self.service).objects.create(
                customer=self.customer,
                service_plan=self.plan,
                currency=self.currency,
                service_name=f"Batch {index}",
                domain=f"batch-{index}.example.test",
                username=f"batch{index}",
                price=10,
            )
            for index in range(5)
        ]
        with self.assertNumQueries(1):
            presentation.prime_hosting_raises([service, *others], at=now)
        with self.assertNumQueries(0):
            presentation.prime_hosting_raises([service, *others], at=now)
            self.assertEqual(presentation.service_raise_public_state(service, at=now), state)
            self.assertTrue(all(presentation.service_raise_public_state(other, at=now) is None for other in others))
            self.assertIsNone(
                presentation.raise_public_state_for(others[0], service.__dict__["_hosting_raise_row"], at=now)
            )

    def test_exact_replay_and_changed_payload_refusal_preserve_overlay_identity(self):
        identifier = uuid4()
        first = self.grant(submission_id=identifier)
        self.assertEqual(self.grant(observe=False, submission_id=identifier, expected_overlay_revision=0).pk, first.pk)
        with self.assertRaises(ValidationError):
            self.grant(observe=False, submission_id=identifier, expected_overlay_revision=0, extra_mib=1024)
        row = ServiceHostingRaise.objects.get(service=self.service)
        with self.assertRaises(ValidationError):
            row.delete()
        with self.assertRaises(ValidationError):
            ServiceHostingRaise.objects.filter(service=self.service).update(revision=0)
        self.assertEqual(HostingLimitApplication.objects.filter(service=self.service, overlay_revision=1).count(), 1)

    def test_foreign_ticket_and_nonoperator_roles_cannot_grant_resources(self):
        other = Customer.objects.create(name="Unrelated customer", status="active")
        ticket = Ticket.objects.create(customer=other, title="Foreign incident", description="No authority")
        with self.assertRaises(ValidationError):
            self.grant(ticket_id=ticket.pk)
        for role in ("support", "billing"):
            actor = User.objects.create_user(email=f"raise-{role}@example.test", staff_role=role, is_staff=True)
            with self.subTest(role=role), self.assertRaises(PermissionDenied):
                self.grant(user=actor)
        self.assertFalse(ServiceHostingRaise.objects.exists())

    def test_native_capacity_loss_keeps_raise_requested_without_false_application(self):
        application = self.grant()
        self.assertEqual(self.apply(application, available=1), "pending")
        self.assertEqual(self.account.effective_disk_quota_mb, 5632)
        limits = ServiceHostingLimits.objects.get(service=self.service)
        self.assertEqual(limits.applied_overlay_revision, 0)
        self.assertIsNone(limits.verified_at)
        self.assertEqual(raise_public_state(self.service.pk).state, "requested")

    def test_migration_review_freezes_full_composed_cap_and_overlay_expiry(self):
        application = self.grant()
        self.assertEqual(self.apply(application), "completed")
        frozen = freeze_migration_limits(self.account)
        self.assertEqual(frozen["application_id"], str(application.pk))
        self.assertEqual(frozen["overlay_revision"], application.overlay_revision)
        self.assertEqual(frozen["overlay_expires_at"], application.overlay_expires_at.isoformat())
        self.assertEqual(frozen["disk_cap_mib"], 6912)

    def test_recreation_reserves_full_composed_cap_before_native_creation(self):
        application = self.grant()
        self.assertEqual(self.apply(application), "completed")
        self.account.status = "provisioning"
        self.account.save(update_fields=["status"])
        parent = VirtualminProvisioningJob.objects.create(
            account=self.account,
            server=self.server,
            operation="create_domain",
            status="running",
            correlation_id="raised-recreate",
        )
        result = reserve_managed_creation(self.account, parent, 10 * 1024**3)
        self.assertTrue(result.is_ok(), result)
        claim = HostingLimitExecution.objects.get(job__parameters__quota_parent__job_id=str(parent.pk))
        self.assertEqual(claim.reserved_bytes, 6912 * 1024**2)
        self.assertIsNone(claim.issued_at)

    def test_migration_reserves_full_composed_destination_cap(self):
        application = self.grant()
        self.assertEqual(self.apply(application), "completed")
        source = VirtualminServer.objects.create(hostname="raised-source.example.test", status="disabled")
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
            return_value=Ok({"healthy": True, "data": {"available_disk_mb": 7936}}),
        ):
            result = reserve_managed_migration(migration)
        self.assertTrue(result.is_ok(), result)
        child = HostingLimitExecution.objects.get(job__parameters__quota_parent__migration_id=str(migration.pk))
        self.assertEqual(child.reserved_bytes, 6912 * 1024**2)
        self.assertIsNone(child.issued_at)

    def test_public_parent_resume_transfers_never_issued_expired_raise_without_losing_reservation(self):
        raised = self.grant()
        self.assertEqual(self.apply(raised), "completed")
        self.application = raised
        migration, _bridge, child, fresh = (
            requalification.HostingNodeDispatchRequalificationTests._qualified_paused_migration(self)
        )
        row = ServiceHostingRaise.objects.get(service=self.service)
        with patch(
            "apps.provisioning.hosting_raise_service.timezone.now", return_value=row.expires_at + timedelta(seconds=1)
        ):
            with patch("apps.provisioning.hosting_limit_tasks.async_task"):
                expired = expire_hosting_raise(self.service.pk)
            self.assertIsNotNone(expired)
            requalification.HostingNodeDispatchRequalificationTests._resume_migration(self, migration)
            fresh["observed_at"] = timezone.now().isoformat()

            def native(server, action, request):
                self.assertEqual(action, "apply")
                self.assertEqual(request["disk_limit_kib"], 5632 * 1024)
                self.assertEqual(request["policy"]["extra_mib"], 0)
                child.refresh_from_db()
                self.assertEqual(child.phase, "superseded")
                replacement = HostingLimitExecution.objects.get(job__parameters__quota_reservation_from=str(child.pk))
                self.assertEqual(replacement.reserved_bytes, 6912 * 1024**2)
                self.assertIsNone(replacement.reservation_released_at)
                self.assertIsNotNone(child.reservation_released_at)
                receipt = self.receipt(cap=5632, request=request)
                receipt["identity"] = fresh["identity"]
                return receipt

            with (
                patch("apps.provisioning.hosting_limit_transport.probe_account_quota", return_value=fresh),
                patch("apps.provisioning.hosting_limit_transport.run_quota_operation", side_effect=native),
            ):
                result = ensure_managed_limits(self.account, migration=migration)
            self.assertTrue(result.is_ok(), result)
            self.assertIsNone(_prepare_dispatch(child.pk, fresh))
        migration.refresh_from_db()
        self.assertEqual(migration.status, "activating")
        self.assertEqual(migration.pre_migration_snapshot["hosting_limits"]["application_id"], str(raised.pk))

    def test_expiry_transfers_prepared_parent_reservation_and_fences_delayed_probe(self):
        if connection.vendor != "postgresql":
            self.skipTest("Independent active-probe recovery proof requires PostgreSQL")
        raised = self.grant()
        self.assertEqual(self.apply(raised), "completed")
        self.application = raised
        migration, _bridge, old, fresh = (
            requalification.HostingNodeDispatchRequalificationTests._qualified_paused_migration(self)
        )
        requalification.HostingNodeDispatchRequalificationTests._resume_migration(self, migration)
        parent = {**old.job.parameters["quota_parent"], "token": str(migration.lease_token)}
        prepared = admit_application(raised.pk, parent=parent)
        self.assertIsNotNone(prepared)
        self.assertEqual(prepared.phase, "prepared")
        self.assertEqual(prepared.reserved_bytes, 6912 * 1024**2)
        entered, release = Event(), Event()
        dispatches = []

        def probe(execution):
            if execution.pk == prepared.pk:
                entered.set()
                assert release.wait(20)
            return {**fresh, "observed_at": timezone.now().isoformat()}

        def native(server, action, request):
            dispatches.append(request)
            self.assertEqual(action, "apply")
            self.assertEqual(request["disk_limit_kib"], 5632 * 1024)
            prepared.refresh_from_db()
            self.assertEqual(prepared.phase, "superseded")
            current = HostingLimitExecution.objects.get(job__parameters__quota_reservation_from=str(prepared.pk))
            self.assertEqual(current.reserved_bytes, 6912 * 1024**2)
            self.assertIsNone(current.reservation_released_at)
            receipt = self.receipt(cap=5632, request=request)
            receipt["identity"] = fresh["identity"]
            return receipt

        with (
            patch("apps.provisioning.hosting_limit_transport.probe_account_quota", side_effect=probe),
            patch("apps.provisioning.hosting_limit_transport.run_quota_operation", side_effect=native),
            database_worker(lambda: apply_hosting_limits(raised.pk, parent=parent)) as (_pid, delayed),
        ):
            try:
                self.assertTrue(entered.wait(10), "The admitted old child never reached its read-only probe")
                with patch(
                    "apps.provisioning.hosting_raise_service.timezone.now",
                    return_value=raised.overlay_expires_at + timedelta(seconds=1),
                ):
                    with patch("apps.provisioning.hosting_limit_tasks.async_task"):
                        expired = expire_hosting_raise(self.service.pk)
                        self.assertIsNotNone(expired)
                    self.assertTrue(migration.acquire_lease(uuid4(), timedelta(minutes=5)))
                    migration.refresh_from_db()
                    self.application = expired
                    requalification.HostingNodeDispatchRequalificationTests._transfer_with_competing_capacity(
                        self, migration, prepared
                    )
                    result = ensure_managed_limits(self.account, migration=migration)
                    self.assertTrue(result.is_ok(), result)
            finally:
                release.set()
            self.assertEqual(delayed.result(timeout=30), "superseded")
        self.assertEqual(len(dispatches), 1)
        self.assertIsNone(HostingLimitExecution.objects.get(pk=prepared.pk).issued_at)

    def test_expired_prepared_parent_retains_full_capacity_until_explicit_handoff(self):
        raised = self.grant(expires_at=timezone.now() + timedelta(minutes=2))
        self.assertEqual(self.apply(raised), "completed")
        self.application = raised
        migration, _bridge, old, fresh = (
            requalification.HostingNodeDispatchRequalificationTests._qualified_paused_migration(self)
        )
        requalification.HostingNodeDispatchRequalificationTests._resume_migration(self, migration)
        parent = {**old.job.parameters["quota_parent"], "token": str(migration.lease_token)}
        prepared = admit_application(raised.pk, parent=parent)
        self.assertIsNotNone(prepared)
        with patch(
            "apps.provisioning.hosting_raise_service.timezone.now",
            return_value=raised.overlay_expires_at + timedelta(seconds=1),
        ):
            with patch("apps.provisioning.hosting_limit_tasks.async_task"):
                self.assertIsNotNone(expire_hosting_raise(self.service.pk))
            with (
                patch(
                    "apps.provisioning.hosting_limit_transport.probe_account_quota",
                    return_value={**fresh, "observed_at": timezone.now().isoformat()},
                ),
                patch(
                    "apps.provisioning.hosting_limit_transport.run_quota_operation",
                    side_effect=AssertionError("Expired positive overlay must not dispatch"),
                ),
            ):
                outcome = apply_hosting_limits(raised.pk, parent=parent)
        prepared.refresh_from_db()
        self.assertIsNone(prepared.reservation_released_at, "Expired overlay released a still-held parent's capacity")
        self.assertEqual(prepared.phase, "attention")
        self.assertIsNone(prepared.issued_at)
        self.assertEqual(prepared.reserved_bytes, 6912 * 1024**2)
        self.assertEqual(outcome, "pending")
