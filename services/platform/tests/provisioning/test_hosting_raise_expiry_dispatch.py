"""Expiry failures must remain local, and elapsed assignments must still remove R."""

from copy import copy
from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from django.test import TransactionTestCase
from django.utils import timezone

from apps.customers.models import Customer
from apps.provisioning.hosting_limit_execution import admit_application, apply_hosting_limits
from apps.provisioning.hosting_limit_models import HostingLimitApplication, ServiceHostingLimits
from apps.provisioning.hosting_limit_override_service import grant_resource_override
from apps.provisioning.hosting_limit_tasks import current_application, dispatch_hosting_limits
from apps.provisioning.hosting_node_policy_models import NodeHostingPolicy
from apps.provisioning.hosting_node_tasks import review_node_hosting
from apps.provisioning.hosting_raise_models import ServiceHostingRaise
from apps.provisioning.hosting_raise_service import expire_hosting_raise, raise_public_state
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from apps.provisioning.virtualmin_security import connection_identity
from tests.provisioning.test_hosting_node_policy import quota_evidence
from tests.provisioning.test_hosting_raises import HostingRaiseFixture


class HostingRaiseExpiryDispatchTests(HostingRaiseFixture, TransactionTestCase):
    def another_lane(self, name, *, apply=True):
        # Reuse only the external native response fixture, with independent real
        # Service/Account/Server/policy rows and the same real staff authority.
        lane = copy(self)
        lane.service = type(self.service).objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name=f"{name}.example.test",
            domain=f"{name}.example.test",
            username=name,
            billing_cycle="monthly",
            price=self.service.price,
            status="active",
        )
        lane.server = VirtualminServer.objects.create(
            hostname=f"{name}-node.example.test", legacy_security_admission=True, status="active"
        )
        lane.server.set_api_password("separate-fixture-native-credential")
        lane.server.save()
        lane.account = VirtualminAccount.objects.create(
            service=lane.service,
            server=lane.server,
            domain=lane.service.domain,
            virtualmin_username=name,
            status="active",
            praho_customer_id=self.customer.pk,
            praho_service_id=lane.service.pk,
        )
        evidence = quota_evidence()
        evidence["identity"] = connection_identity(lane.server)
        lane.policy = NodeHostingPolicy.objects.create(
            server=lane.server,
            connection_identity=evidence["identity"],
            quota_adopted=True,
            quota_verified_at=timezone.now(),
            quota_evidence=evidence,
        )
        lane.native_identity = {key: evidence[key] for key in ("installation", "filesystem_uuid", "boot_id")}
        lane.native_identity.update(domain_id="12345", domain=lane.account.domain, uid=1001, gid=1001)
        with patch("apps.provisioning.hosting_limit_tasks.async_task"):
            lane.application = grant_resource_override(
                user=self.staff,
                service=lane.service,
                target_plan_id=self.application.target_plan_id,
                ticket_id=self.ticket.pk,
                reason="Independent pending resource assignment",
                expected_revision=1,
                submission_id=uuid4(),
                billing_unchanged=True,
                adopt_existing_native_limits=True,
            )
        if apply:
            self.assertEqual(lane.apply(lane.application), "completed")
        return lane

    def replace_native_installation(self):
        self.server.set_api_password("fresh-readopted-fixture-credential")
        self.server.save(update_fields=["encrypted_api_password"])
        identity = connection_identity(self.server)
        inventory = {
            "identity": identity,
            "quota": {**self.policy.quota_evidence, "identity": identity, "installation": str(uuid4())},
        }

        def native(server, action, request):
            if action == "inspect":
                return inventory
            self.assertEqual(action, "quota_policy")
            return {**inventory, "fenced_token": request["token"]}

        with patch("apps.provisioning.hosting_node_tasks.run_node_operation", side_effect=native):
            review = review_node_hosting(str(self.server.pk), str(self.staff.pk), "inspect")
            self.assertEqual(review["outcome"], "inspected", review)
            result = review_node_hosting(
                str(self.server.pk),
                str(self.staff.pk),
                "adopt_quota",
                {"review_id": review["review_id"], "reason": "A genuinely different native installation"},
            )
        self.assertEqual(result["outcome"], "verified", result)

    def assign(self, gib):
        self.service.refresh_from_db()
        current = self.service.service_plan
        target = type(self.plan).objects.create(
            name=f"Reviewed {gib} GiB desired assignment",
            plan_type=current.plan_type,
            disk_space_gb=gib,
            bandwidth_gb=20,
            price_monthly=100,
        )
        with patch("apps.provisioning.hosting_limit_tasks.async_task"):
            return grant_resource_override(
                user=self.staff,
                service=self.service,
                target_plan_id=target.pk,
                ticket_id=self.ticket.pk,
                reason="Explicit resource-only exception, with unchanged billing",
                expected_revision=ServiceHostingLimits.objects.get(service=self.service).revision,
                submission_id=uuid4(),
                billing_unchanged=True,
            )

    def test_invalid_expiry_does_not_abort_healthy_expiry_recovery_or_pending_dispatch(self):
        bad = self.grant()
        self.assertEqual(self.apply(bad), "completed")
        healthy = self.another_lane("healthy")
        raised = healthy.grant(expires_at=bad.overlay_expires_at + timedelta(minutes=1))
        self.assertEqual(healthy.apply(raised), "completed")
        pending = self.another_lane("pending", apply=False)
        recovery = admit_application(pending.application.pk)
        assert recovery is not None
        self.assertEqual(recovery.phase, "prepared")
        self.assertIsNone(recovery.issued_at)
        self.replace_native_installation()
        desired = self.assign(10)
        last_attempt = ServiceHostingRaise.objects.get(service=self.service).updated_at
        # This row is also a pending dispatcher candidate, so catching only the
        # initial batch expiry exception does not make this trajectory pass.
        self.assertNotEqual(ServiceHostingLimits.objects.get(service=self.service).applied_revision, desired.revision)
        at = raised.overlay_expires_at + timedelta(seconds=1)
        with (
            patch("apps.provisioning.hosting_raise_service.timezone.now", return_value=at),
            patch("apps.provisioning.hosting_limit_tasks.async_task") as broker,
            self.assertLogs("apps.provisioning", level="WARNING") as refusals,
        ):
            result = dispatch_hosting_limits()
            cleanup = current_application(healthy.service.pk)
            self.assertEqual(cleanup.authority["kind"], "temporary_raise_expiry")
            self.assertEqual(healthy.apply(cleanup), "completed")
            state = raise_public_state(self.service.pk)
            assert state is not None
            self.assertEqual(state.state, "expired_attention")
        self.assertEqual(result, {"queued": 2, "recovered": 1})
        self.assertEqual(
            {call.args[1] for call in broker.call_args_list}, {str(cleanup.pk), str(pending.application.pk)}
        )
        recovery.refresh_from_db()
        self.assertEqual((recovery.phase, recovery.job.status), ("superseded", "failed"))
        self.assertIsNone(recovery.issued_at)
        self.assertIsNotNone(recovery.reservation_released_at)
        self.assertEqual(healthy.account.effective_disk_quota_mb, 5632)
        self.account.refresh_from_db()
        self.assertEqual(self.account.effective_disk_quota_mb, 6912)
        row = ServiceHostingRaise.objects.get(service=self.service)
        self.assertEqual((row.status, row.revision), ("active", bad.overlay_revision))
        self.assertGreater(row.updated_at, last_attempt, "A failed row must yield its place in the bounded sweep")
        self.assertTrue(
            any(f"raise expiry deferred for service {self.service.pk}:" in line for line in refusals.output)
        )
        self.assertTrue(any(f"scheduling deferred for service {self.service.pk}:" in line for line in refusals.output))
        self.assertFalse(
            HostingLimitApplication.objects.filter(
                service=self.service, authority__kind="temporary_raise_expiry"
            ).exists()
        )

    def test_assignment_after_deadline_cannot_strand_applied_extra_when_desired_is_unlimited(self):
        raised = self.grant()
        self.assertEqual(self.apply(raised), "completed")
        original_price = self.service.price
        with (
            patch(
                "apps.provisioning.hosting_raise_service.timezone.now",
                return_value=raised.overlay_expires_at + timedelta(seconds=1),
            ),
            patch("apps.provisioning.hosting_limit_tasks.async_task"),
        ):
            desired = self.assign(0)
            row = ServiceHostingRaise.objects.get(service=self.service)
            self.assertEqual((row.status, row.revision), ("expired", raised.overlay_revision + 1))
            self.assertEqual(self.apply(desired), "pending", "Keep the native unlimited-cap refusal")
            self.assertEqual(self.account.effective_disk_quota_mb, 6912)
            dispatch_hosting_limits()
            cleanup = current_application(self.service.pk)
            self.assertEqual(cleanup.authority["kind"], "temporary_raise_expiry")
            self.assertEqual((cleanup.revision, cleanup.disk_allowance_mib, cleanup.overlay_extra_mib), (2, 5120, 0))
            self.assertEqual(self.apply(cleanup), "completed")
            self.assertEqual(current_application(self.service.pk).pk, desired.pk)
            self.assertEqual(ServiceHostingRaise.objects.get(service=self.service).revision, row.revision)
        limits = ServiceHostingLimits.objects.get(service=self.service)
        self.assertEqual((limits.revision, limits.operational_revision), (desired.revision, raised.revision))
        self.assertEqual(self.account.effective_disk_quota_mb, 5632)
        self.service.refresh_from_db()
        self.assertEqual(self.service.price, original_price)
        self.assertEqual(self.service.service_plan_id, desired.target_plan_id)

    def test_completed_cleanup_is_not_selected_again_when_later_native_attempt_clears_verification(self):
        raised = self.grant()
        self.assertEqual(self.apply(raised), "completed")
        with (
            patch(
                "apps.provisioning.hosting_raise_service.timezone.now",
                return_value=raised.overlay_expires_at + timedelta(seconds=1),
            ),
            patch("apps.provisioning.hosting_limit_tasks.async_task"),
        ):
            cleanup = expire_hosting_raise(self.service.pk)
            assert cleanup is not None
            self.assertEqual(self.apply(cleanup), "completed")
            desired = self.assign(10)
            with (
                patch(
                    "apps.provisioning.hosting_limit_transport.probe_account_quota", return_value=self.receipt(cap=5632)
                ),
                patch(
                    "apps.provisioning.hosting_limit_transport.run_quota_operation",
                    side_effect=ConnectionError("Owned native boundary lost the response"),
                ),
            ):
                self.assertEqual(apply_hosting_limits(desired.pk), "attention")
            limits = ServiceHostingLimits.objects.get(service=self.service)
            self.assertIsNone(limits.verified_at, "Exercise the actual native dispatch invalidation")
            self.assertEqual(limits.applied_overlay_revision, cleanup.overlay_revision)
            self.assertEqual(current_application(self.service.pk).pk, desired.pk)
            self.assertEqual(ServiceHostingRaise.objects.get(service=self.service).revision, cleanup.overlay_revision)
            self.assertEqual(
                HostingLimitApplication.objects.filter(
                    service=self.service, authority__kind="temporary_raise_expiry"
                ).count(),
                1,
            )

    def test_expired_former_owner_grant_does_not_block_current_owner_reconciliation(self):
        raised = self.grant()
        self.assertEqual(self.apply(raised), "completed")
        owner = Customer.objects.create(name="Later legitimate owner", customer_type="individual")
        with patch("apps.provisioning.hosting_limit_tasks.async_task"):
            type(self.service).objects.filter(pk=self.service.pk).update(customer=owner)
        with (
            patch(
                "apps.provisioning.hosting_raise_service.timezone.now",
                return_value=raised.overlay_expires_at + timedelta(seconds=1),
            ),
            patch("apps.provisioning.hosting_limit_tasks.async_task"),
        ):
            self.assertIsNone(expire_hosting_raise(self.service.pk))
            self.assertIsNone(expire_hosting_raise(self.service.pk))
            first = current_application(self.service.pk)
            dispatch_hosting_limits()
            self.assertEqual(current_application(self.service.pk).pk, first.pk)
        row = ServiceHostingRaise.objects.get(service=self.service)
        self.assertEqual((row.owner_id, row.status, row.extra_mib), (owner.pk, "expired", 0))
        self.assertEqual(first.overlay_extra_mib, 0)
        self.assertFalse(
            HostingLimitApplication.objects.filter(
                service=self.service, authority__kind="temporary_raise_expiry"
            ).exists()
        )
