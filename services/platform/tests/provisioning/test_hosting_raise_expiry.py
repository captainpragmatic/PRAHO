"""Expiry removes only R from an observed operational base, never a pending desire."""

from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.db import transaction
from django.test import TransactionTestCase
from django.utils import timezone

from apps.customers.models import Customer
from apps.provisioning.hosting_limit_assignments import request_service_plan_change
from apps.provisioning.hosting_limit_execution import admit_application, apply_hosting_limits
from apps.provisioning.hosting_limit_models import ServiceHostingLimits
from apps.provisioning.hosting_limit_selectors import prime_current_verification
from apps.provisioning.hosting_limit_tasks import current_application
from apps.provisioning.hosting_node_execution import hosting_transport_allowed
from apps.provisioning.hosting_node_policy import managed_quota_refusal
from apps.provisioning.hosting_node_tasks import review_node_hosting
from apps.provisioning.hosting_raise_models import ServiceHostingRaise
from apps.provisioning.hosting_raise_service import expire_hosting_raise, raise_public_state
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.provisioning.virtualmin_security import connection_identity
from tests.provisioning.test_hosting_raises import HostingRaiseFixture


class HostingRaiseExpiryTests(HostingRaiseFixture, TransactionTestCase):
    def rotate_and_readopt(self, *, installation=None):
        historical = self.policy.connection_identity
        self.server.set_api_password("fixture-rotated-native-credential")
        self.server.save(update_fields=["encrypted_api_password"])
        current = connection_identity(self.server)
        self.assertNotEqual(current, historical)
        self.assertIsNotNone(managed_quota_refusal(self.server))
        inventory = {"identity": current, "quota": {**self.policy.quota_evidence, "identity": current}}
        if installation:
            inventory["quota"]["installation"] = installation

        def native(server, action, request):
            if action == "inspect":
                return inventory
            self.assertEqual(action, "quota_policy")
            self.assertTrue(hosting_transport_allowed(server, {"hosting_action": action, "hosting_request": request}))
            return {**inventory, "fenced_token": request["token"]}

        with patch("apps.provisioning.hosting_node_tasks.run_node_operation", side_effect=native):
            review = review_node_hosting(str(self.server.pk), str(self.staff.pk), "inspect")
            self.assertEqual(review["outcome"], "inspected", review)
            result = review_node_hosting(
                str(self.server.pk),
                str(self.staff.pk),
                "adopt_quota",
                {
                    "review_id": review["review_id"],
                    "reason": "Review the same native baseline on its rotated credentials",
                },
            )
        self.assertEqual(result["outcome"], "verified", result)
        self.assertIsNone(managed_quota_refusal(self.server))
        service = type(self.service).objects.select_related("hosting_limits").get(pk=self.service.pk)
        account = type(self.account).objects.select_related("server__hosting_policy").get(pk=self.account.pk)
        prime_current_verification([service], {service.pk: account})
        self.assertFalse(service.__dict__["_hosting_current_verified"])
        self.assertFalse(service.__dict__["_hosting_operational_verified"])

    def test_rotated_credentials_with_fresh_same_node_readoption_can_remove_only_expired_extra(self):
        raised = self.grant()
        self.assertEqual(self.apply(raised), "completed")
        self.rotate_and_readopt()
        with patch(
            "apps.provisioning.hosting_raise_service.timezone.now",
            return_value=raised.overlay_expires_at + timedelta(seconds=1),
        ):
            cleanup = self.expire(raised)
            self.assertEqual(self.apply(cleanup), "completed")
            self.assertEqual(raise_public_state(self.service.pk).state, "expired")
        self.assertEqual(self.account.effective_disk_quota_mb, 5632)

    def test_readopted_new_installation_cannot_reuse_historical_cleanup_authority(self):
        raised = self.grant()
        self.assertEqual(self.apply(raised), "completed")
        self.rotate_and_readopt(installation=str(uuid4()))
        with (
            patch(
                "apps.provisioning.hosting_raise_service.timezone.now",
                return_value=raised.overlay_expires_at + timedelta(seconds=1),
            ),
            patch("apps.provisioning.hosting_limit_transport.probe_account_quota") as probe,
            patch("apps.provisioning.hosting_limit_transport.run_quota_operation") as native,
            self.assertRaises(ValidationError),
        ):
            expire_hosting_raise(self.service.pk)
        probe.assert_not_called()
        native.assert_not_called()

    def test_new_positive_raise_cannot_activate_an_unapplied_newer_base(self):
        self.assign(20)
        self.observe(available=100 * 1024**3)
        with self.assertRaises(ValidationError):
            self.grant(observe=False)
        self.assertFalse(ServiceHostingRaise.objects.filter(service=self.service).exists())

    def test_pending_unlimited_desire_cannot_strand_previously_applied_temporary_capacity(self):
        raised = self.grant()
        self.assertEqual(self.apply(raised), "completed")
        unlimited = self.assign(0)
        self.assertEqual(self.apply(unlimited), "pending", "The existing unbounded-cap refusal must remain")
        self.assertEqual(self.account.effective_disk_quota_mb, 6912)
        with patch(
            "apps.provisioning.hosting_raise_service.timezone.now",
            return_value=raised.overlay_expires_at + timedelta(seconds=1),
        ):
            cleanup = self.expire(raised)
            self.assertEqual(self.apply(cleanup), "completed")
        self.assertEqual(self.account.effective_disk_quota_mb, 5632)
        self.assertEqual(ServiceHostingLimits.objects.get(service=self.service).revision, unlimited.revision)

    def assign(self, gib):
        target = type(self.plan).objects.create(
            name=f"Unapplied {gib}",
            plan_type=self.plan.plan_type,
            disk_space_gb=gib,
            bandwidth_gb=20,
            price_monthly=100,
        )
        with transaction.atomic(), patch("apps.provisioning.hosting_limit_tasks.async_task"):
            return request_service_plan_change(
                service=self.service,
                target_plan_id=target.pk,
                expected_revision=ServiceHostingLimits.objects.get(service=self.service).revision,
                submission_id=uuid4(),
                reason="An accepted newer desire has not been natively applied",
                authority={"kind": "test_accepted_assignment"},
            )

    def expire(self, raised):
        with patch("apps.provisioning.hosting_limit_tasks.async_task"):
            expired = expire_hosting_raise(self.service.pk)
        self.assertIsNotNone(expired)
        return expired

    def test_expiry_cleans_operational_base_without_applying_newer_desired_base(self):
        raised = self.grant()
        self.assertEqual(self.apply(raised), "completed")
        desired = self.assign(20)
        requests = []

        def native(server, action, request):
            self.assertEqual(action, "apply")
            requests.append(request)
            return self.receipt(cap=request["disk_limit_kib"] // 1024, request=request)

        with patch(
            "apps.provisioning.hosting_raise_service.timezone.now",
            return_value=raised.overlay_expires_at + timedelta(seconds=1),
        ):
            cleanup = self.expire(raised)
            with (
                patch(
                    "apps.provisioning.hosting_limit_transport.probe_account_quota",
                    return_value=self.receipt(cap=6912, available=100 * 1024**3),
                ),
                patch("apps.provisioning.hosting_limit_transport.run_quota_operation", side_effect=native),
            ):
                outcome = apply_hosting_limits(cleanup.pk)
        self.assertEqual(outcome, "completed")
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0]["disk_limit_kib"], 5632 * 1024, "Expiry silently granted the newer pending base")
        limits = ServiceHostingLimits.objects.get(service=self.service)
        self.assertEqual(
            (limits.revision, limits.operational_revision, limits.applied_revision),
            (desired.revision, raised.revision, raised.revision),
        )
        self.assertEqual(limits.applied_overlay_revision, cleanup.overlay_revision)
        desired.refresh_from_db()
        self.assertEqual(desired.disk_allowance_mib, 20 * 1024)

    def test_one_sided_lower_hard_cap_cannot_turn_expiry_into_an_increase(self):
        raised = self.grant()
        self.assertEqual(self.apply(raised), "completed")
        with patch(
            "apps.provisioning.hosting_raise_service.timezone.now",
            return_value=raised.overlay_expires_at + timedelta(seconds=1),
        ):
            cleanup = self.expire(raised)
            probe = self.receipt(cap=6912)
            probe["gid_soft_kib"] = probe["gid_hard_kib"] = 5632 * 1024 - 1
            with (
                patch("apps.provisioning.hosting_limit_transport.probe_account_quota", return_value=probe),
                patch(
                    "apps.provisioning.hosting_limit_transport.run_quota_operation",
                    side_effect=lambda server, action, request: self.receipt(cap=5632, request=request),
                ) as native,
            ):
                apply_hosting_limits(cleanup.pk)
        native.assert_not_called()
        self.assertEqual(
            ServiceHostingLimits.objects.get(service=self.service).applied_overlay_revision, raised.overlay_revision
        )

    def test_newer_desired_application_winning_after_cleanup_discovery_invalidates_old_cleanup(self):
        raised = self.grant()
        self.assertEqual(self.apply(raised), "completed")
        self.assign(20)
        with patch(
            "apps.provisioning.hosting_raise_service.timezone.now",
            return_value=raised.overlay_expires_at + timedelta(seconds=1),
        ):
            cleanup = self.expire(raised)
            newer = self.assign(10)
            self.assertEqual(self.apply(newer, available=100 * 1024**3), "completed")
            with (
                patch("apps.provisioning.hosting_limit_transport.probe_account_quota") as probe,
                patch("apps.provisioning.hosting_limit_transport.run_quota_operation") as native,
            ):
                apply_hosting_limits(cleanup.pk)
        probe.assert_not_called()
        native.assert_not_called()
        self.assertEqual(ServiceHostingLimits.objects.get(service=self.service).operational_revision, newer.revision)

    def test_durable_selection_replays_cleanup_before_leaving_newer_desire_pending(self):
        raised = self.grant()
        self.assertEqual(self.apply(raised), "completed")
        desired = self.assign(20)
        with patch(
            "apps.provisioning.hosting_raise_service.timezone.now",
            return_value=raised.overlay_expires_at + timedelta(seconds=1),
        ):
            cleanup = self.expire(raised)
            self.assertEqual(current_application(self.service.pk).pk, cleanup.pk)
            self.assertEqual(current_application(self.service.pk).pk, cleanup.pk)
            self.assertEqual(self.apply(cleanup), "completed")
            self.assertEqual(
                raise_public_state(self.service.pk).state,
                "expired",
                "A verified old-base cleanup must not claim the temporary allowance still needs removal",
            )
            pending = current_application(self.service.pk)
            self.assertIsNotNone(admit_application(pending.pk))
            self.assertEqual(
                raise_public_state(self.service.pk).state,
                "expired_attention",
                "A newer account epoch must invalidate the previously current operational receipt",
            )
        self.assertEqual(pending.revision, desired.revision)
        self.assertEqual(pending.overlay_revision, cleanup.overlay_revision)
        self.assertEqual(pending.overlay_extra_mib, 0)
        self.assertNotEqual(pending.pk, cleanup.pk)

    def rejected_probe(self, edit, *, rotate=False):
        raised = self.grant()
        self.assertEqual(self.apply(raised), "completed")
        if rotate:
            self.rotate_and_readopt()
        with patch(
            "apps.provisioning.hosting_raise_service.timezone.now",
            return_value=raised.overlay_expires_at + timedelta(seconds=1),
        ):
            cleanup = self.expire(raised)
            probe = self.receipt(cap=6912)
            edit(probe)
            with (
                patch("apps.provisioning.hosting_limit_transport.probe_account_quota", return_value=probe) as observed,
                patch("apps.provisioning.hosting_limit_transport.run_quota_operation") as native,
            ):
                apply_hosting_limits(cleanup.pk)
        observed.assert_called_once()
        native.assert_not_called()
        self.assertEqual(
            ServiceHostingLimits.objects.get(service=self.service).applied_overlay_revision, raised.overlay_revision
        )

    def test_stale_native_observation_refuses_expiry_before_mutation(self):
        self.rejected_probe(lambda probe: probe.update(observed_at=(timezone.now() - timedelta(minutes=3)).isoformat()))

    def test_unknown_hard_cap_refuses_expiry_before_mutation(self):
        self.rejected_probe(lambda probe: probe.update(uid_hard_kib=None))

    def test_future_native_observation_refuses_expiry_before_mutation(self):
        self.rejected_probe(lambda probe: probe.update(observed_at=(timezone.now() + timedelta(hours=1)).isoformat()))

    def test_older_native_helper_cannot_apply_protocol_two_cleanup(self):
        self.rejected_probe(lambda probe: probe.update(quota_protocol=1))

    def test_rotated_qualified_credentials_do_not_bypass_one_sided_hard_cap(self):
        self.rejected_probe(lambda probe: probe.update(gid_hard_kib=5632 * 1024 - 1), rotate=True)

    def test_rotated_unqualified_connection_cannot_create_expiry_mutation_authority(self):
        raised = self.grant()
        self.assertEqual(self.apply(raised), "completed")
        self.server.set_api_password("fixture-unreviewed-native-credential")
        self.server.save(update_fields=["encrypted_api_password"])
        self.assertIsNotNone(managed_quota_refusal(self.server))
        with (
            patch(
                "apps.provisioning.hosting_raise_service.timezone.now",
                return_value=raised.overlay_expires_at + timedelta(seconds=1),
            ),
            patch("apps.provisioning.hosting_limit_transport.probe_account_quota") as probe,
            patch("apps.provisioning.hosting_limit_transport.run_quota_operation") as native,
            self.assertRaises(ValidationError),
        ):
            expire_hosting_raise(self.service.pk)
        probe.assert_not_called()
        native.assert_not_called()

    def test_changed_customer_scope_cannot_reuse_historical_expiry_consent(self):
        raised = self.grant()
        self.assertEqual(self.apply(raised), "completed")
        with patch(
            "apps.provisioning.hosting_raise_service.timezone.now",
            return_value=raised.overlay_expires_at + timedelta(seconds=1),
        ):
            cleanup = self.expire(raised)
            other = Customer.objects.create(name="A different owner", customer_type="individual")
            type(self.service).objects.filter(pk=self.service.pk).update(customer=other)
            with (
                patch("apps.provisioning.hosting_limit_transport.probe_account_quota") as probe,
                patch("apps.provisioning.hosting_limit_transport.run_quota_operation") as native,
            ):
                apply_hosting_limits(cleanup.pk)
        probe.assert_not_called()
        native.assert_not_called()

    def test_canonical_node_change_requires_its_own_operational_receipt(self):
        raised = self.grant()
        self.assertEqual(self.apply(raised), "completed")
        with patch(
            "apps.provisioning.hosting_raise_service.timezone.now",
            return_value=raised.overlay_expires_at + timedelta(seconds=1),
        ):
            cleanup = self.expire(raised)
            other = VirtualminServer.objects.create(hostname="different-expiry-target.example.test")
            self.account.server = other
            self.account.save(update_fields=["server"])
            with (
                patch("apps.provisioning.hosting_limit_transport.probe_account_quota") as probe,
                patch("apps.provisioning.hosting_limit_transport.run_quota_operation") as native,
            ):
                apply_hosting_limits(cleanup.pk)
        probe.assert_not_called()
        native.assert_not_called()

    def test_due_revoked_foreign_owner_records_deadline_without_inheriting_mutation_consent(self):
        raised = self.grant()
        self.assertEqual(self.apply(raised), "completed")
        other = Customer.objects.create(name="A later owner", customer_type="individual")
        with patch("apps.provisioning.hosting_limit_tasks.async_task"):
            type(self.service).objects.filter(pk=self.service.pk).update(customer=other)
        count = self.service.limit_applications.count()
        with (
            patch(
                "apps.provisioning.hosting_raise_service.timezone.now",
                return_value=raised.overlay_expires_at + timedelta(seconds=1),
            ),
            patch("apps.provisioning.hosting_limit_transport.probe_account_quota") as probe,
            patch("apps.provisioning.hosting_limit_transport.run_quota_operation") as native,
        ):
            self.assertIsNone(expire_hosting_raise(self.service.pk))
        row = ServiceHostingRaise.objects.get(service=self.service)
        self.assertEqual((row.owner_id, row.status), (other.pk, "expired"))
        self.assertEqual(self.service.limit_applications.count(), count)
        self.assertIsNone(ServiceHostingLimits.objects.get(service=self.service).verified_at)
        probe.assert_not_called()
        native.assert_not_called()
