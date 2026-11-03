"""Payment acceptance is separate from exact current native verification."""

from copy import copy
from unittest.mock import patch
from uuid import uuid4

from django.db import connection
from django.test import TransactionTestCase
from django.utils import timezone

from apps.billing.plan_change_financial import validate_preserved_plan_coverage
from apps.billing.plan_change_lifecycle import activate_scheduled_plan_change
from apps.billing.plan_change_operations import reconcile_plan_change_operation, reconcile_plan_change_operations
from apps.billing.proforma_service import ProformaPaymentService
from apps.billing.subscription_models import Subscription
from apps.provisioning.hosting_limit_execution import apply_hosting_limits
from apps.provisioning.hosting_limit_models import ServiceHostingLimits
from apps.provisioning.models import Service
from tests.billing import test_plan_change_lifecycle as lifecycle_tests
from tests.helpers.plan_change_checkout import VerifiedPlanChangeCheckoutFixture
from tests.provisioning.test_hosting_safety_observation import HostingSafetyObservationFixture


class PlanOperationFixture(VerifiedPlanChangeCheckoutFixture):
    def paid_change(self):
        change = self.confirm(self.quote())
        paid = ProformaPaymentService.record_payment_and_convert(str(change.proforma_id), change.total_cents, "bank")
        self.assertTrue(paid.is_ok(), paid)
        change.refresh_from_db()
        self.assertEqual(change.status, "applying_limits")
        return change

    def apply(self, change):
        def native(server, action, request):
            self.assertFalse(connection.in_atomic_block)
            self.assertEqual(action, "apply")
            receipt = self.receipt(cap=request["disk_limit_kib"] // 1024, request=request, available=50 * 1024**3)
            receipt["configured_bandwidth_bytes"] = request["bandwidth_limit_bytes"]
            return receipt

        with (
            patch(
                "apps.provisioning.hosting_limit_transport.probe_account_quota",
                return_value=self.receipt(cap=5632, available=50 * 1024**3),
            ),
            patch("apps.provisioning.hosting_limit_transport.run_quota_operation", side_effect=native),
        ):
            self.assertEqual(apply_hosting_limits(change.limit_application_id), "completed")


class PlanChangeOperationsTests(PlanOperationFixture, TransactionTestCase):
    def test_bounded_sweep_advances_a_waiting_service_before_checking_the_next_service(self):
        first = self.paid_change()
        service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name="second-pending.example.test",
            domain="second-pending.example.test",
            username="secondpending",
            billing_cycle="monthly",
            price=80,
            status="active",
        )
        subscription = Subscription.objects.create(
            customer=self.customer,
            product=self.product,
            service=service,
            currency=self.currency,
            subscription_number="SUB-SECOND-PENDING",
            unit_price_cents=8000,
            status="active",
            quantity=1,
            current_period_start=self.subscription.current_period_start,
            current_period_end=self.subscription.current_period_end,
            next_billing_date=self.subscription.next_billing_date,
        )
        # A second service's inconsistent imported commercial evidence must be
        # reviewed, even while the first has no terminal native receipt yet.
        second = copy(first)
        second.pk, second._state = uuid4(), copy(first._state)
        second._state.adding = True
        second.service, second.subscription, second.submission_id = service, subscription, uuid4()
        second.proforma, second.invoice, second.limit_application = None, None, None
        second.next_reconcile_at = timezone.now()
        second.save(force_insert=True)
        validate_preserved_plan_coverage(first)
        self.assertEqual(reconcile_plan_change_operations(limit=1), {"applying_limits": 1})
        self.assertEqual(reconcile_plan_change_operations(limit=1), {"paid_review": 1})
        first.refresh_from_db()
        second.refresh_from_db()
        self.assertEqual((first.status, second.status), ("applying_limits", "paid_review"))

    def test_current_native_receipt_completes_exact_accepted_revision_once(self):
        change = self.paid_change()
        self.apply(change)
        completed = reconcile_plan_change_operation(change.pk)
        self.assertEqual(completed.status, "completed")
        self.assertIsNotNone(completed.applied_at)
        self.assertEqual(reconcile_plan_change_operation(change.pk).applied_at, completed.applied_at)

    def test_completed_old_connection_receipt_cannot_complete_current_operation(self):
        change = self.paid_change()
        self.apply(change)
        self.server.api_port += 1
        self.server.save(update_fields=["api_port"])
        current = reconcile_plan_change_operation(change.pk)
        self.assertEqual(current.status, "limits_attention")
        self.assertIsNone(current.applied_at)


class ScheduledOperationRecoveryTests(PlanOperationFixture, TransactionTestCase):
    probe = HostingSafetyObservationFixture.probe
    safety_request = HostingSafetyObservationFixture.request
    run_observer = HostingSafetyObservationFixture.run_observer
    scheduled = lifecycle_tests.ScheduledPlanChangeTests.scheduled

    def test_healed_frozen_profile_retries_only_resources_without_rewriting_lower_bill(self):
        change = self.scheduled()
        plan = self.target.default_service_plan
        original = dict(plan.features)
        plan.features = {"temporary_catalog_drift": True}
        plan.save(update_fields=["features"])
        accepted = activate_scheduled_plan_change(change.pk, at=change.effective_at)
        self.assertEqual(accepted.status, "limits_attention")
        self.assertIsNone(accepted.limit_application_id)
        self.subscription.refresh_from_db()
        agreed = (self.subscription.product_id, self.subscription.unit_price_cents)
        plan.features = original
        plan.save(update_fields=["features"])
        resumed = reconcile_plan_change_operation(change.pk)
        self.assertIsNotNone(resumed.limit_application_id)
        self.assertEqual(resumed.status, "limits_attention")
        self.subscription.refresh_from_db()
        self.assertEqual((self.subscription.product_id, self.subscription.unit_price_cents), agreed)
        self.assertEqual(ServiceHostingLimits.objects.get(service=self.service).disk_allowance_mib, 2048)
