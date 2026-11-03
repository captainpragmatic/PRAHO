"""Visible disputed coverage blocks new native quota commands before background review."""

from datetime import timedelta
from unittest.mock import patch

from django.db import connection
from django.test import TransactionTestCase
from django.test.utils import CaptureQueriesContext

from apps.audit.services import GDPRDeletionService
from apps.billing.models import Payment
from apps.billing.payment_convergence import PaymentSuccessService
from apps.billing.plan_change_financial import (
    commercial_source_refusal,
    plan_change_native_refusal,
    validate_preserved_plan_coverage,
)
from apps.billing.plan_change_lifecycle import activate_scheduled_plan_change
from apps.infrastructure.node_maintenance_gate import begin_account_job
from apps.provisioning.hosting_limit_execution import apply_hosting_limits
from apps.provisioning.hosting_limit_execution_models import HostingLimitExecution
from apps.provisioning.hosting_limit_models import ServiceHostingLimits
from apps.provisioning.hosting_parent_limits import held_parent_cap_repair_issued, mark_parent_limits_issued
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob
from apps.users.models import CustomerMembership
from tests.billing import test_plan_change_lifecycle as lifecycle_tests
from tests.billing.test_plan_change_intervals import _PlanChangeCoverageFixture
from tests.helpers.plan_change_checkout import VerifiedPlanChangeCheckoutFixture
from tests.provisioning.test_hosting_safety_observation import HostingSafetyObservationFixture


class StripeCoverageFixture(VerifiedPlanChangeCheckoutFixture):
    def cycle(self, **kwargs):
        cycle, invoice, line = _PlanChangeCoverageFixture.cycle(self, paid=False, **kwargs)
        Payment.objects.create(
            customer=self.customer,
            invoice=invoice,
            currency=self.currency,
            amount_cents=invoice.total_cents,
            payment_method="stripe",
            gateway_txn_id="pi_original_paid_coverage",
            meta={"stripe_customer_id": "cus_original_coverage"},
        )
        paid = PaymentSuccessService.converge_gateway_success(
            "pi_original_paid_coverage",
            {"amount_received": invoice.total_cents, "currency": "ron", "customer_id": "cus_original_coverage"},
        )
        self.assertTrue(paid.is_ok(), paid)
        invoice.refresh_from_db()
        self.assertEqual(invoice.status, "paid")
        return cycle, invoice, line

    def dispute(self, intent_id, *, amount):
        with patch("apps.notifications.services.NotificationService.send_admin_alert", return_value=True):
            accepted, message, event = self.deliver_signed_payload(
                {
                    "id": "evt_disputed_financial_coverage",
                    "type": "charge.dispute.created",
                    "data": {
                        "object": {
                            "id": "dp_visible_financial_fact",
                            "payment_intent": intent_id,
                            "amount": amount,
                            "currency": "ron",
                            "reason": "fraudulent",
                        }
                    },
                },
            )
        self.assertTrue(accepted, message)
        self.assertEqual(event.status, "processed")
        self.assertEqual(Payment.objects.get(gateway_txn_id=intent_id).status, "disputed")


class PlanChangeNativeFinancialGateTests(StripeCoverageFixture, TransactionTestCase):
    def settled_topup(self):
        change, attempt, sdk = self.ready_attempt()
        accepted, message, _event = self.signed_delivery(sdk.PaymentIntent.create.call_args.kwargs["metadata"])
        self.assertTrue(accepted, message)
        change.refresh_from_db()
        self.assertEqual(change.status, "applying_limits")
        return change, attempt

    def test_only_the_current_issued_parent_can_repair_its_frozen_paid_cap_after_dispute(self):
        change, attempt = self.settled_topup()
        attempt.refresh_from_db()
        job = VirtualminProvisioningJob.objects.create(
            account=self.account, server=self.server, operation="create_domain"
        )
        self.assertIsNone(begin_account_job(self.account, job))
        scope = {
            "job_id": str(job.pk),
            "token": "",
            "account_server_id": str(self.server.pk),
            "native_server_id": str(self.server.pk),
        }
        application = change.limit_application
        self.assertFalse(held_parent_cap_repair_issued(application, scope), "Planning is not issuance")
        self.assertTrue(mark_parent_limits_issued(job))
        self.dispute(attempt.gateway_intent_id, amount=change.total_cents)
        with CaptureQueriesContext(connection) as queries:
            self.assertIsNotNone(commercial_source_refusal(application), "An origin check grants no issued exception")
            self.assertIsNone(plan_change_native_refusal(application, parent=scope))
        self.assertFalse(any("FOR UPDATE" in query["sql"] or "FOR NO KEY UPDATE" in query["sql"] for query in queries))
        self.assertTrue(mark_parent_limits_issued(job), "The same issued claim may finish mandatory frozen repair")
        VirtualminProvisioningJob.objects.filter(pk=job.pk).update(
            execution_token="00000000-0000-0000-0000-000000000999"
        )
        self.assertIsNotNone(
            plan_change_native_refusal(application, parent=scope), "A prior claim cannot authorize repair"
        )

    def test_actual_paid_then_disputed_topup_never_dispatches_a_new_quota_command(self):
        change, attempt, sdk = self.ready_attempt()
        accepted, message, _event = self.signed_delivery(sdk.PaymentIntent.create.call_args.kwargs["metadata"])
        self.assertTrue(accepted, message)
        change.refresh_from_db()
        self.assertEqual(change.status, "applying_limits")
        self.dispute("pi_signed_plan", amount=attempt.payment.amount_cents)
        change.refresh_from_db()
        self.assertEqual(change.status, "applying_limits", "The deferred review worker must not provide this guard")
        with (
            patch(
                "apps.provisioning.hosting_limit_transport.probe_account_quota",
                return_value=self.receipt(cap=5632, available=50 * 1024**3),
            ) as probe,
            patch("apps.provisioning.hosting_limit_transport.run_quota_operation") as native,
        ):
            apply_hosting_limits(change.limit_application_id)
        native.assert_not_called()
        probe.assert_not_called()
        limits = ServiceHostingLimits.objects.get(service=self.service)
        self.assertEqual(limits.applied_revision, 2)

    def test_public_erasure_after_payment_refuses_new_native_grant_without_ssh(self):
        change, _attempt = self.settled_topup()
        self.customer.customer_type = "individual"
        self.customer.save(update_fields=["customer_type"])
        membership = CustomerMembership.objects.get(user=self.actor, customer=self.customer)
        membership.role = "owner"
        membership.save(update_fields=["role"])
        request = GDPRDeletionService.create_deletion_request(user=self.actor)
        self.assertTrue(request.is_ok(), request)
        erased = GDPRDeletionService.process_deletion_request(request.unwrap())
        self.assertTrue(erased.is_ok(), erased)
        self.customer.refresh_from_db()
        self.assertIsNotNone(self.customer.anonymized_at)
        with (
            patch(
                "apps.provisioning.hosting_limit_transport.probe_account_quota",
                return_value=self.receipt(cap=5632, available=50 * 1024**3),
            ) as probe,
            patch("apps.provisioning.hosting_limit_transport.run_quota_operation") as native,
        ):
            apply_hosting_limits(change.limit_application_id)
        probe.assert_not_called()
        native.assert_not_called()

    def test_dispute_after_native_issuance_never_releases_uncertainty_or_reissues(self):
        change, attempt = self.settled_topup()
        validate_preserved_plan_coverage(change)
        self.assertIsNone(plan_change_native_refusal(change.limit_application))

        def unknown(*args):
            self.assertFalse(connection.in_atomic_block)
            self.dispute("pi_signed_plan", amount=attempt.payment.amount_cents)
            raise OSError("Receipt lost after native issuance")

        with (
            patch(
                "apps.provisioning.hosting_limit_transport.probe_account_quota",
                return_value=self.receipt(cap=5632, available=50 * 1024**3),
            ),
            patch("apps.provisioning.hosting_limit_transport.run_quota_operation", side_effect=unknown) as native,
        ):
            self.assertEqual(apply_hosting_limits(change.limit_application_id), "attention")
            self.assertEqual(apply_hosting_limits(change.limit_application_id), "attention")
        native.assert_called_once()
        execution = HostingLimitExecution.objects.get(job__hosting_limit_application_id=change.limit_application_id)
        self.assertIsNotNone(execution.issued_at)
        self.assertIsNone(execution.reservation_released_at)
        self.assertGreater(execution.reserved_bytes, 0)
        self.assertEqual(execution.job.status, "attention")


class ScheduledCoverageFinancialGateTests(StripeCoverageFixture, TransactionTestCase):
    period_remaining = timedelta(days=10)
    probe = HostingSafetyObservationFixture.probe
    safety_request = HostingSafetyObservationFixture.request
    run_observer = HostingSafetyObservationFixture.run_observer
    scheduled = lifecycle_tests.ScheduledPlanChangeTests.scheduled

    def test_original_dispute_blocks_scheduled_activation_before_any_review_worker(self):
        change = self.scheduled()
        self.dispute("pi_original_paid_coverage", amount=8000)
        activated = activate_scheduled_plan_change(change.pk, at=change.effective_at)
        self.assertEqual(activated.status, "paid_review")
        self.assertIsNone(activated.limit_application_id)
        self.subscription.refresh_from_db()
        self.assertEqual(self.subscription.unit_price_cents, 8000)
