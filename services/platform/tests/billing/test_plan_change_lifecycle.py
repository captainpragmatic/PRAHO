"""Cancellation retains fiscal evidence and never loses an issued provider attempt."""

from datetime import timedelta
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import TransactionTestCase
from django.urls import reverse

from apps.billing.plan_change_lifecycle import (
    activate_scheduled_plan_change,
    activate_scheduled_plan_changes,
    cancel_plan_change,
    expire_unissued_plan_change,
)
from apps.billing.plan_change_payment_models import PlanChangePaymentAttempt
from apps.billing.plan_change_payment_service import reserve_plan_change_payment
from apps.billing.proforma_service import ProformaPaymentService
from apps.billing.recurring_billing import RecurringBillingOrchestrator, fixed_renewal_schedule
from apps.customers.models import Customer
from apps.products.models import ProductPrice, ProductRelationship
from apps.provisioning.hosting_limit_execution import apply_hosting_limits
from apps.provisioning.hosting_limit_models import ServiceHostingLimits
from apps.settings.services import SettingsService
from apps.users.models import CustomerMembership, User
from tests.helpers.plan_change_checkout import VerifiedPlanChangeCheckoutFixture
from tests.provisioning.test_hosting_safety_observation import HostingSafetyObservationFixture


class PlanChangeCancellationTests(VerifiedPlanChangeCheckoutFixture, TransactionTestCase):
    def cancel(self, change, *, customer_id=None, actor_id=None, fingerprint=None):
        return cancel_plan_change(
            change.pk,
            customer_id=customer_id or self.customer.pk,
            actor_id=actor_id or self.actor.pk,
            expected_fingerprint=fingerprint or change.request_fingerprint,
        )

    def test_unpublished_quote_cancels_without_financial_documents_or_gateway(self):
        change = self.quote()
        with patch("apps.billing.plan_change_payment_service._gateway") as gateway:
            result = self.cancel(change)
        self.assertEqual(result.status, "cancelled")
        self.assertIsNone(result.proforma_id)
        gateway.assert_not_called()

    def test_confirmed_unissued_quote_keeps_its_payable_fiscal_evidence(self):
        change = self.confirm(self.quote())
        number = change.proforma.number
        result = self.cancel(change)
        self.assertEqual(result.status, "cancelled")
        result.proforma.refresh_from_db()
        self.assertEqual((result.proforma.number, result.proforma.status), (number, "accepted"))
        self.assertFalse(PlanChangePaymentAttempt.objects.filter(change=change).exists())

    def test_never_issued_durable_attempt_uses_its_existing_terminal_proof(self):
        change = self.confirm(self.quote())
        attempt = reserve_plan_change_payment(
            change.pk,
            customer_id=self.customer.pk,
            actor_id=self.actor.pk,
            expected_fingerprint=change.request_fingerprint,
        )
        with patch("apps.billing.plan_change_payment_service._gateway") as gateway:
            self.assertEqual(self.cancel(change).status, "cancelled")
        gateway.assert_not_called()
        attempt.refresh_from_db()
        self.assertEqual((attempt.state, attempt.provider_status), ("cancelled", "not_submitted"))

    def test_changed_fingerprint_and_other_customer_cannot_cancel(self):
        change = self.quote()
        other = Customer.objects.create(name="Other plan owner", status="active")
        with self.assertRaises(ValidationError):
            self.cancel(change, customer_id=other.pk)
        with self.assertRaises(ValidationError):
            self.cancel(change, fingerprint="0" * 64)
        change.refresh_from_db()
        self.assertEqual(change.status, "quoted")

    def test_another_current_billing_actor_can_cancel_while_customer_is_suspended(self):
        change = self.confirm(self.quote())
        actor = User.objects.create_user(email="another-plan-owner@example.test")
        CustomerMembership.objects.create(user=actor, customer=self.customer, role="owner", is_active=True)
        self.customer.status = "suspended"
        self.customer.save(update_fields=["status"])
        self.assertEqual(self.cancel(change, actor_id=actor.pk).status, "cancelled")

    def transfer_to_another_customer(self):
        other = Customer.objects.create(name="Transferred service owner", status="active")
        self.client.force_login(self.staff)
        response = self.client.post(
            reverse("provisioning:service_edit", args=[self.service.pk]),
            {"customer_id": other.pk, "domain": self.service.domain},
        )
        self.assertEqual(response.status_code, 302, response.content)
        self.service.refresh_from_db()
        self.assertEqual(self.service.customer_id, other.pk)
        return other

    def test_public_staff_owner_transfer_revokes_the_previous_customers_cancellation_scope(self):
        change = self.quote()
        self.transfer_to_another_customer()
        with self.assertRaisesMessage(ValidationError, "Current billing authority"):
            self.cancel(change)
        change.refresh_from_db()
        self.assertEqual(change.status, "quoted")

    def test_expired_confirmed_unissued_quote_retains_document_for_actual_late_money_review(self):
        change = self.confirm(self.quote())
        closed = expire_unissued_plan_change(change.pk, at=change.expires_at + timedelta(microseconds=1))
        self.assertEqual(closed.status, "expired")
        self.assertEqual(closed.proforma_id, change.proforma_id)
        closed.proforma.refresh_from_db()
        self.assertEqual(closed.proforma.status, "accepted")
        paid = ProformaPaymentService.record_payment_and_convert(str(closed.proforma_id), closed.total_cents, "bank")
        self.assertTrue(paid.is_ok(), paid)
        closed.refresh_from_db()
        self.assertEqual(closed.status, "paid_review")
        self.assertEqual(paid.unwrap().status, "paid")
        self.assertIsNone(closed.limit_application_id)

    def test_unissued_quote_expiry_cannot_close_an_existing_durable_attempt(self):
        change = self.confirm(self.quote())
        reserve_plan_change_payment(
            change.pk,
            customer_id=self.customer.pk,
            actor_id=self.actor.pk,
            expected_fingerprint=change.request_fingerprint,
        )
        self.assertEqual(
            expire_unissued_plan_change(change.pk, at=change.expires_at + timedelta(seconds=1)).status,
            "awaiting_payment",
        )


class ScheduledPlanChangeTests(VerifiedPlanChangeCheckoutFixture, TransactionTestCase):
    period_remaining = timedelta(days=10)
    cancel = PlanChangeCancellationTests.cancel
    transfer_to_another_customer = PlanChangeCancellationTests.transfer_to_another_customer
    probe = HostingSafetyObservationFixture.probe
    safety_request = HostingSafetyObservationFixture.request
    run_observer = HostingSafetyObservationFixture.run_observer

    def scheduled(self):
        plan = self.target.default_service_plan
        plan.disk_space_gb, plan.bandwidth_gb = 2, 10
        plan.save(update_fields=["disk_space_gb", "bandwidth_gb"])
        ProductPrice.objects.filter(product=self.target).update(monthly_price_cents=4000)
        ProductRelationship.objects.filter(source_product=self.product, target_product=self.target).delete()
        ProductRelationship.objects.create(
            source_product=self.target, target_product=self.product, relationship_type="upgrades_to"
        )
        job = self.safety_request()
        self.assertEqual(self.run_observer(job), ("completed", 1))
        change = self.confirm(self.quote())
        self.assertEqual(change.status, "scheduled")
        proforma_at, charge_at = fixed_renewal_schedule(self.subscription.current_period_end)
        self.subscription.next_proforma_at = self.subscription.next_billing_date = proforma_at
        self.subscription.next_charge_at = charge_at
        self.subscription.save(update_fields=["next_proforma_at", "next_billing_date", "next_charge_at"])
        return change

    def test_prepared_and_converted_renewal_keep_the_accepted_target_label_and_sku(self):
        change = self.scheduled()
        original_name, original_sku = self.target.name, self.target.slug
        self.target.name, self.target.slug = "Later catalog label", "later-catalog-sku"
        self.target.save(update_fields=["name", "slug"])
        prepared = RecurringBillingOrchestrator.prepare_due_proformas(as_of=self.now)
        self.assertEqual(prepared["proformas_created"], 1, prepared)
        cycle = self.subscription.billing_cycles.get(period_start=change.effective_at)
        line = cycle.proforma.lines.get(billing_cycle=cycle)
        self.assertIn(original_name, line.description)
        self.assertEqual(line.seller_item_id, original_sku)
        self.assertNotIn(self.target.name, line.description)
        paid = ProformaPaymentService.record_payment_and_convert(
            str(cycle.proforma_id), cycle.proforma.total_cents, "bank"
        )
        self.assertTrue(paid.is_ok(), paid)
        converted = paid.unwrap().lines.get(billing_cycle=cycle)
        self.assertEqual((converted.description, converted.seller_item_id), (line.description, original_sku))

    def test_early_paid_lower_renewal_keeps_current_limits_until_exact_effective_date(self):
        change = self.scheduled()
        previous_plan = self.service.service_plan_id
        old_terms = (self.subscription.product_id, self.subscription.unit_price_cents, self.service.price)
        prepared = RecurringBillingOrchestrator.prepare_due_proformas(as_of=self.now)
        self.assertEqual(prepared["proformas_created"], 1, prepared)
        cycle = self.subscription.billing_cycles.get(period_start=change.effective_at)
        self.assertEqual(cycle.unit_price_cents, 4000)
        paid = ProformaPaymentService.record_payment_and_convert(
            str(cycle.proforma_id), cycle.proforma.total_cents, "bank"
        )
        self.assertTrue(paid.is_ok(), paid)
        self.subscription.refresh_from_db()
        paid_period = (self.subscription.current_period_start, self.subscription.current_period_end)
        self.service.refresh_from_db()
        self.assertEqual(self.service.service_plan_id, previous_plan)
        self.assertEqual(
            (self.subscription.product_id, self.subscription.unit_price_cents, self.service.price), old_terms
        )
        self.assertEqual(
            activate_scheduled_plan_change(change.pk, at=change.effective_at - timedelta(microseconds=1)).status,
            "scheduled",
        )
        self.subscription.refresh_from_db()
        self.service.refresh_from_db()
        self.assertEqual(
            (self.subscription.product_id, self.subscription.unit_price_cents, self.service.price), old_terms
        )
        activated = activate_scheduled_plan_change(change.pk, at=change.effective_at)
        self.assertEqual(activated.status, "applying_limits")
        self.subscription.refresh_from_db()
        self.service.refresh_from_db()
        self.assertEqual((self.subscription.unit_price_cents, self.service.price), (4000, 40))
        self.assertEqual(self.service.service_plan_id, change.to_plan_id)
        self.assertEqual((self.subscription.current_period_start, self.subscription.current_period_end), paid_period)
        self.assertEqual(ServiceHostingLimits.objects.get(service=self.service).disk_allowance_mib, 2048)
        self.assertIsNotNone(activated.limit_application_id)

    def test_scheduled_cancellation_refuses_after_the_lower_renewal_is_committed(self):
        change = self.scheduled()
        prepared = RecurringBillingOrchestrator.prepare_due_proformas(as_of=self.now)
        self.assertEqual(prepared["proformas_created"], 1, prepared)
        with self.assertRaisesMessage(ValidationError, "committed renewal"):
            self.cancel(change)
        change.refresh_from_db()
        self.assertEqual(change.status, "scheduled")

    def test_changed_native_profile_preserves_the_lower_bill_and_requires_limits_attention(self):
        change = self.scheduled()
        plan = self.target.default_service_plan
        plan.features = {"changed_after_acceptance": True}
        plan.save(update_fields=["features"])
        activated = activate_scheduled_plan_change(change.pk, at=change.effective_at)
        self.assertEqual(activated.status, "limits_attention")
        self.subscription.refresh_from_db()
        self.assertEqual((self.subscription.product_id, self.subscription.unit_price_cents), (self.target.pk, 4000))
        self.assertIsNone(activated.limit_application_id)
        self.assertEqual(ServiceHostingLimits.objects.get(service=self.service).disk_allowance_mib, 5120)

    def test_usage_growth_after_acceptance_keeps_the_lower_bill_and_leaves_native_limits_pending(self):
        change = self.scheduled()
        self.publish_usage(3072, 1)
        activated = activate_scheduled_plan_change(change.pk, at=change.effective_at)
        self.assertEqual(activated.status, "applying_limits")
        probe = self.receipt(cap=5632)
        probe["observation"] = {
            "files_bytes": 3072 * 1024**2,
            "database_bytes": 1024**2,
            "total_bytes": 3073 * 1024**2,
        }
        with (
            patch("apps.provisioning.hosting_limit_transport.probe_account_quota", return_value=probe),
            patch("apps.provisioning.hosting_limit_transport.run_quota_operation") as native,
        ):
            self.assertEqual(apply_hosting_limits(activated.limit_application_id), "pending")
        native.assert_not_called()
        limits = ServiceHostingLimits.objects.get(service=self.service)
        self.assertEqual((limits.disk_allowance_mib, limits.operational_disk_allowance_mib), (2048, 5120))
        self.subscription.refresh_from_db()
        self.assertEqual(self.subscription.unit_price_cents, 4000)

    def test_public_owner_transfer_prevents_scheduled_assignment_to_another_customers_service(self):
        change = self.scheduled()
        old_price, old_plan = self.service.price, self.service.service_plan_id
        self.transfer_to_another_customer()
        activated = activate_scheduled_plan_change(change.pk, at=change.effective_at)
        self.assertEqual(activated.status, "paid_review")
        self.assertIsNone(activated.limit_application_id)
        self.service.refresh_from_db()
        self.subscription.refresh_from_db()
        self.assertEqual((self.service.price, self.service.service_plan_id), (old_price, old_plan))
        self.assertEqual(self.subscription.unit_price_cents, 8000)

    def test_registered_activation_sweep_survives_acceptance_flag_disable_and_replays_once(self):
        change = self.scheduled()
        self.assertTrue(SettingsService.update_setting("billing.hosting_plan_changes_enabled", False).is_ok())
        self.assertEqual(activate_scheduled_plan_changes(at=change.effective_at), {"applying_limits": 1})
        self.assertEqual(activate_scheduled_plan_changes(at=change.effective_at), {})
        change.refresh_from_db()
        self.assertIsNotNone(change.limit_application_id)
