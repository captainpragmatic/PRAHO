"""Actual renewal preparation honors a service's accepted plan after old frozen periods."""

from decimal import Decimal

from django.test import TestCase

from apps.billing.models import BillingCycle, PriceGrandfathering, Subscription
from apps.billing.metering_models import UsageAggregation, UsageMeter
from apps.billing.metering_service import RatingEngine
from apps.billing.subscription_models import SubscriptionItem
from apps.billing.proforma_service import ProformaPaymentService
from apps.billing.recurring_billing import RecurringBillingOrchestrator, fixed_renewal_schedule
from apps.provisioning.models import Service
from apps.provisioning.hosting_limit_models import ServiceHostingLimits
from tests.billing.test_plan_change_settlement import _PlanChangeSettlementFixture


class PlanChangeRenewalTermsTests(_PlanChangeSettlementFixture, TestCase):
    def test_catalog_allowance_edit_cannot_charge_inside_the_accepted_bandwidth(self) -> None:
        _, product, plan = self.paid_change()
        original = self.subscription.billing_cycles.get(period_start=self.subscription.current_period_start)
        frozen = original.pricing_snapshot
        meter = UsageMeter.objects.create(
            name="bandwidth_gb", display_name="Bandwidth", category="bandwidth", unit="gb",
            aggregation_type="sum", rounding_mode="none",
        )
        SubscriptionItem.objects.create(
            subscription=self.subscription, product=product, currency=self.currency,
            unit_price_cents=100, meta={"meter_name": meter.name},
        )
        plan.bandwidth_gb = 1
        plan.save(update_fields=["bandwidth_gb"])
        prepared = RecurringBillingOrchestrator.prepare_due_proformas(as_of=self.subscription.next_proforma_at)
        self.assertEqual(prepared["errors"], [])
        self.assertEqual(prepared["proformas_created"], 1)
        cycle = BillingCycle.objects.get(subscription=self.subscription, period_start=self.subscription.current_period_end)
        aggregation = UsageAggregation.objects.create(
            meter=meter, customer=self.customer, subscription=self.subscription, billing_cycle=cycle,
            period_start=cycle.period_start, period_end=cycle.period_end,
            total_value=Decimal("50"), status="pending_rating",
        )
        rated = RatingEngine().rate_aggregation(str(aggregation.pk))
        self.assertTrue(rated.is_ok(), rated)
        aggregation.refresh_from_db()
        original.refresh_from_db()
        self.assertEqual(original.pricing_snapshot, frozen)
        self.assertEqual(ServiceHostingLimits.objects.get(service=self.service).bandwidth_allowance_mib, 102400)
        self.assertEqual((aggregation.included_allowance, aggregation.overage_value, aggregation.charge_cents),
                         (Decimal("100"), Decimal("0"), 0))

    def paid_change(self):
        change, proforma, product, plan = self.payable_change()
        paid = ProformaPaymentService.record_payment_and_convert(str(proforma.pk), 6000, "bank")
        self.assertTrue(paid.is_ok(), paid)
        change.refresh_from_db()
        self.assertEqual(change.status, "applying_limits")
        self.subscription.refresh_from_db()
        proforma_at, charge_at = fixed_renewal_schedule(self.subscription.current_period_end)
        self.subscription.next_proforma_at = proforma_at
        self.subscription.next_billing_date = proforma_at
        self.subscription.next_charge_at = charge_at
        self.subscription.save(update_fields=["next_proforma_at", "next_billing_date", "next_charge_at"])
        return change, product, plan

    def test_real_next_renewal_uses_new_price_instead_of_previous_frozen_cycle(self) -> None:
        self.paid_change()
        original = self.subscription.billing_cycles.get(period_start=self.subscription.current_period_start)
        frozen = (original.currency_id, original.quantity, original.unit_price_cents, original.pricing_snapshot)
        result = RecurringBillingOrchestrator.prepare_due_proformas(as_of=self.subscription.next_proforma_at)
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["proformas_created"], 1)
        renewal = BillingCycle.objects.get(
            subscription=self.subscription, period_start=self.subscription.current_period_end
        )
        self.assertEqual(renewal.unit_price_cents, 20000)
        self.assertEqual(renewal.proforma.lines.get(billing_cycle=renewal).unit_price_cents, 20000)
        original.refresh_from_db()
        self.assertEqual(
            (original.currency_id, original.quantity, original.unit_price_cents, original.pricing_snapshot), frozen
        )

    def test_changed_service_terms_override_shared_promise_without_erasing_other_service_promise(self) -> None:
        _, product, plan = self.paid_change()
        promise = PriceGrandfathering.objects.create(
            customer=self.customer,
            product=product,
            currency=self.currency,
            locked_price_cents=1500,
            original_price_cents=1500,
            current_product_price_cents=20000,
            reason="Another service's original promise",
        )
        other_service = Service.objects.create(
            customer=self.customer,
            service_plan=plan,
            currency=self.currency,
            service_name="Other promise",
            username="otherpromise",
            price=200,
            status="active",
        )
        other = Subscription.objects.create(
            customer=self.customer,
            product=product,
            service=other_service,
            currency=self.currency,
            unit_price_cents=20000,
            status="active",
            subscription_number="SUB-OTHER-PROMISE",
            current_period_start=self.subscription.current_period_start,
            current_period_end=self.subscription.current_period_end,
            next_proforma_at=self.subscription.next_proforma_at,
            next_charge_at=self.subscription.next_charge_at,
            next_billing_date=self.subscription.next_billing_date,
        )
        result = RecurringBillingOrchestrator.prepare_due_proformas(as_of=self.subscription.next_proforma_at)
        self.assertEqual(result["errors"], [])
        renewals = BillingCycle.objects.filter(
            subscription_id__in=[self.subscription.pk, other.pk], period_start=self.subscription.current_period_end
        )
        self.assertEqual(
            {row.subscription_id: row.unit_price_cents for row in renewals},
            {self.subscription.pk: 20000, other.pk: 1500},
        )
        promise.refresh_from_db()
        self.assertTrue(promise.is_active)
        self.assertEqual(promise.locked_price_cents, 1500)
