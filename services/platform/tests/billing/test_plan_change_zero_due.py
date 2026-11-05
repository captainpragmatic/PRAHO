"""Rounded-zero acceptance commits real terms without inventing financial documents."""

from datetime import timedelta

from django.core.exceptions import ValidationError
from django.test import TestCase

from apps.billing.models import Invoice, Payment, ProformaInvoice
from apps.billing.plan_change_coverage import load_plan_coverage
from apps.billing.plan_change_models import PlanChangeInterval
from apps.billing.plan_change_settlement import commit_zero_due_plan_change
from apps.products.models import Product
from apps.provisioning.hosting_limit_assignments import assignment_terms_for_plan
from apps.provisioning.hosting_limit_models import HostingLimitApplication, ServiceHostingLimits
from apps.provisioning.models import ServicePlan
from tests.billing.test_plan_change_settlement import _PlanChangeSettlementFixture


class ZeroDuePlanChangeTests(_PlanChangeSettlementFixture, TestCase):
    def zero_quote(self, *, confirmed=True):
        cycle, _, _ = self.cycle(start=self.now - timedelta(days=30), end=self.now + timedelta(hours=1))
        target = ServicePlan.objects.create(
            name="Tiny price increase",
            plan_type="shared_hosting",
            price_monthly="80.01",
            disk_space_gb=20,
        )
        product = Product.objects.create(name="Tiny increase", slug="zero-due-target", default_service_plan=target)
        change = self.change(
            to_plan=target,
            to_product=product,
            target_period_price_cents=8001,
            net_cents=0,
            tax_cents=0,
            total_cents=0,
            current_period_start=cycle.period_start,
            current_period_end=cycle.period_end,
            authority_expires_at=self.now + timedelta(minutes=30),
            quote_snapshot={
                "version": 1,
                "billing_cycle": self.subscription.billing_cycle,
                "quantity": 1,
                "accepted_limits": assignment_terms_for_plan(target).as_snapshot(),
                "coverage": load_plan_coverage(self.subscription, at=self.now).evidence,
            },
        )
        PlanChangeInterval.objects.create(
            change=change,
            ordinal=0,
            period_start=cycle.period_start,
            period_end=cycle.period_end,
            slice_start=self.now,
            base_net_cents=8000,
            prior_supplement_cents=0,
            net_cents=0,
            current_slice=True,
            evidence=change.quote_snapshot["coverage"][str(cycle.pk)],
        )
        if confirmed:
            change.confirm()
            change.save(update_fields=["status"])
        return change, target

    def test_accepted_zero_due_commits_the_same_assignment_without_payment_or_document(self) -> None:
        change, target = self.zero_quote()
        documents = (Invoice.objects.count(), ProformaInvoice.objects.count(), Payment.objects.count())
        old_period = (self.subscription.current_period_start, self.subscription.current_period_end)
        commit_zero_due_plan_change(change)
        change.refresh_from_db()
        self.subscription.refresh_from_db()
        self.service.refresh_from_db()
        self.assertEqual(change.status, "applying_limits")
        self.assertEqual(self.service.service_plan_id, target.pk)
        self.assertEqual(self.subscription.unit_price_cents, 8001)
        self.assertEqual((self.subscription.current_period_start, self.subscription.current_period_end), old_period)
        self.assertEqual(ServiceHostingLimits.objects.get(service=self.service).revision, 2)
        self.assertEqual((Invoice.objects.count(), ProformaInvoice.objects.count(), Payment.objects.count()), documents)
        self.assertIsNone(change.proforma_id)
        self.assertIsNone(change.invoice_id)
        commit_zero_due_plan_change(change)
        self.assertEqual(HostingLimitApplication.objects.filter(service=self.service).count(), 1)

    def test_zero_quote_still_requires_explicit_customer_confirmation(self) -> None:
        change, _ = self.zero_quote(confirmed=False)
        with self.assertRaises(ValidationError):
            commit_zero_due_plan_change(change)
        self.assertFalse(HostingLimitApplication.objects.filter(service=self.service).exists())

    def test_a_positive_payable_quote_cannot_bypass_settlement(self) -> None:
        change, _, _, _ = self.payable_change()
        with self.assertRaises(ValidationError):
            commit_zero_due_plan_change(change)
        self.assertEqual(ServiceHostingLimits.objects.get(service=self.service).revision, 1)
