"""Real proforma conversion must commit the paid plan without advancing entitlement."""

from datetime import timedelta
from decimal import Decimal
from uuid import uuid4

from django.test import TestCase

from apps.audit.services import GDPRDeletionService
from apps.billing.models import ProformaInvoice, ProformaLine
from apps.billing.plan_change_coverage import load_plan_coverage
from apps.billing.plan_change_models import PlanChangeInterval
from apps.billing.proforma_service import ProformaPaymentService
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from apps.promotions.models import Coupon, PromotionApplication, PromotionCampaign, RenewalBenefit
from apps.provisioning.hosting_limit_assignments import assignment_terms_for_plan
from apps.provisioning.hosting_limit_models import HostingLimitApplication, ServiceHostingLimits
from apps.provisioning.models import Service, ServicePlan
from apps.users.models import CustomerMembership
from tests.billing.test_plan_change_intervals import _PlanChangeCoverageFixture


class _PlanChangeSettlementFixture(_PlanChangeCoverageFixture):
    def payable_change(self, *, expired=False):
        cycle, _, _ = self.cycle()
        plan = ServicePlan.objects.create(
            name="Larger", plan_type="shared_hosting", price_monthly=200, disk_space_gb=20, bandwidth_gb=100
        )
        product = Product.objects.create(
            name="Larger", slug="paid-larger", product_type="hosting", default_service_plan=plan
        )
        change = self.change(
            to_product=product,
            to_plan=plan,
            net_cents=6000,
            tax_cents=0,
            total_cents=6000,
            authority_expires_at=self.now - timedelta(seconds=1) if expired else self.now + timedelta(hours=1),
            quote_snapshot={
                "version": 1,
                "billing_cycle": self.subscription.billing_cycle,
                "quantity": 1,
                "labels": {"from": self.product.name, "to": product.name, "to_sku": product.slug},
                "accepted_limits": assignment_terms_for_plan(plan).as_snapshot(),
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
            net_cents=6000,
            current_slice=True,
            evidence=change.quote_snapshot["coverage"][str(cycle.pk)],
        )
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"UPGRADE-{uuid4().hex}",
            subtotal_cents=6000,
            total_cents=6000,
            valid_until=self.now + timedelta(days=1),
            bill_to_country="RO",
            bill_to_name=self.customer.name,
        )
        ProformaLine.objects.create(
            proforma=proforma,
            service=self.service,
            kind="service",
            description="Base to Larger: remaining paid service period",
            quantity=1,
            unit_price_cents=6000,
            period_start=self.now.date(),
            period_end=change.current_period_end.date(),
        )
        proforma.send_proforma()
        proforma.save(update_fields=["status"])
        change.proforma = proforma
        change.confirm()
        change.save(update_fields=["proforma", "status"])
        return change, proforma, product, plan


class PlanChangeSettlementTests(_PlanChangeSettlementFixture, TestCase):
    def test_payment_after_public_erasure_is_retained_for_review_without_switching_resources(self) -> None:
        self.customer.customer_type = "individual"
        self.customer.save(update_fields=["customer_type"])
        CustomerMembership.objects.create(customer=self.customer, user=self.actor, role="owner", is_active=True)
        change, proforma, _, _ = self.payable_change()
        request = GDPRDeletionService.create_deletion_request(user=self.actor)
        self.assertTrue(request.is_ok(), request)
        erased = GDPRDeletionService.process_deletion_request(request.unwrap())
        self.assertTrue(erased.is_ok(), erased)
        self.customer.refresh_from_db()
        self.assertIsNotNone(self.customer.anonymized_at)
        paid = ProformaPaymentService.record_payment_and_convert(str(proforma.pk), 6000, "bank")
        self.assertTrue(paid.is_ok(), paid)
        self.assertEqual(paid.unwrap().status, "paid")
        change.refresh_from_db()
        self.service.refresh_from_db()
        self.assertEqual(change.status, "paid_review")
        self.assertEqual(self.service.service_plan_id, self.plan.pk)
        self.assertFalse(HostingLimitApplication.objects.filter(service=self.service).exists())

    def test_real_conversion_applies_product_money_and_allowance_once(self) -> None:
        change, proforma, product, plan = self.payable_change()
        old_period = (self.subscription.current_period_start, self.subscription.current_period_end)
        result = ProformaPaymentService.record_payment_and_convert(str(proforma.pk), 6000, "bank")
        self.assertTrue(result.is_ok(), result)
        invoice = result.unwrap()
        self.assertEqual(invoice.status, "paid")
        self.service.refresh_from_db()
        self.subscription.refresh_from_db()
        change.refresh_from_db()
        self.assertEqual(self.service.service_plan_id, plan.pk)
        self.assertEqual(self.service.price, Decimal("200.00"))
        self.assertEqual((self.subscription.product_id, self.subscription.unit_price_cents), (product.pk, 20000))
        self.assertEqual((self.subscription.current_period_start, self.subscription.current_period_end), old_period)
        self.assertEqual(change.status, "applying_limits")
        self.assertEqual(change.invoice_id, invoice.pk)
        self.assertEqual(ServiceHostingLimits.objects.get(service=self.service).revision, 2)
        self.assertEqual(HostingLimitApplication.objects.filter(service=self.service).count(), 1)
        self.assertTrue(all(line.billing_cycle_id is None for line in invoice.lines.all()))
        replay = ProformaPaymentService.record_payment_and_convert(str(proforma.pk), 6000, "bank")
        self.assertTrue(replay.is_ok(), replay)
        self.assertEqual(replay.unwrap().pk, invoice.pk)
        self.assertEqual(HostingLimitApplication.objects.filter(service=self.service).count(), 1)

    def test_late_paid_document_is_retained_for_review_without_applying(self) -> None:
        change, proforma, _, _ = self.payable_change(expired=True)
        result = ProformaPaymentService.record_payment_and_convert(str(proforma.pk), 6000, "bank")
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(result.unwrap().status, "paid")
        change.refresh_from_db()
        self.assertEqual(change.status, "paid_review")
        self.assertTrue(change.review_reason)
        self.assertEqual(ServiceHostingLimits.objects.get(service=self.service).revision, 1)
        self.assertFalse(HostingLimitApplication.objects.filter(service=self.service).exists())

    def test_upgrade_releases_unused_future_benefit_budget(self) -> None:
        _, proforma, _, _ = self.payable_change()
        campaign = PromotionCampaign.objects.create(
            name="Original future benefit",
            slug="upgrade-benefit",
            start_date=self.now,
            end_date=self.now + timedelta(days=60),
            budget_cents=10000,
            budget_currency=self.currency,
            reserved_cents=2000,
        )
        order = Order.objects.create(customer=self.customer, currency=self.currency)
        item = OrderItem.objects.create(
            order=order,
            product=self.product,
            quantity=1,
            unit_price_cents=8000,
            product_name=self.product.name,
            product_type="hosting",
        )
        coupon = Coupon.objects.create(
            code="UPGRADE-OLD",
            name="Old recurring benefit",
            discount_type="free_months",
            free_months=2,
            campaign=campaign,
        )
        application = PromotionApplication.objects.create(
            order=order, coupon=coupon, campaign=campaign, status="settled", discount_cents=0, future_cents=2000
        )
        benefit = RenewalBenefit.objects.create(
            application=application,
            order_item=item,
            subscription=self.subscription,
            remaining_cents=2000,
            remaining_months=2,
            monthly_cents=1000,
        )
        result = ProformaPaymentService.record_payment_and_convert(str(proforma.pk), 6000, "bank")
        self.assertTrue(result.is_ok(), result)
        benefit.refresh_from_db()
        campaign.refresh_from_db()
        self.assertEqual(benefit.remaining_cents, 0)
        self.assertIsNotNone(benefit.ended_at)
        self.assertEqual(campaign.reserved_cents, 0)

    def test_unrelated_stale_service_save_cannot_restore_the_old_paid_price(self) -> None:
        _, proforma, _, _ = self.payable_change()
        stale = Service.objects.get(pk=self.service.pk)
        result = ProformaPaymentService.record_payment_and_convert(str(proforma.pk), 6000, "bank")
        self.assertTrue(result.is_ok(), result)
        stale.admin_notes = "Unrelated operator note from an older screen"
        stale.save()
        current = Service.objects.get(pk=self.service.pk)
        self.assertEqual(current.price, Decimal("200.00"))
        self.assertEqual(current.admin_notes, stale.admin_notes)

    def test_explicit_legacy_price_edit_remains_intentional(self) -> None:
        self.service.price = Decimal("75.00")
        self.service.save(update_fields=["price"])
        self.assertEqual(Service.objects.get(pk=self.service.pk).price, Decimal("75.00"))
