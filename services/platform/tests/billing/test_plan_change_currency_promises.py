"""Per-service accepted terms do not consume another service's shared price promise."""

from datetime import timedelta
from decimal import Decimal

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.currency_transitions import prepare_currency_offer, protected_terms_reason
from apps.billing.models import Currency, FXRate, PriceGrandfathering, Subscription, SubscriptionItem
from apps.billing.proforma_service import ProformaPaymentService
from apps.orders.models import Order, OrderItem
from apps.products.models import ProductPrice
from apps.promotions.models import Coupon, PromotionApplication, RenewalBenefit, RenewalBenefitUse
from apps.provisioning.models import Service, ServicePlanPrice
from apps.settings.services import SettingsService
from tests.billing.test_plan_change_settlement import _PlanChangeSettlementFixture


@override_settings(LANGUAGE_CODE="en")
class PlanChangeCurrencyPromiseTests(_PlanChangeSettlementFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.accepted, proforma, self.target_product, self.target_plan = self.payable_change()
        paid = ProformaPaymentService.record_payment_and_convert(str(proforma.pk), 6000, "bank")
        self.assertTrue(paid.is_ok(), paid)
        self.accepted.refresh_from_db()
        # Native completion is a fixture prerequisite, not evidence of native execution.
        self.accepted.complete()
        self.accepted.save(update_fields=["status"])
        self.subscription.refresh_from_db()
        self.promise = PriceGrandfathering.objects.create(
            customer=self.customer,
            product=self.target_product,
            currency=self.currency,
            locked_price_cents=1500,
            original_price_cents=1500,
            current_product_price_cents=20000,
            reason="Another unchanged service's original promise",
        )
        other_service = Service.objects.create(
            customer=self.customer,
            service_plan=self.target_plan,
            currency=self.currency,
            service_name="Original promise",
            username="otherpromise",
            price=15,
            status="active",
        )
        self.other = Subscription.objects.create(
            customer=self.customer,
            product=self.target_product,
            service=other_service,
            currency=self.currency,
            subscription_number="SUB-OTHER-CURRENCY",
            unit_price_cents=1500,
            status="active",
            current_period_start=self.subscription.current_period_start,
            current_period_end=self.subscription.current_period_end,
            next_billing_date=self.subscription.next_billing_date,
        )
        Currency.objects.get_or_create(code="EUR", defaults={"symbol": "EUR"})
        FXRate.objects.create(
            base_code_id="EUR",
            quote_code_id="RON",
            rate=Decimal("5"),
            as_of=timezone.localdate(),
            source=FXRate.Source.BNR,
            source_reference="accepted-plan-currency-test",
            fetched_at=self.now,
        )
        for product in (self.product, self.target_product):
            ProductPrice.objects.create(product=product, currency_id="EUR", monthly_price_cents=4000)
        for plan in (self.plan, self.target_plan):
            ServicePlanPrice.objects.create(service_plan=plan, currency_id="EUR", monthly_price_cents=4000)
        changed = SettingsService.update_setting("billing.default_currency", "EUR")
        self.assertTrue(changed.is_ok(), changed)

    def test_public_offer_uses_changed_terms_while_other_service_keeps_its_promise(self):
        offer = prepare_currency_offer(self.subscription.pk)
        other = prepare_currency_offer(self.other.pk)
        self.assertIsNotNone(offer)
        self.assertIsNotNone(other)
        self.assertEqual((offer.old_terms["unit_price_cents"], other.old_terms["unit_price_cents"]), (20000, 1500))
        self.assertTrue(other.hold_reason)
        self.promise.refresh_from_db()
        self.assertTrue(self.promise.is_active)
        self.assertEqual(self.promise.locked_price_cents, 1500)
        self.assertEqual(offer.hold_reason, "")

    def test_later_explicit_subscription_promise_remains_protected_including_zero(self):
        self.subscription.locked_price_cents = 0
        self.subscription.save(update_fields=["locked_price_cents"])
        offer = prepare_currency_offer(self.subscription.pk)
        self.assertEqual(offer.hold_reason, "The subscription has a protected original price")

    def test_explicit_subscription_item_price_remains_protected(self):
        SubscriptionItem.objects.create(
            subscription=self.subscription,
            product=self.target_product,
            currency=self.currency,
            unit_price_cents=100,
            locked_price_cents=0,
        )
        offer = prepare_currency_offer(self.subscription.pk)
        self.assertEqual(offer.hold_reason, "A subscription item has an indefinite original price guarantee")

    def test_ended_original_currency_benefit_with_reserved_document_value_still_holds(self):
        order = Order.objects.create(customer=self.customer, currency=self.currency)
        item = OrderItem.objects.create(
            order=order,
            product=self.target_product,
            quantity=1,
            unit_price_cents=20000,
            product_name=self.target_product.name,
            product_type="hosting",
        )
        coupon = Coupon.objects.create(
            code="OLD-PLAN-RESERVED", name="Original credit", discount_type="free_months", free_months=1
        )
        application = PromotionApplication.objects.create(
            order=order, coupon=coupon, status="settled", discount_cents=0, future_cents=100
        )
        benefit = RenewalBenefit.objects.create(
            application=application,
            order_item=item,
            subscription=self.subscription,
            currency=self.currency,
            remaining_cents=100,
            remaining_months=0,
            monthly_cents=100,
            ended_at=self.now,
        )
        cycle = self.subscription.billing_cycles.get(period_start=self.subscription.current_period_start)
        use = RenewalBenefitUse.objects.create(benefit=benefit, cycle=cycle, amount_cents=100, months=1)
        offer = prepare_currency_offer(self.subscription.pk)
        self.assertEqual(offer.hold_reason, "An original-currency renewal benefit remains available or reserved")
        benefit.refresh_from_db()
        use.refresh_from_db()
        self.assertEqual((benefit.remaining_cents, use.status), (100, "reserved"))

    def test_future_accepted_terms_do_not_remove_earlier_period_protection(self):
        held = protected_terms_reason(self.subscription, self.accepted.effective_at - timedelta(seconds=1), "RON")
        self.assertEqual(held, "An original or unresolved grandfathered price remains protected")
