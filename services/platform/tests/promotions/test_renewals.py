"""Promised renewal value survives price changes and is consumed once."""

from decimal import Decimal

from django.test import TestCase, override_settings
from django.utils import timezone
from lxml import etree

from apps.audit.models import AuditEvent
from apps.billing.efactura.xml_builder import builder_for
from apps.billing.metering_models import BillingCycle
from apps.billing.models import Currency
from apps.billing.proforma_service import ProformaPaymentService
from apps.billing.recurring_billing import RecurringBillingOrchestrator
from apps.billing.subscription_models import Subscription
from apps.billing.subscription_service import SubscriptionService
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from apps.promotions.engine import release_order
from apps.promotions.gift_cards import pay_document
from apps.promotions.models import (
    Coupon,
    GiftCard,
    GiftCardTransaction,
    PromotionApplication,
    PromotionCampaign,
    RenewalBenefit,
)
from apps.promotions.renewals import end_benefits, reconcile_expired_credits, reserve_cycle, settle_cycle
from tests.billing.test_subscription_invoice_payments import _SubscriptionInvoicePaymentFixture


class RenewalBenefitTests(TestCase):
    def setUp(self) -> None:
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"name": "Leu", "symbol": "lei"})
        customer = Customer.objects.create(name="Renewal buyer", customer_type="individual")
        product = Product.objects.create(name="Renewal plan", slug="renewal-plan", product_type="hosting")
        now = timezone.now()
        self.subscription = Subscription.objects.create(
            customer=customer,
            product=product,
            currency=currency,
            subscription_number="SUB-PROMOTION",
            status="active",
            unit_price_cents=3000,
            locked_price_cents=2500,
            current_period_start=now,
            current_period_end=now + timezone.timedelta(days=30),
            next_billing_date=now,
        )
        order = Order.objects.create(customer=customer, currency=currency)
        item = OrderItem.objects.create(
            order=order,
            product=product,
            quantity=1,
            unit_price_cents=1000,
            product_name=product.name,
            product_type=product.product_type,
        )
        coupon = Coupon.objects.create(code="RENEWAL", name="Renewal", discount_type="free_months", free_months=3)
        application = PromotionApplication.objects.create(
            order=order, coupon=coupon, status="settled", discount_cents=1000, future_cents=2000
        )
        self.benefit = RenewalBenefit.objects.create(
            application=application,
            order_item=item,
            subscription=self.subscription,
            remaining_cents=2000,
            remaining_months=2,
            monthly_cents=Decimal(1000),
        )
        self.cycle = BillingCycle.objects.create(
            subscription=self.subscription, period_start=now, period_end=now + timezone.timedelta(days=30)
        )

    def test_upgrade_keeps_original_credit_and_settlement_is_idempotent(self) -> None:
        self.assertEqual(reserve_cycle(self.subscription, self.cycle, 2500), 1000)
        self.assertEqual(reserve_cycle(self.subscription, self.cycle, 2500), 1000)
        self.benefit.refresh_from_db()
        self.assertEqual(self.benefit.remaining_cents, 2000)
        settle_cycle(self.cycle)
        settle_cycle(self.cycle)
        self.benefit.refresh_from_db()
        self.subscription.refresh_from_db()
        self.assertEqual(self.benefit.remaining_cents, 1000)
        self.assertEqual(self.subscription.locked_price_cents, 2500)
        self.assertEqual(AuditEvent.objects.filter(
            content_type__model="renewalbenefituse", object_id=str(self.benefit.uses.get().pk),
            new_values__status="settled",
        ).count(), 1)

    def test_pause_defers_and_cancellation_ends_unused_value(self) -> None:
        self.subscription.pause()
        self.assertEqual(reserve_cycle(self.subscription, self.cycle, 2500), 0)
        self.benefit.refresh_from_db()
        self.assertEqual(self.benefit.remaining_cents, 2000)
        end_benefits(self.subscription)
        end_benefits(self.subscription)
        self.benefit.refresh_from_db()
        self.assertEqual(self.benefit.remaining_cents, 0)
        self.assertIsNotNone(self.benefit.ended_at)


class RenewalDocumentTests(_SubscriptionInvoicePaymentFixture, TestCase):
    def test_gift_only_renewal_settles_once_with_promised_credit(self):

        subscriptions, document, campaign = self.prepare_discounted_document()
        card = GiftCard.objects.create(
            code="RENEWAL-GIFT",
            status="active",
            currency=self.currency,
            initial_value_cents=document.total_cents,
            current_balance_cents=document.total_cents,
        )
        for _ in range(2):
            paid = pay_document(card.code, document, self.customer, "renewal-gift-payment")
            self.assertEqual(paid["cash_due_cents"], 0)
        card.refresh_from_db()
        campaign.refresh_from_db()
        document.refresh_from_db()
        self.assertEqual((card.current_balance_cents, card.reserved_cents), (0, 0))
        self.assertEqual(document.status, "converted")
        self.assertEqual((campaign.spent_cents, campaign.reserved_cents), (50, 50))
        self.assertEqual(GiftCardTransaction.objects.filter(gift_card=card, transaction_type="redemption").count(), 1)
        self.assertIsNotNone(subscriptions[0].billing_cycles.get().entitlement_applied_at)

    def prepare_discounted_document(self, count: int = 1):
        now = timezone.now()
        self.subscription.current_period_end = now + timezone.timedelta(days=7)
        self.subscription.save(update_fields=["current_period_end"])
        campaign = PromotionCampaign.objects.create(
            name="Renewal budget",
            slug="renewal-budget",
            start_date=now,
            status="active",
            budget_cents=1000,
            budget_currency=self.currency,
            reserved_cents=100 * count,
        )
        subscriptions = []
        for index in range(count):
            subscription = self._create_aligned_subscription(str(index), now)
            subscription.unit_price_cents = 100
            subscription.auto_payment_enabled = False
            subscription.save(update_fields=["unit_price_cents", "auto_payment_enabled"])
            order = Order.objects.create(customer=self.customer, currency=self.currency)
            item = OrderItem.objects.create(
                order=order,
                product=self.product,
                quantity=1,
                unit_price_cents=50,
                product_name=self.product.name,
                product_type=self.product.product_type,
            )
            coupon = Coupon.objects.create(
                code=f"RENEWAL{index}",
                name="Renewal credit",
                discount_type="free_months",
                free_months=3,
                campaign=campaign,
                total_uses=1,
            )
            application = PromotionApplication.objects.create(
                order=order, coupon=coupon, campaign=campaign, status="settled", discount_cents=0, future_cents=100
            )
            RenewalBenefit.objects.create(
                application=application,
                order_item=item,
                subscription=subscription,
                remaining_cents=100,
                remaining_months=2,
                monthly_cents=Decimal(50),
            )
            subscriptions.append(subscription)
        prepared = RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)
        self.assertEqual(prepared["errors"], [])
        self.assertEqual(prepared["proformas_created"], 1, prepared)
        return subscriptions, subscriptions[0].billing_cycles.get().proforma, campaign

    @override_settings(
        EFACTURA_COMPANY_CUI="RO12345678", COMPANY_NAME="Test Company SRL",
        COMPANY_BANK_ACCOUNT="RO49AAAA1B31007593840000", COMPANY_BANK_NAME="Test Bank",
    )
    def test_grouped_renewal_vat_matches_converted_invoice_and_xml(self) -> None:

        subscriptions, proforma, campaign = self.prepare_discounted_document(count=2)
        self.assertEqual(
            (proforma.subtotal_cents, proforma.discount_cents, proforma.tax_cents, proforma.total_cents),
            (100, 100, 21, 121),
        )
        cycles = [subscription.billing_cycles.get() for subscription in subscriptions]
        self.assertEqual(sum(cycle.tax_cents for cycle in cycles), 21)
        paid = ProformaPaymentService.record_payment_and_convert(str(proforma.pk), 121, "bank", reference="QA")
        self.assertTrue(paid.is_ok(), paid)
        proforma.refresh_from_db()
        invoice = paid.unwrap()
        self.assertEqual((invoice.subtotal_cents, invoice.tax_cents, invoice.total_cents), (100, 21, 121))
        xml = etree.fromstring(builder_for(invoice).build().encode())
        namespaces = {
            "cac": "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
            "cbc": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
        }
        self.assertEqual(xml.findtext("cac:TaxTotal/cbc:TaxAmount", namespaces=namespaces), "0.21")
        self.assertEqual(xml.findtext("cac:LegalMonetaryTotal/cbc:TaxInclusiveAmount", namespaces=namespaces), "1.21")
        campaign.refresh_from_db()
        self.assertEqual((campaign.reserved_cents, campaign.spent_cents), (100, 100))

    def test_cancellation_preserves_credit_backing_payable_document(self) -> None:
        subscriptions, proforma, campaign = self.prepare_discounted_document()
        subscription = subscriptions[0]
        subscription.cancel(at_period_end=True)
        campaign.refresh_from_db()
        self.assertEqual(campaign.reserved_cents, 50)
        self.assertEqual(subscription.promotion_benefits.get().remaining_cents, 50)
        reactivated = SubscriptionService.reactivate_subscription(subscription)
        self.assertTrue(reactivated.is_ok(), reactivated)
        paid = ProformaPaymentService.record_payment_and_convert(
            str(proforma.pk), proforma.total_cents, "bank", reference="QA"
        )
        self.assertTrue(paid.is_ok(), paid)
        campaign.refresh_from_db()
        self.assertEqual((campaign.reserved_cents, campaign.spent_cents), (0, 50))
        benefit = subscription.promotion_benefits.get()
        self.assertEqual(benefit.remaining_cents, 0)
        self.assertEqual(benefit.uses.get().status, "settled")

    def test_original_order_refund_keeps_prepared_renewal_credit(self) -> None:

        subscriptions, proforma, campaign = self.prepare_discounted_document()
        benefit = subscriptions[0].promotion_benefits.get()
        release_order(benefit.application.order, full_refund=True)
        campaign.refresh_from_db()
        self.assertEqual(campaign.reserved_cents, 50)
        paid = ProformaPaymentService.record_payment_and_convert(
            str(proforma.pk), proforma.total_cents, "bank", reference="QA"
        )
        self.assertTrue(paid.is_ok(), paid)
        campaign.refresh_from_db()
        self.assertEqual((campaign.reserved_cents, campaign.spent_cents), (0, 50))

    def test_expired_document_releases_hold_after_cancellation(self) -> None:

        subscriptions, proforma, campaign = self.prepare_discounted_document()
        subscriptions[0].cancel(at_period_end=True)
        proforma.valid_until = timezone.now() - timezone.timedelta(seconds=1)
        proforma.save(update_fields=["valid_until"])
        reconcile_expired_credits()
        reconcile_expired_credits()
        campaign.refresh_from_db()
        self.assertEqual(campaign.reserved_cents, 0)
        benefit = subscriptions[0].promotion_benefits.get()
        self.assertEqual((benefit.remaining_cents, benefit.uses.get().status), (0, "released"))
        self.assertEqual(AuditEvent.objects.filter(
            content_type__model="renewalbenefituse", object_id=str(benefit.uses.get().pk),
            new_values__status="released",
        ).count(), 1)
