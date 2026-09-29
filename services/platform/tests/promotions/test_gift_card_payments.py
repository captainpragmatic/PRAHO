"""Gift cards fund tax-inclusive payments, never pre-tax discounts."""

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.billing.models import Currency
from apps.billing.proforma_models import ProformaInvoice
from apps.billing.recurring_billing import RecurringBillingOrchestrator
from apps.customers.models import Customer
from apps.promotions.gift_cards import (
    activate_verified_purchase,
    create_purchase,
    release_expired_reservations,
    reserve_value,
)
from apps.promotions.models import GiftCard, GiftCardTransaction
from tests.billing.test_subscription_invoice_payments import _SubscriptionInvoicePaymentFixture


class GiftCardPaymentTests(TestCase):
    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"name": "Leu", "symbol": "lei"})
        self.customer = Customer.objects.create(name="Gift-card buyer", customer_type="individual")

    def test_expired_abandoned_proforma_releases_balance_once(self):
        card = GiftCard.objects.create(
            code="EXPIRY-CARD",
            currency=self.currency,
            status="active",
            initial_value_cents=5000,
            current_balance_cents=5000,
        )
        document = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="PRO-EXPIRE",
            total_cents=12100,
            valid_until=timezone.now() + timezone.timedelta(days=1),
        )
        reserve_value(card.code, document, self.customer, "expire-hold")
        document.valid_until = timezone.now() - timezone.timedelta(seconds=1)
        document.save(update_fields=["valid_until"])
        self.assertEqual(release_expired_reservations(), 5000)
        self.assertEqual(release_expired_reservations(), 0)
        card.refresh_from_db()
        self.assertEqual((card.current_balance_cents, card.reserved_cents), (5000, 0))

    def test_purchase_stays_unspendable_until_verified_payment_and_activates_once(self) -> None:
        purchase = create_purchase(self.customer, self.currency, 5000, "gift-purchase-1")
        self.assertEqual(purchase.gift_card.current_balance_cents, 0)
        with self.assertRaises(ValidationError):
            activate_verified_purchase(purchase.pk)
        payment = purchase.funding_payment
        payment.succeed()
        payment.save()
        with self.assertRaises(ValidationError):
            activate_verified_purchase(purchase.pk)
        payment.gateway_txn_id = "pi_verified_gift"
        payment.meta = {"stripe_amount_received": 5000, "stripe_currency": "ron"}
        payment.save()
        activate_verified_purchase(purchase.pk)
        activate_verified_purchase(purchase.pk)
        purchase.gift_card.refresh_from_db()
        self.assertEqual(purchase.gift_card.current_balance_cents, 5000)
        self.assertEqual(
            GiftCardTransaction.objects.filter(gift_card=purchase.gift_card, transaction_type="activation").count(), 1
        )
        self.assertIsNone(payment.invoice_id)

    def test_reservation_preserves_vat_and_is_idempotent(self) -> None:
        purchase = create_purchase(self.customer, self.currency, 5000, "gift-purchase-2")
        payment = purchase.funding_payment
        payment.succeed()
        payment.gateway_txn_id = "pi_verified_gift_2"
        payment.meta = {"stripe_amount_received": 5000, "stripe_currency": "ron"}
        payment.save()
        activate_verified_purchase(purchase.pk)
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="PRO-GIFT-1",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            valid_until=timezone.now() + timezone.timedelta(days=10),
        )
        first = reserve_value(purchase.gift_card.code, proforma, self.customer, "gift-hold-1")
        second = reserve_value(purchase.gift_card.code, proforma, self.customer, "gift-hold-1")
        self.assertEqual(first.pk, second.pk)
        self.assertEqual(first.amount_cents, 5000)
        proforma.refresh_from_db()
        purchase.gift_card.refresh_from_db()
        self.assertEqual(
            (proforma.subtotal_cents, proforma.tax_cents, proforma.total_cents, proforma.discount_cents),
            (10000, 2100, 12100, 0),
        )
        self.assertEqual(purchase.gift_card.reserved_cents, 5000)
        with self.assertRaises(ValidationError):
            reserve_value(purchase.gift_card.code, proforma, self.customer, "gift-hold-2")


class GiftCardStaffSettlementTests(_SubscriptionInvoicePaymentFixture, TestCase):
    def test_staff_records_only_remaining_cash_and_rechecks_displayed_amount(self):
        now = timezone.now()
        self._create_aligned_subscription("STAFF-TENDER", now)
        prepared = RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)
        self.assertEqual(prepared["errors"], [])
        document = ProformaInvoice.objects.get()
        card = GiftCard.objects.create(code="STAFF-TENDER", currency=self.currency, status="active",
                                       initial_value_cents=5000, current_balance_cents=5000)
        reserve_value(card.code, document, self.customer, "staff-tender")
        staff = get_user_model().objects.create_user(email="staff-settlement@example.test", staff_role="billing")
        self.client.force_login(staff)
        url = reverse("billing:process_proforma_payment", kwargs={"pk":document.pk})
        self.client.post(url, {"payment_method":"bank"})
        document.refresh_from_db()
        self.assertNotEqual(document.status, "converted")
        self.client.post(url, {"payment_method":"bank", "cash_due_cents":"12100"})
        document.refresh_from_db()
        self.assertNotEqual(document.status, "converted")
        response = self.client.post(url, {"payment_method":"bank", "cash_due_cents":"7100", "reference":"BANK-TEST"})
        self.assertEqual(response.status_code, 302)
        document.refresh_from_db()
        self.assertEqual(document.status, "converted")
        self.assertEqual(list(document.payments.order_by("payment_method").values_list("payment_method","amount_cents")),
                         [("bank",7100),("gift_card",5000)])
