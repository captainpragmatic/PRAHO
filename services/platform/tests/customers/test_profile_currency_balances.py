"""Profile audit balances retain each document's currency and completed refunds."""

from decimal import Decimal

from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone

from apps.audit.services import CustomersAuditService
from apps.billing.models import Currency, FXRate, Invoice, Payment, Refund
from apps.common.types import Ok
from apps.customers.models import Customer, CustomerBillingProfile
from apps.customers.profile_service import ProfileService
from apps.orders.models import Order
from apps.settings.services import SettingsService


class ProfileCurrencyBalancesTests(TestCase):
    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)
        for code in ("RON", "EUR", "USD"):
            Currency.objects.get_or_create(code=code, defaults={"symbol": code})
            if code != "RON":
                FXRate.objects.create(
                    base_code_id=code, quote_code_id="RON", rate=Decimal("5"), as_of=timezone.localdate(),
                    source=FXRate.Source.BNR, source_reference="profile-balance-test", fetched_at=timezone.now(),
                )
        self.customer = Customer.objects.create(name="Profile balance buyer", primary_email="balances@example.test")
        self.profile = CustomerBillingProfile.objects.create(customer=self.customer, credit_limit=Decimal("100.25"))

    def invoice(self, currency, cents, **overrides):
        return Invoice.objects.create(
            customer=self.customer, currency_id=currency, total_cents=cents,
            number=f"PROFILE-{Invoice.objects.count()}", status="issued", **overrides,
        )

    def payment(self, invoice, cents, *, currency=None, status="succeeded", customer=None):
        # Reconstruct issued/overdue legacy invoices for this read-only aggregation.
        # Settlement normally changes their status; these tests must preserve the
        # existing profile contract's explicit issued/overdue invoice selection.
        payment = Payment(
            customer=customer or self.customer, invoice=invoice, currency_id=currency or invoice.currency_id,
            amount_cents=cents, status=status,
        )
        payment._defer_document_settlement = True
        payment.save()
        return payment

    def refund(self, payment, cents, *, status="completed", order=None):
        return Refund.objects.create(
            customer=self.customer, payment=payment, invoice=None if order else payment.invoice,
            order=order, currency_id=payment.currency_id, amount_cents=cents,
            original_amount_cents=payment.amount_cents, status=status,
        )

    def test_audit_does_not_erase_eur_debt_with_a_ron_overpayment(self):
        ron = self.invoice("RON", 10_000)
        self.invoice("EUR", 10_000)
        self.payment(ron, 25_000)
        event = CustomersAuditService.log_billing_profile_event("billing_profile_updated", self.profile)
        self.assertNotIn("account_balance", event.metadata)
        self.assertEqual(event.metadata["account_balances"], {"RON": "0.00", "EUR": "100.00"})
        self.assertEqual(event.metadata["credit_limit_currency"], "RON")
        self.assertEqual(event.metadata["credit_limit"], 100.25)

    def test_overpayments_offset_other_invoices_only_in_the_same_currency(self):
        first = self.invoice("RON", 10_000)
        self.invoice("RON", 20_000)
        self.invoice("EUR", 10_000)
        self.payment(first, 25_000)
        self.assertEqual(self.profile.get_account_balances(), {"RON": Decimal("50.00"), "EUR": Decimal("100.00")})
        self.assertEqual(self.profile.get_account_balance("RON"), Decimal("50.00"))
        self.assertEqual(ProfileService.get_customer_account_balance(self.customer, "EUR"), Decimal("100.00"))

    def test_partial_refund_reduces_the_retained_payment_once(self):
        invoice = self.invoice("RON", 10_000)
        payment = self.payment(invoice, 10_000, status="partially_refunded")
        self.refund(payment, 2500)
        self.refund(payment, 1000, status="pending")
        self.assertEqual(self.profile.get_account_balances(), {"RON": Decimal("25.00")})
        self.assertEqual(invoice.get_remaining_amount(), 2500)
        payment.refresh_from_db()
        self.assertEqual(payment.amount_cents, 10_000)

    def test_full_refund_and_order_linked_refund_follow_the_existing_ledger(self):
        first = self.invoice("RON", 10_000)
        payment = self.payment(first, 10_000, status="refunded")
        self.refund(payment, 10_000)
        second = self.invoice("EUR", 10_000)
        partial = self.payment(second, 10_000, status="partially_refunded")
        order = Order.objects.create(customer=self.customer, currency_id="EUR")
        self.refund(partial, 1234, order=order)
        self.assertEqual(self.profile.get_account_balances(), {"RON": Decimal("100.00"), "EUR": Decimal("12.34")})

    def test_currency_and_customer_mismatched_payments_cannot_reduce_balances(self):
        invoice = self.invoice("RON", 10_000)
        self.payment(invoice, 10_000, currency="EUR")
        other = Customer.objects.create(name="Other buyer")
        self.payment(invoice, 10_000, customer=other)
        self.assertEqual(self.profile.get_account_balances(), {"RON": Decimal("100.00")})

    def test_void_and_draft_invoices_and_uncollected_payments_stay_excluded(self):
        issued = self.invoice("RON", 10_000)
        self.invoice("EUR", 40_000)
        Invoice.objects.filter(currency_id="EUR").update(status="draft")
        for status in ("pending", "failed", "disputed"):
            self.payment(issued, 10_000, status=status)
        self.assertEqual(self.profile.get_account_balances(), {"RON": Decimal("100.00")})
        Invoice.objects.filter(pk=issued.pk).update(status="void")
        self.assertEqual(self.profile.get_account_balances(), {})

    def test_preference_and_selling_currency_switches_do_not_relabel_old_balances(self):
        self.invoice("RON", 1234)
        self.invoice("EUR", 5678)
        expected = {"RON": Decimal("12.34"), "EUR": Decimal("56.78")}
        for code in ("EUR", "USD", "RON"):
            with self.subTest(currency=code):
                self.assertIsInstance(SettingsService.update_setting("billing.default_currency", code), Ok)
                self.profile.preferred_currency = code
                self.profile.save(update_fields=["preferred_currency"])
                self.assertEqual(ProfileService.get_customer_account_balances(self.customer), expected)
                self.assertEqual(self.profile.credit_limit, Decimal("100.25"))

    def test_scalar_compatibility_requires_an_explicit_currency(self):
        with self.assertRaises(TypeError):
            self.profile.get_account_balance()
        with self.assertRaises(TypeError):
            ProfileService.get_customer_account_balance(self.customer)
        self.assertEqual(self.profile.get_account_balance("RON"), Decimal("0.00"))
        self.assertEqual(self.profile.get_account_balance("EUR"), Decimal("0.00"))
        other = Customer.objects.create(name="No profile")
        self.assertEqual(ProfileService.get_customer_account_balances(other), {})
        self.assertEqual(ProfileService.get_customer_account_balance(other, "USD"), Decimal("0.00"))
