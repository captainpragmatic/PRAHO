"""Customer summaries report remaining money in each recorded currency."""

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.models import CreditLedger, Currency, Invoice, Payment
from apps.billing.refund_models import Refund
from apps.users.models import CustomerMembership, User
from tests.factories import CustomerFactory
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
class BillingSummaryCurrencyTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.owner = User.objects.create_user(email="currency-summary@example.test")
        CustomerMembership.objects.create(customer=self.customer, user=self.owner, role="owner", is_primary=True)
        self.currencies = {
            code: Currency.objects.get_or_create(code=code, defaults={"symbol": code})[0]
            for code in ("RON", "EUR", "USD")
        }

    def _invoice(self, code: str, number: str, amount: int, status: str = "issued") -> Invoice:
        return Invoice.objects.create(
            customer=self.customer, currency=self.currencies[code], number=number,
            status=status, subtotal_cents=amount, total_cents=amount, due_at=timezone.now(),
        )

    def _summary(self) -> dict:
        response = self.portal_post(
            "/api/billing/summary/", {"customer_id": self.customer.pk, "user_id": self.owner.pk}
        )
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()["summary"]

    def test_remaining_cash_and_gift_payments_are_grouped_without_cross_currency_addition(self) -> None:
        ron = self._invoice("RON", "INV-RON-1", 10000)
        eur = self._invoice("EUR", "INV-EUR-1", 10000, "overdue")
        usd = self._invoice("USD", "INV-USD-1", 9000)
        payments = [
            Payment(customer=self.customer, invoice=ron, currency=ron.currency, amount_cents=2000,
                    payment_method="bank", status="succeeded"),
            Payment(customer=self.customer, invoice=ron, currency=ron.currency, amount_cents=3000,
                    payment_method="gift_card", status="succeeded"),
            Payment(customer=self.customer, invoice=eur, currency=eur.currency, amount_cents=1000,
                    payment_method="bank", status="partially_refunded"),
            Payment(customer=self.customer, invoice=usd, currency=usd.currency, amount_cents=500,
                    payment_method="stripe", status="failed"),
        ]
        Payment.objects.bulk_create(payments)
        Refund.objects.bulk_create([
            Refund(customer=self.customer, invoice=eur, payment=payments[2], currency=eur.currency,
                   amount_cents=200, original_amount_cents=1000, reference_number="RF-SUMMARY-1", status="completed")
        ])
        self._invoice("RON", "INV-PAID-1", 13000, "paid")
        self._invoice("EUR", "INV-VOID-1", 12000, "void")
        self._invoice("USD", "INV-DRAFT-1", 8000, "draft")
        self._invoice("EUR", "INV-REFUNDED-1", 4000, "refunded")
        Invoice.objects.create(
            customer=self.customer, currency=ron.currency, number="CN-1", status="issued",
            document_kind="credit_note", reverses_invoice=ron, subtotal_cents=-10000, total_cents=-10000,
        )
        other = CustomerFactory()
        Invoice.objects.create(
            customer=other, currency=eur.currency, number="OTHER-1", status="issued",
            subtotal_cents=999999, total_cents=999999,
        )

        summary = self._summary()

        self.assertEqual(summary["amount_due_by_currency"], {"EUR": 9200, "RON": 5000, "USD": 9000})
        self.assertIsNone(summary["total_amount_due_cents"])
        self.assertIsNone(summary["currency_code"])
        self.assertEqual(summary["total_invoices"], 8)
        expected_currencies = dict(Invoice.objects.filter(customer=self.customer).values_list("number", "currency_id"))
        for recent in summary["recent_invoices"]:
            self.assertEqual(recent["currency_code"], expected_currencies[recent["number"]])

    def test_single_currency_compatibility_fields_use_the_remaining_balance(self) -> None:
        invoice = self._invoice("EUR", "INV-EUR-2", 10000)
        Payment.objects.bulk_create([
            Payment(customer=self.customer, invoice=invoice, currency=invoice.currency,
                    amount_cents=2500, payment_method="gift_card", status="succeeded")
        ])

        summary = self._summary()

        self.assertEqual(summary["amount_due_by_currency"], {"EUR": 7500})
        self.assertEqual(summary["total_amount_due_cents"], 7500)
        self.assertEqual(summary["currency_code"], "EUR")

    def test_held_historical_debits_keep_recorded_credit_visible_without_claiming_it_is_spendable(self) -> None:
        for code, amount in (("RON", 500), ("EUR", 2000), ("USD", 50)):
            CreditLedger.objects.create(
                customer=self.customer, currency=self.currencies[code], delta_cents=amount, reason="Recorded credit",
            )
        CreditLedger.objects.bulk_create([
            CreditLedger(customer=self.customer, delta_cents=3500, reason="Old adjustment",
                         currency_hold_reason="No immutable source identifies the original currency"),
            CreditLedger(customer=self.customer, delta_cents=-1000, reason="Old use",
                         currency_hold_reason="No immutable source identifies the original currency"),
        ])

        summary = self._summary()

        self.assertEqual(summary["credit_balance_by_currency"], {"EUR": 2000, "RON": 500, "USD": 50})
        self.assertEqual(summary["spendable_credit_by_currency"], {"EUR": 0, "RON": 0, "USD": 0})
        self.assertEqual([entry["delta_cents"] for entry in summary["held_credit_entries"]], [3500, -1000])
        self.assertTrue(summary["credit_spending_on_hold"])
        self.assertEqual(summary["amount_due_by_currency"], {})
        self.assertIsNone(summary["currency_code"])

    def test_unknown_positive_credit_does_not_freeze_known_credit(self) -> None:
        CreditLedger.objects.create(
            customer=self.customer, currency=self.currencies["EUR"], delta_cents=2000, reason="Recorded credit",
        )
        CreditLedger.objects.bulk_create([
            CreditLedger(customer=self.customer, delta_cents=1500, reason="Old adjustment",
                         currency_hold_reason="No immutable source identifies the original currency")
        ])

        summary = self._summary()

        self.assertEqual(summary["spendable_credit_by_currency"], {"EUR": 2000})
        self.assertFalse(summary["credit_spending_on_hold"])
        self.assertEqual([entry["delta_cents"] for entry in summary["held_credit_entries"]], [1500])
