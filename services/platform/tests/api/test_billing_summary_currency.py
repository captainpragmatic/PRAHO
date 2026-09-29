"""Customer summaries report remaining money in each recorded currency."""

from django.db import connection
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from apps.api.billing.serializers import InvoiceSummarySerializer
from apps.billing.models import CreditLedger, Currency, Invoice, Payment
from apps.billing.refund_models import Refund
from apps.orders.models import Order
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

    def test_summary_query_count_does_not_grow_with_pending_invoices(self) -> None:
        def measured_summary() -> tuple[dict, int]:
            with CaptureQueriesContext(connection) as queries:
                summary = InvoiceSummarySerializer({
                    "customer": self.customer,
                    "invoices_queryset": Invoice.objects.filter(customer=self.customer),
                }).data
            return summary, len(queries)

        first = self._invoice("EUR", "INV-QUERY-0", 10000)
        Payment.objects.bulk_create([
            Payment(customer=self.customer, invoice=first, currency_id="EUR", amount_cents=2500,
                    payment_method="gift_card", status="succeeded"),
        ])
        one_invoice, one_count = measured_summary()
        self.assertEqual(one_invoice["amount_due_by_currency"], {"EUR": 7500})

        Payment.objects.bulk_create([
            Payment(customer=self.customer, invoice=self._invoice("EUR", f"INV-QUERY-{index}", 10000),
                    currency_id="EUR", amount_cents=2500, payment_method="bank", status="succeeded")
            for index in range(1, 25)
        ])
        many_invoices, many_count = measured_summary()

        self.assertEqual(many_invoices["amount_due_by_currency"], {"EUR": 187500})
        self.assertEqual(many_invoices["total_invoices"], 25)
        self.assertEqual([row["amount_due"] for row in many_invoices["recent_invoices"]], [7500] * 5)
        self.assertEqual(many_count, one_count, "Pending invoices must not add individual payment/refund queries")

    def test_grouped_payments_and_refunds_preserve_each_invoice_remainder(self) -> None:
        ron = self._invoice("RON", "INV-MULTI-RON", 10000)
        eur = self._invoice("EUR", "INV-MULTI-EUR", 10000, "overdue")
        usd = self._invoice("USD", "INV-MULTI-USD", 5000)
        overpaid = self._invoice("RON", "INV-MULTI-OVERPAID", 1000)
        returned = self._invoice("EUR", "INV-MULTI-RETURNED", 2000)
        payments = [
            Payment(customer=self.customer, invoice=invoice, currency_id=invoice.currency_id,
                    amount_cents=amount, status=status, payment_method=method)
            for invoice, amount, status, method in (
                (ron, 2000, "succeeded", "gift_card"),
                (ron, 2000, "partially_refunded", "bank"),
                (eur, 4000, "partially_refunded", "bank"),
                (usd, 5000, "refunded", "stripe"),
                (overpaid, 3000, "succeeded", "bank"),
                (returned, 500, "partially_refunded", "bank"),
                (ron, 9000, "failed", "stripe"),
                (eur, 8000, "pending", "stripe"),
                (usd, 7000, "disputed", "stripe"),
            )
        ]
        Payment.objects.bulk_create(payments)
        order = Order.objects.create(customer=self.customer, currency_id="EUR")
        Refund.objects.bulk_create([
            # Equal amounts remain separate refunds; both relationship paths count each row once.
            Refund(customer=self.customer, invoice=ron, payment=payments[1], currency_id="RON",
                   amount_cents=500, original_amount_cents=2000, reference_number=f"RF-MULTI-{index}",
                   status="completed")
            for index in range(2)
        ] + [
            Refund(customer=self.customer, invoice=eur, currency_id="EUR", amount_cents=600,
                   original_amount_cents=10000, reference_number="RF-MULTI-DIRECT", status="completed"),
            Refund(customer=self.customer, order=order, payment=payments[2], currency_id="EUR", amount_cents=900,
                   original_amount_cents=4000, reference_number="RF-MULTI-PAYMENT", status="completed"),
            Refund(customer=self.customer, invoice=eur, payment=payments[2], currency_id="EUR", amount_cents=400,
                   original_amount_cents=4000, reference_number="RF-MULTI-PENDING", status="pending"),
            Refund(customer=self.customer, invoice=usd, payment=payments[3], currency_id="USD", amount_cents=5000,
                   original_amount_cents=5000, reference_number="RF-MULTI-FULL", status="completed"),
            Refund(customer=self.customer, invoice=returned, payment=payments[5], currency_id="EUR", amount_cents=700,
                   original_amount_cents=2000, reference_number="RF-MULTI-CLAMP", status="completed"),
        ])

        summary = self._summary()

        self.assertEqual(summary["amount_due_by_currency"], {"EUR": 9500, "RON": 7000, "USD": 5000})
        self.assertIsNone(summary["total_amount_due_cents"])
        self.assertEqual(
            {row["number"]: row["amount_due"] for row in summary["recent_invoices"]},
            {"INV-MULTI-RON": 7000, "INV-MULTI-EUR": 7500, "INV-MULTI-USD": 5000,
             "INV-MULTI-OVERPAID": 0, "INV-MULTI-RETURNED": 2000},
        )

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
