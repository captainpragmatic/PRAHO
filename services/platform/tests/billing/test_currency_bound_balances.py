"""Historical money keeps its identity when the selling currency changes."""

from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from threading import Barrier, Event

from django.core.exceptions import ValidationError
from django.db import close_old_connections, connection, connections, transaction
from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from apps.billing.metering_models import BillingCycle, UsageAggregation
from apps.billing.models import CreditLedger, Currency, Invoice, Payment, PriceGrandfathering
from apps.billing.subscription_service import GrandfatheringService, SubscriptionService
from apps.billing.usage_invoice_service import UsageInvoiceService
from apps.customers.models import Customer
from tests.billing import test_metering_services as metering_fixtures
from tests.billing.test_subscription_service import make_product, make_subscription


class CurrencyBoundCreditTests(TestCase):
    def setUp(self) -> None:
        self.ron, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
        self.eur, _ = Currency.objects.get_or_create(code="EUR", defaults={"symbol": "€"})
        self.customer = Customer.objects.create(name="Currency balance buyer", customer_type="individual")

    def invoice(self, currency: Currency, number: str) -> Invoice:
        return Invoice.objects.create(
            customer=self.customer, currency=currency, number=number,
            subtotal_cents=1000, total_cents=1000, due_at=timezone.now(),
        )

    def test_manual_credit_requires_original_currency(self) -> None:
        with self.assertRaises(ValidationError):
            CreditLedger.objects.create(customer=self.customer, delta_cents=1200, reason="Manual credit")

    def test_document_evidence_sets_original_currency_and_rejects_conflicts(self) -> None:
        invoice = self.invoice(self.eur, "EUR-CREDIT")
        credit = CreditLedger.objects.create(
            customer=self.customer, invoice=invoice, delta_cents=1200, reason="Invoice adjustment",
        )
        self.assertEqual(credit.currency_id, "EUR")
        self.assertEqual(credit.delta_cents, 1200)
        self.assertEqual(credit.currency_hold_reason, "")
        with self.assertRaises(ValidationError):
            CreditLedger.objects.create(
                customer=self.customer, invoice=invoice, currency=self.ron,
                delta_cents=1200, reason="Incorrect relabel",
            )
        payment = Payment.objects.create(customer=self.customer, currency=self.ron, amount_cents=1000)
        with self.assertRaises(ValidationError):
            CreditLedger.objects.create(
                customer=self.customer, invoice=invoice, payment=payment,
                delta_cents=1200, reason="Conflicting evidence",
            )

    def test_credit_currency_cannot_be_relabelled_after_creation(self) -> None:
        credit = CreditLedger.objects.create(
            customer=self.customer, currency=self.eur, delta_cents=1200, reason="Manual EUR credit",
        )
        credit.currency = self.ron
        with self.assertRaises(ValidationError):
            credit.save()
        credit.refresh_from_db()
        self.assertEqual((credit.currency_id, credit.delta_cents), ("EUR", 1200))

    def test_removing_source_does_not_allow_credit_currency_to_change(self) -> None:
        source = self.invoice(self.eur, "REMOVED-CREDIT-SOURCE")
        credit = CreditLedger.objects.create(
            customer=self.customer, invoice=source, delta_cents=1200, reason="Original invoice credit",
        )
        source.delete()
        credit.refresh_from_db()
        self.assertIsNone(credit.invoice_id)
        credit.currency = self.ron
        with self.assertRaises(ValidationError):
            credit.save()
        credit.refresh_from_db()
        self.assertEqual((credit.currency_id, credit.delta_cents), ("EUR", 1200))

    def test_balances_remain_separate_and_held_legacy_entries_are_reported(self) -> None:
        for currency, value in [(self.ron, 300), (self.eur, 700)]:
            CreditLedger.objects.create(
                customer=self.customer, currency=currency, delta_cents=value, reason="Explicit credit",
            )
        # Historical migrations retain this entry without inventing a currency.
        CreditLedger.objects.bulk_create([
            CreditLedger(customer=self.customer, delta_cents=900, reason="Legacy manual credit",
                         currency_hold_reason="No immutable source identifies the original currency")
        ])
        service = UsageInvoiceService()
        self.assertEqual(service._get_customer_credit_balance(self.customer, self.ron), 300)
        self.assertEqual(service._get_customer_credit_balance(self.customer, self.eur), 700)
        self.assertEqual(CreditLedger.balances_for_customer(self.customer), {"EUR": 700, "RON": 300})
        held = CreditLedger.held_entries_for_customer(self.customer)
        self.assertEqual([entry["delta_cents"] for entry in held], [900])
        self.assertTrue(held[0]["currency_hold_reason"])

    def test_unattributed_debit_holds_spending_without_erasing_known_balances(self) -> None:
        CreditLedger.objects.create(
            customer=self.customer, currency=self.eur, delta_cents=1200, reason="Original EUR credit",
        )
        CreditLedger.objects.bulk_create([
            CreditLedger(customer=self.customer, delta_cents=-300, reason="Legacy use",
                         currency_hold_reason="No immutable source identifies the original currency")
        ])
        self.assertEqual(CreditLedger.balances_for_customer(self.customer), {"EUR": 1200})
        self.assertEqual(UsageInvoiceService()._get_customer_credit_balance(self.customer, self.eur), 0)


class UsageInvoiceCurrencyIsolationTests(TestCase):
    def setUp(self) -> None:
        metering_fixtures.UsageInvoiceServiceTestCase.setUp(self)

    def test_euro_credit_cannot_pay_a_ron_usage_invoice(self) -> None:
        eur, _ = Currency.objects.get_or_create(code="EUR", defaults={"symbol": "€"})
        source = Invoice.objects.create(
            customer=self.customer, currency=eur, number="EUR-ORIGINAL",
            subtotal_cents=5000, total_cents=5000, due_at=timezone.now(),
        )
        CreditLedger.objects.create(customer=self.customer, invoice=source, delta_cents=5000, reason="Euro refund")
        CreditLedger.objects.create(
            customer=self.customer, invoice=self.collection_invoice, delta_cents=1000, reason="RON refund",
        )
        result = self.service.generate_invoice_from_cycle(str(self.billing_cycle.id))
        self.assertTrue(result.is_ok(), result)
        invoice = Invoice.objects.get(pk=result.unwrap()["invoice_id"])
        self.assertEqual(invoice.currency_id, "RON")
        self.assertEqual(invoice.get_remaining_amount(), 2025)
        payment = Payment.objects.get(invoice=invoice, meta__source="customer_credit")
        self.assertEqual((payment.currency_id, payment.amount_cents), ("RON", 1000))
        self.assertEqual(CreditLedger.balances_for_customer(self.customer), {"EUR": 5000, "RON": 0})


class GrandfatheringCurrencyTests(TestCase):
    def setUp(self) -> None:
        self.ron, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
        self.eur, _ = Currency.objects.get_or_create(code="EUR", defaults={"symbol": "€"})
        self.customer = Customer.objects.create(name="Protected buyer", customer_type="individual")
        self.product = make_product()

    def protection(self, currency: Currency, price: int) -> PriceGrandfathering:
        return PriceGrandfathering.objects.create(
            customer=self.customer, product=self.product, currency=currency,
            locked_price_cents=price, original_price_cents=price,
            current_product_price_cents=2999, reason="Original promise",
        )

    def test_other_currency_protection_cannot_reprice_a_new_subscription(self) -> None:
        self.protection(self.eur, 300)
        result = SubscriptionService.create_subscription(
            self.customer, self.product, {"currency_code": "RON", "apply_grandfathering": True},
        )
        self.assertTrue(result.is_ok(), result)
        self.assertIsNone(result.unwrap().locked_price_cents)

    def test_same_customer_product_can_keep_distinct_currency_promises(self) -> None:
        ron = self.protection(self.ron, 1500)
        eur = self.protection(self.eur, 300)
        self.assertEqual(ron.locked_price, Decimal("15"))
        self.assertEqual(eur.locked_price, Decimal("3"))
        result = SubscriptionService.create_subscription(
            self.customer, self.product, {"currency_code": "RON", "apply_grandfathering": True},
        )
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(result.unwrap().locked_price_cents, 1500)

    def test_price_increase_only_protects_the_named_currency(self) -> None:
        ron = make_subscription(self.customer, self.product, self.ron, unit_price_cents=1500)
        eur = make_subscription(self.customer, self.product, self.eur, unit_price_cents=300)
        result = GrandfatheringService.apply_grandfathering_for_price_increase(
            self.product, 1500, 1800, currency=self.ron,
        )
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(result.unwrap(), 1)
        ron.refresh_from_db()
        eur.refresh_from_db()
        self.assertEqual(ron.locked_price_cents, 1500)
        self.assertIsNone(eur.locked_price_cents)

    def test_price_increase_preserves_an_existing_zero_price_promise(self) -> None:
        subscription = make_subscription(self.customer, self.product, self.ron, unit_price_cents=1500)
        subscription.apply_grandfathered_price(0, "Original free service promise")
        result = GrandfatheringService.apply_grandfathering_for_price_increase(
            self.product, 1500, 1800, currency=self.ron,
        )
        self.assertTrue(result.is_ok(), result)
        subscription.refresh_from_db()
        self.assertEqual(subscription.locked_price_cents, 0)
        self.assertEqual(subscription.locked_price_reason, "Original free service promise")
        self.assertEqual(result.unwrap(), 0)

    def test_expiring_one_currency_keeps_the_other_promise(self) -> None:
        self.protection(self.ron, 1500)
        self.protection(self.eur, 300)
        ron = make_subscription(self.customer, self.product, self.ron, unit_price_cents=1800)
        eur = make_subscription(self.customer, self.product, self.eur, unit_price_cents=400)
        ron.apply_grandfathered_price(1500, "Original RON promise")
        eur.apply_grandfathered_price(300, "Original EUR promise")
        result = GrandfatheringService.expire_grandfathering(self.customer, self.product, currency=self.ron)
        self.assertTrue(result.is_ok(), result)
        ron.refresh_from_db()
        eur.refresh_from_db()
        self.assertIsNone(ron.locked_price_cents)
        self.assertEqual(eur.locked_price_cents, 300)

    def test_unknown_legacy_currency_preserves_protection_until_review(self) -> None:
        PriceGrandfathering.objects.bulk_create([
            PriceGrandfathering(
                customer=self.customer, product=self.product, locked_price_cents=1500,
                original_price_cents=1500, current_product_price_cents=2000, reason="Legacy promise",
                currency_hold_reason="Original monetary unit unknown",
            )
        ])
        result = SubscriptionService.create_subscription(
            self.customer, self.product, {"currency_code": "RON", "apply_grandfathering": True},
        )
        self.assertTrue(result.is_err())
        self.assertIn("price protection needs review", result.unwrap_err())
        self.assertTrue(PriceGrandfathering.objects.get(customer=self.customer).is_active)


class ConcurrentUsageCreditTests(TransactionTestCase):
    """Exercise the row lock on PostgreSQL and the same allocations sequentially on SQLite."""

    def setUp(self) -> None:
        metering_fixtures.UsageInvoiceServiceTestCase.setUp(self)
        CreditLedger.objects.create(
            customer=self.customer, currency=self.currency, delta_cents=4000, reason="Shared account credit",
        )

    @staticmethod
    def generate(cycle_id: str, ready: Barrier | None = None):
        close_old_connections()
        try:
            if ready:
                ready.wait(timeout=10)
            return UsageInvoiceService().generate_invoice_from_cycle(cycle_id)
        finally:
            connections.close_all()

    def test_customer_lock_precedes_available_credit_check(self) -> None:
        if connection.vendor != "postgresql":
            result = self.service.generate_invoice_from_cycle(str(self.billing_cycle.pk))
            self.assertTrue(result.is_ok(), result)
            self.assertEqual(CreditLedger.available_balance_for_customer(self.customer, self.currency), 975)
            return
        reached_credit_section = Event()
        balance_checked = Event()

        def observe_sql(execute, sql, params, many, context):
            if "SELECT" in sql and "FOR UPDATE" in sql and '"customers"' in sql:
                reached_credit_section.set()
            if "SUM(" in sql and "billing_credit_ledgers" in sql:
                reached_credit_section.set()
                balance_checked.set()
            return execute(sql, params, many, context)

        def generate_while_observed():
            close_old_connections()
            try:
                with connection.execute_wrapper(observe_sql):
                    return self.generate(str(self.billing_cycle.pk))
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=1) as pool:
            with transaction.atomic():
                Customer.objects.select_for_update().get(pk=self.customer.pk)
                pending = pool.submit(generate_while_observed)
                self.assertTrue(reached_credit_section.wait(timeout=10), "Worker did not reach credit locking")
                self.assertFalse(balance_checked.wait(timeout=0.2), "Credit was read without owning the customer lock")
            result = pending.result(timeout=20)
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(CreditLedger.available_balance_for_customer(self.customer, self.currency), 975)

    def test_two_usage_cycles_cannot_spend_the_same_credit(self) -> None:
        second_subscription = make_subscription(self.customer, self.product, self.currency)
        second_cycle = BillingCycle.objects.create(
            subscription=second_subscription, period_start=self.billing_cycle.period_start,
            period_end=self.billing_cycle.period_end, status="closed", usage_charge_cents=2500,
        )
        UsageAggregation.objects.create(
            meter=self.meter, customer=self.customer, subscription=second_subscription, billing_cycle=second_cycle,
            period_start=second_cycle.period_start, period_end=second_cycle.period_end,
            total_value=Decimal(50), billable_value=Decimal(50), overage_value=Decimal(50),
            charge_cents=2500, status="rated",
        )
        cycle_ids = [str(self.billing_cycle.pk), str(second_cycle.pk)]
        if connection.vendor == "postgresql":
            ready = Barrier(2)
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(self.generate, cycle_id, ready) for cycle_id in cycle_ids]
                results = [future.result(timeout=30) for future in futures]
        else:
            results = [self.service.generate_invoice_from_cycle(cycle_id) for cycle_id in cycle_ids]
        self.assertTrue(all(result.is_ok() for result in results), results)
        payments = Payment.objects.filter(customer=self.customer, meta__source="customer_credit")
        self.assertEqual(sum(payments.values_list("amount_cents", flat=True)), 4000)
        self.assertEqual(CreditLedger.available_balance_for_customer(self.customer, self.currency), 0)
        invoices = Invoice.objects.filter(pk__in=[result.unwrap()["invoice_id"] for result in results])
        self.assertEqual(sum(invoice.get_remaining_amount() for invoice in invoices), 2050)
