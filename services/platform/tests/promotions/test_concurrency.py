"""Financial reservations under real concurrent PostgreSQL transactions."""

from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from threading import Barrier, Event
from time import monotonic, sleep
from unittest import skipUnless

from django.core.exceptions import ValidationError
from django.db import close_old_connections, connection, connections, transaction
from django.test import TransactionTestCase
from django.utils import timezone

from apps.billing.invoice_models import Invoice
from apps.billing.metering_models import BillingCycle
from apps.billing.models import Currency
from apps.billing.payment_models import Payment
from apps.billing.payment_service import _mark_invoice_payment_attempt_failed
from apps.billing.proforma_models import ProformaInvoice
from apps.billing.recurring_billing import RecurringBillingOrchestrator
from apps.billing.subscription_models import Subscription
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from apps.promotions.engine import freeze_order, quote_order
from apps.promotions.gift_cards import pay_document, reserve_value
from apps.promotions.models import Coupon, GiftCard, GiftCardReservation, PromotionCampaign
from apps.promotions.tender_refunds import refund_document
from apps.settings.services import SettingsService
from tests.billing.test_subscription_invoice_payments import _SubscriptionInvoicePaymentFixture


@skipUnless(connection.vendor == "postgresql", "Row-lock races require PostgreSQL")
class PromotionConcurrencyTests(TransactionTestCase):
    def setUp(self):
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "name": "Leu"})
        self.customers = [
            Customer.objects.create(name=f"Race buyer {index}", customer_type="individual") for index in range(2)
        ]
        self.product = Product.objects.create(name="Race hosting", slug="race-hosting", product_type="shared_hosting")

    def race(self, operation):
        barrier = Barrier(2)

        def run(index):
            close_old_connections()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SET lock_timeout = '5s'")
                barrier.wait(timeout=10)
                try:
                    operation(index)
                    return "reserved"
                except ValidationError:
                    return "unavailable"
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as pool:
            return list(pool.map(run, range(2)))

    def test_same_balance_cannot_be_reserved_on_two_documents(self):
        card = GiftCard.objects.create(
            code="RACE-CARD",
            currency=self.currency,
            status="active",
            initial_value_cents=1000,
            current_balance_cents=1000,
        )
        documents = [
            ProformaInvoice.objects.create(
                customer=customer,
                currency=self.currency,
                number=f"PRO-RACE-{index}",
                total_cents=1000,
                valid_until=timezone.now() + timezone.timedelta(days=1),
            )
            for index, customer in enumerate(self.customers)
        ]
        results = self.race(
            lambda index: reserve_value(card.code, documents[index], self.customers[index], f"race-{index}")
        )
        self.assertCountEqual(results, ["reserved", "unavailable"])
        card.refresh_from_db()
        self.assertEqual(card.reserved_cents, 1000)
        self.assertEqual(GiftCardReservation.objects.filter(status="reserved").count(), 1)

    def test_same_campaign_budget_cannot_back_two_checkouts(self):
        SettingsService.update_setting("promotions.new_offers_enabled", True, reason="Concurrent quote test")
        self.addCleanup(SettingsService._clear_setting_cache, "promotions.new_offers_enabled")
        campaign = PromotionCampaign.objects.create(
            name="Race budget",
            slug="race-budget",
            status="active",
            start_date=timezone.now(),
            budget_currency=self.currency,
            budget_cents=500,
        )
        coupon = Coupon.objects.create(
            code="RACE", name="Race", campaign=campaign, discount_type="percent", discount_percent=50
        )
        orders = []
        quotes = []
        for customer in self.customers:
            order = Order.objects.create(customer=customer, currency=self.currency)
            OrderItem.objects.create(
                order=order,
                product=self.product,
                product_name=self.product.name,
                product_type=self.product.product_type,
                quantity=1,
                unit_price_cents=1000,
                tax_rate=Decimal("0.21"),
            )
            order.calculate_totals()
            orders.append(order)
            quotes.append(quote_order(order, list(order.items.all()), [coupon.code])["quote_token"])
        results = self.race(lambda index: freeze_order(orders[index], [coupon.code], quotes[index]))
        self.assertCountEqual(results, ["reserved", "unavailable"])
        campaign.refresh_from_db()
        coupon.refresh_from_db()
        self.assertEqual((campaign.reserved_cents, campaign.spent_cents, coupon.total_uses), (500, 0, 1))


@skipUnless(connection.vendor == "postgresql", "Row-lock races require PostgreSQL")
class RenewalPaymentConcurrencyTests(_SubscriptionInvoicePaymentFixture, TransactionTestCase):
    def test_previous_renewal_refund_does_not_deadlock_current_payment_failure(self):
        card = GiftCard.objects.create(
            code="REFUND-DUNNING",
            currency=self.currency,
            status="active",
            initial_value_cents=self.invoice.total_cents,
            current_balance_cents=self.invoice.total_cents,
        )
        pay_document(card.code, self.invoice, self.customer, "old-renewal-payment")
        current_invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="CURRENT-RENEWAL",
            total_cents=12100,
        )
        current_payment = Payment.objects.create(
            customer=self.customer,
            currency=self.currency,
            invoice=current_invoice,
            amount_cents=12100,
            payment_method="stripe",
            meta={"source": "recurring_billing"},
        )
        self.subscription.refresh_from_db()

        BillingCycle.objects.create(
            subscription=self.subscription,
            invoice=current_invoice,
            period_start=self.subscription.current_period_end,
            period_end=self.subscription.current_period_end + timezone.timedelta(days=30),
        )
        locked = Event()
        ready = Event()
        backend = []

        def failure():
            close_old_connections()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SET lock_timeout = '8s'")
                    cursor.execute("SELECT pg_backend_pid()")
                    backend.append(cursor.fetchone()[0])
                ready.set()
                if not locked.wait(10):
                    raise AssertionError("Refund did not lock its subscription")
                _mark_invoice_payment_attempt_failed(current_payment.pk, "card declined")
            finally:
                connections.close_all()

        def interleave(execute, sql, params, many, context):
            result = execute(sql, params, many, context)
            if not locked.is_set() and '"billing_subscriptions"' in sql and "FOR UPDATE" in sql:
                locked.set()
                deadline = monotonic() + 10
                while True:
                    with connection.cursor() as cursor:
                        cursor.execute("SELECT cardinality(pg_blocking_pids(%s))", [backend[0]])
                        if cursor.fetchone()[0]:
                            break
                    self.assertLess(monotonic(), deadline, "Failure never reached the shared financial locks")
                    sleep(0.01)
            return result

        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(failure)
            self.assertTrue(ready.wait(10))
            with connection.execute_wrapper(interleave):
                command = refund_document(self.invoice.pk, 12100, "refund-old-renewal", reason="customer_request")
            pending.result(timeout=10)
        self.assertEqual(command.status, "completed")
        card.refresh_from_db()
        current_payment.refresh_from_db()
        self.assertEqual(card.current_balance_cents, 12100)
        self.assertEqual(current_payment.status, "failed")

    def test_overdue_processing_cannot_deadlock_a_gift_renewal_payment(self):
        now = timezone.now()
        subscription = self._create_aligned_subscription("DUNNING-RACE", now)
        result = RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)
        self.assertEqual(result["errors"], [])
        document = ProformaInvoice.objects.get()
        card = GiftCard.objects.create(
            code="DUNNING-RACE",
            currency=self.currency,
            status="active",
            initial_value_cents=document.total_cents,
            current_balance_cents=document.total_cents,
        )
        ready = Event()
        backend = []

        def dunning():
            close_old_connections()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SET lock_timeout = '8s'")
                    cursor.execute("SELECT pg_backend_pid()")
                    backend.append(cursor.fetchone()[0])
                ready.set()
                return RecurringBillingOrchestrator.mark_overdue_renewals(as_of=subscription.current_period_end)
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=1) as pool:
            with transaction.atomic():
                Subscription.objects.select_for_update().get(pk=subscription.pk)
                pending = pool.submit(dunning)
                self.assertTrue(ready.wait(10))
                deadline = monotonic() + 10
                while True:
                    with connection.cursor() as cursor:
                        cursor.execute("SELECT cardinality(pg_blocking_pids(%s))", [backend[0]])
                        if cursor.fetchone()[0]:
                            break
                    self.assertLess(monotonic(), deadline, "Dunning never reached the held subscription")
                    sleep(0.01)
                paid = pay_document(card.code, document, self.customer, "dunning-race")
                self.assertEqual(paid["cash_due_cents"], 0)
            self.assertEqual(pending.result(timeout=10), 0)
        card.refresh_from_db()
        subscription.refresh_from_db()
        self.assertEqual(card.current_balance_cents, 0)
        self.assertEqual(subscription.status, "active")
        self.assertGreater(subscription.current_period_end, now)
