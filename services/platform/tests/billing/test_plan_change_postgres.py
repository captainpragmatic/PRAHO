"""Financial locks protect mutations without blocking unrelated FK references."""

from datetime import timedelta
from threading import Event

from django.core.cache import cache
from django.db import connection, transaction
from django.test import TransactionTestCase

from apps.audit.services import GDPRDeletionService
from apps.billing.models import BillingCycle, Currency, Invoice, Payment, ProformaInvoice, Subscription
from apps.billing.payment_convergence import PaymentSuccessService
from apps.billing.proforma_service import ProformaPaymentService
from apps.billing.recurring_billing import RecurringBillingOrchestrator, fixed_renewal_schedule
from apps.promotions.locking import lock_document_context
from apps.users.models import CustomerMembership
from tests.billing.test_plan_change_intervals import _PlanChangeCoverageFixture
from tests.billing.test_plan_change_settlement import _PlanChangeSettlementFixture
from tests.common.postgres_locking import backend_pid, database_worker, wait_for_blocker
from tests.helpers.task_queue import quiet_task_queue


class _FinancialPostgresFixture:
    def setUp(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("Financial row-lock acceptance requires PostgreSQL")
        cache.clear()
        self.addCleanup(cache.clear)
        quiet_task_queue(self)
        super().setUp()


class FinancialContextPostgresTests(_FinancialPostgresFixture, _PlanChangeCoverageFixture, TransactionTestCase):
    def test_paid_cycle_convergence_keeps_subscription_fk_references_compatible(self) -> None:
        cycle, invoice, _ = self.cycle()
        converged, release = Event(), Event()
        self.addCleanup(release.set)
        backend_pid()

        def settle_and_hold():
            with transaction.atomic():
                document = Invoice.objects.select_for_update().get(pk=invoice.pk)
                lock_document_context(document)
                error = PaymentSuccessService._converge_invoice(document)
                if error is not None:
                    raise AssertionError(error)
                converged.set()
                if not release.wait(15):
                    raise AssertionError("The FK compatibility observer did not release settlement")
            return "committed"

        def reference_subscription():
            with transaction.atomic():
                subscription = Subscription.objects.get(pk=self.subscription.pk)
                placeholder = BillingCycle.objects.create(
                    subscription=subscription,
                    period_start=cycle.period_end + timedelta(days=30),
                    period_end=cycle.period_end + timedelta(days=60),
                )
            return str(placeholder.pk)

        with database_worker(settle_and_hold) as (holder, settlement):
            try:
                self.assertTrue(converged.wait(10), "Settlement did not reach its locked post-convergence boundary")
                with database_worker(reference_subscription) as (reference_pid, reference):
                    try:
                        self.assertNotEqual(reference_pid, holder)
                        try:
                            inserted = reference.result(timeout=2)
                        except TimeoutError:
                            # The sole FK is Subscription. PostgreSQL defers its
                            # key-share check to COMMIT; observe the exact holder.
                            wait_for_blocker(reference_pid, holder, reference, table="", operation="COMMIT")
                            self.fail("Paid convergence upgraded the subscription to an unnecessary FOR UPDATE lock")
                        self.assertTrue(BillingCycle.objects.filter(pk=inserted).exists())
                    finally:
                        release.set()
            finally:
                release.set()
            self.assertEqual(settlement.result(timeout=10), "committed")


class PaidPlanCustomerLockTests(_FinancialPostgresFixture, _PlanChangeSettlementFixture, TransactionTestCase):
    def test_real_paid_change_keeps_unrelated_customer_fk_inserts_compatible(self) -> None:
        _, proforma, _, _ = self.payable_change()
        reference_currency, _ = Currency.objects.get_or_create(code="EUR", defaults={"symbol": "€"})
        converged, release = Event(), Event()
        self.addCleanup(release.set)
        backend_pid()

        def settle_and_hold():
            with transaction.atomic():
                result = ProformaPaymentService.record_payment_and_convert(str(proforma.pk), 6000, "bank")
                if result.is_err():
                    raise AssertionError(result)
                converged.set()
                if not release.wait(15):
                    raise AssertionError("The customer FK observer did not release paid settlement")
            return "committed"

        def reference_customer():
            with transaction.atomic():
                reference = Payment.objects.create(
                    customer_id=self.customer.pk,
                    currency_id=reference_currency.pk,
                    amount_cents=0,
                    payment_method="bank",
                )
            return reference.pk

        with database_worker(settle_and_hold) as (holder, settlement):
            try:
                if not converged.wait(10):
                    if settlement.done():
                        settlement.result()
                    self.fail("Paid settlement did not reach the customer lock boundary")
                with database_worker(reference_customer) as (reference_pid, reference):
                    try:
                        try:
                            payment_id = reference.result(timeout=2)
                        except TimeoutError:
                            # Currency is independent and no document FK is set:
                            # this exact COMMIT waits on the shared Customer FK.
                            wait_for_blocker(reference_pid, holder, reference, table="", operation="COMMIT")
                            self.fail("Paid bookkeeping unnecessarily upgraded the Customer to FOR UPDATE")
                        self.assertTrue(Payment.objects.filter(pk=payment_id).exists())
                    finally:
                        release.set()
            finally:
                release.set()
            self.assertEqual(settlement.result(timeout=10), "committed")


class RenewalCustomerBoundaryTests(_FinancialPostgresFixture, _PlanChangeCoverageFixture, TransactionTestCase):
    def test_public_erasure_and_renewal_preparation_cannot_publish_erased_identity(self) -> None:
        self.customer.customer_type = "individual"
        self.customer.primary_email = self.actor.email
        self.customer.save(update_fields=["customer_type", "primary_email"])
        CustomerMembership.objects.create(customer=self.customer, user=self.actor, role="owner", is_active=True)
        # An exact paid interval with its renewal already due for preparation.
        self.subscription.current_period_start = self.now - timedelta(days=14)
        self.subscription.current_period_end = self.now + timedelta(days=14)
        proforma_at, charge_at = fixed_renewal_schedule(self.subscription.current_period_end)
        self.subscription.next_proforma_at = proforma_at
        self.subscription.next_billing_date = proforma_at
        self.subscription.next_charge_at = charge_at
        self.subscription.save(
            update_fields=[
                "current_period_start",
                "current_period_end",
                "next_proforma_at",
                "next_billing_date",
                "next_charge_at",
            ]
        )
        self.cycle()
        request = GDPRDeletionService.create_deletion_request(user=self.actor)
        self.assertTrue(request.is_ok(), request)
        locked, release = Event(), Event()
        self.addCleanup(release.set)
        old_name, old_email = self.customer.name, self.customer.primary_email

        def erase():
            def observe(execute, sql, params, many, context):
                result = execute(sql, params, many, context)
                if not locked.is_set() and 'FROM "customers"' in sql and "FOR UPDATE" in sql:
                    locked.set()
                    if not release.wait(15):
                        raise AssertionError("Renewal observer did not release the actual erasure lock")
                return result

            with connection.execute_wrapper(observe):
                return GDPRDeletionService.process_deletion_request(request.unwrap())

        with database_worker(erase) as (eraser_pid, erasure):
            try:
                self.assertTrue(locked.wait(10), "Public erasure did not lock its owned customer")
                with database_worker(lambda: RecurringBillingOrchestrator.prepare_due_proformas(as_of=proforma_at)) as (
                    reader_pid,
                    preparation,
                ):
                    try:
                        waiting = wait_for_blocker(reader_pid, eraser_pid, preparation, table="", operation="")
                        self.assertTrue(
                            waiting.lstrip().startswith("COMMIT")
                            or ('FROM "customers"' in waiting and waiting.lstrip().startswith("SELECT")),
                            waiting,
                        )
                    finally:
                        release.set()
                    result = preparation.result(timeout=15)
                    self.assertIsInstance(result["errors"], list)
                erased = erasure.result(timeout=10)
                self.assertTrue(erased.is_ok(), erased)
            finally:
                release.set()
        self.customer.refresh_from_db()
        self.assertIsNotNone(self.customer.anonymized_at)
        self.assertFalse(ProformaInvoice.objects.filter(customer=self.customer, bill_to_name=old_name).exists())
        self.assertFalse(ProformaInvoice.objects.filter(customer=self.customer, bill_to_email=old_email).exists())
