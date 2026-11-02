"""Runtime contracts and real PostgreSQL snapshot/lock tests for the shared primitive."""

from __future__ import annotations

from threading import Event
from unittest import skipUnless
from unittest.mock import patch

from django.db import DatabaseError, connection, transaction
from django.db.models import Count, OuterRef
from django.test import SimpleTestCase, TestCase, TransactionTestCase
from django.test.utils import CaptureQueriesContext

from apps.billing.subscription_models import Subscription
from apps.common.row_locks import lock_many_and_load, lock_one_and_load
from apps.customers.models import Customer, CustomerPaymentMethod
from apps.provisioning.models import Service
from tests.billing.test_subscription_invoice_payments import _SubscriptionInvoicePaymentFixture
from tests.common.postgres_locking import backend_pid, database_worker, wait_for_blocker


class RowLockShapeTests(SimpleTestCase):
    def test_rejects_preexisting_lock_without_executing_sql(self) -> None:
        with self.assertRaises(ValueError):
            lock_many_and_load(Subscription.objects.select_for_update())


class RowLockContractTests(_SubscriptionInvoicePaymentFixture, TestCase):
    def test_two_queries_preserve_relations_deferred_fields_and_business_order(self) -> None:
        queryset = Subscription.objects.select_related("customer", "service").defer("notes").order_by("-pk")
        with self.assertNumQueries(2):
            rows = lock_many_and_load(queryset)
            self.assertEqual([row.pk for row in rows], [self.subscription.pk])
            self.assertEqual(rows[0].customer.pk, self.customer.pk)
            self.assertEqual(rows[0].service.pk, self.service.pk)
        self.assertIn("notes", rows[0].get_deferred_fields())

    def test_prefetch_is_retained_and_input_cache_is_never_reused(self) -> None:
        queryset = Subscription.objects.select_related("customer").prefetch_related("billing_cycles")
        stale = list(queryset)
        Customer.objects.filter(pk=self.customer.pk).update(company_name="Fresh company")
        with self.assertNumQueries(3):
            rows = lock_many_and_load(queryset)
            self.assertEqual(rows[0].customer.company_name, "Fresh company")
            self.assertEqual(list(rows[0].billing_cycles.all()), [self.billing_cycle])
        self.assertIsNot(rows[0], stale[0])

    def test_single_cardinality_and_optional_bulk_contract(self) -> None:
        self.assertEqual(lock_one_and_load(Subscription.objects.filter(pk=self.subscription.pk)).pk, self.subscription.pk)
        with self.assertRaises(Subscription.DoesNotExist):
            lock_one_and_load(Subscription.objects.filter(pk=None))
        self.assertEqual(lock_many_and_load(Subscription.objects.filter(pk=None)), [])
        with self.assertRaises(Customer.MultipleObjectsReturned):
            Customer.objects.create(name="Second", primary_email="second@example.test")
            lock_one_and_load(Customer.objects.all())

    def test_write_router_selects_both_statements(self) -> None:
        with (
            patch("django.db.router.db_for_write", return_value="default") as writer,
            patch("django.db.router.db_for_read", side_effect=AssertionError("Read alias used")),
        ):
            rows = lock_many_and_load(Subscription.objects.filter(pk=self.subscription.pk))
        self.assertEqual(rows[0].pk, self.subscription.pk)
        writer.assert_called()

    def test_refuses_unsupported_query_shapes_before_sql(self) -> None:
        base = Subscription.objects.all()
        shapes = [
            base.select_for_update(), base[:1], base.values("pk"), base.values_list("pk", flat=True),
            base.distinct(), base.annotate(n=Count("pk")), base.alias(n=Count("pk")),
            base.union(base), base.filter(pk=OuterRef("pk")), base.extra(select={"constant": "1"}),
            base.filter(customer_id__in=Customer.objects.filter(pk=OuterRef("customer_id")).values("pk")),
            base.extra(where=["1=1"]), base.extra(tables=["customers_customer"]), base.extra(order_by=["pk"]),
        ]
        for queryset in shapes:
            with self.subTest(query=str(type(queryset))), self.assertNumQueries(0), self.assertRaises(ValueError):
                lock_many_and_load(queryset)
        with self.assertRaises(ValueError):
            lock_many_and_load(base, nowait=True, skip_locked=True)


@skipUnless(connection.vendor == "postgresql", "Requires PostgreSQL row locks and fresh statement snapshots")
class RowLockPostgresTests(_SubscriptionInvoicePaymentFixture, TransactionTestCase):
    def test_atomic_is_required(self) -> None:
        with self.assertRaises(transaction.TransactionManagementError):
            lock_many_and_load(Subscription.objects.all())

    def _after_wait(self, writer, queryset):
        start = Event()
        owner = backend_pid()

        def read():
            assert start.wait(10)
            with transaction.atomic():
                return lock_many_and_load(queryset)

        with database_worker(read) as (pid, pending):
            try:
                with transaction.atomic():
                    Subscription.objects.select_for_update(of=("self",)).get(pk=self.subscription.pk)
                    writer()
                    start.set()
                    wait_for_blocker(pid, owner, pending, table=Subscription._meta.db_table)
            finally:
                start.set()
            return pending.result(timeout=30)

    def test_updated_root_and_related_values_are_both_fresh(self) -> None:
        def write():
            Subscription.objects.filter(pk=self.subscription.pk).update(quantity=3)
            Customer.objects.filter(pk=self.customer.pk).update(company_name="After wait")

        rows = self._after_wait(write, Subscription.objects.select_related("customer"))
        self.assertEqual((rows[0].quantity, rows[0].customer.company_name), (3, "After wait"))

    def test_retargeted_fk_with_joined_filter_is_loaded(self) -> None:
        other = CustomerPaymentMethod.objects.create(customer=self.customer, method_type="stripe_card", display_name="Other", is_active=True)
        rows = self._after_wait(
            lambda: Subscription.objects.filter(pk=self.subscription.pk).update(saved_payment_method=other),
            Subscription.objects.filter(saved_payment_method__is_active=True).select_related("saved_payment_method"),
        )
        self.assertEqual([row.saved_payment_method.pk for row in rows], [other.pk])

    def test_old_joined_eligibility_is_excluded_after_wait(self) -> None:
        rows = self._after_wait(
            lambda: Service.objects.filter(pk=self.service.pk).update(auto_renew=False),
            Subscription.objects.filter(service__auto_renew=True).select_related("service"),
        )
        self.assertEqual(rows, [])

    def test_nullable_transitions_and_retargeting(self) -> None:
        Subscription.objects.filter(pk=self.subscription.pk).update(auto_payment_enabled=False, payment_authorization=None)
        original = self.payment_method
        replacement = CustomerPaymentMethod.objects.create(customer=self.customer, method_type="stripe_card", display_name="Replacement")
        for before, after in ((None, original), (original, None), (original, replacement)):
            Subscription.objects.filter(pk=self.subscription.pk).update(saved_payment_method=before)
            rows = self._after_wait(
                lambda target=after: Subscription.objects.filter(pk=self.subscription.pk).update(saved_payment_method=target),
                Subscription.objects.select_related("saved_payment_method"),
            )
            self.assertEqual(rows[0].saved_payment_method, after)

    def test_outer_lock_has_no_joins_even_with_joined_filters_and_ordering(self) -> None:
        with transaction.atomic(), CaptureQueriesContext(connection) as queries:
            lock_many_and_load(
                Subscription.objects.filter(service__auto_renew=True).select_related("customer").order_by("customer__name")
            )
        self.assertEqual(len(queries), 2)
        sql = queries[0]["sql"]
        outer = sql.split(" IN (SELECT ")[0]
        self.assertNotIn("JOIN", outer)
        self.assertIn('SELECT "billing_subscriptions"."id" AS "pk"', outer)
        self.assertIn('ORDER BY 1 ASC FOR UPDATE OF "billing_subscriptions"', sql)
        self.assertNotIn("FOR UPDATE", queries[1]["sql"])

    def test_third_writer_commit_between_lock_and_load_is_visible(self) -> None:
        edited = False

        def after_lock(execute, sql, params, many, context):
            nonlocal edited
            result = execute(sql, params, many, context)
            if "FOR UPDATE" in sql and not edited:
                edited = True
                with database_worker(lambda: Customer.objects.filter(pk=self.customer.pk).update(company_name="Third")) as (_, pending):
                    self.assertEqual(pending.result(timeout=10), 1)
            return result

        with transaction.atomic(), connection.execute_wrapper(after_lock):
            row = lock_one_and_load(Subscription.objects.select_related("customer"))
        self.assertTrue(edited)
        self.assertEqual(row.customer.company_name, "Third")

    def test_skip_locked_and_nowait_are_forwarded(self) -> None:
        with transaction.atomic():
            Subscription.objects.select_for_update().get(pk=self.subscription.pk)

            def skip():
                with transaction.atomic():
                    return lock_many_and_load(Subscription.objects.all(), skip_locked=True)

            with database_worker(skip) as (_, pending):
                self.assertEqual(pending.result(timeout=10), [])

            def immediate():
                with transaction.atomic():
                    return lock_many_and_load(Subscription.objects.all(), nowait=True)

            with database_worker(immediate) as (_, pending), self.assertRaises(DatabaseError):
                pending.result(timeout=10)

    def test_no_key_lock_allows_independent_fk_reference_through_commit(self) -> None:
        with transaction.atomic():
            with CaptureQueriesContext(connection) as queries:
                lock_one_and_load(Customer.objects.filter(pk=self.customer.pk), no_key=True)
            self.assertIn("FOR NO KEY UPDATE", queries[0]["sql"])
            with database_worker(lambda: CustomerPaymentMethod.objects.create(customer_id=self.customer.pk, method_type="stripe_card", display_name="Independent")) as (_, pending):
                self.assertEqual(pending.result(timeout=10).customer_id, self.customer.pk)

    def test_opposite_business_orders_both_lock_the_batch_in_pk_order(self) -> None:
        second = Customer.objects.create(name="Second batch root", primary_email="batch@example.test")
        for ordering in ("pk", "-pk"):
            start = Event()

            def read(start=start, ordering=ordering):
                assert start.wait(10)
                with transaction.atomic(), CaptureQueriesContext(connection) as queries:
                    rows = lock_many_and_load(Customer.objects.filter(pk__in=[self.customer.pk, second.pk]).order_by(ordering))
                    return [row.pk for row in rows], len(queries)

            owner = backend_pid()
            with database_worker(read) as (pid, pending):
                try:
                    with transaction.atomic():
                        Customer.objects.select_for_update().get(pk=second.pk)
                        start.set()
                        wait_for_blocker(pid, owner, pending, table=Customer._meta.db_table)

                        def first_is_owned():
                            with transaction.atomic():
                                Customer.objects.select_for_update(nowait=True).get(pk=self.customer.pk)

                        with database_worker(first_is_owned) as (_, probe), self.assertRaises(DatabaseError):
                            probe.result(timeout=10)
                finally:
                    start.set()
                rows, query_count = pending.result(timeout=30)
            expected = sorted([self.customer.pk, second.pk], reverse=ordering.startswith("-"))
            self.assertEqual(rows, expected)
            self.assertEqual(query_count, 2)
