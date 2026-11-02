"""Reconciliation uses the same Customer -> Service admission as immediate cancellation."""

from threading import Event
from unittest import skipUnless
from unittest.mock import patch

from django.core.cache import cache
from django.db import connection
from django.test import TransactionTestCase

from apps.billing.subscription_service import SubscriptionService
from apps.customers.models import Customer
from apps.provisioning.models import Service
from apps.provisioning.virtualmin_tasks import reconcile_virtualmin_service_state
from tests.billing.test_subscription_invoice_payments import _SubscriptionInvoicePaymentFixture
from tests.common.postgres_locking import backend_pid, database_worker, wait_for_blocker


@skipUnless(connection.vendor == "postgresql", "Requires PostgreSQL cancellation/reconciliation row waits")
class ReconciliationCancellationLockTests(_SubscriptionInvoicePaymentFixture, TransactionTestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.enterContext(patch("django_q.tasks.async_task"))
        super().setUp()
        Service.objects.filter(pk=self.service.pk).update(domain="reconciliation.example.com")

    def test_cancellation_and_reconciliation_serialize_without_dispatching_cancelled_service(self) -> None:
        start = Event()
        owner = backend_pid()
        observed = []

        def reconcile():
            assert start.wait(10)
            return reconcile_virtualmin_service_state(str(self.service.pk))

        with patch("apps.provisioning.virtualmin_tasks.async_task", return_value="queued-test") as enqueue, database_worker(reconcile) as (pid, pending):
            def pause_customer(execute, sql, params, many, context):
                result = execute(sql, params, many, context)
                if not observed and Customer._meta.db_table in sql and "FOR NO KEY UPDATE" in sql:
                    start.set()
                    observed.append(wait_for_blocker(pid, owner, pending, table=Customer._meta.db_table))
                return result

            try:
                with connection.execute_wrapper(pause_customer):
                    cancelled = SubscriptionService.cancel_subscription(self.subscription, at_period_end=False)
            finally:
                start.set()
            result = pending.result(timeout=30)
        self.assertTrue(cancelled.is_ok(), cancelled)
        self.assertTrue(result["success"], result)
        self.service.refresh_from_db()
        self.assertEqual(self.service.status, "expired")
        tasks = [call.args[0] for call in enqueue.call_args_list if call.args]
        self.assertNotIn("apps.provisioning.virtualmin_tasks.provision_virtualmin_account", tasks)
