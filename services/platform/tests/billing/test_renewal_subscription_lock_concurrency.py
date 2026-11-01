"""Renewal preparation reads current mandates after a real PostgreSQL lock wait."""

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Event
from time import monotonic
from unittest import skipUnless
from unittest.mock import patch
from uuid import uuid4

from django.core.cache import cache
from django.db import close_old_connections, connection, connections, transaction
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from apps.billing.currency_policy import get_selling_currency_policy
from apps.billing.recurring_authorization_service import RecurringPaymentAuthorizationService
from apps.billing.recurring_billing import RecurringBillingOrchestrator
from apps.billing.recurring_models import RecurringPaymentAuthorization
from apps.billing.subscription_models import Subscription
from apps.customers.models import CustomerPaymentMethod
from apps.provisioning.models import Service
from apps.users.models import CustomerMembership, User
from tests.billing.test_subscription_invoice_payments import _SubscriptionInvoicePaymentFixture


@skipUnless(connection.vendor == "postgresql", "PostgreSQL row-lock visibility is required")
@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
)
class RenewalSubscriptionLockConcurrencyTests(_SubscriptionInvoicePaymentFixture, TransactionTestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.enterContext(patch("django_q.tasks.async_task"))
        super().setUp()
        self.billing_cycle.delete()
        self.at = timezone.now()
        # Deliberately misaligned: preparing the due renewal must save the
        # subscription schedule and validate the newly selected mandate.
        Subscription.objects.filter(pk=self.subscription.pk).update(
            next_proforma_at=self.at - timedelta(days=20),
            next_charge_at=self.at,
        )
        self.owner = User.objects.create_user(email=f"renewal-lock-{uuid4().hex}@example.test")
        CustomerMembership.objects.create(customer=self.customer, user=self.owner, role="owner", is_primary=True)
        get_selling_currency_policy()  # Publish settings before either competing transaction.

    def _change_auto_payment(self, authorization: RecurringPaymentAuthorization | None) -> None:
        changed = RecurringPaymentAuthorizationService.set_subscription_auto_payment(
            subscription=Subscription.objects.get(pk=self.subscription.pk),
            authorization=authorization,
            enabled=authorization is not None,
            actor=self.owner,
        )
        self.assertTrue(changed.is_ok(), changed)

    def _wait_for_subscription(self, pid: int, owner_pid: int, pending) -> None:
        deadline, poll = monotonic() + 10, Event()
        while monotonic() < deadline:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_stat_clear_snapshot()")
                cursor.execute(
                    "SELECT wait_event_type, pg_blocking_pids(pid), query FROM pg_stat_activity WHERE pid = %s", [pid]
                )
                row = cursor.fetchone()
            if row and owner_pid in row[1]:
                self.assertEqual(row[0], "Lock")
                # PostgreSQL bounds pg_stat_activity query text; the full eager
                # SELECT can exceed it before the trailing FOR UPDATE clause.
                self.assertIn('"billing_subscriptions"', row[2])
                return
            if pending.done():
                self.fail(f"Renewal completed without reaching the subscription lock: {pending.result()}")
            poll.wait(0.01)
        self.fail("Renewal preparation did not wait for the subscription writer")

    def _prepare_after(self, writer: Callable[[], None]):
        ready, start = Event(), Event()
        worker_pids: list[int] = []

        def prepare():
            close_old_connections()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SET lock_timeout = '15s'")
                    cursor.execute("SET statement_timeout = '20s'")
                    cursor.execute("SELECT pg_backend_pid()")
                    worker_pids.append(cursor.fetchone()[0])
                ready.set()
                if not start.wait(10):
                    raise AssertionError("Subscription writer never reached its update")
                return RecurringBillingOrchestrator.prepare_due_proformas(as_of=self.at)
            finally:
                connections.close_all()

        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_backend_pid()")
            owner_pid = cursor.fetchone()[0]
        waited = False
        with ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(prepare)
            self.assertTrue(ready.wait(10), "Renewal connection did not start")

            def observe_write(execute, sql, params, many, context):
                nonlocal waited
                result = execute(sql, params, many, context)
                if not waited and sql.startswith('UPDATE "billing_subscriptions"'):
                    waited = True
                    start.set()
                    self._wait_for_subscription(worker_pids[0], owner_pid, pending)
                return result

            try:
                with transaction.atomic(), connection.execute_wrapper(observe_write):
                    writer()
            finally:
                start.set()
            self.assertTrue(waited, "Writer never updated its locked subscription")
            return pending.result(timeout=25)

    def _assert_prepared(self, result, *, automatic: bool) -> None:
        self.assertEqual(result["errors"], [], result)
        self.assertEqual(
            (result["subscriptions_checked"], result["cycles_prepared"], result["proformas_created"]), (1, 1, 1)
        )
        cycle = self.subscription.billing_cycles.get(proforma__isnull=False)
        self.assertEqual(cycle.collection_status, "prepared")
        self.assertEqual(cycle.proforma.meta["collection_mode"], "automatic" if automatic else "manual")
        self.subscription.refresh_from_db()
        self.assertEqual(self.subscription.next_billing_date, self.subscription.next_proforma_at)

    def test_enabling_auto_payment_while_renewal_waits_preserves_the_new_mandate(self) -> None:
        Subscription.objects.filter(pk=self.subscription.pk).update(
            auto_payment_enabled=False,
            saved_payment_method=None,
            payment_authorization=None,
        )
        result = self._prepare_after(lambda: self._change_auto_payment(self.authorization))
        self._assert_prepared(result, automatic=True)
        self.assertEqual(self.subscription.saved_payment_method_id, self.payment_method.pk)
        self.assertEqual(self.subscription.payment_authorization_id, self.authorization.pk)

    def test_retargeted_mandate_and_customer_edit_are_reloaded_after_the_wait(self) -> None:
        method = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type="stripe_card",
            stripe_customer_id="cus_replacement",
            stripe_payment_method_id="pm_replacement",
            display_name="Replacement card",
            is_active=True,
        )
        authorization = RecurringPaymentAuthorization.objects.create(
            customer=self.customer,
            payment_method=method,
            status="active",
            setup_intent_id="seti_replacement",
            terms_version=self.authorization.terms_version,
            terms_text=self.authorization.terms_text,
            terms_text_hash=self.authorization.terms_text_hash,
            granted_by_role="owner",
            granted_at=self.at,
        )

        def switch_and_edit():
            self._change_auto_payment(authorization)
            type(self.customer).objects.filter(pk=self.customer.pk).update(company_name="Current billing name SRL")

        result = self._prepare_after(switch_and_edit)
        self._assert_prepared(result, automatic=True)
        self.assertEqual(self.subscription.saved_payment_method_id, method.pk)
        self.assertEqual(self.subscription.payment_authorization_id, authorization.pk)
        cycle = self.subscription.billing_cycles.get(proforma__isnull=False)
        self.assertEqual(cycle.proforma.bill_to_name, "Current billing name SRL")

    def test_disabling_auto_payment_while_renewal_waits_keeps_manual_collection(self) -> None:
        result = self._prepare_after(lambda: self._change_auto_payment(None))
        self._assert_prepared(result, automatic=False)
        self.assertIsNone(self.subscription.saved_payment_method_id)
        self.assertIsNone(self.subscription.payment_authorization_id)

    def test_service_opt_out_while_renewal_waits_is_rechecked_before_preparation(self) -> None:
        def opt_out():
            self._change_auto_payment(self.authorization)
            Service.objects.filter(pk=self.service.pk).update(auto_renew=False)

        result = self._prepare_after(opt_out)
        self.assertEqual(result["errors"], [], result)
        self.assertEqual(
            (result["subscriptions_checked"], result["cycles_prepared"], result["proformas_created"]), (0, 0, 0)
        )
        self.assertFalse(self.subscription.billing_cycles.filter(proforma__isnull=False).exists())
