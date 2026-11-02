"""Public recurring operations preserve batched mandate reads and one Cycle lock order."""

from datetime import timedelta
from unittest import skipUnless
from unittest.mock import patch

from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from apps.billing.gateways.base import PaymentIntentResult
from apps.billing.metering_models import BillingCycle
from apps.billing.models import Invoice, Payment
from apps.billing.payment_convergence import PaymentSuccessService
from apps.billing.recurring_billing import RecurringBillingOrchestrator
from apps.billing.recurring_models import RecurringPaymentAuthorization
from apps.billing.subscription_models import Subscription
from apps.customers.models import CustomerPaymentMethod
from tests.billing.test_subscription_invoice_payments import _SubscriptionInvoicePaymentFixture


@skipUnless(connection.vendor == "postgresql", "Requires PostgreSQL generated locking SQL")
class RecurringLockBatchTests(_SubscriptionInvoicePaymentFixture, TestCase):
    def test_public_entitlement_validation_keeps_mandates_batched_and_bank_details_deferred(self) -> None:
        second = self._create_aligned_subscription("BATCH", timezone.now())
        invoice = Invoice.objects.create(customer=self.customer, currency=self.currency,
            number="INV-BATCHED-LOCKS", subtotal_cents=20000, tax_cents=4200, total_cents=24200)
        invoice.issue()
        invoice.save()
        BillingCycle.objects.filter(pk=self.billing_cycle.pk).update(invoice=invoice)
        other_cycle = BillingCycle.objects.create(subscription=second, invoice=invoice, status="upcoming",
            collection_status="scheduled", period_start=self.billing_cycle.period_start,
            period_end=self.billing_cycle.period_end, base_charge_cents=10000, tax_cents=2100, total_cents=12100)
        payment = Payment.objects.create(customer=self.customer, currency=self.currency, invoice=invoice,
            amount_cents=24200, payment_method="stripe", gateway_txn_id="pi_batched_mandates")
        with CaptureQueriesContext(connection) as captured:
            result = PaymentSuccessService.converge_gateway_success(payment.gateway_txn_id, {
                "amount_received": 24200, "currency": "ron", "customer_id": self.payment_method.stripe_customer_id,
                "payment_method_id": self.payment_method.stripe_payment_method_id,
            })
        self.assertTrue(result.is_ok(), result)
        for subscription in (self.subscription, second):
            subscription.refresh_from_db()
            self.assertEqual(subscription.current_period_end, other_cycle.period_end)
        standalone = [row["sql"] for row in captured if any(
            f'FROM "{model._meta.db_table}"' in row["sql"] for model in (CustomerPaymentMethod, RecurringPaymentAuthorization)
        )]
        self.assertEqual(standalone, [], "save()/clean() must use the freshly batched related rows")
        mandate_loads = [row["sql"] for row in captured if f'FROM "{Subscription._meta.db_table}"' in row["sql"]
                        and f'JOIN "{CustomerPaymentMethod._meta.db_table}"' in row["sql"]]
        self.assertEqual(len(mandate_loads), 1)
        self.assertNotIn('"bank_details"', mandate_loads[0])

    def test_both_public_collection_phases_acquire_cycles_in_pk_order(self) -> None:
        now = timezone.now()
        self._create_aligned_subscription("LOCKONE", now)
        self._create_aligned_subscription("LOCKTWO", now)
        prepared = RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)
        self.assertEqual(prepared["proformas_created"], 1, prepared)
        with patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway") as gateway, CaptureQueriesContext(connection) as captured:
            gateway.return_value.create_off_session_payment_intent.return_value = PaymentIntentResult(
                success=True, payment_intent_id="pi_collection_order", client_secret=None, error=None,
            )
            collected = RecurringBillingOrchestrator.collect_due_proformas(as_of=now + timedelta(days=8))
        self.assertEqual(collected["payments_created"], 1, collected)
        locks = [row["sql"] for row in captured if f'FROM "{BillingCycle._meta.db_table}"' in row["sql"]
                 and "FOR UPDATE" in row["sql"]]
        self.assertEqual(len(locks), 2, locks)
        for sql in locks:
            self.assertIn('ORDER BY 1 ASC FOR UPDATE OF "billing_cycles"', sql)
