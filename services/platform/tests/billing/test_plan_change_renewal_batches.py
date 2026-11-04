"""New commercial checks must not add reads for every ordinary renewal."""

from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from apps.billing.models import BillingCycle
from apps.billing.recurring_billing import RecurringBillingOrchestrator
from tests.billing.test_subscription_invoice_payments import _SubscriptionInvoicePaymentFixture


class PlanChangeRenewalBatchTests(_SubscriptionInvoicePaymentFixture, TestCase):
    def assert_preparation_reads_commercial_state_once(self, count: int) -> None:
        now = timezone.now()
        subscriptions = [self._create_aligned_subscription(f"TERMS{index}", now) for index in range(count)]
        with CaptureQueriesContext(connection) as captured:
            prepared = RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)
        self.assertEqual(prepared["errors"], [])
        self.assertEqual(prepared["cycles_prepared"], count)
        cycles = list(BillingCycle.objects.filter(subscription_id__in=[row.pk for row in subscriptions]))
        self.assertEqual(len(cycles), count)
        for cycle in cycles:
            self.assertEqual(cycle.proforma.lines.get(billing_cycle=cycle).unit_price_cents, 10000)
        reads = [row["sql"] for row in captured if row["sql"].lstrip().startswith("SELECT")]
        accepted = [sql for sql in reads if 'FROM "billing_plan_changes"' in sql]
        attempts = [sql for sql in reads if 'FROM "billing_plan_change_payment_attempts"' in sql]
        self.assertEqual(len(accepted), 1, accepted)
        self.assertEqual(attempts, [], "The one commercial batch must include charge holds without per-row queries")
        self.assertIn('JOIN "billing_plan_change_payment_attempts"', accepted[0])

    def test_one_real_renewal_reads_accepted_terms_and_charge_holds_once(self) -> None:
        self.assert_preparation_reads_commercial_state_once(1)

    def test_five_real_renewals_use_the_same_fixed_commercial_read_count(self) -> None:
        self.assert_preparation_reads_commercial_state_once(5)
