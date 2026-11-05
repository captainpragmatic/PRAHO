"""Expired original-currency coverage must not prevent a new current-currency quote."""

from copy import copy, deepcopy
from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.db import transaction
from django.test import TransactionTestCase, override_settings

from apps.billing.currency_policy import get_selling_currency_policy
from apps.billing.plan_change_coverage import _apply_supplement_coverage
from apps.billing.plan_change_lifecycle import activate_scheduled_plan_change
from apps.billing.plan_change_operations import reconcile_plan_change_operation
from apps.billing.plan_change_quote_service import plan_change_options, quote_plan_change
from apps.billing.plan_change_safety import current_safety_used_bytes
from apps.billing.proforma_service import ProformaPaymentService
from apps.billing.recurring_billing import RecurringBillingOrchestrator
from apps.products.models import ProductPrice
from apps.provisioning.hosting_limit_models import ServiceHostingLimits
from tests.billing import test_plan_change_historical_authority as historical_authority
from tests.billing import test_plan_change_lifecycle as lifecycle_cases
from tests.billing.test_plan_change_native_gate import StripeCoverageFixture
from tests.billing.test_plan_change_operations import PlanOperationFixture
from tests.provisioning.test_hosting_safety_observation import HostingSafetyObservationFixture


@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
class PlanChangeCurrencyFollowupTests(StripeCoverageFixture, TransactionTestCase):
    period_remaining = timedelta(days=15)
    completed_change = historical_authority.HistoricalAuthorityRestoreTests.completed_change
    change_currency_through_notified_renewals = (
        historical_authority.HistoricalAuthorityRestoreTests.change_currency_through_notified_renewals
    )
    safety_request = HostingSafetyObservationFixture.request
    run_observer = HostingSafetyObservationFixture.run_observer
    probe = HostingSafetyObservationFixture.probe
    scheduled = lifecycle_cases.ScheduledPlanChangeTests.scheduled

    def setUp(self):
        super().setUp()
        with transaction.atomic():
            get_selling_currency_policy(lock=True)

    def fresh_safety(self):
        self.publish_usage(1, 1)
        self.account.refresh_from_db()
        limits = ServiceHostingLimits.objects.get(service=self.service)
        job = self.safety_request()
        probe = self.receipt(cap=self.account.effective_disk_quota_mb)
        probe.pop("observation")
        probe["configured_bandwidth_bytes"] = limits.operational_bandwidth_allowance_mib * 1024**2
        self.assertEqual(self.run_observer(job, probe=probe), ("completed", 1))
        self.assertEqual(current_safety_used_bytes(self.service), 2 * 1024**2)

    def options_and_quote(self, at):
        options = plan_change_options(self.service.pk, customer_id=self.customer.pk, actor_id=self.actor.pk, at=at)
        target = next(option for option in options if option["product_id"] == str(self.product.pk))
        self.assertTrue(target["available"], target)
        self.assertEqual(target["currency"], "EUR")
        return quote_plan_change(
            self.service.pk,
            customer_id=self.customer.pk,
            actor_id=self.actor.pk,
            target_product_id=self.product.pk,
            submission_id=uuid4(),
            expected_limit_revision=ServiceHostingLimits.objects.get(service=self.service).revision,
            at=at,
        )

    def test_real_paid_change_then_notified_currency_activation_allows_new_eur_options_and_quote(self):
        original = self.completed_change()
        original_invoice = original.invoice
        frozen = (
            original.currency_id,
            original_invoice.currency_id,
            original_invoice.subtotal_cents,
            original_invoice.tax_cents,
            original_invoice.total_cents,
        )
        at = self.change_currency_through_notified_renewals()
        with patch("django.utils.timezone.now", return_value=at):
            self.fresh_safety()
            quote = self.options_and_quote(at)
        self.assertEqual(
            (quote.currency_id, quote.direction, quote.target_period_price_cents), ("EUR", "downgrade", 1600)
        )
        self.assertTrue(all(source["currency"] == "EUR" for source in quote.quote_snapshot["coverage"].values()))
        original.refresh_from_db()
        original_invoice.refresh_from_db()
        self.assertEqual(
            (
                original.currency_id,
                original_invoice.currency_id,
                original_invoice.subtotal_cents,
                original_invoice.tax_cents,
                original_invoice.total_cents,
            ),
            frozen,
        )

    def test_real_scheduled_boundary_then_notified_eur_activation_allows_a_later_upgrade_quote(self):
        scheduled = self.scheduled()
        with patch("django.utils.timezone.now", return_value=scheduled.effective_at):
            scheduled = activate_scheduled_plan_change(scheduled.pk)
            self.assertEqual(scheduled.status, "applying_limits")
            PlanOperationFixture.apply(self, scheduled)
            self.assertEqual(reconcile_plan_change_operation(scheduled.pk).status, "completed")
            prepared = RecurringBillingOrchestrator.prepare_due_proformas(as_of=scheduled.effective_at)
            self.assertEqual(prepared["proformas_created"], 1, prepared)
            cycle = self.subscription.billing_cycles.get(period_start=scheduled.effective_at)
            self.assertEqual(cycle.unit_price_cents, 4000)
            paid = ProformaPaymentService.record_payment_and_convert(
                str(cycle.proforma_id), cycle.proforma.total_cents, "bank"
            )
            self.assertTrue(paid.is_ok(), paid)
            at = self.change_currency_through_notified_renewals()
        self.assertFalse(scheduled.intervals.exists())
        self.assertIsNone(scheduled.invoice_id)
        self.assertIsNone(scheduled.proforma_id)
        ProductPrice.objects.filter(product=self.product, currency_id="EUR").update(monthly_price_cents=8000)
        with patch("django.utils.timezone.now", return_value=at):
            self.fresh_safety()
            quote = self.options_and_quote(at)
        self.assertEqual(
            (quote.currency_id, quote.direction, quote.target_period_price_cents), ("EUR", "upgrade", 8000)
        )
        self.assertGreater(quote.total_cents, 0)
        self.assertEqual(scheduled.target_period_price_cents, 4000)

    def test_intersecting_currency_mismatch_and_malformed_past_allocations_still_require_review(self):
        original = self.completed_change()
        parts = list(original.intervals.all())
        self.assertEqual(len(parts), 1)
        source = next(iter(original.quote_snapshot["coverage"].values()))
        start, end = parts[0].period_end + timedelta(days=60), parts[0].period_end + timedelta(days=90)
        current_id = str(uuid4())
        values = {current_id: (4000, True, {"period_start": start.isoformat(), "period_end": end.isoformat()})}
        subscription = copy(self.subscription)
        subscription.currency_id = "EUR"
        cases = []

        def candidate():
            row = copy(original)
            row.quote_snapshot = deepcopy(original.quote_snapshot)
            row._prefetched_objects_cache = {"intervals": [copy(part) for part in parts]}
            return row

        missing = candidate()
        missing._prefetched_objects_cache["intervals"] = []
        cases.append(("missing allocations", missing, values))
        current = candidate()
        current._prefetched_objects_cache["intervals"][0].evidence = {**source, "cycle_id": current_id}
        cases.append(("allocation refers to selected cycle", current, values))
        wrong_sum = candidate()
        wrong_sum._prefetched_objects_cache["intervals"][0].net_cents += 1
        cases.append(("net sum mismatch", wrong_sum, values))
        malformed = candidate()
        key = next(iter(malformed.quote_snapshot["coverage"]))
        malformed.quote_snapshot["coverage"][key]["period_end"] = "invalid"
        malformed._prefetched_objects_cache["intervals"][0].evidence = malformed.quote_snapshot["coverage"][key]
        cases.append(("invalid window", malformed, values))
        overlapping = candidate()
        other_id = str(uuid4())
        duplicate = copy(parts[0])
        duplicate.net_cents = 0
        duplicate.evidence = {**source, "cycle_id": other_id}
        overlapping.quote_snapshot["coverage"][other_id] = duplicate.evidence
        overlapping._prefetched_objects_cache["intervals"].append(duplicate)
        cases.append(("overlapping allocation windows", overlapping, values))
        future = candidate()
        future.effective_at = start + timedelta(days=1)
        cases.append(("future agreement", future, values))
        uncommitted = candidate()
        uncommitted.committed_at = None
        cases.append(("uncommitted agreement", uncommitted, values))
        document = candidate()
        document.invoice = copy(original.invoice)
        document.invoice.currency_id = "EUR"
        cases.append(("original supplement document mismatch", document, values))
        cases.extend(self.invalid_scheduled_history(candidate, values))
        cases.append(
            (
                "intersecting original coverage",
                candidate(),
                {str(parts[0].evidence["cycle_id"]): (source["base_net_cents"], True, source)},
            )
        )
        for label, row, selected in cases:
            with self.subTest(label=label), self.assertRaises(ValidationError):
                _apply_supplement_coverage(subscription, selected, next(iter(selected)), 4000, start, changes=[row])

    def invalid_scheduled_history(self, candidate, values):
        document = candidate()
        document.direction = "downgrade"
        document.net_cents = document.tax_cents = document.total_cents = 0
        document._prefetched_objects_cache["intervals"] = []
        amount = candidate()
        amount.direction = "downgrade"
        amount.invoice = amount.proforma = None
        amount._prefetched_objects_cache["intervals"] = []
        return [
            ("document-bearing scheduled agreement", document, values),
            ("nonzero scheduled agreement", amount, values),
        ]
