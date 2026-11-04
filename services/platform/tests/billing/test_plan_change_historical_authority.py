"""Historical paid authority survives legitimate later billing terms, never disputed funds."""

from datetime import timedelta
from decimal import Decimal
from unittest.mock import patch

from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from apps.billing.currency_transitions import activate_due_currency_terms, prepare_currency_offer, send_currency_notice
from apps.billing.models import Currency, FXRate
from apps.billing.plan_change_operations import reconcile_plan_change_operation
from apps.billing.proforma_service import ProformaPaymentService
from apps.billing.recurring_billing import RecurringBillingOrchestrator, fixed_renewal_schedule
from apps.products.models import ProductPrice
from apps.provisioning.models import ServicePlan, ServicePlanPrice
from apps.settings.services import SettingsService
from tests.billing.test_plan_change_native_gate import StripeCoverageFixture
from tests.billing.test_plan_change_operations import PlanOperationFixture
from tests.provisioning.test_hosting_limit_execution import HostingLimitWorkerFixture
from tests.provisioning.test_managed_single_restore_limits import ManagedSingleRestoreFixture


class HistoricalAuthorityRestoreFixture(ManagedSingleRestoreFixture, StripeCoverageFixture):
    def setUp(self):
        ManagedSingleRestoreFixture.setUp(self)
        self.setup_commercial_fixture()

    @property
    def native_identity(self):
        return self.identity

    def receipt(self, cap=1024, request=None, available=100 * 1024**3):
        return HostingLimitWorkerFixture.receipt(self, cap=cap, request=request, available=available)

    def fresh_receipt(self, cap, request=None):
        receipt = {
            **self.receipt(cap, request),
            "observation": {
                "files_bytes": 1024**2,
                "database_bytes": 1024**2,
                "total_bytes": 2 * 1024**2,
            },
        }
        if request:
            receipt["configured_bandwidth_bytes"] = request["bandwidth_limit_bytes"]
        return receipt

    def completed_change(self):
        change = PlanOperationFixture.paid_change(self)
        PlanOperationFixture.apply(self, change)
        self.assertEqual(reconcile_plan_change_operation(change.pk).status, "completed")
        return change

    def change_currency_through_notified_renewals(self):
        Currency.objects.get_or_create(code="EUR", defaults={"symbol": "EUR"})
        FXRate.objects.create(
            base_code_id="EUR",
            quote_code_id="RON",
            rate=Decimal("5"),
            as_of=timezone.localdate(),
            source=FXRate.Source.BNR,
            source_reference="historical-authority-regression",
            fetched_at=timezone.now(),
        )
        for product, amount in ((self.product, 1600), (self.target, 4000)):
            ProductPrice.objects.create(product=product, currency_id="EUR", monthly_price_cents=amount)
        for plan in ServicePlan.objects.all():
            ServicePlanPrice.objects.create(service_plan=plan, currency_id="EUR", monthly_price_cents=4000)
        self.assertTrue(SettingsService.update_setting("billing.default_currency", "EUR").is_ok())
        self.subscription.refresh_from_db()
        self.subscription.next_proforma_at, self.subscription.next_charge_at = fixed_renewal_schedule(
            self.subscription.current_period_end
        )
        self.subscription.next_billing_date = self.subscription.next_proforma_at
        self.subscription.save(update_fields=["next_proforma_at", "next_charge_at", "next_billing_date"])
        offer = prepare_currency_offer(self.subscription.pk)
        self.assertIsNotNone(offer)
        self.assertEqual(offer.hold_reason, "")
        self.assertTrue(send_currency_notice(offer.pk))
        for expected in ("RON", "EUR"):
            self.subscription.refresh_from_db()
            prepare_at, _charge_at = fixed_renewal_schedule(self.subscription.current_period_end)
            with patch("django.utils.timezone.now", return_value=prepare_at):
                prepared = RecurringBillingOrchestrator.prepare_due_proformas(as_of=prepare_at)
                self.assertEqual(prepared["proformas_created"], 1, prepared)
                cycle = self.subscription.billing_cycles.get(period_start=self.subscription.current_period_end)
                self.assertEqual(cycle.currency_id, expected)
                paid = ProformaPaymentService.record_payment_and_convert(
                    str(cycle.proforma_id), cycle.proforma.total_cents, "bank"
                )
                self.assertTrue(paid.is_ok(), paid)
        self.assertEqual(activate_due_currency_terms(as_of=cycle.period_start), 1)
        self.subscription.refresh_from_db()
        self.service.refresh_from_db()
        self.assertEqual((self.subscription.currency_id, self.service.currency_id), ("EUR", "EUR"))
        return cycle.period_start + timedelta(minutes=1)


@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
class HistoricalAuthorityRestoreTests(HistoricalAuthorityRestoreFixture, TransactionTestCase):
    def test_visible_dispute_before_a_new_public_restore_never_issues_the_archive_writer(self):
        self.completed_change()
        self.dispute("pi_original_paid_coverage", amount=8000)
        job, outcome = self.execute_restore()
        self.assertNotEqual(outcome["status"], "completed", (outcome, job.status))
        self.assertEqual(self.node_variables, [], "A visible dispute must refuse before destructive restore issuance")

    def test_legitimate_later_currency_transition_does_not_revoke_the_existing_native_restore_authority(self):
        change = self.completed_change()
        restore_at = self.change_currency_through_notified_renewals()
        with patch("django.utils.timezone.now", return_value=restore_at):
            job, outcome = self.execute_restore()
        self.assertEqual(outcome["status"], "completed", (outcome, job.status))
        self.assertEqual(len(self.node_variables), 1)
        self.assertEqual(self.quota_requests[0]["disk_limit_kib"], 22528 * 1024)
        change.refresh_from_db()
        self.assertEqual(change.currency_id, "RON")
        self.assertEqual(self.service.currency_id, "EUR")
