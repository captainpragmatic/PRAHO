"""Renewal documents use notified future terms while current service terms remain stable."""

from datetime import timedelta
from decimal import Decimal

from django.test import TestCase
from django.utils import timezone

from apps.billing.models import BillingCycle, Currency, FXRate
from apps.billing.recurring_billing import RecurringBillingOrchestrator, fixed_renewal_schedule
from apps.common.types import Ok
from apps.notifications.models import EmailLog
from apps.products.models import ProductPrice
from apps.provisioning.models import ServicePlanPrice
from apps.settings.services import SettingsService
from tests.billing.test_subscription_invoice_payments import _SubscriptionInvoicePaymentFixture


class _CurrencyRenewalWorkflowFixture(_SubscriptionInvoicePaymentFixture):
    def setUp(self):
        super().setUp()
        self.billing_cycle.delete()
        self.now = timezone.now()
        self.subscription.current_period_start = self.now
        self.subscription.current_period_end = self.now + timedelta(days=90)
        self.subscription.next_proforma_at, self.subscription.next_charge_at = fixed_renewal_schedule(
            self.subscription.current_period_end,
        )
        self.subscription.next_billing_date = self.subscription.next_proforma_at
        self.subscription.save()
        self.current_cycle = BillingCycle.objects.create(
            subscription=self.subscription, period_start=self.subscription.current_period_start,
            period_end=self.subscription.current_period_end, status="active",
        )
        for code, amount in (("RON", 10000), ("EUR", 2200), ("USD", 2500)):
            Currency.objects.get_or_create(code=code, defaults={"symbol": code})
            ProductPrice.objects.create(product=self.product, currency_id=code, monthly_price_cents=amount)
            if code != "RON":
                ServicePlanPrice.objects.create(service_plan=self.service_plan, currency_id=code, monthly_price_cents=amount)
                FXRate.objects.create(
                    base_code_id=code, quote_code_id="RON", rate=Decimal("5"), as_of=timezone.localdate(),
                    source=FXRate.Source.BNR, source_reference="renewal-workflow-test", fetched_at=self.now,
                )
        self.assertIsInstance(SettingsService.update_setting("billing.default_currency", "EUR"), Ok)

    def offer(self, *, accepted_days=None):
        from apps.billing.currency_transitions import prepare_currency_offer  # noqa: PLC0415

        offer = prepare_currency_offer(self.subscription.pk)
        self.assertIsNotNone(offer)
        if accepted_days is not None:
            log = EmailLog.objects.create(
                customer=self.customer, to_addr=offer.notice_recipient, subject=offer.notice_subject,
                body_text=offer.notice_body, body_encrypted=False, status="sent",
            )
            accepted_at = self.subscription.next_proforma_at - timedelta(days=accepted_days)
            EmailLog.objects.filter(pk=log.pk).update(sent_at=accepted_at)
            log.refresh_from_db()
            offer.notice_email = log
            offer.accept_notice()
            offer.save()
        return offer

    def prepare(self):
        result = RecurringBillingOrchestrator.prepare_due_proformas(as_of=self.subscription.next_proforma_at)
        self.assertEqual(result["errors"], [], result)
        self.assertEqual(result["cycles_prepared"], 1, result)
        return self.subscription.billing_cycles.get(proforma__isnull=False)


class CurrencyRenewalWorkflowTests(_CurrencyRenewalWorkflowFixture, TestCase):
    def test_pending_notice_keeps_original_currency_and_price(self):
        self.offer()
        cycle = self.prepare()
        self.assertEqual((cycle.proforma.currency_id, cycle.unit_price_cents), ("RON", 10000))

    def test_less_than_thirty_days_keeps_original_terms(self):
        self.offer(accepted_days=29)
        cycle = self.prepare()
        self.assertEqual((cycle.proforma.currency_id, cycle.unit_price_cents), ("RON", 10000))

    def test_thirty_days_uses_exact_offer_and_keeps_current_service_terms(self):
        offer = self.offer(accepted_days=30)
        cycle = self.prepare()
        self.assertEqual((cycle.proforma.currency_id, cycle.unit_price_cents, cycle.quantity), ("EUR", 2200, 1))
        self.assertEqual(cycle.proforma.lines.get().unit_price_cents, 2200)
        self.assertEqual(cycle.proforma.meta["collection_mode"], "automatic")
        self.subscription.refresh_from_db()
        self.service.refresh_from_db()
        self.assertEqual((self.subscription.currency_id, self.subscription.unit_price_cents), ("RON", 10000))
        self.assertEqual((self.service.currency_id, self.service.price), ("RON", Decimal("100")))
        offer.refresh_from_db()
        self.assertEqual(offer.status, "committed")
        self.assertEqual(offer.committed_cycle_id, cycle.pk)

    def test_target_price_change_requires_new_notice(self):
        old = self.offer(accepted_days=31)
        ProductPrice.objects.filter(product=self.product, currency_id="EUR").update(monthly_price_cents=2300)
        new = self.offer()
        self.assertNotEqual(new.pk, old.pk)
        old.refresh_from_db()
        self.assertEqual(old.status, "superseded")
        self.assertEqual(self.prepare().proforma.currency_id, "RON")

    def test_indefinite_zero_price_guarantee_keeps_original_currency(self):
        self.subscription.locked_price_cents = 0
        self.subscription.locked_price_expires_at = None
        self.subscription.save(update_fields=["locked_price_cents", "locked_price_expires_at"])
        offer = self.offer()
        self.assertTrue(offer.hold_reason)
        self.assertEqual(self.prepare().proforma.currency_id, "RON")

    def test_changed_policy_revision_invalidates_an_uncommitted_notice(self):
        self.offer(accepted_days=31)
        self.assertIsInstance(SettingsService.update_setting("billing.default_currency", "USD"), Ok)
        self.assertEqual(self.prepare().proforma.currency_id, "RON")
