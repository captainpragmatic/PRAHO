"""Currency renewal commitments use accepted notices and actual period boundaries."""

from datetime import timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch

from django.core import mail
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.db import transaction
from django.test import TestCase, override_settings

from apps.billing.models import BillingCycle
from apps.billing.payment_models import Payment
from apps.billing.payment_service import PaymentService
from apps.billing.proforma_service import ProformaPaymentService
from apps.billing.recurring_billing import RecurringBillingOrchestrator
from apps.billing.subscription_currency_models import SubscriptionCurrencyTransition
from apps.billing.subscription_models import PriceGrandfathering, SubscriptionItem
from apps.common.types import Ok
from apps.notifications.models import EmailLog
from apps.orders.models import Order, OrderItem
from apps.products.models import ProductPrice
from apps.promotions.models import Coupon, PromotionApplication, RenewalBenefit, RenewalBenefitUse
from apps.settings.services import SettingsService
from tests.billing.test_currency_renewal_workflow import _CurrencyRenewalWorkflowFixture
from tests.billing.test_subscription_invoice_payments import _intent_result


@override_settings(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class SubscriptionCurrencyTransitionTests(_CurrencyRenewalWorkflowFixture, TestCase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)

    def pay(self, cycle: BillingCycle, at):
        with patch("django.utils.timezone.now", return_value=at):
            result = ProformaPaymentService.record_payment_and_convert(
                str(cycle.proforma_id), cycle.proforma.total_cents, "bank", reference="Local currency QA"
            )
        self.assertTrue(result.is_ok(), result)
        cycle.refresh_from_db()
        return cycle.invoice.payments.get()

    def test_actual_notice_acceptance_is_idempotent_and_starts_clock_at_send(self) -> None:
        from apps.billing.currency_transitions import send_currency_notice  # noqa: PLC0415

        offer = self.offer()
        with patch("django.utils.timezone.now", return_value=self.now):
            self.assertTrue(send_currency_notice(offer.pk))
        stored = SubscriptionCurrencyTransition.objects.get(pk=offer.pk)
        self.assertEqual(stored.status, "notified")
        self.assertEqual(stored.notice_accepted_at, self.now)
        self.assertEqual(stored.preparation_not_before, self.now + timedelta(days=30))
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].body, offer.notice_body)
        self.assertFalse(send_currency_notice(offer.pk))
        self.assertEqual(len(mail.outbox), 1)

    def test_failed_notice_keeps_old_terms_and_can_retry_after_claim_expires(self) -> None:
        from apps.billing.currency_transitions import send_currency_notice  # noqa: PLC0415

        offer = self.offer()
        with patch("django.core.mail.EmailMessage.send", side_effect=OSError("Local SMTP failure")):
            self.assertFalse(send_currency_notice(offer.pk, as_of=self.now))
        stored = SubscriptionCurrencyTransition.objects.get(pk=offer.pk)
        self.assertIsNone(stored.notice_accepted_at)
        self.assertEqual(stored.notice_email.status, "failed")
        self.assertEqual(self.prepare().currency_id, "RON")
        self.assertFalse(send_currency_notice(offer.pk, as_of=self.now + timedelta(minutes=1)))
        self.assertTrue(send_currency_notice(offer.pk, as_of=self.now + timedelta(hours=1)))

    def test_repair_recovers_accepted_log_after_interrupted_link_without_resending(self) -> None:
        from apps.billing.currency_transitions import send_currency_notice  # noqa: PLC0415

        offer = self.offer()
        accepted = EmailLog.objects.create(
            customer=self.customer, to_addr=offer.notice_recipient, subject=offer.notice_subject,
            body_text=offer.notice_body, body_encrypted=False, status="sent",
            template_key=f"subscription_currency_notice:{offer.pk}",
        )
        self.assertTrue(send_currency_notice(offer.pk))
        stored = SubscriptionCurrencyTransition.objects.get(pk=offer.pk)
        self.assertEqual(stored.notice_email_id, accepted.pk)
        self.assertEqual(stored.notice_accepted_at, accepted.sent_at)
        self.assertEqual(len(getattr(mail, "outbox", [])), 0)

    def test_recovered_email_with_different_body_cannot_start_the_notice_period(self) -> None:
        from apps.billing.currency_transitions import send_currency_notice  # noqa: PLC0415

        offer = self.offer()
        EmailLog.objects.create(
            customer=self.customer, to_addr=offer.notice_recipient, subject=offer.notice_subject,
            body_text="Different monetary promise", body_encrypted=False, status="sent",
            template_key=f"subscription_currency_notice:{offer.pk}",
        )
        with self.assertRaisesMessage(ValidationError, "exact currency offer"):
            send_currency_notice(offer.pk)
        offer.refresh_from_db()
        self.assertEqual(offer.status, "pending")
        self.assertIsNone(offer.notice_accepted_at)
        self.assertEqual(self.prepare().currency_id, "RON")

    def test_changed_customer_recipient_requires_a_new_notice_without_sending_old_offer(self) -> None:
        from apps.billing.currency_transitions import send_currency_notice  # noqa: PLC0415

        old = self.offer()
        self.customer.primary_email = "new-recipient@example.test"
        self.customer.save(update_fields=["primary_email"])
        self.assertFalse(send_currency_notice(old.pk))
        old.refresh_from_db()
        self.assertEqual(old.status, "superseded")
        self.assertEqual(self.subscription.currency_transitions.get(status="pending").notice_recipient, self.customer.primary_email)
        self.assertEqual(len(getattr(mail, "outbox", [])), 0)

    def test_early_payment_preserves_current_terms_until_exact_boundary(self) -> None:
        from apps.billing.currency_transitions import activate_due_currency_terms  # noqa: PLC0415

        self.offer(accepted_days=30)
        cycle = self.prepare()
        payment = self.pay(cycle, cycle.period_start - timedelta(days=1))
        self.subscription.refresh_from_db()
        self.service.refresh_from_db()
        self.assertEqual(self.subscription.current_period_end, cycle.period_end)
        self.assertEqual((self.subscription.currency_id, self.service.currency_id), ("RON", "RON"))
        self.assertEqual((self.subscription.last_payment_currency_id, self.subscription.last_payment_id), ("EUR", payment.pk))
        self.assertEqual(activate_due_currency_terms(as_of=cycle.period_start - timedelta(microseconds=1)), 0)
        self.assertEqual(activate_due_currency_terms(as_of=cycle.period_start), 1)
        self.subscription.refresh_from_db()
        self.service.refresh_from_db()
        self.assertEqual((self.subscription.currency_id, self.subscription.unit_price_cents), ("EUR", 2200))
        self.assertEqual((self.service.currency_id, self.service.price), ("EUR", Decimal("22")))
        self.assertEqual(self.subscription.effective_terms_cycle_id, cycle.pk)
        self.assertEqual(activate_due_currency_terms(as_of=cycle.period_start), 0)
        cycle.refresh_from_db()
        self.assertEqual((cycle.currency_id, cycle.unit_price_cents), ("EUR", 2200))

    def test_multi_unit_renewal_preserves_per_unit_service_price(self) -> None:
        from apps.api.services.serializers import ServiceListSerializer  # noqa: PLC0415
        from apps.billing.currency_transitions import activate_due_currency_terms  # noqa: PLC0415

        self.subscription.quantity = 3
        self.subscription.save(update_fields=["quantity"])
        self.offer(accepted_days=30)
        cycle = self.prepare()
        self.assertEqual((cycle.unit_price_cents, cycle.quantity), (2200, 3))
        self.assertEqual(cycle.proforma.subtotal_cents, 6600)
        self.assertEqual(activate_due_currency_terms(as_of=cycle.period_start - timedelta(microseconds=1)), 0)
        self.service.refresh_from_db()
        self.assertEqual((self.service.currency_id, self.service.price), ("RON", Decimal("100")))

        self.assertEqual(activate_due_currency_terms(as_of=cycle.period_start), 1)

        self.subscription.refresh_from_db()
        self.service.refresh_from_db()
        self.assertEqual((self.subscription.currency_id, self.subscription.total_price_cents), ("EUR", 6600))
        self.assertEqual((self.service.currency_id, self.service.price), ("EUR", Decimal("22")))
        self.assertEqual(ServiceListSerializer(self.service).data["monthly_price"], Decimal("22"))
        self.assertEqual(activate_due_currency_terms(as_of=cycle.period_start), 0)
        cycle.refresh_from_db()
        self.assertEqual((cycle.currency_id, cycle.unit_price_cents, cycle.quantity), ("EUR", 2200, 3))
        self.assertEqual(cycle.proforma.subtotal_cents, 6600)

    def test_ineligible_service_cannot_commit_or_activate_a_notified_renewal(self) -> None:
        from apps.billing.currency_transitions import activate_due_currency_terms  # noqa: PLC0415
        from apps.provisioning.models import Service  # noqa: PLC0415

        offer = self.offer(accepted_days=30)
        for status in ("pending", "provisioning", "failed", "terminated", "expired"):
            with self.subTest(status=status):
                # Seed each eligibility case; this is not a service FSM transition.
                Service.objects.filter(pk=self.service.pk).update(status=status)
                result = RecurringBillingOrchestrator.prepare_due_proformas(as_of=self.subscription.next_proforma_at)
                self.assertEqual(result["errors"], [], result)
                self.assertEqual((result["subscriptions_checked"], result["cycles_prepared"]), (0, 0))
                self.assertFalse(self.subscription.billing_cycles.filter(proforma__isnull=False).exists())
                offer.refresh_from_db()
                self.assertEqual(offer.status, "notified")
                self.assertIsNone(offer.committed_cycle_id)
                self.assertEqual(activate_due_currency_terms(as_of=self.subscription.current_period_end), 0)
                self.subscription.refresh_from_db()
                self.service.refresh_from_db()
                self.assertEqual((self.subscription.currency_id, self.service.currency_id), ("RON", "RON"))
                self.assertIsNone(self.subscription.effective_terms_at)

        # The same accepted offer can proceed once the service is eligible.
        Service.objects.filter(pk=self.service.pk).update(status="active")
        cycle = self.prepare()
        self.assertEqual(activate_due_currency_terms(as_of=cycle.period_start), 1)
        self.service.refresh_from_db()
        self.assertEqual((self.service.currency_id, self.service.price), ("EUR", Decimal("22")))

    def test_existing_automatic_mandate_collects_notified_document_in_its_recorded_currency(self) -> None:
        self.offer(accepted_days=30)
        cycle = self.prepare()
        self.assertIsInstance(SettingsService.update_setting("billing.default_currency", "USD"), Ok)
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.return_value = _intent_result(payment_intent_id="pi_currency_terms_eur")
        with patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway", return_value=gateway):
            result = PaymentService.create_payment_intent_for_proforma(
                cycle.proforma_id, self.payment_method.stripe_payment_method_id,
            )
        self.assertTrue(result["success"], result)
        submitted = gateway.create_off_session_payment_intent.call_args.kwargs
        self.assertEqual((submitted["currency"], submitted["amount_cents"]), ("EUR", cycle.proforma.total_cents))
        self.assertEqual(submitted["payment_method_id"], self.payment_method.stripe_payment_method_id)
        payment = Payment.objects.get(gateway_txn_id="pi_currency_terms_eur")
        self.assertEqual(payment.currency_id, "EUR")
        self.subscription.refresh_from_db()
        self.assertEqual(self.subscription.currency_id, "RON")
        self.assertEqual(self.subscription.payment_authorization_id, self.authorization.pk)

    def test_same_customer_renewals_use_separate_documents_for_their_frozen_currencies(self) -> None:
        protected = self._create_aligned_subscription("protected", self.subscription.next_proforma_at)
        protected.next_charge_at = self.subscription.next_charge_at
        protected.locked_price_cents = 5000
        protected.save(update_fields=["next_charge_at", "locked_price_cents"])
        self.offer(accepted_days=30)

        result = RecurringBillingOrchestrator.prepare_due_proformas(as_of=self.subscription.next_proforma_at)

        self.assertEqual(result["errors"], [], result)
        self.assertEqual(result["cycles_prepared"], 2, result)
        euro = self.subscription.billing_cycles.get(proforma__isnull=False)
        ron = protected.billing_cycles.get(proforma__isnull=False)
        self.assertNotEqual(euro.proforma_id, ron.proforma_id)
        self.assertEqual((euro.currency_id, euro.proforma.currency_id, euro.proforma.subtotal_cents), ("EUR", "EUR", 2200))
        self.assertEqual((ron.currency_id, ron.proforma.currency_id, ron.proforma.subtotal_cents), ("RON", "RON", 5000))
        self.assertEqual(euro.proforma.lines.get().unit_price_cents, 2200)
        self.assertEqual(ron.proforma.lines.get().unit_price_cents, 5000)
        self.assertEqual(self.subscription.currency_transitions.get(status="committed").committed_cycle_id, euro.pk)
        self.assertIn("protected", protected.currency_transitions.get(status="pending").hold_reason)

    def test_committed_offer_survives_policy_change_and_next_offer_uses_committed_baseline(self) -> None:
        from apps.billing.currency_transitions import activate_due_currency_terms  # noqa: PLC0415

        first = self.offer(accepted_days=30)
        cycle = self.prepare()
        self.assertIsInstance(SettingsService.update_setting("billing.default_currency", "USD"), Ok)
        next_offer = self.offer()
        self.assertEqual((next_offer.old_terms["currency"], next_offer.target_terms["currency"]), ("EUR", "USD"))
        first.refresh_from_db()
        self.assertEqual(first.status, "committed")
        self.assertEqual(activate_due_currency_terms(as_of=cycle.period_start), 1)
        self.subscription.refresh_from_db()
        self.assertEqual((self.subscription.currency_id, self.subscription.unit_price_cents), ("EUR", 2200))

    def test_known_zero_target_price_is_committed_and_does_not_activate_early(self) -> None:
        ProductPrice.objects.filter(product=self.product, currency_id="EUR").update(monthly_price_cents=0)
        self.offer(accepted_days=30)
        with patch("django.utils.timezone.now", return_value=self.subscription.next_proforma_at):
            cycle = self.prepare()
        self.assertEqual((cycle.currency_id, cycle.unit_price_cents, cycle.proforma.total_cents), ("EUR", 0, 0))
        self.subscription.refresh_from_db()
        self.assertEqual(self.subscription.currency_id, "RON")

    def test_lock_expiry_is_evaluated_at_renewal_start_and_existing_cycle_is_immutable(self) -> None:
        self.subscription.locked_price_cents = 0
        self.subscription.locked_price_expires_at = self.subscription.current_period_end
        self.subscription.save(update_fields=["locked_price_cents", "locked_price_expires_at"])
        offer = self.offer(accepted_days=30)
        self.assertFalse(offer.hold_reason)
        self.assertEqual(self.prepare().currency_id, "EUR")
        self.current_cycle.refresh_from_db()
        self.assertEqual((self.current_cycle.currency_id, self.current_cycle.unit_price_cents), ("RON", 10000))

    def test_grandfathered_zero_price_holds_notified_transition(self) -> None:
        self.offer(accepted_days=30)
        PriceGrandfathering.objects.create(
            customer=self.customer, product=self.product, currency_id="RON", locked_price_cents=0,
            original_price_cents=10000, current_product_price_cents=12000,
        )
        cycle = self.prepare()
        self.assertEqual((cycle.currency_id, cycle.unit_price_cents), ("RON", 0))
        self.assertEqual(self.subscription.currency_transitions.get(status="pending").hold_reason[:2], "An")

    def test_zero_price_item_lock_holds_notified_transition(self) -> None:
        self.offer(accepted_days=30)
        SubscriptionItem.objects.create(
            subscription=self.subscription, product=self.product, unit_price_cents=100, locked_price_cents=0,
        )
        self.assertEqual(self.prepare().currency_id, "RON")
        self.assertIn("item", self.subscription.currency_transitions.get(status="notified").hold_reason)

    def test_ended_benefit_with_pending_reservation_preserves_original_terms(self) -> None:
        self.offer(accepted_days=30)
        order = Order.objects.create(customer=self.customer, currency_id="RON")
        item = OrderItem.objects.create(
            order=order, product=self.product, product_name=self.product.name, product_type="hosting",
            quantity=1, unit_price_cents=10000,
        )
        coupon = Coupon.objects.create(code="SUB-PROMISE", name="Promise", discount_type="free_months", free_months=1)
        application = PromotionApplication.objects.create(
            order=order, coupon=coupon, status="settled", discount_cents=0, future_cents=100,
        )
        benefit = RenewalBenefit.objects.create(
            application=application, order_item=item, subscription=self.subscription, remaining_cents=100,
            remaining_months=0, monthly_cents=100, ended_at=self.now,
        )
        RenewalBenefitUse.objects.create(benefit=benefit, cycle=self.current_cycle, amount_cents=100, months=1)
        cycle = self.prepare()
        self.assertEqual(cycle.currency_id, "RON")
        self.assertIn("benefit", self.subscription.currency_transitions.get(status="notified").hold_reason)

    def test_cancelled_subscription_does_not_activate_committed_future_terms(self) -> None:
        from apps.billing.currency_transitions import activate_due_currency_terms  # noqa: PLC0415

        self.offer(accepted_days=30)
        cycle = self.prepare()
        self.subscription.cancel(at_period_end=False)
        self.assertEqual(activate_due_currency_terms(as_of=cycle.period_start), 0)
        self.subscription.refresh_from_db()
        self.service.refresh_from_db()
        self.assertEqual((self.subscription.status, self.subscription.currency_id), ("cancelled", "RON"))
        self.assertEqual(self.service.currency_id, "RON")

    def test_prepared_original_document_is_never_repriced_when_notice_matures(self) -> None:
        self.offer(accepted_days=29)
        cycle = self.prepare()
        result = RecurringBillingOrchestrator.prepare_due_proformas(
            as_of=self.subscription.next_proforma_at + timedelta(days=2)
        )
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["cycles_prepared"], 0)
        cycle.refresh_from_db()
        self.assertEqual((cycle.currency_id, cycle.unit_price_cents, cycle.proforma.currency_id), ("RON", 10000, "RON"))

    def test_same_currency_revision_round_trip_requires_a_fresh_notice(self) -> None:
        old = self.offer(accepted_days=30)
        self.assertIsInstance(SettingsService.update_setting("billing.default_currency", "USD"), Ok)
        self.assertIsInstance(SettingsService.update_setting("billing.default_currency", "EUR"), Ok)
        cycle = self.prepare()
        old.refresh_from_db()
        self.assertEqual(old.status, "superseded")
        self.assertEqual(cycle.currency_id, "RON")

    def test_unavailable_target_price_keeps_original_billing_terms(self) -> None:
        self.offer(accepted_days=30)
        price = ProductPrice.objects.get(product=self.product, currency_id="EUR")
        price.is_active = False
        price.save(update_fields=["is_active"])
        cycle = self.prepare()
        self.assertEqual((cycle.currency_id, cycle.unit_price_cents), ("RON", 10000))

    def test_late_original_cycle_settlement_cannot_roll_effective_pricing_back(self) -> None:
        from apps.billing.currency_transitions import activate_due_currency_terms  # noqa: PLC0415
        from apps.billing.payment_convergence import PaymentSuccessService  # noqa: PLC0415

        self.offer(accepted_days=30)
        cycle = self.prepare()
        payment = self.pay(cycle, cycle.period_start)
        self.assertEqual(activate_due_currency_terms(as_of=cycle.period_start), 0)
        self.subscription.refresh_from_db()
        error = PaymentSuccessService._apply_cycle_entitlement(
            cycle=self.current_cycle, subscription=self.subscription, service=self.service,
            paid_at=cycle.period_start + timedelta(days=1),
        )
        self.assertIn("Stale billing cycle", error)
        self.subscription.refresh_from_db()
        self.service.refresh_from_db()
        self.assertEqual((self.subscription.currency_id, self.subscription.unit_price_cents), ("EUR", 2200))
        self.assertEqual((self.subscription.last_payment_currency_id, self.subscription.last_payment_id), ("EUR", payment.pk))
        self.assertEqual((self.service.currency_id, self.service.price), ("EUR", Decimal("22")))

    def test_late_payment_after_cancellation_cannot_extend_entitlement(self) -> None:
        self.offer(accepted_days=30)
        cycle = self.prepare()
        self.subscription.cancel(at_period_end=False)
        self.subscription.refresh_from_db()
        paid_through = self.subscription.current_period_end
        with patch("django.utils.timezone.now", return_value=cycle.period_start):
            ProformaPaymentService.record_payment_and_convert(
                str(cycle.proforma_id), cycle.proforma.total_cents, "bank", reference="Cancelled local renewal"
            )
        self.subscription.refresh_from_db()
        cycle.refresh_from_db()
        self.assertEqual((self.subscription.status, self.subscription.current_period_end), ("cancelled", paid_through))
        self.assertIsNone(cycle.entitlement_applied_at)

    def test_switch_queues_notice_reconciliation_only_after_successful_commit(self) -> None:
        with patch("django_q.tasks.async_task") as enqueue, self.captureOnCommitCallbacks(execute=True):
            self.assertIsInstance(SettingsService.update_setting("billing.default_currency", "USD"), Ok)
            enqueue.assert_not_called()
        enqueue.assert_any_call("apps.billing.tasks.reconcile_currency_transition_notices")

    def test_rolled_back_switch_cannot_queue_customer_notice(self) -> None:
        with (
            patch("django_q.tasks.async_task") as enqueue,
            self.captureOnCommitCallbacks(execute=True),
            self.assertRaisesMessage(ValueError, "rollback"),
            transaction.atomic(),
        ):
            self.assertIsInstance(SettingsService.update_setting("billing.default_currency", "USD"), Ok)
            raise ValueError("rollback")
        enqueue.assert_not_called()

    def test_daily_reconciliation_repairs_notice_once_without_creating_billing_document(self) -> None:
        from apps.billing.tasks import reconcile_currency_transition_notices  # noqa: PLC0415

        first = reconcile_currency_transition_notices()
        second = reconcile_currency_transition_notices()
        self.assertEqual(first["subscriptions"]["notices_sent"], 1)
        self.assertEqual(second["subscriptions"]["notices_sent"], 0)
        self.assertEqual(len(mail.outbox), 1)
        self.assertFalse(self.subscription.billing_cycles.filter(proforma__isnull=False).exists())

    def test_notice_repair_is_registered_with_existing_billing_scheduler(self) -> None:
        from django_q.models import Schedule  # noqa: PLC0415

        from apps.billing.tasks import setup_billing_scheduled_tasks  # noqa: PLC0415

        with patch("apps.billing.metering_tasks.register_scheduled_tasks"):
            setup_billing_scheduled_tasks()
            setup_billing_scheduled_tasks()
        schedule = Schedule.objects.get(name="billing-currency-transition-notices")
        self.assertEqual(schedule.func, "apps.billing.tasks.reconcile_currency_transition_notices")
        self.assertEqual(schedule.cron, "0 1 * * *")
