"""One unsettled plan attempt pauses conflicting renewal claims, not settled quota work."""

import hashlib
from datetime import timedelta
from threading import Event
from unittest import skipUnless
from unittest.mock import patch

from django.db import connection
from django.test import TransactionTestCase
from django.utils import timezone

from apps.billing.payment_service import PaymentService
from apps.billing.plan_change_payment_service import reserve_plan_change_payment
from apps.billing.proforma_service import ProformaPaymentService
from apps.billing.recurring_authorization_service import RecurringPaymentAuthorizationService
from apps.billing.recurring_billing import RecurringBillingOrchestrator, fixed_renewal_schedule
from apps.billing.recurring_models import RecurringPaymentAuthorization
from apps.customers.models import Customer, CustomerPaymentMethod
from apps.settings.services import SettingsService
from tests.common.postgres_locking import database_worker, wait_for_blocker
from tests.helpers.plan_change_checkout import VerifiedPlanChangeCheckoutFixture


class PlanChangeRenewalHoldTests(VerifiedPlanChangeCheckoutFixture, TransactionTestCase):
    period_remaining = timedelta(days=10)

    def setUp(self):
        super().setUp()
        proforma_at, charge_at = fixed_renewal_schedule(self.subscription.current_period_end)
        self.subscription.next_proforma_at = proforma_at
        self.subscription.next_charge_at = charge_at
        self.subscription.next_billing_date = proforma_at
        self.subscription.save(update_fields=["next_proforma_at", "next_charge_at", "next_billing_date"])

    def reserve(self):
        change = self.confirm(self.quote())
        reserve_plan_change_payment(
            change.pk,
            customer_id=self.customer.pk,
            actor_id=self.actor.pk,
            expected_fingerprint=change.request_fingerprint,
        )
        return change

    def test_real_preparation_waits_for_a_durably_reserved_plan_charge(self):
        self.reserve()
        result = RecurringBillingOrchestrator.prepare_due_proformas(as_of=self.now)
        self.assertEqual(result["proformas_created"], 0, result)
        self.assertIn("plan-change payment", " ".join(result["errors"]))

    def enroll(self):
        method = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type="stripe_card",
            stripe_customer_id="cus_plan_renewal",
            stripe_payment_method_id="pm_plan_renewal",
            display_name="Visa 4242",
            is_active=True,
        )
        authorization = RecurringPaymentAuthorization.objects.create(
            customer=self.customer,
            payment_method=method,
            status="active",
            setup_intent_id="seti_plan_renewal",
            terms_version=RecurringPaymentAuthorizationService.TERMS_VERSION,
            terms_text=RecurringPaymentAuthorizationService.TERMS_TEXT,
            terms_text_hash=hashlib.sha256(RecurringPaymentAuthorizationService.TERMS_TEXT.encode()).hexdigest(),
            granted_by=self.actor,
            granted_by_role="billing",
            granted_at=timezone.now(),
        )
        enrolled = RecurringPaymentAuthorizationService.set_subscription_auto_payment(
            subscription=self.subscription,
            authorization=authorization,
            enabled=True,
            actor=self.actor,
        )
        self.assertTrue(enrolled.is_ok(), enrolled)
        self.assertTrue(SettingsService.update_setting("billing.recurring_auto_collection_enabled", True).is_ok())
        return method

    def test_real_saved_card_collection_refuses_before_any_new_payment_or_gateway(self):
        method = self.enroll()
        prepared = RecurringBillingOrchestrator.prepare_due_proformas(as_of=self.now)
        self.assertEqual(prepared["proformas_created"], 1, prepared)
        cycle = self.subscription.billing_cycles.get(period_start=self.subscription.current_period_end)
        self.reserve()
        with patch("apps.billing.payment_service.PaymentGatewayFactory") as gateways:
            gateways.create_gateway.return_value.create_off_session_payment_intent.return_value = {
                "success": True,
                "payment_intent_id": "pi_conflicting_renewal",
                "client_secret": None,
                "error": None,
            }
            result = PaymentService.create_payment_intent_for_proforma(
                cycle.proforma_id, method.stripe_payment_method_id
            )
        self.assertFalse(result["success"], result)
        self.assertIn("plan-change payment", result["error"])
        self.assertFalse(cycle.proforma.payments.exists())
        gateways.assert_not_called()

    def test_expired_application_authority_releases_preparation_without_dropping_money_recovery(self):
        change = self.reserve()
        result = RecurringBillingOrchestrator.prepare_due_proformas(
            as_of=change.authority_expires_at + timedelta(seconds=1)
        )
        self.assertEqual(result["proformas_created"], 1, result)
        change.payment_attempt.refresh_from_db()
        self.assertEqual(change.payment_attempt.state, "reserved")
        self.assertEqual(
            self.subscription.billing_cycles.get(period_start=self.subscription.current_period_end).unit_price_cents,
            8000,
        )

    @skipUnless(connection.vendor == "postgresql", "Requires PostgreSQL row locks and observed blocker PIDs")
    def test_final_renewal_claim_waits_for_plan_claim_then_abandons_its_unissued_reservation(self):
        method = self.enroll()
        prepared = RecurringBillingOrchestrator.prepare_due_proformas(as_of=self.now)
        self.assertEqual(prepared["proformas_created"], 1, prepared)
        cycle = self.subscription.billing_cycles.get(period_start=self.subscription.current_period_end)
        change = self.confirm(self.quote())
        entered, release = Event(), Event()

        def reserve_plan():
            def held(execute, sql, params, many, context):
                result = execute(sql, params, many, context)
                if 'INSERT INTO "billing_plan_change_payment_attempts"' in sql:
                    entered.set()
                    self.assertTrue(release.wait(10))
                return result

            with connection.execute_wrapper(held):
                return reserve_plan_change_payment(
                    change.pk,
                    customer_id=self.customer.pk,
                    actor_id=self.actor.pk,
                    expected_fingerprint=change.request_fingerprint,
                )

        def collect():
            return PaymentService.create_payment_intent_for_proforma(cycle.proforma_id, method.stripe_payment_method_id)

        with patch("apps.billing.payment_service.PaymentGatewayFactory") as gateways:
            gateways.create_gateway.return_value.create_off_session_payment_intent.return_value = {
                "success": True,
                "payment_intent_id": "pi_should_not_be_submitted",
                "client_secret": None,
                "error": None,
            }
            with database_worker(reserve_plan) as (owner, reserved):
                try:
                    self.assertTrue(entered.wait(10))
                    with database_worker(collect) as (waiter, collected):
                        try:
                            wait_for_blocker(waiter, owner, collected, table=Customer._meta.db_table)
                            release.set()
                            self.assertIsNotNone(reserved.result(timeout=20))
                            result = collected.result(timeout=20)
                        finally:
                            release.set()
                finally:
                    release.set()
        self.assertFalse(result["success"], result)
        gateways.create_gateway.return_value.create_off_session_payment_intent.assert_not_called()
        abandoned = cycle.proforma.payments.get()
        self.assertEqual(abandoned.status, "failed")
        self.assertIs(abandoned.meta["reservation_abandoned"], True)
        self.assertFalse(abandoned.gateway_txn_id)

    def test_committed_money_with_only_quota_pending_does_not_block_normal_renewal(self):
        change = self.confirm(self.quote())
        paid = ProformaPaymentService.record_payment_and_convert(str(change.proforma_id), change.total_cents, "bank")
        self.assertTrue(paid.is_ok(), paid)
        change.refresh_from_db()
        self.assertEqual(change.status, "applying_limits")
        result = RecurringBillingOrchestrator.prepare_due_proformas(as_of=self.now)
        self.assertEqual(result["proformas_created"], 1, result)
        self.assertEqual(
            self.subscription.billing_cycles.get(period_start=self.subscription.current_period_end).unit_price_cents,
            20000,
        )
