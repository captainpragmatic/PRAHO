"""New spending must not bypass the standalone plan-change funding contract."""

import hashlib
from unittest.mock import patch
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.db import transaction
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from apps.billing.models import Payment
from apps.billing.payment_service import PaymentService
from apps.billing.plan_change_payment_models import PlanChangePaymentAttempt
from apps.billing.plan_change_payment_service import reserve_plan_change_payment
from apps.billing.plan_change_quote_service import _create_proforma
from apps.billing.proforma_service import ProformaPaymentService
from apps.billing.recurring_authorization_service import RecurringPaymentAuthorizationService
from apps.billing.recurring_models import RecurringPaymentAuthorization
from apps.customers.models import CustomerPaymentMethod
from apps.promotions.models import GiftCard
from apps.settings.services import SettingsService
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin
from tests.helpers.plan_change_checkout import VerifiedPlanChangeCheckoutFixture


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
class PlanChangeFundingTests(VerifiedPlanChangeCheckoutFixture, HMACTestMixin, TransactionTestCase):
    def test_existing_off_session_helper_refuses_even_with_a_real_saved_mandate(self):
        change = self.confirm(self.quote())
        self.assertTrue(SettingsService.update_setting("billing.recurring_auto_collection_enabled", True).is_ok())
        method = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type="stripe_card",
            stripe_customer_id="cus_existing_plan_owner",
            stripe_payment_method_id="pm_existing_plan_owner",
            display_name="Visa 4242",
            is_active=True,
        )
        RecurringPaymentAuthorization.objects.create(
            customer=self.customer,
            payment_method=method,
            status="active",
            setup_intent_id="seti_existing_plan_owner",
            terms_version=RecurringPaymentAuthorizationService.TERMS_VERSION,
            terms_text=RecurringPaymentAuthorizationService.TERMS_TEXT,
            terms_text_hash=hashlib.sha256(RecurringPaymentAuthorizationService.TERMS_TEXT.encode()).hexdigest(),
            granted_by=self.actor,
            granted_by_role="billing",
            granted_at=timezone.now(),
        )
        with patch("apps.billing.payment_service.PaymentGatewayFactory") as gateways:
            result = PaymentService.create_payment_intent_for_proforma(
                change.proforma_id, method.stripe_payment_method_id
            )
        self.assertFalse(result["success"])
        self.assertIn("no billing cycles", result["error"])
        gateways.assert_not_called()
        self.assertFalse(change.proforma.payments.exists())

    def gift_request(self, change, *, amount=1000):
        self.operation_key = str(uuid4())
        card = GiftCard.objects.create(
            code="PLAN-FUNDING-BALANCE",
            currency=self.currency,
            initial_value_cents=10000,
            current_balance_cents=10000,
            status="active",
            ledger_version=2,
        )
        response = self.portal_post(
            "/api/billing/gift-card-payment/",
            {
                "customer_id": self.customer.pk,
                "user_id": self.actor.pk,
                "action": "gift_card_payment",
                "document_type": "proforma",
                "document_number": change.proforma.number,
                "code": card.code,
                "operation_key": self.operation_key,
                "amount_cents": amount,
            },
        )
        return card, response

    def test_signed_gift_payment_refuses_new_spending_for_a_closed_change(self):
        change = self.confirm(self.quote())
        change.cancel()
        change.save()
        card, response = self.gift_request(change)
        self.assertEqual(response.status_code, 400, response.content)
        card.refresh_from_db()
        self.assertEqual((card.current_balance_cents, card.reserved_cents), (10000, 0))
        self.assertFalse(change.proforma.gift_card_reservations.exists())
        self.assertFalse(Payment.objects.filter(proforma_id=change.proforma_id).exists())

    def test_existing_partial_gift_prevents_a_second_full_amount_card_claim(self):
        change, _card = self.existing_reserved_change(amount=1000)
        with self.assertRaises(ValidationError):
            reserve_plan_change_payment(
                change.pk,
                customer_id=self.customer.pk,
                actor_id=self.actor.pk,
                expected_fingerprint=change.request_fingerprint,
            )
        self.assertFalse(PlanChangePaymentAttempt.objects.filter(change=change).exists())
        self.assertFalse(Payment.objects.filter(proforma_id=change.proforma_id).exists())

    def existing_reserved_change(self, *, amount):
        # Reproduce an existing hold using the actual signed ordinary-document
        # route before its first PlanChange binding. No guard or tender writer
        # is mocked; new production PlanChange documents are bound atomically.
        change = self.quote()
        with transaction.atomic():
            _create_proforma(change, self.customer, self.service)
            card, response = self.gift_request(change, amount=amount)
            self.assertEqual(response.status_code, 200, response.content)
            self.assertEqual(response.json()["cash_due_cents"], change.total_cents - amount)
            change.confirm()
            change.save(update_fields=["status", "confirmed_at", "proforma", "updated_at"])
        return change, card

    def test_signed_gift_payment_points_active_change_to_its_dedicated_checkout(self):
        change = self.confirm(self.quote())
        card, response = self.gift_request(change)
        self.assertEqual(response.status_code, 400, response.content)
        self.assertIn("plan-change checkout", response.json()["error"])
        card.refresh_from_db()
        self.assertEqual((card.current_balance_cents, card.reserved_cents), (10000, 0))

    def test_existing_gift_replay_and_late_capture_preserve_received_money_for_review(self):
        change, card = self.existing_reserved_change(amount=1000)
        hold = change.proforma.gift_card_reservations.get()
        response = self.portal_post(
            "/api/billing/gift-card-payment/",
            {
                "customer_id": self.customer.pk,
                "user_id": self.actor.pk,
                "action": "gift_card_payment",
                "document_type": "proforma",
                "document_number": change.proforma.number,
                "code": card.code,
                "operation_key": self.operation_key,
                "amount_cents": hold.amount_cents,
            },
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(change.proforma.gift_card_reservations.count(), 1)
        change.cancel()
        change.save()
        converted = ProformaPaymentService.record_payment_and_convert(
            str(change.proforma_id), 6260, "bank", reference="Previously received transfer"
        )
        self.assertTrue(converted.is_ok(), converted)
        change.refresh_from_db()
        self.assertEqual(change.status, "paid_review")
        invoice = converted.unwrap()
        self.assertEqual(invoice.status, "paid")
        self.assertEqual(invoice.payments.get(payment_method="gift_card").amount_cents, 1000)
        self.assertEqual(invoice.payments.get(payment_method="bank").amount_cents, 6260)
        card.refresh_from_db()
        self.assertEqual((card.current_balance_cents, card.reserved_cents), (9000, 0))
