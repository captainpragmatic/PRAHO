"""A lost browser checkout response never creates a second provider identity."""

import hashlib
import json
from datetime import timedelta
from threading import Event
from unittest.mock import patch
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.db import connection
from django.test import TransactionTestCase
from django.utils import timezone

from apps.billing.models import InvoiceSequence, Payment
from apps.billing.plan_change_payment_models import PlanChangePaymentAttempt
from apps.billing.plan_change_payment_service import (
    cancel_plan_change_payment,
    recover_plan_change_payment,
    reserve_plan_change_payment,
    submit_plan_change_payment,
)
from apps.integrations.webhooks.stripe import StripeWebhookProcessor
from apps.settings.services import SettingsService
from apps.users.models import CustomerMembership
from tests.billing.test_plan_change_settlement import _PlanChangeSettlementFixture
from tests.common.postgres_locking import database_worker


class PlanChangeReservationRefusalTests(_PlanChangeSettlementFixture, TransactionTestCase):
    def test_real_reservation_requires_native_proof_before_creating_money_attempt(self):
        self.assertTrue(SettingsService.update_setting("billing.hosting_plan_changes_enabled", True).is_ok())
        CustomerMembership.objects.create(customer=self.customer, user=self.actor, role="billing", is_active=True)
        change, proforma, _, _ = self.payable_change()
        with self.assertRaisesMessage(ValidationError, "managed quota"):
            reserve_plan_change_payment(
                change.pk,
                customer_id=self.customer.pk,
                actor_id=self.actor.pk,
                expected_fingerprint=change.request_fingerprint,
            )
        self.assertFalse(proforma.payments.exists())
        self.assertFalse(PlanChangePaymentAttempt.objects.exists())


class PlanChangeSubmissionTests(_PlanChangeSettlementFixture, TransactionTestCase):
    def setUp(self):
        super().setUp()
        self.change_row, self.proforma, _, _ = self.payable_change()
        attempt_id = uuid4()
        self.payment = Payment.objects.create(
            customer=self.customer,
            proforma=self.proforma,
            currency=self.currency,
            amount_cents=self.change_row.total_cents,
            payment_method="stripe",
            idempotency_key=f"pc:{attempt_id}",
            meta={
                "source": "hosting_plan_change",
                "plan_change_id": str(self.change_row.pk),
                "plan_change_attempt_id": str(attempt_id),
                "quote_fingerprint": self.change_row.request_fingerprint,
            },
        )
        payload = {
            "document_id": str(self.proforma.pk),
            "document_type": "proforma",
            "amount_cents": self.payment.amount_cents,
            "currency": self.currency.code,
            "metadata": {
                "platform": "PRAHO",
                "source": "hosting_plan_change",
                "customer_id": str(self.customer.pk),
                "payment_id": str(self.payment.pk),
                "plan_change_id": str(self.change_row.pk),
                "attempt_id": str(attempt_id),
                "proforma_id": str(self.proforma.pk),
                "quote_fingerprint": self.change_row.request_fingerprint,
            },
            "idempotency_key": self.payment.idempotency_key,
        }
        self.attempt = PlanChangePaymentAttempt.objects.create(
            id=attempt_id,
            change=self.change_row,
            payment=self.payment,
            payload=payload,
            payload_hash=hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            idempotency_key=self.payment.idempotency_key,
        )

    def gateway(self, **payload):
        self.assertFalse(connection.in_atomic_block)
        durable = PlanChangePaymentAttempt.objects.get(pk=self.attempt.pk)
        self.assertEqual(durable.state, "submitting")
        self.assertEqual(durable.payload, payload)
        self.assertIsNotNone(durable.lease_token)
        self.assertEqual(Payment.objects.count(), 2)  # Original paid cycle and this supplement.
        return {"success": True, "payment_intent_id": "pi_plan", "client_secret": "test-secret", "error": None}

    def submit(self):
        return submit_plan_change_payment(self.attempt.pk)

    def test_durable_claim_precedes_gateway_and_duplicate_reuses_encrypted_result(self):
        with patch("apps.billing.plan_change_payment_service._gateway") as factory:
            factory.return_value.create_on_session_document_intent.side_effect = self.gateway
            first = self.submit()
            second = self.submit()
        self.assertEqual(first, second)
        self.assertEqual(first["state"], "ready")
        self.assertEqual(first["client_secret"], "test-secret")
        factory.return_value.create_on_session_document_intent.assert_called_once()
        self.attempt.refresh_from_db()
        self.payment.refresh_from_db()
        self.assertEqual(self.payment.gateway_txn_id, "pi_plan")
        self.assertTrue(self.attempt.client_secret_ciphertext.startswith("aes:v2:"))
        self.assertNotIn("test-secret", json.dumps(self.payment.meta))
        self.assertNotIn("test-secret", self.attempt.client_secret_ciphertext)

    def test_unknown_replays_exact_payload_key_and_payment_after_expired_lease(self):
        with patch("apps.billing.plan_change_payment_service._gateway") as factory:
            creator = factory.return_value.create_on_session_document_intent
            creator.side_effect = RuntimeError("response lost")
            self.assertEqual(self.submit()["state"], "unknown")
            self.attempt.refresh_from_db()
            self.attempt.lease_expires_at = timezone.now() - timedelta(seconds=1)
            self.attempt.save(update_fields=["lease_expires_at"])
            # Replay deliberately does not need the original quote TTL again.
            creator.side_effect = self.gateway
            result = self.submit()
        self.assertEqual(result["state"], "ready")
        self.assertEqual(creator.call_args_list[0], creator.call_args_list[1])
        self.assertEqual(PlanChangePaymentAttempt.objects.count(), 1)

    def test_unknown_past_replay_window_never_calls_create_again(self):
        self.attempt.state = "unknown"
        self.attempt.first_submitted_at = timezone.now() - timedelta(hours=24)
        self.attempt.replay_until = timezone.now() - timedelta(seconds=1)
        self.attempt.save(update_fields=["state", "first_submitted_at", "replay_until"])
        with patch("apps.billing.plan_change_payment_service._gateway") as factory:
            self.assertEqual(self.submit()["state"], "review")
        factory.assert_not_called()
        self.payment.refresh_from_db()
        self.assertEqual(self.payment.status, "pending")

    def test_payload_identity_is_immutable(self):
        self.attempt.payload = {**self.attempt.payload, "amount_cents": 1}
        with self.assertRaises(ValidationError):
            self.attempt.save()

    def event(self, status, *, succeeded=False):
        return {
            "data": {
                "object": {
                    "id": "pi_plan",
                    "status": status,
                    "amount": 6000,
                    "amount_received": 6000 if succeeded else 0,
                    "currency": "ron",
                    "customer": None,
                    "payment_method": "pm_customer_present",
                    "metadata": {**self.attempt.payload["metadata"], "praho_proforma_id": str(self.proforma.pk)},
                }
            }
        }

    def test_webhook_before_request_binding_settles_exact_original_payment_and_quote(self):
        def gateway(**payload):
            self.assertFalse(connection.in_atomic_block)
            success, message = StripeWebhookProcessor().handle_payment_intent_event(
                "payment_intent.succeeded", self.event("succeeded", succeeded=True)
            )
            self.assertTrue(success, message)
            return {"success": True, "payment_intent_id": "pi_plan", "client_secret": "test-secret", "error": None}

        with patch("apps.billing.plan_change_payment_service._gateway") as factory:
            factory.return_value.create_on_session_document_intent.side_effect = gateway
            self.assertEqual(self.submit()["state"], "succeeded")
        self.payment.refresh_from_db()
        self.change_row.refresh_from_db()
        self.assertEqual(self.payment.status, "succeeded")
        self.assertEqual(self.change_row.status, "applying_limits")
        self.assertIsNotNone(self.change_row.limit_application_id)

    def test_failed_card_can_retry_same_intent_and_later_succeed(self):
        with patch("apps.billing.plan_change_payment_service._gateway") as factory:
            factory.return_value.create_on_session_document_intent.side_effect = self.gateway
            self.assertEqual(self.submit()["state"], "ready")
        success, message = StripeWebhookProcessor().handle_payment_intent_event(
            "payment_intent.payment_failed", self.event("requires_payment_method")
        )
        self.assertTrue(success, message)
        self.payment.refresh_from_db()
        self.assertEqual(self.payment.status, "pending")
        success, message = StripeWebhookProcessor().handle_payment_intent_event(
            "payment_intent.succeeded", self.event("succeeded", succeeded=True)
        )
        self.assertTrue(success, message)
        self.payment.refresh_from_db()
        self.assertEqual(self.payment.status, "succeeded")

    def test_never_submitted_cancellation_has_local_proof_and_no_gateway_call(self):
        with patch("apps.billing.plan_change_payment_service._gateway") as factory:
            result = cancel_plan_change_payment(self.attempt.pk)
        self.assertEqual(result["state"], "cancelled")
        factory.assert_not_called()
        self.payment.refresh_from_db()
        self.attempt.refresh_from_db()
        self.assertEqual(self.payment.status, "failed")
        self.assertEqual(self.payment.meta["plan_change_terminal_proof"], "never_submitted")
        self.assertEqual(self.attempt.provider_status, "not_submitted")

    def test_lost_provider_cancellation_reply_retains_pending_payment_and_hold(self):
        with patch("apps.billing.plan_change_payment_service._gateway") as factory:
            factory.return_value.create_on_session_document_intent.side_effect = self.gateway
            self.submit()
            factory.return_value.cancel_on_session_document_intent.side_effect = RuntimeError("reply lost")
            result = cancel_plan_change_payment(self.attempt.pk)
        self.assertEqual(result["state"], "unknown")
        self.payment.refresh_from_db()
        self.change_row.refresh_from_db()
        self.assertEqual(self.payment.status, "pending")
        self.assertEqual(self.change_row.status, "payment_in_flight")

    def test_verified_original_cancellation_records_terminal_proof(self):
        with patch("apps.billing.plan_change_payment_service._gateway") as factory:
            factory.return_value.create_on_session_document_intent.side_effect = self.gateway
            self.submit()
            factory.return_value.cancel_on_session_document_intent.return_value = {
                "success": True,
                "status": "canceled",
                "amount": 6000,
                "currency": "ron",
                "customer_id": None,
                "metadata": self.event("canceled")["data"]["object"]["metadata"],
            }
            self.assertEqual(cancel_plan_change_payment(self.attempt.pk)["state"], "cancelled")
            call = factory.return_value.cancel_on_session_document_intent.call_args.kwargs
        self.assertEqual(call["idempotency_key"], f"pc-cancel:{self.attempt.pk}")
        self.change_row.refresh_from_db()
        self.payment.refresh_from_db()
        self.assertEqual(self.change_row.status, "cancelled")
        self.assertEqual(self.payment.meta["plan_change_terminal_proof"], "provider_cancelled")

    def test_received_money_recovers_failed_conversion_without_another_gateway_intent(self):
        with patch("apps.billing.plan_change_payment_service._gateway") as factory:
            factory.return_value.create_on_session_document_intent.side_effect = self.gateway
            self.submit()
        InvoiceSequence.objects.filter(scope="default").delete()
        success, _ = StripeWebhookProcessor().handle_payment_intent_event(
            "payment_intent.succeeded", self.event("succeeded", succeeded=True)
        )
        self.assertFalse(success)
        self.payment.refresh_from_db()
        self.assertEqual(self.payment.status, "succeeded")
        InvoiceSequence.objects.get_or_create(scope="default", defaults={"prefix": "INV"})
        with patch("apps.billing.plan_change_payment_service._gateway") as factory:
            self.assertEqual(recover_plan_change_payment(self.attempt.pk)["state"], "succeeded")
        factory.assert_not_called()
        self.change_row.refresh_from_db()
        self.assertEqual(self.change_row.status, "applying_limits")
        self.assertIsNotNone(self.change_row.invoice_id)

    def test_simultaneous_clicks_have_one_provider_call_while_first_is_outside_transaction(self):
        entered, release = Event(), Event()

        def held(**payload):
            result = self.gateway(**payload)
            entered.set()
            self.assertTrue(release.wait(10))
            return result

        with patch("apps.billing.plan_change_payment_service._gateway") as factory:
            factory.return_value.create_on_session_document_intent.side_effect = held
            with database_worker(self.submit) as (_pid, pending):
                try:
                    self.assertTrue(entered.wait(10))
                    self.assertEqual(self.submit()["state"], "submitting")
                    self.assertEqual(factory.return_value.create_on_session_document_intent.call_count, 1)
                finally:
                    release.set()
                self.assertEqual(pending.result(timeout=10)["state"], "ready")

    def test_expired_never_issued_reservation_closes_without_provider_call(self):
        with (
            patch("apps.billing.plan_change_payment_service.timezone.now", return_value=self.now + timedelta(hours=2)),
            patch("apps.billing.plan_change_payment_service._gateway") as factory,
        ):
            self.assertEqual(recover_plan_change_payment(self.attempt.pk)["state"], "cancelled")
        factory.assert_not_called()
        self.change_row.refresh_from_db()
        self.assertEqual(self.change_row.status, "expired")
