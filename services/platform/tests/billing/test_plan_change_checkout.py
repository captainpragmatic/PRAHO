"""Real quote→confirmation→claim→Stripe SDK seam with persisted native capability."""

import json
import logging
from datetime import timedelta
from decimal import Decimal
from threading import Event
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import stripe
from django.core.exceptions import ValidationError
from django.db import connection, transaction
from django.test import TransactionTestCase

from apps.audit.models import AuditEvent
from apps.billing.gateways.stripe_gateway import StripeGateway
from apps.billing.models import Payment, ProformaInvoice
from apps.billing.plan_change_payment_models import PlanChangePaymentAttempt
from apps.billing.plan_change_payment_service import (
    cancel_plan_change_payment,
    recover_plan_change_payment,
    recover_plan_change_payments,
    reserve_plan_change_payment,
    submit_plan_change_payment,
)
from apps.billing.plan_change_quote_service import confirm_plan_change
from apps.billing.proforma_service import ProformaPaymentService
from apps.customers.models import Customer
from apps.integrations.models import WebhookEvent
from apps.integrations.webhooks.stripe import StripeWebhookProcessor
from apps.products.models import ProductPrice
from apps.provisioning.hosting_limit_models import ServiceHostingLimits
from tests.common.postgres_locking import database_worker, wait_for_blocker
from tests.helpers.plan_change_checkout import VerifiedPlanChangeCheckoutFixture as _PlanChangeCheckoutFixture


class PlanChangeCheckoutTests(_PlanChangeCheckoutFixture, TransactionTestCase):
    def test_signed_webhook_enters_document_conversion_after_fact_transaction_commit(self):
        change, attempt, sdk = self.ready_attempt()
        original = ProformaPaymentService.record_payment_and_convert
        entered = []

        def converted(*args, **kwargs):
            entered.append(True)
            self.assertFalse(
                connection.in_atomic_block, "Document conversion inherited the Payment-first webhook transaction"
            )
            return original(*args, **kwargs)

        with patch.object(ProformaPaymentService, "record_payment_and_convert", side_effect=converted):
            accepted, message, event = self.signed_delivery(sdk.PaymentIntent.create.call_args.kwargs["metadata"])
        self.assertTrue(accepted, message)
        self.assertTrue(entered)
        self.assertEqual(event.status, "processed")
        change.refresh_from_db()
        self.assertEqual(change.status, "applying_limits")
        self.assertEqual(Payment.objects.get(pk=attempt.payment_id).status, "succeeded")

    def test_verified_webhook_event_does_not_persist_the_provider_client_secret(self):
        _change, _attempt, sdk = self.ready_attempt()
        original = WebhookEvent.save
        inserted = []

        def saved(event, *args, **kwargs):
            if event._state.adding and event.source == "stripe":
                inserted.append(True)
                self.assertNotIn("client_secret", event.payload["data"]["object"])
            return original(event, *args, **kwargs)

        with patch.object(WebhookEvent, "save", new=saved):
            accepted, message, event = self.signed_delivery(sdk.PaymentIntent.create.call_args.kwargs["metadata"])
        self.assertTrue(accepted, message)
        self.assertTrue(inserted)
        event.refresh_from_db()
        self.assertNotIn("client_secret", event.payload["data"]["object"])
        self.assertNotIn("opaque-provider-secret", json.dumps(event.payload))

    def test_callback_crash_keeps_a_durable_paid_recovery_journal(self):
        change, attempt, sdk = self.ready_attempt()
        with patch(
            "apps.billing.plan_change_payment_service.recover_plan_change_payment",
            side_effect=RuntimeError("callback interrupted"),
        ):
            accepted, message, event = self.signed_delivery(sdk.PaymentIntent.create.call_args.kwargs["metadata"])
        self.assertTrue(accepted, message)
        self.assertEqual(event.status, "processed")
        attempt.refresh_from_db()
        self.assertEqual(attempt.state, "review")
        self.assertEqual(Payment.objects.get(pk=attempt.payment_id).status, "succeeded")
        self.customer.refresh_from_db()
        positive_before = [
            entry for entry in self.customer.meta.get("credit_history", []) if entry["event_type"] == "positive_payment"
        ]
        self.assertEqual(positive_before, [])
        with patch("apps.billing.plan_change_payment_service._gateway") as gateway:
            self.assertEqual(recover_plan_change_payment(attempt.pk)["state"], "succeeded")
            self.assertEqual(recover_plan_change_payment(attempt.pk)["state"], "succeeded")
        gateway.assert_not_called()
        self.customer.refresh_from_db()
        positive_after = [
            entry for entry in self.customer.meta["credit_history"] if entry["event_type"] == "positive_payment"
        ]
        self.assertEqual(len(positive_after), 1)
        change.refresh_from_db()
        self.assertEqual(change.status, "applying_limits")

    def test_bad_signature_never_creates_an_event_or_accepts_funds(self):
        _change, attempt, sdk = self.ready_attempt()
        accepted, _message, event = self.signed_delivery(
            sdk.PaymentIntent.create.call_args.kwargs["metadata"], valid=False
        )
        self.assertFalse(accepted)
        self.assertIsNone(event)
        self.assertFalse(WebhookEvent.objects.filter(source="stripe").exists())
        self.assertEqual(Payment.objects.get(pk=attempt.payment_id).status, "pending")

    def test_webhook_before_submission_reply_cannot_hide_lost_callback_recovery(self):
        change = self.confirm(self.quote())
        attempt = reserve_plan_change_payment(
            change.pk,
            customer_id=self.customer.pk,
            actor_id=self.actor.pk,
            expected_fingerprint=change.request_fingerprint,
        )
        sdk = MagicMock()
        sdk.error = stripe.error
        gateway = StripeGateway.__new__(StripeGateway)
        gateway._stripe, gateway.logger = sdk, logging.getLogger("test.plan-checkout")

        def provider(**payload):
            with patch(
                "apps.billing.plan_change_payment_service.recover_plan_change_payment",
                side_effect=RuntimeError("callback lost"),
            ):
                accepted, message, _event = self.signed_delivery(payload["metadata"])
            self.assertTrue(accepted, message)
            return SimpleNamespace(id="pi_signed_plan", client_secret="opaque-provider-secret")

        sdk.PaymentIntent.create.side_effect = provider
        with patch("apps.billing.plan_change_payment_service._gateway", return_value=gateway):
            self.assertEqual(submit_plan_change_payment(attempt.pk)["state"], "review")
            self.assertEqual(submit_plan_change_payment(attempt.pk)["state"], "review")
        sdk.PaymentIntent.create.assert_called_once()
        with patch("apps.billing.plan_change_payment_service._gateway") as gateway_lookup:
            self.assertEqual(recover_plan_change_payments(), {"succeeded": 1})
        gateway_lookup.assert_not_called()
        change.refresh_from_db()
        self.assertEqual(change.status, "applying_limits")

    def test_actual_webhook_waits_for_document_owner_without_retaining_payment_lock(self):
        self.assert_fact_wait_releases_payment(status="succeeded")

    def test_signed_cancellation_waits_without_retaining_payment_lock(self):
        self.assert_fact_wait_releases_payment(status="canceled")

    def test_signed_cancellation_callback_loss_recovers_without_another_provider_call(self):
        change, attempt, sdk = self.ready_attempt()
        with patch(
            "apps.billing.plan_change_payment_service._close_cancelled_change", side_effect=RuntimeError("callback lost")
        ):
            accepted, message, event = self.signed_delivery(
                sdk.PaymentIntent.create.call_args.kwargs["metadata"], status="canceled"
            )
        self.assertTrue(accepted, message)
        self.assertEqual(event.status, "processed")
        attempt.refresh_from_db()
        self.assertEqual((attempt.state, attempt.provider_status), ("review", "canceled"))
        self.assertEqual(Payment.objects.get(pk=attempt.payment_id).status, "pending")
        with patch("apps.billing.plan_change_payment_service._gateway") as gateway:
            self.assertEqual(recover_plan_change_payment(attempt.pk)["state"], "cancelled")
        gateway.assert_not_called()
        change.refresh_from_db()
        self.assertEqual(change.status, "cancelled")
        self.assertEqual(Payment.objects.get(pk=attempt.payment_id).status, "failed")

    def assert_fact_wait_releases_payment(self, *, status):
        change, attempt, sdk = self.ready_attempt()
        entered, release = Event(), Event()

        def cancellation():
            def held(execute, sql, params, many, context):
                result = execute(sql, params, many, context)
                if not entered.is_set() and '"billing_plan_changes"' in sql and "FOR NO KEY UPDATE" in sql:
                    entered.set()
                    self.assertTrue(release.wait(10))
                return result

            with connection.execute_wrapper(held):
                return cancel_plan_change_payment(attempt.pk)

        def delivery():
            return self.signed_delivery(sdk.PaymentIntent.create.call_args.kwargs["metadata"], status=status)

        with (
            patch("apps.billing.plan_change_payment_service._gateway") as gateway,
            database_worker(cancellation) as (owner, cancelled),
        ):
            gateway.return_value.cancel_on_session_document_intent.return_value = {"success": False, "status": "unknown"}
            try:
                self.assertTrue(entered.wait(10))
                with database_worker(delivery) as (pid, delivered):
                    try:
                        wait_for_blocker(
                            pid, owner, delivered, table=(Customer._meta.db_table, ProformaInvoice._meta.db_table)
                        )
                        # Both a post-commit customer-history callback and the
                        # fiscal converter may wait on this exact document-first
                        # operation. Neither may still own the gateway Payment.
                        expected_status = "succeeded" if status == "succeeded" else "pending"
                        self.assertEqual(Payment.objects.get(pk=attempt.payment_id).status, expected_status)
                        with transaction.atomic():
                            self.assertEqual(
                                Payment.objects.select_for_update(nowait=True).get(pk=attempt.payment_id).status,
                                expected_status,
                            )
                        release.set()
                        if status == "succeeded":
                            self.assertNotEqual(cancelled.result(timeout=20)["state"], "cancelled")
                        else:
                            cancelled.result(timeout=20)
                        accepted, message, event = delivered.result(timeout=20)
                    finally:
                        release.set()
            finally:
                release.set()
        self.assertTrue(accepted, message)
        self.assertEqual(event.status, "processed")
        if status == "succeeded":
            gateway.assert_not_called()
        change.refresh_from_db()
        self.assertEqual(change.status, "applying_limits" if status == "succeeded" else "cancelled")
        self.assertEqual(Payment.objects.get(pk=attempt.payment_id).status, "succeeded" if status == "succeeded" else "failed")
        if status != "succeeded":
            return
        self.customer.refresh_from_db()
        positive_events = [
            event for event in self.customer.meta["credit_history"] if event["event_type"] == "positive_payment"
        ]
        self.assertEqual(len(positive_events), 1)
        recorded_meta = self.customer.meta.copy()
        self.assertEqual(recover_plan_change_payment(attempt.pk)["state"], "succeeded")
        self.customer.refresh_from_db()
        self.assertEqual(self.customer.meta, recorded_meta)

    def test_real_public_coordinators_claim_once_and_converge_same_paid_document(self):
        change = self.confirm(self.quote())
        original_period = (self.subscription.current_period_start, self.subscription.current_period_end)
        attempt = reserve_plan_change_payment(
            change.pk,
            customer_id=self.customer.pk,
            actor_id=self.actor.pk,
            expected_fingerprint=change.request_fingerprint,
        )
        replay = reserve_plan_change_payment(
            change.pk,
            customer_id=self.customer.pk,
            actor_id=self.actor.pk,
            expected_fingerprint=change.request_fingerprint,
        )
        self.assertEqual(attempt.pk, replay.pk)
        sdk = MagicMock()
        sdk.error = stripe.error
        gateway = StripeGateway.__new__(StripeGateway)
        gateway._stripe, gateway.logger = sdk, logging.getLogger("test.plan-checkout")

        def create(**payload):
            self.assertFalse(connection.in_atomic_block)
            stored = PlanChangePaymentAttempt.objects.get(pk=attempt.pk)
            self.assertEqual(stored.state, "submitting")
            self.assertEqual(payload["metadata"]["payment_id"], str(attempt.payment_id))
            self.assertEqual((payload["amount"], payload["currency"]), (7260, "ron"))
            self.assertIs(payload["confirm"], False)
            self.assertNotIn("customer", payload)
            self.assertNotIn("off_session", payload)
            return SimpleNamespace(id="pi_real_plan_checkout", client_secret="opaque-customer-secret")

        sdk.PaymentIntent.create.side_effect = create
        with patch("apps.billing.plan_change_payment_service._gateway", return_value=gateway):
            result = submit_plan_change_payment(attempt.pk)
            self.assertEqual(result["state"], "ready")
            self.assertEqual(submit_plan_change_payment(attempt.pk), result)
        sdk.PaymentIntent.create.assert_called_once()
        metadata = sdk.PaymentIntent.create.call_args.kwargs["metadata"]
        succeeded, message = StripeWebhookProcessor().handle_payment_intent_event(
            "payment_intent.succeeded",
            {
                "data": {
                    "object": {
                        "id": "pi_real_plan_checkout",
                        "status": "succeeded",
                        "amount": 7260,
                        "amount_received": 7260,
                        "currency": "ron",
                        "customer": None,
                        "metadata": metadata,
                    }
                }
            },
        )
        self.assertTrue(succeeded, message)
        change.refresh_from_db()
        self.service.refresh_from_db()
        self.subscription.refresh_from_db()
        self.assertEqual(change.status, "applying_limits")
        self.assertEqual(self.service.service_plan_id, self.target.default_service_plan_id)
        self.assertEqual((self.subscription.product_id, self.subscription.unit_price_cents), (self.target.pk, 20000))
        self.assertEqual(
            (self.subscription.current_period_start, self.subscription.current_period_end), original_period
        )
        self.assertEqual(ServiceHostingLimits.objects.get(service=self.service).revision, 3)
        self.assertEqual(Payment.objects.filter(proforma_id=change.proforma_id).count(), 1)
        self.assertFalse(change.proforma.lines.exclude(billing_cycle=None).exists())
        self.assertEqual(change.invoice.status, "paid")
        self.assertNotIn(
            "opaque-customer-secret", json.dumps(list(AuditEvent.objects.values_list("new_values", flat=True)))
        )


class PlanChangeZeroCheckoutTests(_PlanChangeCheckoutFixture, TransactionTestCase):
    period_remaining = timedelta(hours=1)

    def test_explicit_zero_due_confirmation_uses_real_consumer_without_payable_documents(self):
        ProductPrice.objects.filter(product=self.target).update(monthly_price_cents=8001)
        change = self.quote()
        self.assertEqual((change.net_cents, change.tax_cents, change.total_cents), (0, 0, 0))
        with self.assertRaisesMessage(ValidationError, "Explicitly confirm"):
            self.confirm(change)
        with patch("apps.billing.plan_change_payment_service._gateway") as gateway:
            accepted = confirm_plan_change(
                change.pk,
                customer_id=self.customer.pk,
                actor_id=self.actor.pk,
                expected_fingerprint=change.request_fingerprint,
                accept_zero_due=True,
            )
        gateway.assert_not_called()
        self.assertEqual(accepted.status, "applying_limits")
        self.assertIsNone(accepted.proforma_id)
        self.assertIsNone(accepted.invoice_id)
        self.assertFalse(PlanChangePaymentAttempt.objects.exists())
        self.assertEqual(Payment.objects.count(), 1)  # Only the already-paid base interval.
        self.subscription.refresh_from_db()
        self.service.refresh_from_db()
        self.assertEqual((self.subscription.product_id, self.subscription.unit_price_cents), (self.target.pk, 8001))
        self.assertEqual(self.service.price, Decimal("80.01"))
