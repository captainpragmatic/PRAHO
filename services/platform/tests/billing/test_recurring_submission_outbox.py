"""Durable recurring-payment submission and reconciliation regressions (#335, #409)."""

from __future__ import annotations

import importlib
import uuid
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.apps import apps as django_apps
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone

from apps.billing.gateways.base import PaymentConfirmResult, PaymentIntentResult
from apps.billing.payment_models import Payment, RecurringPaymentSubmission
from apps.billing.payment_service import PaymentService, _submit_recurring_charge_under_revocation_lock
from apps.billing.recurring_billing import RecurringBillingOrchestrator
from apps.billing.tasks import reconcile_recurring_payment_submissions
from apps.common.types import Err
from apps.settings.services import SettingsService
from tests.billing.test_subscription_invoice_payments import (
    _intent_result,
    _SubscriptionInvoicePaymentFixture,
)


class RecurringSubmissionStateTestCase(_SubscriptionInvoicePaymentFixture, TestCase):
    """The database, not a caller-local flag, owns whether Stripe may be called."""

    def test_submission_claim_is_durable_before_gateway_io(self) -> None:
        gateway = MagicMock()

        def observe_claim(**_kwargs: object) -> PaymentIntentResult:
            submission = RecurringPaymentSubmission.objects.get(payment__invoice=self.invoice)
            self.assertEqual(submission.state, RecurringPaymentSubmission.State.IN_FLIGHT)
            self.assertEqual(submission.attempt_count, 1)
            self.assertIsNotNone(submission.claimed_at)
            return _intent_result(payment_intent_id="pi_durable_claim_335")

        gateway.create_off_session_payment_intent.side_effect = observe_claim
        with patch(
            "apps.billing.payment_service.PaymentGatewayFactory.create_gateway",
            return_value=gateway,
        ):
            result = PaymentService.create_payment_intent_for_invoice(
                invoice_id=self.invoice.id,
                payment_method_id=self.payment_method.stripe_payment_method_id,
            )

        self.assertTrue(result["success"], result)
        payment = Payment.objects.get(invoice=self.invoice)
        submission = payment.recurring_submission
        self.assertEqual(payment.gateway_txn_id, "pi_durable_claim_335")
        self.assertEqual(submission.state, RecurringPaymentSubmission.State.SUBMITTED)
        self.assertIsNotNone(submission.submitted_at)

    def test_gateway_exception_records_last_error_on_the_durable_row(self) -> None:
        """A raising gateway must leave a diagnostic on the claim the reconciler
        will later pick up, not a silent in-flight row with an empty last_error."""
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.side_effect = RuntimeError("gateway wiring bug")

        with patch(
            "apps.billing.payment_service.PaymentGatewayFactory.create_gateway",
            return_value=gateway,
        ):
            result = PaymentService.create_payment_intent_for_invoice(
                invoice_id=self.invoice.id,
                payment_method_id=self.payment_method.stripe_payment_method_id,
            )

        self.assertFalse(result["success"], result)
        submission = RecurringPaymentSubmission.objects.get(payment__invoice=self.invoice)
        self.assertEqual(submission.state, RecurringPaymentSubmission.State.IN_FLIGHT)
        self.assertIn("gateway wiring bug", submission.last_error)

    def test_second_worker_cannot_submit_an_in_flight_attempt(self) -> None:
        payment = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            payment_method="stripe",
            amount_cents=self.invoice.total_cents,
            currency=self.currency,
            status="pending",
            idempotency_key=f"invoice:{self.invoice.id}:stripe:1",
            meta={
                "invoice_id": str(self.invoice.id),
                "invoice_number": self.invoice.number,
                "customer_id": str(self.customer.id),
                "platform": "PRAHO",
                "source": "recurring_billing",
                "gateway": "stripe",
                "stripe_customer_id": self.payment_method.stripe_customer_id,
                "stripe_payment_method_id": self.payment_method.stripe_payment_method_id,
            },
        )
        RecurringPaymentSubmission.objects.create(
            payment=payment,
            state=RecurringPaymentSubmission.State.IN_FLIGHT,
            claimed_at=timezone.now(),
            attempt_count=1,
        )
        gateway = MagicMock()

        with patch(
            "apps.billing.payment_service.PaymentGatewayFactory.create_gateway",
            return_value=gateway,
        ):
            result = PaymentService.create_payment_intent_for_invoice(
                invoice_id=self.invoice.id,
                payment_method_id=self.payment_method.stripe_payment_method_id,
            )

        self.assertFalse(result["success"], result)
        self.assertIn("in flight", (result.get("error") or "").lower())
        gateway.create_off_session_payment_intent.assert_not_called()
        payment.refresh_from_db()
        self.assertEqual(payment.status, "pending")
        self.assertFalse(payment.gateway_txn_id)

    def test_missing_durable_state_is_never_treated_as_safe_to_abandon(self) -> None:
        payment = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            payment_method="stripe",
            amount_cents=self.invoice.total_cents,
            currency=self.currency,
            status="pending",
            idempotency_key=f"invoice:{self.invoice.id}:stripe:missing-state",
            meta={"source": "recurring_billing"},
        )
        SettingsService.update_setting(
            key="billing.recurring_auto_collection_enabled",
            value=False,
            reason="Exercise missing durable-state fail-closed behavior",
        )

        result, submitted = _submit_recurring_charge_under_revocation_lock(
            customer_id=self.customer.id,
            payment=payment,
            revalidate=lambda: None,
            submit=lambda: _intent_result(payment_intent_id="pi_must_not_submit_missing_state"),
        )

        self.assertFalse(submitted)
        self.assertFalse(result["success"])
        payment.refresh_from_db()
        self.assertEqual(payment.status, "pending")

    def test_resumed_never_submitted_reservation_is_abandoned_after_disable(self) -> None:
        payment = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            payment_method="stripe",
            amount_cents=self.invoice.total_cents,
            currency=self.currency,
            status="pending",
            idempotency_key=f"invoice:{self.invoice.id}:stripe:1",
            meta={
                "invoice_id": str(self.invoice.id),
                "invoice_number": self.invoice.number,
                "customer_id": str(self.customer.id),
                "platform": "PRAHO",
                "source": "recurring_billing",
                "gateway": "stripe",
                "stripe_customer_id": self.payment_method.stripe_customer_id,
                "stripe_payment_method_id": self.payment_method.stripe_payment_method_id,
            },
        )
        submission = RecurringPaymentSubmission.objects.create(
            payment=payment,
            state=RecurringPaymentSubmission.State.RESERVED,
        )
        SettingsService.update_setting(
            key="billing.recurring_auto_collection_enabled",
            value=False,
            reason="Exercise durable pre-submit state",
        )
        gateway = MagicMock()

        with patch(
            "apps.billing.payment_service.PaymentGatewayFactory.create_gateway",
            return_value=gateway,
        ):
            result = PaymentService.create_payment_intent_for_invoice(
                invoice_id=self.invoice.id,
                payment_method_id=self.payment_method.stripe_payment_method_id,
            )

        self.assertFalse(result["success"], result)
        gateway.create_off_session_payment_intent.assert_not_called()
        payment.refresh_from_db()
        submission.refresh_from_db()
        self.assertEqual(payment.status, "failed")
        self.assertEqual(submission.state, RecurringPaymentSubmission.State.ABANDONED)

    def test_submitted_state_requires_claim_and_submission_evidence(self) -> None:
        payment = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            payment_method="stripe",
            amount_cents=self.invoice.total_cents,
            currency=self.currency,
            status="pending",
            idempotency_key=f"invoice:{self.invoice.id}:stripe:invalid-state",
            meta={"source": "recurring_billing"},
        )

        with self.assertRaises(IntegrityError), transaction.atomic():
            RecurringPaymentSubmission.objects.create(
                payment=payment,
                state=RecurringPaymentSubmission.State.SUBMITTED,
                claimed_at=timezone.now(),
                attempt_count=1,
            )

    def test_migration_quarantines_unbound_attempts_and_recovers_all_bound_unfinished_work(self) -> None:
        unbound = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            payment_method="stripe",
            amount_cents=self.invoice.total_cents,
            currency=self.currency,
            status="pending",
            idempotency_key=f"invoice:{self.invoice.id}:stripe:legacy-unbound",
            meta={"source": "recurring_billing"},
        )
        bound = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            payment_method="stripe",
            amount_cents=self.invoice.total_cents,
            currency=self.currency,
            status="pending",
            gateway_txn_id="pi_legacy_bound_335",
            idempotency_key=f"invoice:{self.invoice.id}:stripe:legacy-bound",
            meta={"source": "recurring_billing"},
        )
        now = timezone.now()
        legacy_subscription = self._create_aligned_subscription("LEGACY-CONVERSION", now)
        preparation = RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)
        self.assertEqual(preparation["proformas_created"], 1, preparation)
        legacy_proforma = legacy_subscription.billing_cycles.get().proforma
        succeeded_unconverted = Payment.objects.create(
            customer=self.customer,
            proforma=legacy_proforma,
            payment_method="stripe",
            amount_cents=legacy_proforma.total_cents,
            currency=self.currency,
            status="succeeded",
            gateway_txn_id="pi_legacy_succeeded_unconverted_409",
            idempotency_key=f"proforma:{legacy_proforma.id}:stripe:legacy-succeeded",
            meta={"source": "recurring_billing"},
        )
        migration = importlib.import_module("apps.billing.migrations.0044_recurring_payment_submission")

        migration.backfill_unfinished_recurring_submissions(
            django_apps,
            SimpleNamespace(connection=SimpleNamespace(alias="default")),
        )

        unbound.refresh_from_db()
        bound.refresh_from_db()
        succeeded_unconverted.refresh_from_db()
        self.assertEqual(unbound.recurring_submission.state, RecurringPaymentSubmission.State.MANUAL_REVIEW)
        self.assertEqual(bound.recurring_submission.state, RecurringPaymentSubmission.State.SUBMITTED)
        self.assertEqual(
            succeeded_unconverted.recurring_submission.state,
            RecurringPaymentSubmission.State.SUBMITTED,
        )
        self.assertIsNone(unbound.recurring_submission.submitted_at)
        self.assertIsNotNone(bound.recurring_submission.submitted_at)
        self.assertIsNotNone(succeeded_unconverted.recurring_submission.submitted_at)


class RecurringSubmissionReconciliationTestCase(_SubscriptionInvoicePaymentFixture, TestCase):
    """Missed webhooks must not leave a known or ambiguous Stripe attempt forever."""

    def _stale(self, submission: RecurringPaymentSubmission) -> None:
        old = timezone.now() - timedelta(hours=1)
        update_fields = {
            "claimed_at": old,
            "updated_at": old,
        }
        if submission.state == RecurringPaymentSubmission.State.SUBMITTED:
            update_fields["submitted_at"] = old
        RecurringPaymentSubmission.objects.filter(id=submission.id).update(
            **update_fields,
        )

    def test_bound_succeeded_intent_converges_without_webhook(self) -> None:
        payment = self._create_pending_invoice_payment("pi_missed_success_409")
        submission = payment.recurring_submission
        self._stale(submission)
        gateway = MagicMock()
        gateway.confirm_payment.return_value = self._succeeded_gateway_result()

        with patch(
            "apps.billing.payment_service.PaymentGatewayFactory.create_gateway",
            return_value=gateway,
        ):
            result = reconcile_recurring_payment_submissions(stale_after_seconds=0)

        self.assertTrue(result["success"], result)
        self.assertEqual(result["payments_converged"], 1)
        payment.refresh_from_db()
        self.invoice.refresh_from_db()
        self.assertEqual(payment.status, "succeeded")
        self.assertEqual(self.invoice.status, "paid")

    def test_bound_declined_intent_enters_dunning_without_webhook(self) -> None:
        payment = self._create_pending_invoice_payment("pi_missed_failure_409")
        submission = payment.recurring_submission
        self._stale(submission)
        gateway = MagicMock()
        gateway.confirm_payment.return_value = PaymentConfirmResult(
            success=True,
            status="requires_payment_method",
            error=None,
            amount=payment.amount_cents,
            amount_received=0,
            currency=self.currency.code.lower(),
            customer_id=self.payment_method.stripe_customer_id,
            payment_method_id=self.payment_method.stripe_payment_method_id,
            metadata=payment.meta,
        )

        with patch(
            "apps.billing.payment_service.PaymentGatewayFactory.create_gateway",
            return_value=gateway,
        ):
            result = reconcile_recurring_payment_submissions(stale_after_seconds=0)

        self.assertTrue(result["success"], result)
        self.assertEqual(result["payments_failed"], 1)
        payment.refresh_from_db()
        self.billing_cycle.refresh_from_db()
        self.subscription.refresh_from_db()
        self.assertEqual(payment.status, "failed")
        self.assertEqual(self.billing_cycle.collection_status, "past_due")
        self.assertEqual(self.subscription.status, "past_due")

    def test_gateway_retrieval_error_leaves_payment_pending_and_reports_failure(self) -> None:
        payment = self._create_pending_invoice_payment("pi_retrieve_error_409")
        self._stale(payment.recurring_submission)
        gateway = MagicMock()
        gateway.confirm_payment.return_value = PaymentConfirmResult(
            success=False,
            status="failed",
            error="Stripe unavailable",
        )

        with patch(
            "apps.billing.payment_service.PaymentGatewayFactory.create_gateway",
            return_value=gateway,
        ):
            result = reconcile_recurring_payment_submissions(stale_after_seconds=0)

        self.assertFalse(result["success"], result)
        self.assertEqual(len(result["errors"]), 1)
        payment.refresh_from_db()
        self.assertEqual(payment.status, "pending")
        self.assertEqual(payment.recurring_submission.last_error, "Stripe unavailable")

    def test_gateway_initialization_failure_releases_row_lease_and_reports_failure(self) -> None:
        payment = self._create_pending_invoice_payment("pi_gateway_init_error_409")
        self._stale(payment.recurring_submission)

        with patch(
            "apps.billing.payment_service.PaymentGatewayFactory.create_gateway",
            side_effect=RuntimeError("Stripe configuration unavailable"),
        ):
            result = reconcile_recurring_payment_submissions(stale_after_seconds=0)

        self.assertFalse(result["success"], result)
        payment.refresh_from_db()
        submission = payment.recurring_submission
        self.assertIsNone(submission.reconcile_claim_token)
        self.assertIsNone(submission.reconcile_claim_expires_at)
        self.assertIn("Stripe configuration unavailable", submission.last_error)

    def test_decline_fact_mismatch_fails_closed_without_entering_dunning(self) -> None:
        payment = self._create_pending_invoice_payment("pi_mismatched_failure_409")
        self._stale(payment.recurring_submission)
        gateway = MagicMock()
        gateway.confirm_payment.return_value = PaymentConfirmResult(
            success=True,
            status="requires_payment_method",
            error=None,
            amount=payment.amount_cents - 1,
            amount_received=0,
            currency=self.currency.code.lower(),
            customer_id=self.payment_method.stripe_customer_id,
            payment_method_id=self.payment_method.stripe_payment_method_id,
            metadata=payment.meta,
        )

        with (
            patch(
                "apps.billing.payment_service.PaymentGatewayFactory.create_gateway",
                return_value=gateway,
            ),
            patch("apps.common.validators.log_security_event") as security_log,
        ):
            result = reconcile_recurring_payment_submissions(stale_after_seconds=0)

        self.assertFalse(result["success"], result)
        payment.refresh_from_db()
        self.billing_cycle.refresh_from_db()
        self.assertEqual(payment.status, "pending")
        self.assertEqual(self.billing_cycle.collection_status, "scheduled")
        security_log.assert_called_once()

    def test_missed_proforma_success_webhook_still_converts_and_advances_entitlement(self) -> None:
        now = timezone.now()
        subscription = self._create_aligned_subscription("RECONCILE-PROFORMA", now)
        preparation = RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)
        self.assertEqual(preparation["proformas_created"], 1, preparation)
        cycle = subscription.billing_cycles.get()
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.return_value = _intent_result(
            payment_intent_id="pi_missed_proforma_success_409"
        )
        with patch(
            "apps.billing.payment_service.PaymentGatewayFactory.create_gateway",
            return_value=gateway,
        ):
            creation = PaymentService.create_payment_intent_for_proforma(
                cycle.proforma_id,
                self.payment_method.stripe_payment_method_id,
            )
        self.assertTrue(creation["success"], creation)
        payment = Payment.objects.get(gateway_txn_id="pi_missed_proforma_success_409")
        self._stale(payment.recurring_submission)
        gateway.confirm_payment.return_value = PaymentConfirmResult(
            success=True,
            status="succeeded",
            error=None,
            amount_received=payment.amount_cents,
            currency=self.currency.code.lower(),
            customer_id=self.payment_method.stripe_customer_id,
            payment_method_id=self.payment_method.stripe_payment_method_id,
            metadata={
                **payment.meta,
                "proforma_id": str(payment.proforma_id),
                "customer_id": str(payment.customer_id),
                "source": "recurring_billing",
                "payment_attempt": str(payment.id),
            },
        )

        with patch(
            "apps.billing.payment_service.PaymentGatewayFactory.create_gateway",
            return_value=gateway,
        ):
            result = reconcile_recurring_payment_submissions(stale_after_seconds=0)

        self.assertTrue(result["success"], result)
        payment.refresh_from_db()
        cycle.refresh_from_db()
        subscription.refresh_from_db()
        self.assertEqual(payment.status, "succeeded")
        self.assertIsNotNone(payment.invoice_id)
        self.assertEqual(payment.invoice.status, "paid")
        self.assertEqual(payment.proforma.status, "converted")
        self.assertEqual(cycle.collection_status, "paid")
        self.assertEqual(subscription.status, "active")

    def test_failed_proforma_conversion_is_retried_after_payment_already_succeeded(self) -> None:
        now = timezone.now()
        subscription = self._create_aligned_subscription("RETRY-CONVERSION", now)
        preparation = RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)
        self.assertEqual(preparation["proformas_created"], 1, preparation)
        cycle = subscription.billing_cycles.get()
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.return_value = _intent_result(
            payment_intent_id="pi_retry_proforma_conversion_409"
        )
        with patch(
            "apps.billing.payment_service.PaymentGatewayFactory.create_gateway",
            return_value=gateway,
        ):
            creation = PaymentService.create_payment_intent_for_proforma(
                cycle.proforma_id,
                self.payment_method.stripe_payment_method_id,
            )
        self.assertTrue(creation["success"], creation)
        payment = Payment.objects.get(gateway_txn_id="pi_retry_proforma_conversion_409")
        self._stale(payment.recurring_submission)
        gateway.confirm_payment.return_value = PaymentConfirmResult(
            success=True,
            status="succeeded",
            error=None,
            amount_received=payment.amount_cents,
            currency=self.currency.code.lower(),
            customer_id=self.payment_method.stripe_customer_id,
            payment_method_id=self.payment_method.stripe_payment_method_id,
            metadata={
                **payment.meta,
                "proforma_id": str(payment.proforma_id),
                "customer_id": str(payment.customer_id),
                "source": "recurring_billing",
                "payment_attempt": str(payment.id),
            },
        )

        with (
            patch(
                "apps.billing.payment_service.PaymentGatewayFactory.create_gateway",
                return_value=gateway,
            ),
            patch(
                "apps.billing.proforma_service.ProformaPaymentService.record_payment_and_convert",
                return_value=Err("temporary conversion failure"),
            ),
        ):
            first = reconcile_recurring_payment_submissions(stale_after_seconds=0)

        self.assertFalse(first["success"], first)
        payment.refresh_from_db()
        self.assertEqual(payment.status, "succeeded")
        self.assertIsNone(payment.invoice_id)

        with patch(
            "apps.billing.payment_service.PaymentGatewayFactory.create_gateway",
            return_value=gateway,
        ):
            second = reconcile_recurring_payment_submissions(stale_after_seconds=0)

        self.assertTrue(second["success"], second)
        payment.refresh_from_db()
        cycle.refresh_from_db()
        self.assertIsNotNone(payment.invoice_id)
        self.assertEqual(payment.invoice.status, "paid")
        self.assertEqual(cycle.collection_status, "paid")

    def test_stale_unbound_claim_replays_the_same_idempotency_key(self) -> None:
        payment = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            payment_method="stripe",
            amount_cents=self.invoice.total_cents,
            currency=self.currency,
            status="pending",
            idempotency_key=f"invoice:{self.invoice.id}:stripe:1",
            meta={
                "invoice_id": str(self.invoice.id),
                "invoice_number": self.invoice.number,
                "customer_id": str(self.customer.id),
                "platform": "PRAHO",
                "source": "recurring_billing",
                "gateway": "stripe",
                "stripe_customer_id": self.payment_method.stripe_customer_id,
                "stripe_payment_method_id": self.payment_method.stripe_payment_method_id,
            },
        )
        submission = RecurringPaymentSubmission.objects.create(
            payment=payment,
            state=RecurringPaymentSubmission.State.IN_FLIGHT,
            claimed_at=timezone.now() - timedelta(hours=1),
            attempt_count=1,
        )
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.return_value = _intent_result(
            payment_intent_id="pi_replayed_unknown_335"
        )
        gateway.confirm_payment.return_value = PaymentConfirmResult(
            success=True,
            status="processing",
            error=None,
        )

        with patch(
            "apps.billing.payment_service.PaymentGatewayFactory.create_gateway",
            return_value=gateway,
        ):
            result = reconcile_recurring_payment_submissions(stale_after_seconds=0)

        self.assertTrue(result["success"], result)
        gateway.create_off_session_payment_intent.assert_called_once()
        self.assertEqual(
            gateway.create_off_session_payment_intent.call_args.kwargs["idempotency_key"],
            payment.idempotency_key,
        )
        payment.refresh_from_db()
        submission.refresh_from_db()
        self.assertEqual(payment.gateway_txn_id, "pi_replayed_unknown_335")
        self.assertEqual(payment.status, "pending")
        self.assertEqual(submission.attempt_count, 2)
        self.assertEqual(submission.state, RecurringPaymentSubmission.State.SUBMITTED)

    def test_returned_intent_is_recovered_when_local_binding_was_not_completed(self) -> None:
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.side_effect = [
            PaymentIntentResult(
                success=False,
                payment_intent_id="pi_returned_before_binding_335",
                client_secret=None,
                error="response handling interrupted",
                retryable=True,
            ),
            _intent_result(payment_intent_id="pi_returned_before_binding_335"),
        ]
        gateway.confirm_payment.return_value = PaymentConfirmResult(
            success=True,
            status="processing",
            error=None,
        )
        with patch(
            "apps.billing.payment_service.PaymentGatewayFactory.create_gateway",
            return_value=gateway,
        ):
            creation = PaymentService.create_payment_intent_for_invoice(
                invoice_id=self.invoice.id,
                payment_method_id=self.payment_method.stripe_payment_method_id,
            )
        self.assertFalse(creation["success"], creation)
        payment = Payment.objects.get(invoice=self.invoice)
        self.assertFalse(payment.gateway_txn_id)
        self.assertEqual(payment.recurring_submission.state, RecurringPaymentSubmission.State.SUBMITTED)
        self._stale(payment.recurring_submission)

        with patch(
            "apps.billing.payment_service.PaymentGatewayFactory.create_gateway",
            return_value=gateway,
        ):
            result = reconcile_recurring_payment_submissions(stale_after_seconds=0)

        self.assertTrue(result["success"], result)
        payment.refresh_from_db()
        self.assertEqual(payment.gateway_txn_id, "pi_returned_before_binding_335")
        self.assertEqual(
            [call.kwargs["idempotency_key"] for call in gateway.create_off_session_payment_intent.call_args_list],
            [payment.idempotency_key, payment.idempotency_key],
        )

    def test_reconciliation_is_bounded_and_reports_remaining_backlog(self) -> None:
        for index in range(3):
            payment = Payment.objects.create(
                customer=self.customer,
                invoice=self.invoice,
                payment_method="stripe",
                amount_cents=self.invoice.total_cents,
                currency=self.currency,
                status="pending",
                gateway_txn_id=f"pi_backlog_{index}",
                idempotency_key=f"invoice:{self.invoice.id}:stripe:{index + 1}",
                meta={"source": "recurring_billing"},
            )
            RecurringPaymentSubmission.objects.create(
                payment=payment,
                state=RecurringPaymentSubmission.State.SUBMITTED,
                claimed_at=timezone.now() - timedelta(hours=1),
                submitted_at=timezone.now() - timedelta(hours=1),
                attempt_count=1,
            )
        gateway = MagicMock()
        gateway.confirm_payment.return_value = PaymentConfirmResult(
            success=True,
            status="processing",
            error=None,
        )

        with patch(
            "apps.billing.payment_service.PaymentGatewayFactory.create_gateway",
            return_value=gateway,
        ):
            result = reconcile_recurring_payment_submissions(batch_size=2, stale_after_seconds=0)

        self.assertTrue(result["success"], result)
        self.assertEqual(result["payments_checked"], 2)
        self.assertGreaterEqual(result["backlog_remaining"], 1)
        self.assertEqual(gateway.confirm_payment.call_count, 2)

    def test_active_row_lease_is_not_stolen(self) -> None:
        payment = self._create_pending_invoice_payment("pi_active_lease_409")
        submission = payment.recurring_submission
        RecurringPaymentSubmission.objects.filter(id=submission.id).update(
            submitted_at=timezone.now() - timedelta(hours=1),
            updated_at=timezone.now() - timedelta(hours=1),
            reconcile_claim_token=uuid.uuid4(),
            reconcile_claim_expires_at=timezone.now() + timedelta(minutes=5),
        )
        gateway = MagicMock()

        with patch(
            "apps.billing.payment_service.PaymentGatewayFactory.create_gateway",
            return_value=gateway,
        ):
            result = reconcile_recurring_payment_submissions(stale_after_seconds=0)

        self.assertTrue(result["success"], result)
        self.assertEqual(result["payments_checked"], 0)
        gateway.confirm_payment.assert_not_called()

    def test_legacy_ambiguous_attempt_requires_manual_review_without_gateway_io(self) -> None:
        payment = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            payment_method="stripe",
            amount_cents=self.invoice.total_cents,
            currency=self.currency,
            status="pending",
            idempotency_key=f"invoice:{self.invoice.id}:stripe:legacy-unknown",
            meta={"source": "recurring_billing"},
        )
        RecurringPaymentSubmission.objects.create(
            payment=payment,
            state=RecurringPaymentSubmission.State.MANUAL_REVIEW,
        )
        gateway = MagicMock()

        with patch(
            "apps.billing.payment_service.PaymentGatewayFactory.create_gateway",
            return_value=gateway,
        ):
            result = reconcile_recurring_payment_submissions(stale_after_seconds=0)

        self.assertFalse(result["success"], result)
        self.assertEqual(result["manual_review_required"], 1)
        self.assertEqual(result["payments_checked"], 0)
        gateway.confirm_payment.assert_not_called()
        gateway.create_off_session_payment_intent.assert_not_called()

    def test_pending_intent_is_not_polled_again_before_the_stale_window(self) -> None:
        payment = self._create_pending_invoice_payment("pi_poll_cooldown_409")
        self._stale(payment.recurring_submission)
        gateway = MagicMock()
        gateway.confirm_payment.return_value = PaymentConfirmResult(
            success=True,
            status="processing",
            error=None,
        )

        with patch(
            "apps.billing.payment_service.PaymentGatewayFactory.create_gateway",
            return_value=gateway,
        ):
            first = reconcile_recurring_payment_submissions()
            second = reconcile_recurring_payment_submissions()

        self.assertTrue(first["success"], first)
        self.assertEqual(first["payments_checked"], 1)
        self.assertTrue(second["success"], second)
        self.assertEqual(second["payments_checked"], 0)
        gateway.confirm_payment.assert_called_once_with("pi_poll_cooldown_409")

    def test_overlapping_reconciliation_run_skips_without_gateway_io(self) -> None:
        with patch("apps.billing.tasks.DistributedLock.acquire", return_value=False):
            result = reconcile_recurring_payment_submissions(stale_after_seconds=0)

        self.assertTrue(result["success"], result)
        self.assertTrue(result["skipped"])
        self.assertEqual(result["payments_checked"], 0)

    def test_skipped_run_still_reports_the_real_backlog_to_monitoring(self) -> None:
        """A lock-skipped run must not report zeros over an actual backlog."""
        payment = self._create_pending_invoice_payment("pi_skip_backlog_409")
        self._stale(payment.recurring_submission)

        with patch("apps.billing.tasks.DistributedLock.acquire", return_value=False):
            result = reconcile_recurring_payment_submissions(stale_after_seconds=0)

        self.assertTrue(result["success"], result)
        self.assertTrue(result["skipped"])
        self.assertEqual(result["payments_checked"], 0)
        self.assertEqual(result["payments_pending"], 0)
        self.assertGreaterEqual(result["backlog_remaining"], 1)
