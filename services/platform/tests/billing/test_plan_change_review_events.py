"""Financial invalidation facts remain immutable and cannot acquire business FK locks."""

from contextlib import ExitStack
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.db import connection, transaction
from django.test import TestCase, TransactionTestCase

from apps.billing.models import Payment
from apps.billing.plan_change_review_models import PlanChangeReviewEvent
from apps.billing.plan_change_review_service import process_financial_review, sweep_financial_reviews
from apps.billing.proforma_models import ProformaInvoice
from apps.customers.models import Customer
from apps.settings.services import SettingsService
from tests.common.postgres_locking import backend_pid, database_worker, wait_for_blocker
from tests.helpers.plan_change_checkout import VerifiedPlanChangeCheckoutFixture


class PlanChangeReviewEventTests(TestCase):
    def event(self) -> PlanChangeReviewEvent:
        return PlanChangeReviewEvent.objects.create(
            fact_key="b" * 64,
            source_kind="payment",
            source_id="42",
            reason="dispute",
            customer_id=7,
            payment_id=42,
            invoice_id=13,
        )

    def test_existing_fact_cannot_be_retargeted_by_model_save(self) -> None:
        event = self.event()
        event.invoice_id = 14
        with self.assertRaises(ValidationError):
            event.save()
        event.refresh_from_db()
        self.assertEqual(event.invoice_id, 13)

    def test_queryset_cannot_replace_or_delete_financial_evidence(self) -> None:
        event = self.event()
        with self.assertRaises(ValidationError):
            PlanChangeReviewEvent.objects.filter(pk=event.pk).update(source_id="99")
        with self.assertRaises(ValidationError):
            PlanChangeReviewEvent.objects.filter(pk=event.pk).delete()

    def test_constructed_existing_primary_key_cannot_overwrite_a_fact(self) -> None:
        event = self.event()
        replacement = PlanChangeReviewEvent(
            id=event.pk,
            fact_key=event.fact_key,
            source_kind="payment",
            source_id="99",
            reason="dispute",
            customer_id=7,
            payment_id=99,
            invoice_id=13,
        )
        with self.assertRaises(ValidationError):
            replacement.save()


class SignedPlanChangeReviewTests(VerifiedPlanChangeCheckoutFixture, TransactionTestCase):
    @staticmethod
    def dispute_payload():
        return {
            "id": "evt_review_" + uuid4().hex,
            "type": "charge.dispute.created",
            "api_version": "2023-10-16",
            "data": {
                "object": {
                    "id": "dp_plan_review",
                    "payment_intent": "pi_signed_plan",
                    "amount": 7260,
                    "currency": "ron",
                    "reason": "fraudulent",
                }
            },
        }

    def disputed_change(self):
        change, attempt, _sdk = self.ready_attempt()
        success, message, _paid_event = self.signed_delivery(attempt.payload["metadata"])
        self.assertTrue(success, message)
        change.refresh_from_db()
        self.assertEqual(change.status, "applying_limits")
        self.assertTrue(SettingsService.update_setting("billing.hosting_plan_changes_enabled", False).is_ok())
        success, message, event = self.deliver_signed_payload(self.dispute_payload())
        self.assertTrue(success, message)
        self.assertIsNotNone(event)
        payment = Payment.objects.get(pk=attempt.payment_id)
        self.assertEqual(payment.status, "disputed")
        return change, payment

    def test_signed_dispute_records_the_financial_fact_before_any_review_worker(self) -> None:
        change, payment = self.disputed_change()
        events = list(PlanChangeReviewEvent.objects.filter(payment_id=payment.pk))
        self.assertEqual(len(events), 1)
        self.assertEqual(
            (events[0].customer_id, events[0].invoice_id, events[0].reason, events[0].source_id),
            (self.customer.pk, change.invoice_id, "dispute", "dp_plan_review"),
        )
        self.assertIsNone(events[0].processed_at)
        self.assertEqual(events[0].reviewed_changes, [])

    def test_actual_payment_first_webhook_commits_its_journal_while_customer_is_locked(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("Requires independent PostgreSQL transactions")
        _change, attempt, _sdk = self.ready_attempt()
        success, message, _event = self.signed_delivery(attempt.payload["metadata"])
        self.assertTrue(success, message)
        with transaction.atomic():
            Customer.all_objects.select_for_update(of=("self",)).get(pk=self.customer.pk)
            with database_worker(lambda: self.deliver_signed_payload(self.dispute_payload())) as (_pid, pending):
                success, message, event = pending.result(timeout=10)
                self.assertTrue(success, message)
                self.assertIsNotNone(event)
            self.assertEqual(PlanChangeReviewEvent.objects.filter(payment_id=attempt.payment_id).count(), 1)

    def test_dispute_review_is_durable_replayable_and_never_reverses_assigned_terms(self) -> None:
        change, payment = self.disputed_change()
        event = PlanChangeReviewEvent.objects.get(payment_id=payment.pk)
        self.subscription.refresh_from_db()
        self.service.refresh_from_db()
        before = (
            self.subscription.product_id,
            self.subscription.unit_price_cents,
            self.service.service_plan_id,
            self.service.price,
            change.limit_application_id,
        )
        for _delivery in range(2):
            process_financial_review(str(event.pk))
            change.refresh_from_db()
            self.assertEqual(change.status, "paid_review")
            self.assertIn("disput", change.review_reason)
        self.subscription.refresh_from_db()
        self.service.refresh_from_db()
        self.assertEqual(
            (
                self.subscription.product_id,
                self.subscription.unit_price_cents,
                self.service.service_plan_id,
                self.service.price,
                change.limit_application_id,
            ),
            before,
        )
        event.refresh_from_db()
        self.assertIsNotNone(event.processed_at)
        self.assertEqual(event.reviewed_changes, [str(change.pk)])

    def test_worker_waits_for_its_document_before_customer_and_sweep_recovers_lost_enqueue(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("Requires PostgreSQL row-lock observation")
        change, payment = self.disputed_change()
        event = PlanChangeReviewEvent.objects.get(payment_id=payment.pk)

        with database_worker(lambda: process_financial_review(str(event.pk))) as (_pid, first):
            first.result(timeout=30)
        # A second source on the original coverage invoice must invalidate the
        # accepted supplement too, including after completion of the first event.
        base_invoice = self.subscription.billing_cycles.order_by("period_start").first().invoice
        base_payment = base_invoice.payments.get()
        base_payment.dispute_payment()
        base_payment.save(update_fields=["status"])
        second = PlanChangeReviewEvent.objects.get(payment_id=base_payment.pk)
        blocker = backend_pid()
        with ExitStack() as workers, transaction.atomic():
            ProformaInvoice.objects.select_for_update(of=("self",)).get(pk=change.proforma_id)
            pid, pending = workers.enter_context(database_worker(sweep_financial_reviews))
            wait_for_blocker(pid, blocker, pending, table="billing_proforma_invoices")
            # Customer is not retained while this worker waits for its document.
            with database_worker(lambda: self._claim_customer_nowait(Customer, self.customer.pk)) as (
                _customer_pid,
                claim,
            ):
                self.assertTrue(claim.result(timeout=10))
        # The independent worker commits once the document owner releases it.
        self.assertEqual(pending.result(timeout=30), 1)
        second.refresh_from_db()
        self.assertIsNotNone(second.processed_at)
        self.assertEqual(second.reviewed_changes, [str(change.pk)])
        self.assertEqual(sweep_financial_reviews(), 0)

    @staticmethod
    def _claim_customer_nowait(model, customer_id: int) -> bool:
        with transaction.atomic():
            model.all_objects.select_for_update(of=("self",), nowait=True).get(pk=customer_id)
        return True
