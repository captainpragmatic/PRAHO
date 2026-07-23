"""Durable outbox state for PRAHO-owned recurring PaymentIntent submission."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from django.db import transaction
from django.utils import timezone

from .payment_models import Payment, RecurringPaymentSubmission

if TYPE_CHECKING:
    from .gateways.base import PaymentIntentResult


def ensure_recurring_submission(
    payment: Payment,
    *,
    payment_created: bool,
) -> RecurringPaymentSubmission:
    """Return the durable state row for a recurring Payment reservation.

    A missing row on an existing unbound Payment predates the outbox deployment
    and is therefore ambiguous: it may already have reached the gateway, but it
    has no durable authorization claim. Quarantine it for manual review rather
    than abandoning or automatically replaying it.
    """
    if payment_created:
        defaults: dict[str, object] = {
            "state": RecurringPaymentSubmission.State.RESERVED,
            "attempt_count": 0,
        }
    else:
        evidence_at = payment.updated_at or timezone.now()
        defaults = {
            "state": (
                RecurringPaymentSubmission.State.SUBMITTED
                if payment.gateway_txn_id
                else RecurringPaymentSubmission.State.MANUAL_REVIEW
            ),
            "claimed_at": evidence_at if payment.gateway_txn_id else None,
            "submitted_at": evidence_at if payment.gateway_txn_id else None,
            "attempt_count": 1 if payment.gateway_txn_id else 0,
        }
    submission, _created = RecurringPaymentSubmission.objects.get_or_create(
        payment=payment,
        defaults=defaults,
    )
    return submission


@transaction.atomic
def claim_recurring_submission(payment_id: int) -> str | None:
    """Atomically linearize one recurring attempt before gateway I/O."""
    submission = RecurringPaymentSubmission.objects.select_for_update(of=("self",)).get(payment_id=payment_id)
    if submission.state == RecurringPaymentSubmission.State.ABANDONED:
        return "Recurring payment submission was abandoned"
    if submission.state == RecurringPaymentSubmission.State.MANUAL_REVIEW:
        return "Recurring payment submission requires manual Stripe reconciliation"
    if submission.state != RecurringPaymentSubmission.State.RESERVED:
        return "Recurring payment submission is already in flight"

    submission.claim()
    submission.claimed_at = timezone.now()
    submission.attempt_count += 1
    submission.last_error = ""
    submission.save(
        update_fields=[
            "state",
            "claimed_at",
            "attempt_count",
            "last_error",
            "updated_at",
        ]
    )
    return None


@transaction.atomic
def mark_recurring_submission_abandoned_if_reserved(payment_id: int) -> bool:
    """Mark only a durably pre-submit reservation as abandoned."""
    submission = (
        RecurringPaymentSubmission.objects.select_for_update(of=("self",)).filter(payment_id=payment_id).first()
    )
    if submission is None:
        payment_source = Payment.objects.only("meta").get(id=payment_id).meta.get("source")
        # Checkout reservations predate and do not use the recurring outbox.
        # A recurring attempt without its control row is ambiguous, never
        # evidence that no provider request occurred.
        return not isinstance(payment_source, str) or payment_source != "recurring_billing"
    if submission.state != RecurringPaymentSubmission.State.RESERVED:
        return False
    submission.abandon()
    submission.save(update_fields=["state", "updated_at"])
    return True


def record_recurring_submission_result(payment_id: int, result: PaymentIntentResult) -> None:
    """Persist gateway-return evidence without guessing an ambiguous outcome."""
    with transaction.atomic():
        submission = RecurringPaymentSubmission.objects.select_for_update(of=("self",)).get(payment_id=payment_id)
        if submission.state not in {
            RecurringPaymentSubmission.State.IN_FLIGHT,
            RecurringPaymentSubmission.State.SUBMITTED,
        }:
            raise RuntimeError(f"Cannot record a gateway result for submission state '{submission.state}'")
        payment_intent_id = result.get("payment_intent_id") or ""
        submission.last_error = result.get("error") or ""
        update_fields = ["last_error", "updated_at"]
        if payment_intent_id:
            submission.mark_submitted()
            submission.submitted_at = timezone.now()
            update_fields.extend(["state", "submitted_at"])
        submission.save(update_fields=update_fields)


def record_recurring_submission_replay_started(
    submission_id: int,
    claim_token: UUID,
) -> RecurringPaymentSubmission:
    """Record one idempotent replay before the reconciler contacts Stripe."""
    with transaction.atomic():
        submission = (
            RecurringPaymentSubmission.objects.select_for_update(of=("self",))
            .select_related("payment__currency", "payment__invoice", "payment__proforma")
            .get(
                id=submission_id,
                state__in=[
                    RecurringPaymentSubmission.State.IN_FLIGHT,
                    RecurringPaymentSubmission.State.SUBMITTED,
                ],
                reconcile_claim_token=claim_token,
            )
        )
        submission.claimed_at = timezone.now()
        submission.attempt_count += 1
        submission.last_error = ""
        submission.save(update_fields=["claimed_at", "attempt_count", "last_error", "updated_at"])
        return submission
