"""Standalone customer-present checkout; one durable identity survives uncertain I/O."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import timedelta
from typing import Any, TypedDict
from uuid import UUID, uuid4

from django.core.exceptions import ValidationError
from django.db import connection, transaction
from django.utils import timezone
from django.utils.translation import gettext as _

from apps.common.encryption import decrypt_sensitive_data, encrypt_sensitive_data
from apps.common.types import Err, Ok, Result
from apps.promotions.locking import lock_document_context

from .gateways.base import BasePaymentGateway, PaymentGatewayFactory
from .payment_models import Payment
from .plan_change_models import PlanChange
from .plan_change_payment_models import PlanChangePaymentAttempt
from .proforma_models import ProformaInvoice
from .validators import log_security_event

LEASE = timedelta(minutes=2)
REPLAY_WINDOW = timedelta(hours=23)
MAX_CLIENT_SECRET_LENGTH = 4096


class PlanPaymentResult(TypedDict):
    state: str
    attempt_id: str
    payment_id: int
    payment_intent_id: str
    client_secret: str | None
    error: str | None


def payload_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _gateway() -> BasePaymentGateway:
    return PaymentGatewayFactory.create_gateway("stripe")


def _autocommit() -> None:
    if connection.in_atomic_block:
        raise RuntimeError("Plan payment gateway operations require autocommit")


@contextmanager
def _locked_change(change_id: UUID | str) -> Iterator[tuple[PlanChange, ProformaInvoice]]:
    hint = PlanChange.objects.values("proforma_id").get(pk=change_id)
    if hint["proforma_id"] is None:
        raise ValidationError(_("Confirm a positive standalone proforma before reserving payment."))
    with transaction.atomic():
        document = ProformaInvoice.objects.select_for_update(of=("self",), no_key=True).get(pk=hint["proforma_id"])
        lock_document_context(document)
        change = PlanChange.objects.get(pk=change_id)
        if change.proforma_id != document.pk:
            raise ValidationError(_("The commercial document changed; reload its current payment context."))
        yield change, document


def _identity(attempt: PlanChangePaymentAttempt, payment: Payment, change: PlanChange) -> None:
    payload = attempt.payload
    if (
        attempt.payload_hash != payload_hash(payload)
        or payload.get("idempotency_key") != attempt.idempotency_key
        or payment.idempotency_key != attempt.idempotency_key
        or payment.payment_method != "stripe"
        or payment.customer_id != change.customer_id
        or payment.proforma_id != change.proforma_id
        or payment.currency_id != change.currency_id
        or payment.amount_cents != change.total_cents
        or payload.get("amount_cents") != payment.amount_cents
        or payload.get("document_id") != str(payment.proforma_id)
        or payload.get("document_type") != "proforma"
        or payload.get("currency") != payment.currency.code
        or (payment.meta or {}).get("source") != "hosting_plan_change"
        or (payment.meta or {}).get("plan_change_id") != str(change.pk)
        or (payment.meta or {}).get("plan_change_attempt_id") != str(attempt.pk)
        or (payment.meta or {}).get("quote_fingerprint") != change.request_fingerprint
    ):
        log_security_event(
            "plan_change_payment_binding_rejected",
            {"attempt_id": str(attempt.pk), "payment_id": payment.pk, "plan_change_id": str(change.pk)},
        )
        raise ValidationError(_("The plan payment's durable owner, document or payload differs."))


@contextmanager
def _locked_attempt(attempt_id: UUID | str) -> Iterator[tuple[PlanChangePaymentAttempt, Payment, PlanChange]]:
    hint = PlanChangePaymentAttempt.objects.values("change_id", "payment_id").get(pk=attempt_id)
    with _locked_change(hint["change_id"]) as (change, _document):
        payment = Payment.objects.select_for_update(of=("self",), no_key=True).get(pk=hint["payment_id"])
        attempt = PlanChangePaymentAttempt.objects.select_for_update(of=("self",)).get(pk=attempt_id)
        _identity(attempt, payment, change)
        yield attempt, payment, change


def _result(attempt: PlanChangePaymentAttempt, change: PlanChange) -> PlanPaymentResult:
    secret = None
    if (
        attempt.state == "ready"
        and attempt.client_secret_ciphertext
        and timezone.now() < change.authority_expires_at
        and change.status == "payment_in_flight"
    ):
        secret = decrypt_sensitive_data(attempt.client_secret_ciphertext, aad=f"plan-payment:{attempt.pk}".encode())
    return {
        "state": attempt.state,
        "attempt_id": str(attempt.pk),
        "payment_id": attempt.payment_id,
        "payment_intent_id": attempt.gateway_intent_id,
        "client_secret": secret,
        "error": attempt.last_error or None,
    }


def reserve_plan_change_payment(
    change_id: UUID | str,
    *,
    customer_id: int,
    actor_id: int,
    expected_fingerprint: str,
) -> PlanChangePaymentAttempt:
    """The signed API authorizes the actor; bind its exact accepted quote here."""
    from .plan_change_validation import (  # noqa: PLC0415 -- Mandatory first-claim validator.
        PlanChangeConflict,
        validate_payment_claim,
    )

    with _locked_change(change_id) as (change, document):
        if change.customer_id != customer_id or change.requested_by_id != actor_id:
            raise ValidationError(_("This payment does not belong to the requested customer and accepted quote."))
        if change.request_fingerprint != expected_fingerprint:
            raise PlanChangeConflict(_("The payment quote changed. Reload its current fingerprint."))
        existing = PlanChangePaymentAttempt.objects.filter(change_id=change.pk).first()
        if existing is not None:
            return existing
        if (
            change.status != "awaiting_payment"
            or change.confirmed_at is None
            or change.direction != "upgrade"
            or change.total_cents <= 0
            or timezone.now() >= min(change.expires_at, change.authority_expires_at)
            or document.status not in {"sent", "accepted"}
            or document.customer_id != customer_id
            or document.currency_id != change.currency_id
            or (document.subtotal_cents, document.tax_cents, document.total_cents)
            != (change.net_cents, change.tax_cents, change.total_cents)
        ):
            raise ValidationError(_("The confirmed standalone quote is no longer payable."))
        validate_payment_claim(change)
        attempt_id = uuid4()
        key = f"pc:{attempt_id}"
        payment = Payment.objects.create(
            customer_id=customer_id,
            proforma=document,
            currency_id=change.currency_id,
            amount_cents=change.total_cents,
            payment_method="stripe",
            idempotency_key=key,
            meta={
                "source": "hosting_plan_change",
                "plan_change_id": str(change.pk),
                "plan_change_attempt_id": str(attempt_id),
                "quote_fingerprint": change.request_fingerprint,
            },
        )
        payload = {
            "document_id": str(document.pk),
            "document_type": "proforma",
            "amount_cents": change.total_cents,
            "currency": change.currency.code,
            "metadata": {
                "platform": "PRAHO",
                "source": "hosting_plan_change",
                "customer_id": str(customer_id),
                "payment_id": str(payment.pk),
                "plan_change_id": str(change.pk),
                "attempt_id": str(attempt_id),
                "proforma_id": str(document.pk),
                "quote_fingerprint": change.request_fingerprint,
            },
            "idempotency_key": key,
        }
        return PlanChangePaymentAttempt.objects.create(
            id=attempt_id,
            change=change,
            payment=payment,
            payload=payload,
            payload_hash=payload_hash(payload),
            idempotency_key=key,
        )


def _claim_submission(attempt_id: UUID | str) -> PlanPaymentResult | tuple[UUID, dict[str, Any]]:
    """Commit the immutable request and lease before returning any gateway authority."""
    with _locked_attempt(attempt_id) as (attempt, payment, change):
        now = timezone.now()
        if payment.status == "succeeded":
            # Payment success alone does not certify document conversion. A
            # lost commit callback must remain discoverable by the sweep.
            if attempt.state != "succeeded":
                attempt.state = "review"
            attempt.save(update_fields=["state", "updated_at"])
            return _result(attempt, change)
        if attempt.state in {"succeeded", "cancelled", "refused", "review"} or (
            attempt.state == "ready" and attempt.client_secret_ciphertext
        ):
            return _result(attempt, change)
        if attempt.lease_expires_at and attempt.lease_expires_at > now:
            return _result(attempt, change)
        if (attempt.replay_until is not None and now >= attempt.replay_until) or (
            attempt.first_submitted_at is None
            and (now >= change.authority_expires_at or change.status != "awaiting_payment")
        ):
            attempt.state, attempt.last_error = "review", "Payment authority or safe provider replay window expired"
            attempt.save(update_fields=["state", "last_error", "updated_at"])
            return _result(attempt, change)
        token = uuid4()
        attempt.state, attempt.lease_token, attempt.lease_expires_at = "submitting", token, now + LEASE
        if attempt.first_submitted_at is None:
            attempt.first_submitted_at, attempt.replay_until = now, now + REPLAY_WINDOW
        attempt.submission_count += 1
        attempt.last_error = ""
        attempt.save()
        if change.status == "awaiting_payment":
            change.begin_payment()
            change.save(update_fields=["status", "updated_at"])
        payload = attempt.payload
    return token, payload


def submit_plan_change_payment(attempt_id: UUID | str) -> PlanPaymentResult:
    """No new identity after uncertain issuance, quote expiry, or lease takeover."""
    _autocommit()
    claim = _claim_submission(attempt_id)
    if isinstance(claim, dict):
        return claim
    token, payload = claim
    try:
        response = _gateway().create_on_session_document_intent(**payload)
    except Exception:
        # SDK diagnostics can contain request secrets. Persist only a safe classification.
        response = {"success": False, "payment_intent_id": "", "client_secret": None, "retryable": True, "error": None}
    with _locked_attempt(attempt_id) as (attempt, payment, change):
        if attempt.lease_token != token:
            return _result(attempt, change)
        if attempt.state == "cancelled" or payment.status not in {"pending", "succeeded"}:
            attempt.lease_token = attempt.lease_expires_at = None
            attempt.save(update_fields=["lease_token", "lease_expires_at", "updated_at"])
            return _result(attempt, change)
        intent = response.get("payment_intent_id")
        if response.get("success") and isinstance(intent, str) and intent.startswith("pi_"):
            if (payment.gateway_txn_id and payment.gateway_txn_id != intent) or (
                attempt.gateway_intent_id and attempt.gateway_intent_id != intent
            ):
                attempt.state, attempt.last_error = "review", "Provider identity differs from the original attempt"
            else:
                payment.gateway_txn_id = attempt.gateway_intent_id = intent
                payment.save(update_fields=["gateway_txn_id", "updated_at"])
                secret = response.get("client_secret")
                if isinstance(secret, str) and 0 < len(secret) <= MAX_CLIENT_SECRET_LENGTH:
                    attempt.client_secret_ciphertext = encrypt_sensitive_data(
                        secret, aad=f"plan-payment:{attempt.pk}".encode()
                    )
                attempt.state = "succeeded" if payment.status == "succeeded" else "ready"
                attempt.last_error = ""
        else:
            attempt.state = "unknown" if response.get("retryable", True) else "refused"
            attempt.last_error = (
                "Provider submission is uncertain" if attempt.state == "unknown" else "Provider refused checkout"
            )
        attempt.lease_token = None
        attempt.lease_expires_at = None
        attempt.save()
        return _result(attempt, change)


def recover_unlinked_plan_change_attempt(
    gateway_intent_id: str,
    facts: Mapping[str, Any],
) -> Result[Payment, str]:
    """Payment→Attempt ONLY: an early authenticated webhook never takes higher business locks."""
    from .payment_convergence import PaymentSuccessService  # noqa: PLC0415 -- Shared exact fact validator.

    if not connection.in_atomic_block:
        raise RuntimeError("Early plan payment binding requires an atomic transaction")
    metadata = facts.get("metadata")
    if not isinstance(metadata, Mapping):
        return Err("Plan-change payment metadata is missing")
    attempt_id = metadata.get("attempt_id")
    if not isinstance(attempt_id, str):
        return Err("Plan-change payment attempt identity is missing")
    try:
        hint = PlanChangePaymentAttempt.objects.filter(pk=attempt_id).values("payment_id").first()
    except (ValueError, ValidationError, TypeError):
        hint = None
    if hint is None:
        return Err("Plan-change payment attempt was not found")
    payment = Payment.objects.select_for_update(of=("self",), no_key=True).get(pk=hint["payment_id"])
    attempt = PlanChangePaymentAttempt.objects.select_for_update(of=("self",)).get(payment_id=payment.pk)
    error = PaymentSuccessService._validate_gateway_facts(payment, facts)
    if (
        error
        or not isinstance(gateway_intent_id, str)
        or not gateway_intent_id.startswith("pi_")
        or attempt.first_submitted_at is None
        or attempt.payload_hash != payload_hash(attempt.payload)
        or any(metadata.get(key) != value for key, value in attempt.payload["metadata"].items())
        or (payment.gateway_txn_id and payment.gateway_txn_id != gateway_intent_id)
        or (attempt.gateway_intent_id and attempt.gateway_intent_id != gateway_intent_id)
    ):
        return Err(error or "Plan-change payment binding differs from its original issued attempt")
    payment.gateway_txn_id = attempt.gateway_intent_id = gateway_intent_id
    payment.save(update_fields=["gateway_txn_id", "updated_at"])
    attempt.save(update_fields=["gateway_intent_id", "updated_at"])
    return Ok(payment)


def stage_plan_change_settlement(payment: Payment) -> None:
    """Journal under Payment→Attempt; document recovery runs after the outermost commit."""
    if not connection.in_atomic_block:
        raise RuntimeError("The paid plan recovery journal requires its gateway-fact transaction")
    attempt = PlanChangePaymentAttempt.objects.select_for_update(of=("self",)).get(payment_id=payment.pk)
    _identity(attempt, payment, attempt.change)
    attempt.state = "review"
    attempt.last_error = "Payment received; original document convergence pending"
    attempt.lease_token = attempt.lease_expires_at = None
    attempt.save(update_fields=["state", "last_error", "lease_token", "lease_expires_at", "updated_at"])
    # Queue delivery/callback success is never authority. The persisted review
    # row remains in the bounded sweep if this process dies after committing facts.
    transaction.on_commit(lambda: recover_plan_change_payment(attempt.pk), robust=True)


def observe_plan_change_intent(gateway_intent_id: str, intent: Mapping[str, Any]) -> Result[Payment, str]:
    """A failed card/required SCA is pending; only actual provider cancellation is terminal."""
    facts = {
        "amount_received": intent.get("amount"),
        "currency": intent.get("currency"),
        "customer_id": intent.get("customer"),
        "metadata": intent.get("metadata"),
    }
    with transaction.atomic():
        bound = recover_unlinked_plan_change_attempt(gateway_intent_id, facts)
        if bound.is_err():
            return bound
        payment = bound.unwrap()
        attempt = PlanChangePaymentAttempt.objects.get(payment_id=payment.pk)
        status = intent.get("status")
        if status not in {
            "requires_payment_method",
            "requires_confirmation",
            "requires_action",
            "processing",
            "canceled",
        }:
            return Err("Unsupported standalone plan intent status")
        if payment.status == "pending" and attempt.provider_status != "canceled":
            attempt.provider_status = str(status)
            if status == "canceled":
                # Do not run Payment failure signals while the webhook owns
                # Payment ahead of Customer. Retain the verified provider fact
                # durably; terminal local effects use document-first recovery.
                attempt.state = "review"
                attempt.last_error = "Provider cancellation verified; local terminal convergence pending"
                attempt.lease_token = attempt.lease_expires_at = None
                transaction.on_commit(lambda: _close_cancelled_change(attempt.pk), robust=True)
            elif attempt.state not in {"review", "cancelled", "refused"}:
                attempt.state = "ready"
            attempt.save(
                update_fields=["state", "provider_status", "last_error", "lease_token", "lease_expires_at", "updated_at"]
            )
        return Ok(payment)


def _close_quote(change: PlanChange, *, expired: bool) -> None:
    if change.status == "payment_in_flight":
        change.expire_payment() if expired else change.cancel_payment()
    elif change.status == "awaiting_payment":
        change.expire() if expired else change.cancel()
    else:
        return
    change.save(update_fields=["status", "updated_at"])


def _close_cancelled_change(attempt_id: UUID | str) -> None:
    """Payment-first webhook releases its locks before entering document context."""
    with _locked_attempt(attempt_id) as (attempt, payment, change):
        if attempt.provider_status == "canceled" and payment.status == "pending":
            _finish_cancelled(
                attempt, payment, change, not_submitted=False, expired=timezone.now() >= change.authority_expires_at
            )
        elif attempt.state == "cancelled":
            _close_quote(change, expired=timezone.now() >= change.authority_expires_at)


def _finish_cancelled(
    attempt: PlanChangePaymentAttempt,
    payment: Payment,
    change: PlanChange,
    *,
    not_submitted: bool,
    expired: bool,
) -> None:
    proof = "never_submitted" if not_submitted else "provider_cancelled"
    if payment.status != "pending":
        raise ValidationError(_("A settled or disputed payment cannot be cancelled by checkout."))
    payment.apply_gateway_event("failed", {"plan_change_terminal_proof": proof})
    attempt.state = "cancelled"
    attempt.provider_status = "not_submitted" if not_submitted else "canceled"
    attempt.lease_token = attempt.lease_expires_at = None
    attempt.last_error = ""
    attempt.save()
    _close_quote(change, expired=expired)


def cancel_plan_change_payment(attempt_id: UUID | str, *, expired: bool = False) -> PlanPaymentResult:  # noqa: PLR0911 -- Refuse each unsafe terminal proof independently.
    """Release only proven never-issued work or a verified original cancelled PI."""
    _autocommit()
    with _locked_attempt(attempt_id) as (attempt, payment, change):
        if attempt.state == "cancelled":
            _close_quote(change, expired=expired)
            return _result(attempt, change)
        if payment.status == "succeeded":
            return _result(attempt, change)
        if attempt.provider_status == "canceled":
            _finish_cancelled(attempt, payment, change, not_submitted=False, expired=expired)
            return _result(attempt, change)
        if attempt.first_submitted_at is None:
            _finish_cancelled(attempt, payment, change, not_submitted=True, expired=expired)
            return _result(attempt, change)
        if not attempt.gateway_intent_id or (attempt.lease_expires_at and attempt.lease_expires_at > timezone.now()):
            return _result(attempt, change)
        token = uuid4()
        attempt.lease_token, attempt.lease_expires_at = token, timezone.now() + LEASE
        attempt.state, attempt.provider_status = "submitting", "cancel_requested"
        attempt.save()
        intent_id, payload = attempt.gateway_intent_id, attempt.payload
    try:
        facts = _gateway().cancel_on_session_document_intent(
            payment_intent_id=intent_id,
            amount_cents=payload["amount_cents"],
            currency=payload["currency"],
            metadata=payload["metadata"],
            idempotency_key=f"pc-cancel:{attempt_id}",
        )
    except Exception:
        facts = {"success": False, "status": "unknown", "error": None}
    if facts.get("success") and facts.get("status") == "succeeded":
        return _converge_recovered_success(attempt_id, intent_id, facts)
    with _locked_attempt(attempt_id) as (attempt, payment, change):
        if attempt.lease_token != token or payment.status == "succeeded":
            return _result(attempt, change)
        if attempt.state == "cancelled":
            _close_quote(change, expired=expired)
            return _result(attempt, change)
        if facts.get("success") and facts.get("status") == "canceled" and _facts_match(payment, facts):
            _finish_cancelled(attempt, payment, change, not_submitted=False, expired=expired)
        else:
            attempt.state, attempt.last_error = "unknown", "Original provider cancellation remains uncertain"
            attempt.lease_token = attempt.lease_expires_at = None
            attempt.save()
        return _result(attempt, change)


def _facts_match(payment: Payment, facts: Mapping[str, Any]) -> bool:
    from .payment_convergence import PaymentSuccessService  # noqa: PLC0415

    checked = {**facts, "amount_received": facts.get("amount"), "customer_id": facts.get("customer_id")}
    return PaymentSuccessService._validate_gateway_facts(payment, checked) is None


def _converge_recovered_success(
    attempt_id: UUID | str,
    intent_id: str,
    facts: Mapping[str, Any],
) -> PlanPaymentResult:
    from .payment_convergence import PaymentSuccessService  # noqa: PLC0415
    from .proforma_service import ProformaPaymentService  # noqa: PLC0415

    settled = PaymentSuccessService.converge_gateway_success(intent_id, facts)
    if settled.is_ok():
        payment = settled.unwrap()
        if payment.proforma_id is not None:
            converted = ProformaPaymentService.record_payment_and_convert(
                str(payment.proforma_id),
                payment.amount_cents,
                "stripe",
                existing_payment=payment,
            )
            if converted.is_err():
                with _locked_attempt(attempt_id) as (attempt, _payment, change):
                    attempt.state, attempt.last_error = (
                        "review",
                        "Payment received; original document conversion pending",
                    )
                    attempt.lease_token = attempt.lease_expires_at = None
                    attempt.save()
                    return _result(attempt, change)
    with _locked_attempt(attempt_id) as (attempt, payment, change):
        attempt.state = "succeeded" if settled.is_ok() else "review"
        attempt.last_error = "" if settled.is_ok() else "Verified provider facts require payment review"
        attempt.lease_token = attempt.lease_expires_at = None
        attempt.save()
        return _result(attempt, change)


def recover_plan_change_payment(attempt_id: UUID | str) -> PlanPaymentResult:  # noqa: PLR0911, PLR0912 -- Reconcile each definitive/uncertain provider outcome.
    """Read a bound PI indefinitely; replay an unbound create only inside its original window."""
    _autocommit()
    with _locked_attempt(attempt_id) as (attempt, payment, change):
        paid = payment.status == "succeeded"
        if attempt.provider_status == "canceled" and payment.status == "pending":
            _finish_cancelled(
                attempt, payment, change, not_submitted=False, expired=timezone.now() >= change.authority_expires_at
            )
            return _result(attempt, change)
        if paid:
            from .signals import (  # noqa: PLC0415 -- Avoid billing signal cycle.
                settle_plan_change_payment_credit,
            )

            settle_plan_change_payment_credit(payment)
        never_issued_expired = attempt.first_submitted_at is None and (
            timezone.now() >= change.authority_expires_at or change.status in {"cancelled", "expired"}
        )
        intent_id = attempt.gateway_intent_id
        if paid or not intent_id:
            replay = True
        else:
            replay = False
            if attempt.state == "cancelled" or (attempt.lease_expires_at and attempt.lease_expires_at > timezone.now()):
                return _result(attempt, change)
            token = uuid4()
            attempt.lease_token, attempt.lease_expires_at = token, timezone.now() + LEASE
            attempt.save(update_fields=["lease_token", "lease_expires_at", "updated_at"])
    if never_issued_expired:
        return cancel_plan_change_payment(attempt_id, expired=True)
    if paid:
        # Gateway facts already committed. Retry real fiscal conversion rather
        # than silently declaring a paid-but-unfulfilled proforma complete.
        from .proforma_service import ProformaPaymentService  # noqa: PLC0415

        converted = ProformaPaymentService.record_payment_and_convert(
            str(payment.proforma_id),
            payment.amount_cents,
            "stripe",
            existing_payment=payment,
        )
        with _locked_attempt(attempt_id) as (attempt, _payment, change):
            attempt.state = "succeeded" if converted.is_ok() else "review"
            attempt.last_error = "" if converted.is_ok() else "Payment received; original document conversion pending"
            attempt.lease_token = attempt.lease_expires_at = None
            attempt.save()
            return _result(attempt, change)
    if replay:
        return submit_plan_change_payment(attempt_id)
    try:
        facts = _gateway().confirm_payment(intent_id)
    except Exception:
        facts = {"success": False, "status": "unknown", "error": None}
    if facts.get("success") and facts.get("status") == "succeeded":
        return _converge_recovered_success(attempt_id, intent_id, facts)
    with _locked_attempt(attempt_id) as (attempt, payment, change):
        if attempt.lease_token != token:
            return _result(attempt, change)
        status = facts.get("status")
        if (
            facts.get("success")
            and _facts_match(payment, facts)
            and status
            in {
                "requires_payment_method",
                "requires_confirmation",
                "requires_action",
                "processing",
                "canceled",
            }
        ):
            attempt.provider_status = str(status)
            if status == "canceled":
                _finish_cancelled(
                    attempt, payment, change, not_submitted=False, expired=timezone.now() >= change.authority_expires_at
                )
                return _result(attempt, change)
            attempt.state = "ready"
        else:
            attempt.state, attempt.last_error = "unknown", "Original provider status remains uncertain"
        attempt.lease_token = attempt.lease_expires_at = None
        attempt.save()
        result = _result(attempt, change)
        authority_expired = timezone.now() >= change.authority_expires_at
    return cancel_plan_change_payment(attempt_id, expired=True) if authority_expired else result


def recover_plan_change_payments(*, limit: int = 50) -> dict[str, int]:
    """Durable bounded scheduler entrypoint; queue delivery is never payment authority."""
    _autocommit()
    counts: dict[str, int] = {}
    identifiers = list(
        PlanChangePaymentAttempt.objects.exclude(state__in=("cancelled", "refused", "succeeded"))
        .order_by("updated_at")
        .values_list("pk", flat=True)[:limit]
    )
    for identifier in identifiers:
        try:
            state = recover_plan_change_payment(identifier)["state"]
        except (ValidationError, ValueError, RuntimeError):
            state = "review"
        counts[state] = counts.get(state, 0) + 1
    return counts
