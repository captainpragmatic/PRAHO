"""Durable customer-present voucher funding, isolated from recurring collection."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext as _

from apps.common.types import Err, Ok, Result

from .models import GiftCard, GiftCardFundingAttempt, GiftCardPurchase

if TYPE_CHECKING:
    from apps.billing.payment_models import Payment

UNBOUND_RETRY_WINDOW = timedelta(hours=23)
FUNDING_STATES = frozenset(
    {
        "requires_payment_method",
        "requires_confirmation",
        "requires_action",
        "processing",
        "succeeded",
        "canceled",
    }
)


def _attempt_for_purchase(purchase: GiftCardPurchase, payment: Payment) -> GiftCardFundingAttempt:
    existing = GiftCardFundingAttempt.objects.filter(purchase=purchase).first()
    if existing is not None:
        return existing
    if not payment.idempotency_key:
        raise ValidationError(_("The original funding request identifier needs review."))
    attempt = GiftCardFundingAttempt(
        purchase=purchase,
        amount_cents=payment.amount_cents,
        currency_id=payment.currency_id,
        idempotency_key=payment.idempotency_key,
    )
    metadata = {
        "source": "gift_card_funding",
        "purchase_id": str(purchase.pk),
        "customer_id": str(purchase.customer_id),
    }
    legacy_started = all((payment.meta or {}).get(key) == value for key, value in metadata.items())
    if legacy_started:
        # The original request's creation time is not known; this earlier timestamp
        # conservatively bounds replay and preserves the exact old Stripe parameters.
        attempt.first_submitted_at = payment.created_at
    else:
        metadata["gift_funding_attempt_id"] = str(attempt.pk)
    attempt.request_metadata = metadata
    attempt.gateway_intent_id = payment.gateway_txn_id or None
    attempt.client_secret = str((payment.meta or {}).get("client_secret") or "")
    attempt.save()
    return attempt


def _response(attempt: GiftCardFundingAttempt, *, success: bool = True) -> dict[str, Any]:
    return {
        "success": success,
        "payment_intent_id": attempt.gateway_intent_id or "",
        "client_secret": attempt.client_secret or None,
        "status": attempt.status,
        "error": None if success else _("Payment verification is temporarily unavailable. Please try again."),
    }


def start_funding(purchase: GiftCardPurchase) -> dict[str, Any]:  # noqa: C901, PLR0915  # Reserve, call provider, bind exact identity
    """Commit one immutable request before I/O; never recreate an expired unbound request."""
    from apps.billing.gateways import PaymentGatewayFactory  # noqa: PLC0415  # ADR-0007
    from apps.billing.payment_models import Payment  # noqa: PLC0415  # ADR-0007

    with transaction.atomic(durable=True):
        purchase = GiftCardPurchase.objects.select_for_update().get(pk=purchase.pk)
        card = GiftCard.objects.select_for_update().get(pk=purchase.gift_card_id)
        payment = Payment.objects.select_for_update().get(pk=purchase.funding_payment_id)
        if payment.payment_method != "stripe":
            raise ValidationError(_("This purchase is awaiting a bank transfer."))
        if (payment.amount_cents, payment.currency_id, payment.customer_id) != (
            card.initial_value_cents,
            card.currency_id,
            purchase.customer_id,
        ):
            raise ValidationError(_("The original gift-card funding details require review."))
        attempt = _attempt_for_purchase(purchase, payment)
        if attempt.status == "canceled" or (payment.status != "pending" and not purchase.funded_at):
            raise ValidationError(_("This payment is closed. Create a new purchase to pay again."))
        expired_unbound = (
            not attempt.gateway_intent_id
            and attempt.first_submitted_at is not None
            and timezone.now() - attempt.first_submitted_at >= UNBOUND_RETRY_WINDOW
        )
        if expired_unbound:
            attempt.status = "needs_review"  # fsm-bypass: Durable gift attempt CharField
            attempt.error_code = "unbound_idempotency_window_expired"
            attempt.save(update_fields=["status", "error_code"])
        elif not attempt.gateway_intent_id:
            attempt.first_submitted_at = attempt.first_submitted_at or timezone.now()
            attempt.status = "submitting"  # fsm-bypass: Durable gift attempt CharField
            attempt.save(update_fields=["first_submitted_at", "status"])
            payment.meta = {**payment.meta, **attempt.request_metadata}
            payment.save(update_fields=["meta", "updated_at"])
    if expired_unbound:
        raise ValidationError(_("This payment needs review before another charge can be attempted."))
    if attempt.gateway_intent_id:
        return refresh_funding(purchase.pk)
    try:
        result = PaymentGatewayFactory.create_gateway("stripe").create_payment_intent(
            order_id=str(purchase.pk),
            amount_cents=attempt.amount_cents,
            currency=attempt.currency_id,
            metadata=attempt.request_metadata,
            idempotency_key=attempt.idempotency_key,
        )
    except (OSError, TimeoutError, ValueError, ImportError):
        result = {"success": False, "payment_intent_id": "", "client_secret": None, "error": "provider_unavailable"}
    with transaction.atomic():
        GiftCardPurchase.objects.select_for_update().get(pk=purchase.pk)
        locked_payment = Payment.objects.select_for_update().get(pk=payment.pk)
        attempt = GiftCardFundingAttempt.objects.select_for_update().get(pk=attempt.pk)
        remote_id = result.get("payment_intent_id")
        if result.get("success") and isinstance(remote_id, str) and remote_id:
            if attempt.gateway_intent_id not in {None, "", remote_id} or locked_payment.gateway_txn_id not in {
                None,
                "",
                remote_id,
            }:
                raise ValidationError(_("The funding attempt is already linked to a different payment."))
            attempt.gateway_intent_id = remote_id
            attempt.client_secret = str(result.get("client_secret") or attempt.client_secret)
            if attempt.status in {"reserved", "submitting", "unknown"}:
                attempt.status = "requires_payment_method"  # fsm-bypass: Durable gift attempt CharField
            locked_payment.gateway_txn_id = remote_id
            locked_payment.meta = {**locked_payment.meta, "client_secret": attempt.client_secret}
            locked_payment.save(update_fields=["gateway_txn_id", "meta", "updated_at"])
        elif not attempt.gateway_intent_id:
            attempt.status = "unknown"  # fsm-bypass: Durable gift attempt CharField
            attempt.error_code = "provider_response_unavailable"
        attempt.save(update_fields=["gateway_intent_id", "client_secret", "status", "error_code"])
        return _response(attempt, success=bool(attempt.gateway_intent_id))


def refresh_funding(purchase_id: UUID | str) -> dict[str, Any]:
    from apps.billing.gateways import PaymentGatewayFactory  # noqa: PLC0415  # ADR-0007

    attempt = GiftCardFundingAttempt.objects.filter(purchase__pk=purchase_id).first()
    if attempt is None:
        raise ValidationError(_("Start the payment before checking its provider status."))
    if not attempt.gateway_intent_id:
        raise ValidationError(_("This purchase has no verified payment-provider reference yet."))
    facts = PaymentGatewayFactory.create_gateway("stripe").confirm_payment(attempt.gateway_intent_id)
    if not facts.get("success"):
        return _response(attempt, success=False)
    convergence = converge_gift_funding(attempt.gateway_intent_id, facts)
    if convergence is None or convergence.is_err():
        raise ValidationError(convergence.unwrap_err() if convergence is not None else _("Gift purchase not found."))
    attempt.refresh_from_db()
    return _response(attempt)


def _purchase_for_intent(intent_id: str, facts: Mapping[str, Any]) -> GiftCardPurchase | None:
    purchase = GiftCardPurchase.objects.filter(funding_payment__gateway_txn_id=intent_id).first()
    if purchase is not None:
        return purchase
    metadata = facts.get("metadata")
    if not isinstance(metadata, Mapping) or metadata.get("source") != "gift_card_funding":
        return None
    purchase_id = metadata.get("purchase_id")
    customer_id = metadata.get("customer_id")
    attempt_id = metadata.get("gift_funding_attempt_id")
    if not isinstance(purchase_id, str) or not isinstance(customer_id, str) or not isinstance(attempt_id, str):
        return None
    try:
        return GiftCardPurchase.objects.filter(
            pk=purchase_id,
            customer_id=customer_id,
            funding_attempt__id=attempt_id,
        ).first()
    except (ValidationError, ValueError, TypeError):
        return None


def converge_gift_funding(  # noqa: C901, PLR0911  # Reject each financial identity mismatch before state changes
    intent_id: str,
    facts: Mapping[str, Any],
) -> Result[Payment, str] | None:
    """Only verified provider facts can fund the exact durable purchase/attempt pair."""
    from apps.billing.payment_models import Payment  # noqa: PLC0415  # ADR-0007

    from .gift_cards import activate_verified_purchase  # noqa: PLC0415  # Function-level cycle

    snapshot = _purchase_for_intent(intent_id, facts)
    if snapshot is None:
        metadata = facts.get("metadata")
        if isinstance(metadata, Mapping) and metadata.get("source") == "gift_card_funding":
            return Err("Gift-card funding attempt was not found")
        return None
    with transaction.atomic():
        purchase = GiftCardPurchase.objects.select_for_update().get(pk=snapshot.pk)
        card = GiftCard.objects.select_for_update().get(pk=purchase.gift_card_id)
        payment = Payment.objects.select_for_update().get(pk=purchase.funding_payment_id)
        attempt = GiftCardFundingAttempt.objects.select_for_update().filter(purchase=purchase).first()
        status = facts.get("status")
        amount = facts.get("amount_received") if status == "succeeded" else facts.get("amount")
        if (
            status not in FUNDING_STATES
            or type(amount) is not int
            or amount != card.initial_value_cents
            or payment.amount_cents != card.initial_value_cents
            or payment.currency_id != card.currency_id
            or payment.customer_id != purchase.customer_id
            or payment.payment_method != "stripe"
            or not isinstance(facts.get("currency"), str)
            or str(facts["currency"]).upper() != card.currency_id
        ):
            return Err("Gift-card gateway status, amount, currency or buyer mismatch")
        if payment.gateway_txn_id not in {None, "", intent_id}:
            return Err("Gift-card gateway payment identity mismatch")
        if attempt is not None:
            metadata = facts.get("metadata")
            if (
                attempt.gateway_intent_id not in {None, "", intent_id}
                or attempt.amount_cents != payment.amount_cents
                or attempt.currency_id != payment.currency_id
                or not isinstance(metadata, Mapping)
                or any(metadata.get(key) != value for key, value in attempt.request_metadata.items())
            ):
                return Err("Gift-card immutable funding attempt metadata mismatch")
        elif not payment.gateway_txn_id:
            return Err("Gift-card funding requires a durable attempt before gateway I/O")
        if purchase.funded_at is not None:
            return Ok(payment)
        if payment.status != "pending":
            return Err("Gift-card funding is already closed")
        payment.gateway_txn_id = intent_id
        payment.meta = {**payment.meta, "stripe_status": status, "stripe_payment_intent": intent_id}
        payment.save(update_fields=["gateway_txn_id", "meta", "updated_at"])
        if attempt is not None:
            attempt.gateway_intent_id = intent_id
            attempt.status = str(status)  # fsm-bypass: Durable gift attempt CharField
            attempt.checked_at = timezone.now()
            attempt.error_code = ""
            attempt.save(update_fields=["gateway_intent_id", "status", "checked_at", "error_code"])
        if status == "succeeded":
            payment._defer_document_settlement = True
            payment.apply_gateway_event(
                "succeeded",
                {
                    "stripe_amount_received": amount,
                    "stripe_currency": facts["currency"],
                },
            )
            activate_verified_purchase(purchase.pk)
        elif status == "canceled":
            payment.apply_gateway_event("failed", {"gift_funding_canceled": True})
        # A declined intent returns to requires_payment_method and remains the same
        # customer-present attempt. Recurring collection/dunning is never entered.
        return Ok(payment)
