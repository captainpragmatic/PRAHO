"""Original-tender refund holds, durable submissions and verified provider facts."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.db.models import Sum
from django.utils import timezone
from django.utils.translation import gettext as _

from apps.common.types import Err, Ok, Result, Retriability

from .models import GiftCard, GiftCardFundingRefund, GiftCardPurchase, GiftCardTransaction

if TYPE_CHECKING:
    from apps.billing.payment_models import Payment
    from apps.users.models import User

REFUND_STATUSES = frozenset({"pending", "requires_action", "succeeded", "failed", "canceled"})
REFUND_REASONS = frozenset({"requested_by_customer", "duplicate", "fraudulent"})
MAX_REFERENCE_LENGTH = 100
UNBOUND_RETRY_WINDOW = timedelta(hours=23)
TERMINAL_REFUND_STATES = frozenset({"succeeded", "failed", "canceled"})


def _invalid(message: str) -> Err[str]:
    return Err(message, retriability=Retriability.NOT_RETRIABLE)


def _lock_purchase(purchase_id: UUID | str) -> tuple[GiftCardPurchase, GiftCard, Payment]:
    from apps.billing.payment_models import Payment  # noqa: PLC0415  # ADR-0007

    purchase = GiftCardPurchase.objects.select_for_update().get(pk=purchase_id)
    card = GiftCard.objects.select_for_update().get(pk=purchase.gift_card_id)
    payment = Payment.objects.select_for_update().get(pk=purchase.funding_payment_id)
    return purchase, card, payment


@transaction.atomic
def reserve_funding_refund(
    purchase_id: UUID | str,
    amount_cents: int,
    key: str,
    *,
    actor: User,
    reason: str = "requested_by_customer",
) -> GiftCardFundingRefund:
    """Hold unused value locally. This records a request, never a money transfer."""
    if not actor.can_manage_financial_data:
        raise PermissionDenied
    if type(amount_cents) is not int or amount_cents <= 0 or reason not in REFUND_REASONS:
        raise ValidationError(_("Enter a valid refund amount and reason."))
    if not isinstance(key, str) or not key or len(key) > MAX_REFERENCE_LENGTH:
        raise ValidationError(_("A refund request identifier is required."))
    purchase, card, payment = _lock_purchase(purchase_id)
    identity = hashlib.sha256(f"gift-funding-refund:{purchase.pk}:{key}".encode()).hexdigest()
    existing = GiftCardFundingRefund.objects.filter(idempotency_key=identity).first()
    if existing:
        if (existing.amount_cents, existing.currency_id, existing.reason) != (amount_cents, card.currency_id, reason):
            raise ValidationError(_("This refund request already has different details."))
        return existing
    if (
        not purchase.funded_at
        or card.spending_frozen_at
        or payment.status not in {"succeeded", "partially_refunded"}
        or payment.payment_method not in {"stripe", "bank"}
        or payment.currency_id != card.currency_id
        or payment.amount_cents != card.initial_value_cents
        or (payment.payment_method == "stripe" and not payment.gateway_txn_id)
    ):
        raise ValidationError(_("This gift-card funding needs review before a refund."))
    committed = (
        purchase.funding_refunds.exclude(status__in=["failed", "canceled"]).aggregate(total=Sum("amount_cents"))[
            "total"
        ]
        or 0
    )
    if amount_cents > min(card.available_balance_cents, payment.amount_cents - committed):
        raise ValidationError(_("Refund only unused, unreserved value within the original funding amount."))
    refund = GiftCardFundingRefund.objects.create(
        purchase=purchase,
        currency_id=card.currency_id,
        amount_cents=amount_cents,
        idempotency_key=identity,
        reason=reason,
        created_by=actor,
        held_cents=amount_cents,
        funding_intent_id=(payment.gateway_txn_id or "") if payment.payment_method == "stripe" else "",
        status="awaiting_bank_transfer" if payment.payment_method == "bank" else "reserved",
    )
    card.refund_held_cents += amount_cents
    card.save(update_fields=["refund_held_cents", "updated_at"])
    return refund


def refund_purchase(
    purchase_id: UUID | str,
    amount_cents: int,
    key: str,
    *,
    actor: User,
    reason: str = "requested_by_customer",
) -> GiftCardFundingRefund:
    """Commit the hold before Stripe I/O; bank refunds await separate staff confirmation."""
    with transaction.atomic(durable=True):
        refund = reserve_funding_refund(purchase_id, amount_cents, key, actor=actor, reason=reason)
    return refresh_refund(refund.pk)


def _prepare_refund(refund_id: UUID | str) -> GiftCardFundingRefund:
    snapshot = GiftCardFundingRefund.objects.only("purchase_id").get(pk=refund_id)
    problem = ""
    with transaction.atomic(durable=True):
        purchase, card, payment = _lock_purchase(snapshot.purchase_id)
        refund = GiftCardFundingRefund.objects.select_for_update().get(pk=refund_id)
        if refund.status in TERMINAL_REFUND_STATES or refund.status == "awaiting_bank_transfer":
            return refund
        if (
            payment.payment_method != "stripe"
            or not payment.gateway_txn_id
            or not purchase.funded_at
            or refund.currency_id != card.currency_id
            or payment.currency_id != card.currency_id
            or payment.amount_cents != card.initial_value_cents
            or refund.funding_intent_id not in {"", payment.gateway_txn_id}
        ):
            problem = "original_funding_mismatch"
        elif not refund.funding_intent_id and (refund.first_submitted_at or refund.gateway_refund_id):
            # No new provider parameters may be inferred for an old submitted request.
            problem = "original_funding_unknown"
        elif not refund.gateway_refund_id and (
            refund.created_by_id is None
            or refund.held_cents != refund.amount_cents
            or refund.applied_cents
            or card.refund_held_cents < refund.held_cents
            or card.current_balance_cents < card.reserved_cents + card.refund_held_cents
        ):
            problem = "original_refund_hold_unverified"
        elif not refund.gateway_refund_id and (
            refund.status == "needs_review"
            or card.spending_frozen_at
            or (refund.first_submitted_at and timezone.now() - refund.first_submitted_at >= UNBOUND_RETRY_WINDOW)
        ):
            problem = "unbound_refund_requires_review"
        if problem:
            refund.status = "needs_review"  # fsm-bypass: Durable gift refund CharField
            refund.error_code = problem
            refund.save(update_fields=["status", "error_code"])
        else:
            refund.funding_intent_id = refund.funding_intent_id or payment.gateway_txn_id or ""
            refund.checked_at = timezone.now()
            if not refund.gateway_refund_id:
                refund.first_submitted_at = refund.first_submitted_at or timezone.now()
                refund.status = "submitting"  # fsm-bypass: Durable gift refund CharField
            refund.save(update_fields=["funding_intent_id", "checked_at", "first_submitted_at", "status"])
    if problem:
        raise ValidationError(_("This refund needs review before another provider request."))
    return refund


def _record_provider_problem(refund_id: UUID | str, *, review: bool) -> GiftCardFundingRefund:
    with transaction.atomic():
        refund = GiftCardFundingRefund.objects.select_for_update().get(pk=refund_id)
        if refund.status not in TERMINAL_REFUND_STATES:
            if review:
                refund.status = "needs_review"  # fsm-bypass: Durable gift refund CharField
            elif not refund.gateway_refund_id:
                refund.status = "unknown"  # fsm-bypass: Durable gift refund CharField
            refund.error_code = "provider_verification_required" if review else "provider_unavailable"
            refund.save(update_fields=["status", "error_code"])
        return refund


def _submit_refund(refund: GiftCardFundingRefund) -> GiftCardFundingRefund:
    from apps.billing.gateways import PaymentGatewayFactory  # noqa: PLC0415  # ADR-0007

    try:
        response = PaymentGatewayFactory.create_gateway("stripe").refund_payment(
            refund.funding_intent_id,
            amount_cents=refund.amount_cents,
            reason=refund.reason,
            idempotency_key=refund.idempotency_key,
            metadata={"gift_refund_id": str(refund.pk)},
        )
    except (OSError, ValueError, ImportError):
        return _record_provider_problem(refund.pk, review=False)
    remote_id = response.get("refund_id")
    if not response.get("success") or not isinstance(remote_id, str) or not remote_id:
        return _record_provider_problem(refund.pk, review=False)
    with transaction.atomic():
        refund = GiftCardFundingRefund.objects.select_for_update().get(pk=refund.pk)
        if refund.gateway_refund_id not in {None, "", remote_id}:
            raise ValidationError(_("This refund already has a different provider identity."))
        refund.gateway_refund_id = remote_id
        refund.save(update_fields=["gateway_refund_id"])
    return refund


def refresh_refund(refund_id: UUID | str) -> GiftCardFundingRefund:
    """Recover an existing request; only authoritative retrieval changes held value."""
    from apps.billing.gateways import PaymentGatewayFactory  # noqa: PLC0415  # ADR-0007

    refund = _prepare_refund(refund_id)
    if refund.status in TERMINAL_REFUND_STATES or refund.status == "awaiting_bank_transfer":
        return refund
    if not refund.gateway_refund_id:
        refund = _submit_refund(refund)
        if not refund.gateway_refund_id or refund.status in TERMINAL_REFUND_STATES:
            return refund
    try:
        facts = PaymentGatewayFactory.create_gateway("stripe").retrieve_refund(refund.gateway_refund_id)
    except (OSError, ValueError, ImportError):
        return _record_provider_problem(refund.pk, review=False)
    if not facts.get("success"):
        return _record_provider_problem(refund.pk, review=False)
    metadata = facts.get("metadata", {})
    if (
        facts.get("refund_id") != refund.gateway_refund_id
        or facts.get("payment_intent_id") != refund.funding_intent_id
        or facts.get("amount_cents") != refund.amount_cents
        or str(facts.get("currency", "")).upper() != refund.currency_id
        or not isinstance(metadata, Mapping)
        or (refund.created_by_id is not None and metadata.get("gift_refund_id") != str(refund.pk))
        or (metadata.get("gift_refund_id") is not None and metadata.get("gift_refund_id") != str(refund.pk))
    ):
        _record_provider_problem(refund.pk, review=True)
        raise ValidationError(_("The provider refund does not match the original request."))
    result = converge_gift_refund(facts)
    if result is None or result.is_err():
        _record_provider_problem(refund.pk, review=True)
        raise ValidationError(_("The provider refund needs review before changing voucher value."))
    return result.unwrap()


def _freeze(card: GiftCard, reason: str) -> None:
    if card.spending_frozen_at is None:
        card.spending_frozen_at = timezone.now()
        card.spending_freeze_reason = reason
        card.save(update_fields=["spending_frozen_at", "spending_freeze_reason", "updated_at"])


def _record_value_change(refund: GiftCardFundingRefund, card: GiftCard, payment: Payment, delta: int) -> None:
    refund.settlement_version += 1
    prefix = "funding-refund" if delta < 0 else "funding-refund-return"
    operation = f"{prefix}:{refund.pk}"
    if refund.settlement_version > 1:
        operation += f":{refund.settlement_version}"
    GiftCardTransaction.objects.create(
        gift_card=card,
        payment=payment,
        customer_id=payment.customer_id,
        created_by=refund.created_by,
        ledger_version=2,
        operation_key=operation,
        transaction_type="refund",
        amount_cents=delta,
        balance_after_cents=card.current_balance_cents,
        description="Verified original-tender voucher funding refund",
    )


def _project_purchase(purchase: GiftCardPurchase, payment: Payment) -> None:
    refunded = purchase.funding_refunds.filter(status="succeeded").aggregate(total=Sum("amount_cents"))["total"] or 0
    if purchase.status != "disputed":
        purchase.status = (  # fsm-bypass: Purchase projection CharField
            "refunded" if refunded >= payment.amount_cents else "partially_refunded" if refunded else "funded"
        )
        purchase.save(update_fields=["status"])
    if payment.status == "disputed":
        return
    target = "refunded" if refunded >= payment.amount_cents else "partially_refunded" if refunded else "succeeded"
    if target == payment.status:
        return
    if target == "succeeded" and payment.status in {"refunded", "partially_refunded"}:
        payment.restore_after_refund_reversal()
        payment.save(update_fields=["status", "updated_at"])
    elif target == "partially_refunded" and payment.status == "refunded":
        payment.restore_partial_after_refund_reversal()
        payment.save(update_fields=["status", "updated_at"])
    else:
        payment.apply_gateway_event(target)


def _apply_state(
    refund: GiftCardFundingRefund,
    purchase: GiftCardPurchase,
    card: GiftCard,
    payment: Payment,
    status: str,
) -> None:
    """Apply a verified state while all purchase, card, payment and refund rows are locked."""
    available = max(0, card.current_balance_cents - card.reserved_cents - card.refund_held_cents + refund.held_cents)
    if status == "succeeded":
        debit = min(max(0, refund.amount_cents - refund.applied_cents), available)
        card.refund_held_cents -= refund.held_cents
        refund.held_cents = 0
        if debit:
            card.current_balance_cents -= debit
            refund.applied_cents += debit
            _record_value_change(refund, card, payment, -debit)
        refund.shortfall_cents = refund.amount_cents - refund.applied_cents
    elif status in {"failed", "canceled"}:
        card.refund_held_cents -= refund.held_cents
        refund.held_cents = 0
        if refund.applied_cents:
            card.current_balance_cents += refund.applied_cents
            _record_value_change(refund, card, payment, refund.applied_cents)
            refund.applied_cents = 0
        refund.shortfall_cents = 0
    elif not refund.held_cents and not refund.applied_cents:
        refund.held_cents = min(refund.amount_cents, available)
        card.refund_held_cents += refund.held_cents
        refund.shortfall_cents = refund.amount_cents - refund.held_cents
    if refund.shortfall_cents:
        _freeze(card, f"funding_refund_shortfall:{refund.pk}")
    if card.status in {"active", "partially_used", "depleted"}:
        card.status = (  # fsm-bypass: Card balance projection, independent of freeze
            "depleted"
            if card.current_balance_cents == 0
            else "active"
            if card.current_balance_cents == card.initial_value_cents
            else "partially_used"
        )
    card.save(update_fields=["current_balance_cents", "refund_held_cents", "status", "updated_at"])
    refund.status = status  # fsm-bypass: Verified refund state CharField
    refund.checked_at = timezone.now()
    refund.error_code = ""
    refund.save()
    if purchase.funded_at:
        _project_purchase(purchase, payment)


def _matching_refund(
    purchase: GiftCardPurchase,
    refund_id: str,
    amount: int,
    metadata: Mapping[str, Any],
) -> GiftCardFundingRefund | None:
    marker = metadata.get("gift_refund_id")
    if marker is not None:
        if not isinstance(marker, str):
            raise ValidationError(_("Gift refund metadata is invalid."))
        try:
            refund = purchase.funding_refunds.select_for_update().filter(pk=marker).first()
        except (ValidationError, ValueError, TypeError) as exc:
            raise ValidationError(_("Gift refund metadata is invalid.")) from exc
        if refund is None:
            raise ValidationError(_("Gift refund identity does not match its funding purchase."))
    else:
        refund = GiftCardFundingRefund.objects.select_for_update().filter(gateway_refund_id=refund_id).first()
        if refund and refund.created_by_id:
            raise ValidationError(_("A requested gift refund is missing its original provider metadata."))
    if refund and (
        refund.purchase_id != purchase.pk
        or refund.amount_cents != amount
        or refund.gateway_refund_id not in {None, "", refund_id}
    ):
        raise ValidationError(_("Gift refund amount or provider identity mismatch."))
    return refund


def converge_gift_refund(  # noqa: C901, PLR0911, PLR0912  # Validate each identity before financial writes
    facts: Mapping[str, Any],
) -> Result[GiftCardFundingRefund, str] | None:
    """Consume verified provider facts; never infer an early identity from amount alone."""
    intent_id = facts.get("payment_intent_id")
    if not isinstance(intent_id, str) or not intent_id:
        return None
    snapshot = GiftCardPurchase.objects.filter(funding_payment__gateway_txn_id=intent_id).first()
    if snapshot is None:
        return None
    refund_id, amount, currency, status = (
        facts.get(key) for key in ("refund_id", "amount_cents", "currency", "status")
    )
    metadata = facts.get("metadata", {})
    if (
        not isinstance(refund_id, str)
        or not refund_id
        or type(amount) is not int
        or amount <= 0
        or not isinstance(currency, str)
        or not isinstance(status, str)
        or status not in REFUND_STATUSES
        or not isinstance(metadata, Mapping)
    ):
        return _invalid("Malformed gift refund provider facts")
    event_created = facts.get("event_created")
    if event_created is not None and (type(event_created) is not int or event_created < 0):
        return _invalid("Invalid gift refund event time")
    with transaction.atomic():
        purchase, card, payment = _lock_purchase(snapshot.pk)
        if (
            payment.payment_method != "stripe"
            or payment.gateway_txn_id != intent_id
            or currency.upper() != card.currency_id
            or payment.currency_id != card.currency_id
            or payment.amount_cents != card.initial_value_cents
            or amount > payment.amount_cents
        ):
            return _invalid("Gift refund original funding identity, currency or amount mismatch")
        try:
            refund = _matching_refund(purchase, refund_id, amount, metadata)
        except ValidationError as exc:
            return _invalid(str(exc))
        if refund is None:
            refund = GiftCardFundingRefund.objects.create(
                purchase=purchase,
                amount_cents=amount,
                currency_id=card.currency_id,
                idempotency_key=f"external-gift-refund:{hashlib.sha256(refund_id.encode()).hexdigest()}",
                gateway_refund_id=refund_id,
                funding_intent_id=intent_id,
            )
        if refund.currency_id != card.currency_id or refund.funding_intent_id not in {"", intent_id}:
            return _invalid("Gift refund recorded currency or original intent mismatch")
        if (
            event_created is not None
            and refund.gateway_event_created is not None
            and event_created < refund.gateway_event_created
        ):
            return Ok(refund)
        if refund.status in TERMINAL_REFUND_STATES and status in {"pending", "requires_action"}:
            return Ok(refund)
        if status == "succeeded":
            other_refunded = (
                purchase.funding_refunds.filter(status="succeeded")
                .exclude(pk=refund.pk)
                .aggregate(total=Sum("amount_cents"))["total"]
                or 0
            )
            if amount + other_refunded > payment.amount_cents:
                _freeze(card, "gift_refund_exceeds_original_funding")
                return _invalid("Gift refunds exceed original funding; manual review required")
        refund.gateway_refund_id = refund_id
        refund.funding_intent_id = intent_id
        if event_created is not None:
            refund.gateway_event_created = event_created
        _apply_state(refund, purchase, card, payment, str(status))
        return Ok(refund)


@transaction.atomic
def record_bank_refund(refund_id: UUID | str, *, reference: str, actor: User) -> GiftCardFundingRefund:
    """Record staff confirmation that an external original-tender bank transfer occurred."""
    if not actor.can_manage_financial_data:
        raise PermissionDenied
    if not reference.strip() or len(reference) > MAX_REFERENCE_LENGTH:
        raise ValidationError(_("Enter the bank refund reference."))
    snapshot = GiftCardFundingRefund.objects.get(pk=refund_id)
    purchase, card, payment = _lock_purchase(snapshot.purchase_id)
    refund = GiftCardFundingRefund.objects.select_for_update().get(pk=refund_id)
    if payment.payment_method != "bank":
        raise ValidationError(_("This refund must return through its original card provider."))
    if refund.bank_reference:
        if refund.bank_reference != reference.strip():
            raise ValidationError(_("This bank refund already has a different reference."))
        return refund
    if refund.status != "awaiting_bank_transfer":
        raise ValidationError(_("This bank refund is not awaiting confirmation."))
    refund.bank_reference = reference.strip()
    refund.confirmed_by = actor
    _apply_state(refund, purchase, card, payment, "succeeded")
    return refund


@transaction.atomic
def freeze_purchase_for_dispute(intent_id: str, dispute_id: str) -> bool:
    """Keep a funding dispute freeze independent from card status and service refunds."""
    snapshot = GiftCardPurchase.objects.filter(funding_payment__gateway_txn_id=intent_id).first()
    if snapshot is None:
        return False
    purchase, card, payment = _lock_purchase(snapshot.pk)
    _freeze(card, f"funding_dispute:{dispute_id}")
    purchase.status = "disputed"  # fsm-bypass: Dispute projection CharField
    purchase.save(update_fields=["status"])
    if payment.status in {"pending", "succeeded", "partially_refunded"}:
        payment.apply_gateway_event("disputed", {"dispute_id": dispute_id})
    return True
