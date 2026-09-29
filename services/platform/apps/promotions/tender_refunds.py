"""Durable refunds allocated across the original service-payment tenders."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Sum
from django.utils import timezone
from django.utils.translation import gettext as _

from apps.billing.gateways.base import GATEWAY_PAYMENT_METHODS, PaymentGatewayFactory

from .audit import audit_ledger_transition
from .gift_cards import _operation_key
from .models import (
    GiftCard,
    GiftCardTransaction,
    TenderRefundCommand,
    TenderRefundLeg,
)
from .pricing import allocate

if TYPE_CHECKING:
    from apps.billing.invoice_models import Invoice
    from apps.billing.refund_models import Refund
    from apps.billing.refund_service import RefundData, RefundGatewayFacts, RefundResult
    from apps.common.types import Result
    from apps.users.models import User

RESERVING = ("pending", "processing", "approved", "completed")


def _lock_document(invoice_id: int | None) -> Invoice:
    from apps.billing.invoice_models import Invoice  # noqa: PLC0415

    from .locking import lock_document_context  # noqa: PLC0415

    if invoice_id is None:
        raise ValidationError(_("This refund is not linked to a service invoice."))
    invoice = Invoice.objects.select_for_update().get(pk=invoice_id)
    lock_document_context(invoice)
    return invoice


def _create_leg_intent(leg: TenderRefundLeg, invoice: Invoice) -> Refund:
    from apps.billing.refund_service import RefundService  # noqa: PLC0415

    result = RefundService._create_refund_intent(
        order=None,
        invoice=invoice,
        payment=leg.payment,
        refund_data={"refund_type": "partial", "amount_cents": leg.amount_cents, "reason": leg.command.reason},
        actor=leg.command.created_by,
    )
    if result.is_err():
        raise ValidationError(result.unwrap_err())
    refund = result.unwrap()
    refund.metadata = {**refund.metadata, "tender_command": str(leg.command_id), "tender_leg": leg.pk}
    refund.save(update_fields=["metadata"])
    leg.refund = refund
    leg.status = "pending"  # fsm-bypass: Locked ledger CharField; no protected FSM field
    leg.error = ""
    leg.save(update_fields=["refund", "status", "error"])
    return refund


def _reserve_command(  # noqa: C901, PLR0912  # Validate every original tender before persisting the command
    invoice_id: int, amount_cents: int, key: str, reason: str, actor: User | None
) -> TenderRefundCommand:
    from apps.billing.payment_models import Payment  # noqa: PLC0415
    from apps.billing.refund_models import Refund  # noqa: PLC0415

    with transaction.atomic(durable=True):
        invoice = _lock_document(invoice_id)
        operation = _operation_key(invoice.customer_id, "tender-refund", key)
        existing = TenderRefundCommand.objects.filter(operation_key=operation).first()
        if existing:
            if existing.invoice_id != invoice.pk or existing.amount_cents != amount_cents or existing.reason != reason:
                raise ValidationError(_("This refund request already has different details."))
            return existing
        if type(amount_cents) is not int or amount_cents <= 0:
            raise ValidationError(_("The refund amount must be a positive number of cents."))
        if invoice.status not in {"paid", "partially_refunded"}:
            raise ValidationError(_("This invoice is not refundable."))
        if invoice.tender_refund_commands.exclude(
            status="completed"
        ).exists():  # fsm-bypass: TenderRefundCommand is a locked ledger CharField
            raise ValidationError(_("Finish or reconcile the existing refund before starting another."))
        payments = list(
            Payment.objects.select_for_update()
            .filter(invoice=invoice, amount_cents__gt=0, status__in=["succeeded", "partially_refunded", "refunded"])
            .order_by("pk")
        )
        if not payments or sum(payment.amount_cents for payment in payments) != invoice.total_cents:
            raise ValidationError(_("The original payment allocation needs review before refunding."))
        for payment in payments:
            if payment.customer_id != invoice.customer_id or payment.currency_id != invoice.currency_id:
                raise ValidationError(_("Payment customer or currency does not match the invoice."))
            if payment.payment_method == "gift_card" and not hasattr(payment, "gift_card_reservation"):
                raise ValidationError(_("The original gift-card payment is missing its allocation."))
        if Refund.objects.filter(payment__in=payments, status__in=["pending", "processing", "approved"]).exists():
            raise ValidationError(_("An earlier refund still needs settlement."))
        previous = {
            str(row["payment_id"]): row["refunded_total"]
            for row in Refund.objects.filter(payment__in=payments, status="completed")
            .values("payment_id")
            .annotate(refunded_total=Sum("amount_cents"))
        }
        already = sum(previous.values())
        if amount_cents > invoice.total_cents - already:
            raise ValidationError(_("The refund exceeds the remaining paid amount."))
        targets = allocate(already + amount_cents, {str(payment.pk): payment.amount_cents for payment in payments})
        allocations = allocate(
            amount_cents,
            {
                str(payment.pk): max(0, targets.get(str(payment.pk), 0) - previous.get(str(payment.pk), 0))
                for payment in payments
            },
        )
        if sum(allocations.values()) != amount_cents:
            raise ValidationError(_("The refund allocation needs review."))
        command = TenderRefundCommand.objects.create(
            invoice=invoice,
            customer=invoice.customer,
            amount_cents=amount_cents,
            operation_key=operation,
            reason=reason,
            created_by=actor,
        )
        for payment in payments:
            amount = allocations.get(str(payment.pk), 0)
            if amount:
                leg = TenderRefundLeg.objects.create(command=command, payment=payment, amount_cents=amount)
                _create_leg_intent(leg, invoice)
        return command


def _project_leg(leg: TenderRefundLeg, invoice: Invoice) -> None:
    from apps.billing.refund_service import RefundService  # noqa: PLC0415

    refund = leg.refund
    if refund is None:
        raise ValidationError(_("The refund has no durable payment instruction."))
    if refund.status == "completed" and leg.payment.payment_method == "gift_card":
        card = GiftCard.objects.select_for_update().get(pk=leg.payment.gift_card_reservation.gift_card_id)
        operation = f"refund:{refund.pk}"
        if not GiftCardTransaction.objects.filter(operation_key=operation).exists():
            card.current_balance_cents += refund.amount_cents
            if card.status in {"depleted", "partially_used"}:
                card.status = (  # fsm-bypass: GiftCard.status is a CharField
                    "partially_used" if card.current_balance_cents < card.initial_value_cents else "active"
                )  # fsm-bypass: Locked ledger CharField; no protected FSM field
            card.save(update_fields=["current_balance_cents", "status", "updated_at"])
            GiftCardTransaction.objects.create(
                gift_card=card,
                payment=leg.payment,
                ledger_version=2,
                operation_key=operation,
                transaction_type="refund",
                amount_cents=refund.amount_cents,
                balance_after_cents=card.current_balance_cents,
                customer=invoice.customer,
                created_by=leg.command.created_by,
                description=f"Refund of {invoice.number}",
            )
    projection = RefundService._project_settled_refunds(leg.payment, invoice)
    if projection.is_err():
        raise ValidationError(projection.unwrap_err())
    leg.status = (  # fsm-bypass: Locked ledger CharField; no protected FSM field
        "completed"
        if refund.status == "completed"
        else "failed"
        if refund.status in {"failed", "cancelled", "rejected"}
        else "processing"
    )
    leg.save(update_fields=["status", "error"])
    states = set(leg.command.legs.values_list("status", flat=True))
    leg.command.status = (  # fsm-bypass: Refund command status is a CharField
        "completed" if states == {"completed"} else "failed" if "failed" in states else "processing"
    )  # fsm-bypass: Locked ledger CharField; no protected FSM field
    leg.command.save(update_fields=["status"])


def _settle_leg(leg_id: int, gateway_status: str, gateway_id: str = "") -> None:
    from apps.billing.payment_models import Payment  # noqa: PLC0415
    from apps.billing.refund_models import Refund  # noqa: PLC0415
    from apps.billing.refund_service import RefundService  # noqa: PLC0415

    snapshot = TenderRefundLeg.objects.select_related("command").get(pk=leg_id)
    with transaction.atomic():
        invoice = _lock_document(snapshot.command.invoice_id)
        payment = Payment.objects.select_for_update().get(pk=snapshot.payment_id)
        leg = TenderRefundLeg.objects.select_for_update().select_related("command").get(pk=leg_id)
        if leg.refund_id is None:
            raise ValidationError(_("The refund has no durable payment instruction."))
        refund = Refund.objects.select_for_update().get(pk=leg.refund_id)
        if gateway_id:
            if refund.gateway_refund_id not in {"", gateway_id}:
                raise ValidationError(_("Refund gateway identity changed."))
            refund.gateway_refund_id = gateway_id
            refund.save(update_fields=["gateway_refund_id"])
        advanced = RefundService._advance_refund_status(refund, gateway_status)
        if advanced.is_err():
            raise ValidationError(advanced.unwrap_err())
        leg.refund, leg.payment = refund, payment
        _project_leg(leg, invoice)


def _submit_leg(leg_id: int) -> None:
    from apps.billing.payment_models import Payment  # noqa: PLC0415
    from apps.billing.refund_models import Refund  # noqa: PLC0415
    from apps.billing.refund_service import RefundService  # noqa: PLC0415

    snapshot = TenderRefundLeg.objects.select_related("command").get(pk=leg_id)
    with transaction.atomic(durable=True):
        invoice = _lock_document(snapshot.command.invoice_id)
        payment = Payment.objects.select_for_update().get(pk=snapshot.payment_id)
        leg = TenderRefundLeg.objects.select_for_update(of=("self",)).select_related("command").get(pk=leg_id)
        if leg.status == "completed":
            return
        refund = Refund.objects.select_for_update().get(pk=leg.refund_id) if leg.refund_id else None
        leg.refund = refund
        if refund is None or refund.status in {"failed", "cancelled", "rejected"}:
            # A verified terminal failure is a new gateway attempt, kept on the same leg.
            refund = _create_leg_intent(leg, invoice)
        if refund.gateway_refund_id:
            _project_leg(leg, invoice)
            return
        if payment.payment_method in GATEWAY_PAYMENT_METHODS and refund.created_at < timezone.now() - timedelta(
            hours=23
        ):
            raise ValidationError(_("This refund attempt needs gateway reconciliation before retry."))
        leg.status = "processing"  # fsm-bypass: Locked ledger CharField; no protected FSM field
        leg.save(update_fields=["status"])
    if payment.payment_method in GATEWAY_PAYMENT_METHODS:
        if not payment.gateway_txn_id:
            raise ValidationError(_("The original gateway payment is missing."))
        result = PaymentGatewayFactory.create_gateway(payment.payment_method).refund_payment(
            gateway_txn_id=payment.gateway_txn_id,
            amount_cents=refund.amount_cents,
            idempotency_key=f"refund:{refund.pk}",
        )
        if (
            not result.get("success")
            or not result.get("refund_id")
            or result.get("amount_refunded_cents") != refund.amount_cents
        ):
            raise ValidationError(_("The gateway refund needs reconciliation before retry."))
        verified_gateway_id = str(result["refund_id"])
        # Persist the provider's observed result before any local projection can
        # fail. A retry of that projection must never resubmit the gateway leg.
        with transaction.atomic(durable=True):
            verified = Refund.objects.select_for_update().get(pk=refund.pk)
            if verified.gateway_refund_id not in {"", verified_gateway_id}:
                raise ValidationError(_("Refund gateway identity changed."))
            verified.gateway_refund_id = verified_gateway_id
            advanced = RefundService._advance_refund_status(verified, result["status"])
            if advanced.is_err():
                raise ValidationError(advanced.unwrap_err())
            verified.save(update_fields=["gateway_refund_id"])
        _settle_leg(leg.pk, result["status"], verified_gateway_id)
    else:
        _settle_leg(leg.pk, "succeeded")


def refund_document(
    invoice_id: int, amount_cents: int, key: str, *, reason: str, actor: User | None = None
) -> TenderRefundCommand:
    """Commit every leg before provider I/O; retries skip all completed legs."""
    command = _reserve_command(invoice_id, amount_cents, key, reason, actor)
    return _run_command(command)


def resume_refund(invoice_id: int, command_id: str, *, actor: User) -> TenderRefundCommand:
    from apps.audit.services import AuditService  # noqa: PLC0415

    command = TenderRefundCommand.objects.get(pk=command_id, invoice_id=invoice_id)
    AuditService.log_simple_event(
        "refund_retry",
        content_object=command,
        user=actor,
        description="Resumed the unfinished legs of a split refund",
        metadata={"invoice_id": invoice_id},
    )
    return _run_command(command)


def _run_command(command: TenderRefundCommand) -> TenderRefundCommand:
    if command.status == "completed":
        return command
    # Restore local balances first. A provider timeout then exercises the same durable retry path.
    legs = sorted(
        command.legs.select_related("payment"), key=lambda leg: (leg.payment.payment_method != "gift_card", leg.pk)
    )
    for leg in legs:
        try:
            _submit_leg(leg.pk)
        except (ValidationError, TimeoutError, ConnectionError) as exc:
            # An unknown network outcome retains the intent and its exact provider key.
            with transaction.atomic():
                _lock_document(command.invoice_id)
                leg.refresh_from_db()
                command.refresh_from_db()
                if leg.status not in {"completed", "failed"} and TenderRefundLeg.objects.filter(
                    pk=leg.pk, status=leg.status
                ).update(status="failed", error=str(exc)[:500]):  # fsm-bypass: Ledger CharField CAS
                    audit_ledger_transition(leg, leg.status, "failed", command.created_by)
                if command.status not in {"completed", "failed"} and TenderRefundCommand.objects.filter(
                    pk=command.pk, status=command.status
                ).update(status="failed"):  # fsm-bypass: Ledger CharField CAS
                    audit_ledger_transition(command, command.status, "failed", command.created_by)
    command.refresh_from_db()
    return command


def refund_from_existing_flow(
    invoice_id: int, data: RefundData, actor: User | None = None
) -> Result[RefundResult, str]:
    from apps.billing.invoice_models import Invoice  # noqa: PLC0415
    from apps.billing.refund_models import Refund  # noqa: PLC0415
    from apps.billing.refund_service import RefundReason, RefundType  # noqa: PLC0415
    from apps.common.types import Err, Ok  # noqa: PLC0415

    invoice = Invoice.objects.get(pk=invoice_id)
    full = data.get("refund_type", "full") in ("full", RefundType.FULL)
    raw_reason = data.get("reason") or "customer_request"
    reason = raw_reason.value if isinstance(raw_reason, RefundReason) else str(raw_reason)
    requested = data.get("amount_cents", data.get("amount", 0))
    key = data.get("idempotency_key") or f"legacy:{invoice_id}:{'full' if full else requested}:{reason}"
    existing = TenderRefundCommand.objects.filter(
        operation_key=_operation_key(invoice.customer_id, "tender-refund", key)
    ).first()
    settled = (
        Refund.objects.filter(payment__invoice=invoice, status="completed").aggregate(total=Sum("amount_cents"))[
            "total"
        ]
        or 0
    )
    amount = existing.amount_cents if full and existing else invoice.total_cents - settled if full else requested
    try:
        command = refund_document(invoice_id, amount, key, reason=reason, actor=actor)
    except ValidationError as exc:
        return Err("; ".join(exc.messages))
    return Ok(
        {
            "success": command.status != "failed",
            "refund_id": str(command.pk),
            "amount_refunded_cents": command.amount_cents,
            "refund_type": "full" if full else "partial",
            "invoice_id": invoice_id,
            "refund_status": command.status,
            "payment_refund_processed": command.status == "completed",
            "audit_entries_created": command.legs.count(),
        }
    )


def converge_tender_refund(facts: RefundGatewayFacts) -> Result[Refund | None, str] | None:
    """Commit verified gateway facts before retryable local ledger projection."""
    from apps.billing.refund_models import Refund  # noqa: PLC0415
    from apps.billing.refund_service import RefundService  # noqa: PLC0415
    from apps.common.types import Err, Ok  # noqa: PLC0415

    candidates = TenderRefundLeg.objects.filter(payment__gateway_txn_id=facts["payment_intent_id"])
    leg = candidates.filter(refund__gateway_refund_id=facts["refund_id"]).first()
    if leg is None:
        pending = list(
            candidates.filter(
                refund__gateway_refund_id="", refund__status__in=RESERVING, amount_cents=facts["amount_cents"]
            )[:2]
        )
        if len(pending) > 1:
            return Err("Several refund instructions match this payment; review required")
        leg = pending[0] if pending else None
    if leg is None:
        return None
    try:
        with transaction.atomic():
            _lock_document(leg.command.invoice_id)
            if leg.refund_id is None:
                raise ValidationError(_("The refund has no durable payment instruction."))
            refund = (
                Refund.objects.select_for_update(of=("self",)).select_related("payment__currency").get(pk=leg.refund_id)
            )
            if (
                refund.amount_cents != facts["amount_cents"]
                or refund.payment is None
                or refund.payment.currency.code.upper() != facts["currency"].upper()
            ):
                raise ValidationError(_("The gateway refund amount or currency does not match its instruction."))
            refund.gateway_refund_id = facts["refund_id"]
            advanced = RefundService._advance_refund_status(refund, facts["status"])
            if advanced.is_err():
                raise ValidationError(advanced.unwrap_err())
            refund.save(update_fields=["gateway_refund_id"])
        _settle_leg(leg.pk, facts["status"], facts["refund_id"])
        refund.refresh_from_db()
        return Ok(refund)
    except ValidationError as exc:
        return Err("; ".join(exc.messages))
