"""Purchased voucher funding and tender settlement, separate from service revenue."""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypedDict

from django.core.exceptions import PermissionDenied, ValidationError
from django.core.validators import validate_email
from django.db import transaction
from django.db.models import Sum
from django.utils import timezone
from django.utils.translation import gettext as _

from apps.audit.services import AuditService
from apps.billing.currency_service import assert_currency_issuable

from .models import GiftCard, GiftCardPurchase, GiftCardReservation, GiftCardTransaction

if TYPE_CHECKING:
    from apps.billing.payment_models import Payment
    from apps.customers.models import Customer
    from apps.users.models import User

MAX_REQUEST_LENGTH = 100
MIN_PURCHASE_CENTS = 100
MAX_PURCHASE_CENTS = 100_000_000
MAX_GIFT_MESSAGE_LENGTH = 2000
MAX_GIFT_RECIPIENT_NAME_LENGTH = 200


class GiftRecipient(TypedDict, total=False):
    email: str
    name: str
    message: str


def _recipient_snapshot(recipient: Mapping[str, Any] | None) -> GiftRecipient:
    if recipient is not None and (not isinstance(recipient, Mapping) or set(recipient) - {"email", "name", "message"}):
        raise ValidationError(_("Enter valid gift recipient details."))
    snapshot = {key: (recipient or {}).get(key, "") for key in ("email", "name", "message")}
    if any(not isinstance(value, str) for value in snapshot.values()):
        raise ValidationError(_("Enter valid gift recipient details."))
    if len(snapshot["name"]) > MAX_GIFT_RECIPIENT_NAME_LENGTH or len(snapshot["message"]) > MAX_GIFT_MESSAGE_LENGTH:
        raise ValidationError(_("The recipient name or gift message is too long."))
    snapshot["email"] = snapshot["email"].strip()
    if snapshot["email"]:
        validate_email(snapshot["email"])
    return GiftRecipient(email=snapshot["email"], name=snapshot["name"], message=snapshot["message"])


def _assert_purchase_replay(  # noqa: PLR0913  # Compare each immutable purchase input explicitly
    purchase: GiftCardPurchase,
    currency_code: str,
    amount_cents: int,
    method: str,
    recipient: GiftRecipient,
    buyer_email: str,
    is_gift: bool,
) -> None:
    if (
        purchase.funding_payment.amount_cents != amount_cents
        or purchase.gift_card.initial_value_cents != amount_cents
        or purchase.funding_payment.currency_id != currency_code
        or purchase.gift_card.currency_id != currency_code
        or purchase.funding_payment.payment_method != method
        or purchase.gift_card.recipient_email != recipient.get("email", "")
        or purchase.gift_card.recipient_name != recipient.get("name", "")
        or purchase.gift_card.personal_message != recipient.get("message", "")
        or purchase.buyer_email != buyer_email
        or purchase.is_gift != is_gift
    ):
        raise ValidationError(_("This purchase request already has different details."))


@transaction.atomic
def create_public_purchase(  # noqa: PLR0913  # Explicit signed buyer and immutable sale inputs
    customer: Customer,
    amount_cents: int,
    key: str,
    *,
    policy_revision: int,
    currency_code: str,
    method: str,
    recipient: GiftRecipient | None,
    is_gift: bool,
    actor: User,
) -> GiftCardPurchase:
    from apps.billing.currency_policy import require_current_selling_policy  # noqa: PLC0415  # ADR-0007
    from apps.billing.models import Currency  # noqa: PLC0415  # ADR-0007

    from .gift_purchase_policy import gift_purchase_options  # noqa: PLC0415

    if (
        type(is_gift) is not bool
        or type(amount_cents) is not int
        or type(policy_revision) is not int
        or not MIN_PURCHASE_CENTS <= amount_cents <= MAX_PURCHASE_CENTS
    ):
        raise ValidationError(_("Choose valid gift-card purchase details."))
    snapshot = _recipient_snapshot(recipient)
    if (is_gift and not snapshot["email"]) or (not is_gift and any(snapshot.values())):
        raise ValidationError(_("Choose a recipient for a gift, or leave recipient fields empty for yourself."))
    operation = _operation_key(customer.pk, "gift-purchase", key)
    existing = (
        GiftCardPurchase.objects.select_related("funding_payment", "gift_card")
        .filter(
            customer=customer,
            funding_payment__idempotency_key=operation,
        )
        .first()
    )
    if existing is not None:
        if existing.buyer_actor_id != actor.pk:
            raise ValidationError(_("This purchase request belongs to a different buyer."))
        _assert_purchase_replay(existing, currency_code, amount_cents, method, snapshot, existing.buyer_email, is_gift)
        return existing
    buyer_email = actor.email.strip()
    validate_email(buyer_email)
    require_current_selling_policy(currency_code, policy_revision)
    options = gift_purchase_options(currency_code)
    if (
        not options["sales_enabled"]
        or amount_cents not in options["denominations_cents"]
        or method not in options["payment_methods"]
    ):
        raise ValidationError(_("Gift-card sales or the selected denomination and payment method are unavailable."))
    currency = Currency.objects.get(pk=currency_code)
    return create_purchase(
        customer,
        currency,
        amount_cents,
        key,
        method=method,
        recipient=snapshot,
        actor=actor,
        buyer_email=buyer_email,
        is_gift=is_gift,
    )


def _operation_key(customer_id: Any, operation: str, key: str) -> str:
    if not key or len(key) > MAX_REQUEST_LENGTH:
        raise ValidationError(_("A request identifier is required."))
    return hashlib.sha256(f"{customer_id}:{operation}:{key}".encode()).hexdigest()


@transaction.atomic
def create_purchase(  # noqa: PLR0913  # Funding identity and optional recipient/actor remain explicit
    customer: Any,
    currency: Any,
    amount_cents: int,
    key: str,
    *,
    method: str = "stripe",
    recipient: GiftRecipient | None = None,
    actor: Any = None,
    buyer_email: str | None = None,
    is_gift: bool | None = None,
) -> GiftCardPurchase:
    from apps.billing.payment_models import Payment  # noqa: PLC0415
    from apps.customers.models import Customer  # noqa: PLC0415

    if (
        type(amount_cents) is not int
        or not MIN_PURCHASE_CENTS <= amount_cents <= MAX_PURCHASE_CENTS
        or method not in {"stripe", "bank"}
    ):
        raise ValidationError(_("Choose a valid purchase amount and payment method."))
    Customer.objects.select_for_update().get(pk=customer.pk)
    recipient = _recipient_snapshot(recipient)
    is_gift = bool(recipient["email"]) if is_gift is None else is_gift
    buyer_email = buyer_email if buyer_email is not None else customer.primary_email
    operation = _operation_key(customer.pk, "gift-purchase", key)
    existing = GiftCardPurchase.objects.filter(funding_payment__idempotency_key=operation).first()
    if existing:
        _assert_purchase_replay(existing, currency.code, amount_cents, method, recipient, buyer_email, is_gift)
        return existing
    assert_currency_issuable(currency.code, timezone.localdate())
    card = GiftCard(
        code=GiftCard.generate_code(),
        initial_value_cents=amount_cents,
        current_balance_cents=0,
        currency=currency,
        purchased_by=customer,
        ledger_version=2,
        recipient_email=recipient.get("email", ""),
        recipient_name=recipient.get("name", ""),
        personal_message=recipient.get("message", ""),
    )
    card._audit_actor = actor
    card.full_clean()
    card.save()
    payment = Payment.objects.create(
        customer=customer,
        currency=currency,
        amount_cents=amount_cents,
        payment_method=method,
        idempotency_key=operation,
        created_by=actor,
        meta={"source": "gift_card_funding"},
    )
    return GiftCardPurchase.objects.create(
        gift_card=card,
        customer=customer,
        funding_payment=payment,
        receipt_number=f"GCF-{uuid.uuid4().hex.upper()}",
        buyer_email=buyer_email,
        buyer_name=customer.name,
        buyer_actor=actor,
        is_gift=is_gift,
    )


def start_funding(purchase: GiftCardPurchase) -> dict[str, Any]:
    """Persist an exact gateway attempt before network I/O; retries reuse its key."""
    from .gift_funding import start_funding as start_purchase_funding  # noqa: PLC0415  # Public compatibility facade

    return start_purchase_funding(purchase)


@transaction.atomic
def activate_verified_purchase(purchase_id: Any) -> GiftCardPurchase:
    from apps.billing.payment_models import Payment  # noqa: PLC0415

    purchase = GiftCardPurchase.objects.select_for_update().get(pk=purchase_id)
    card = GiftCard.objects.select_for_update().get(pk=purchase.gift_card_id)
    payment = Payment.objects.select_for_update().get(pk=purchase.funding_payment_id)
    if purchase.funded_at is not None:
        return purchase
    if (
        payment.status != "succeeded"
        or payment.customer_id != purchase.customer_id
        or payment.amount_cents != card.initial_value_cents
        or payment.currency_id != card.currency_id
    ):
        raise ValidationError(_("The gift-card purchase payment is not verified."))
    if payment.payment_method == "stripe":
        if (
            not payment.gateway_txn_id
            or payment.meta.get("stripe_amount_received") != payment.amount_cents
            or str(payment.meta.get("stripe_currency", "")).upper() != card.currency.code.upper()
        ):
            raise ValidationError(_("Verified gateway payment facts are required."))
    elif payment.payment_method != "bank" or not payment.created_by_id or not payment.reference_number:
        raise ValidationError(_("A staff-recorded bank payment reference is required."))
    if card.status != "pending" or card.current_balance_cents or card.reserved_cents or purchase.status != "pending":
        raise ValidationError(_("This gift card cannot be activated."))
    card.status = "active"  # fsm-bypass: Locked ledger CharField; no protected FSM field
    card.current_balance_cents = card.initial_value_cents
    card.activated_at = timezone.now()
    card.save(update_fields=["status", "current_balance_cents", "activated_at", "updated_at"])
    GiftCardTransaction.objects.create(
        gift_card=card,
        payment=payment,
        ledger_version=2,
        operation_key=f"fund:{purchase.pk}",
        transaction_type="activation",
        amount_cents=card.initial_value_cents,
        balance_after_cents=card.current_balance_cents,
        customer=purchase.customer,
        created_by=payment.created_by,
        description="Verified voucher funding",
    )
    purchase.status = "funded"  # fsm-bypass: Locked ledger CharField; no protected FSM field
    purchase.funded_at = card.activated_at
    purchase.save(update_fields=["status", "funded_at"])
    AuditService.log_simple_event(
        "gift_card_activated",
        content_object=card,
        user=payment.created_by,
        description="Gift card funded after verified payment",
        metadata={"purchase_id": str(purchase.pk), "payment_id": payment.pk, "amount_cents": payment.amount_cents},
    )
    from .gift_delivery import queue_purchase_delivery  # noqa: PLC0415  # Activation/delivery dependency cycle

    queue_purchase_delivery(purchase.pk)
    return purchase


@transaction.atomic
def record_bank_funding(purchase_id: Any, *, reference: str, actor: Any) -> GiftCardPurchase:
    from apps.billing.payment_models import Payment  # noqa: PLC0415

    if not actor.can_manage_financial_data:
        raise PermissionDenied
    if not reference.strip() or len(reference) > MAX_REQUEST_LENGTH:
        raise ValidationError(_("Enter the bank payment reference."))
    purchase = GiftCardPurchase.objects.select_for_update().get(pk=purchase_id)
    GiftCard.objects.select_for_update().get(pk=purchase.gift_card_id)
    payment = Payment.objects.select_for_update().get(pk=purchase.funding_payment_id)
    if payment.payment_method != "bank":
        raise ValidationError(_("This purchase is awaiting a card payment."))
    if payment.status == "pending":
        payment.created_by = actor
        payment.reference_number = reference.strip()
        payment.succeed()
        payment.save(update_fields=["created_by", "reference_number", "status", "updated_at"])
    return activate_verified_purchase(purchase.pk)


def reserved_value(document: Any) -> int:
    return document.gift_card_reservations.filter(status="reserved").aggregate(total=Sum("amount_cents"))["total"] or 0


def cash_due(proforma: Any) -> int:
    if proforma.status == "converted":
        return 0
    return max(0, int(proforma.total_cents) - reserved_value(proforma))


def preview_value(code: str, currency_id: Any, total_cents: int) -> dict[str, Any]:
    """Quote existing balance as tender without revealing the bearer code."""
    if not code.strip():
        return {"id": "", "amount_cents": 0}
    card = GiftCard.objects.filter(code=code.strip().upper()).first()
    if card is None or not card.is_valid or card.currency_id != currency_id:
        raise ValidationError(_("Gift card unavailable for this currency."))
    available = card.available_balance_cents
    if available <= 0 or total_cents <= 0:
        raise ValidationError(_("There is no gift-card balance to apply to this order."))
    return {"id": str(card.pk), "amount_cents": min(available, total_cents)}


@transaction.atomic
def reserve_value(  # noqa: PLR0913  # Signed actor supplements the immutable reservation identity
    code: str, document: Any, customer: Any, key: str, amount_cents: int | None = None, *, actor: User | None = None
) -> GiftCardReservation:
    from apps.billing.invoice_models import Invoice  # noqa: PLC0415
    from apps.billing.proforma_service import ProformaPaymentService  # noqa: PLC0415

    document = type(document).objects.select_for_update().get(pk=document.pk)
    if document.customer_id != customer.pk:
        raise PermissionDenied
    from .locking import lock_document_context  # noqa: PLC0415

    lock_document_context(document, gift_code=code)
    operation = _operation_key(customer.pk, "gift-redemption", key)
    existing = GiftCardReservation.objects.filter(operation_key=operation).select_related("gift_card").first()
    invoice = isinstance(document, Invoice)
    if existing:
        same_document = existing.invoice_id == document.pk if invoice else existing.proforma_id == document.pk
        if (
            not same_document
            or existing.gift_card.code != code.strip().upper()
            or (amount_cents is not None and existing.amount_cents != amount_cents)
        ):
            raise ValidationError(_("This payment request already has different details."))
        return existing
    if invoice:
        if document.status not in {"issued", "overdue"}:
            raise ValidationError(_("This invoice cannot accept payment."))
        outstanding = document.get_remaining_amount() - reserved_value(document)
    else:
        reason = ProformaPaymentService.payment_block_reason(document, manual=True)
        if reason:
            raise ValidationError(reason)
        outstanding = cash_due(document)
    if document.payments.filter(payment_method="stripe", status__in=["pending", "succeeded"]).exists():
        raise ValidationError(_("An existing card payment must be resolved first."))
    try:
        card = GiftCard.objects.select_for_update().get(code=code.strip().upper())
    except GiftCard.DoesNotExist as exc:
        raise ValidationError(_("Gift card unavailable.")) from exc
    if not card.is_valid or card.currency_id != document.currency_id:
        raise ValidationError(_("Gift card unavailable for this document or currency."))
    available = card.available_balance_cents
    amount = min(available, outstanding) if amount_cents is None else amount_cents
    if type(amount) is not int or amount <= 0 or amount > min(available, outstanding):
        raise ValidationError(_("Choose an amount within the available card balance and document balance."))
    hold = GiftCardReservation(
        gift_card=card,
        customer=customer,
        invoice=document if invoice else None,
        proforma=None if invoice else document,
        amount_cents=amount,
        operation_key=operation,
    )
    hold._audit_actor = actor  # type: ignore[attr-defined]  # Request-scoped actor consumed by the audit signal
    hold.save()
    card.reserved_cents += amount
    card.save(update_fields=["reserved_cents", "updated_at"])
    return hold


@transaction.atomic
def capture_reservations(document: Any, invoice: Any) -> list[Payment]:
    from apps.billing.payment_models import Payment  # noqa: PLC0415

    document = type(document).objects.select_for_update().get(pk=document.pk)
    if (
        document is not invoice
        and type(document) is not type(invoice)
        and invoice.converted_from_proforma_id != document.pk
    ):
        raise ValidationError(_("Gift-card settlement invoice does not belong to this proforma."))
    holds = list(document.gift_card_reservations.filter(status="reserved").order_by("gift_card_id", "pk"))
    cards = {
        card.pk: card
        for card in GiftCard.objects.select_for_update()
        .filter(pk__in={hold.gift_card_id for hold in holds})
        .order_by("pk")
    }
    payments = []
    for hold in holds:
        card = cards[hold.gift_card_id]
        if (
            hold.customer_id != document.customer_id
            or invoice.customer_id != document.customer_id
            or card.currency_id != document.currency_id
        ):
            raise ValidationError(_("Gift-card settlement document mismatch."))
        if (
            card.status == "cancelled"
            or not card.is_active
            or card.spending_frozen_at is not None
            or card.reserved_cents < hold.amount_cents
            or card.current_balance_cents - card.refund_held_cents < hold.amount_cents
        ):
            raise ValidationError(_("Gift-card funds require review before settlement."))
        payment = Payment.objects.create(
            customer=document.customer,
            invoice=invoice,
            proforma=hold.proforma,
            payment_method="gift_card",
            amount_cents=hold.amount_cents,
            currency=document.currency,
            idempotency_key=f"gift:{hold.pk}",
            meta={"gift_card_id": str(card.pk), "ledger_version": 2},
        )
        payment._defer_document_settlement = True
        payment.succeed()
        payment.save(update_fields=["status", "updated_at"])
        card.current_balance_cents -= hold.amount_cents
        card.reserved_cents -= hold.amount_cents
        if card.status in {"active", "partially_used", "depleted"}:
            card.status = (  # fsm-bypass: GiftCard.status is a CharField
                "partially_used" if card.current_balance_cents else "depleted"
            )  # fsm-bypass: Locked ledger CharField; no protected FSM field
        card.save(update_fields=["current_balance_cents", "reserved_cents", "status", "updated_at"])
        GiftCardTransaction.objects.create(
            gift_card=card,
            payment=payment,
            ledger_version=2,
            operation_key=f"capture:{hold.pk}",
            transaction_type="redemption",
            amount_cents=-hold.amount_cents,
            balance_after_cents=card.current_balance_cents,
            customer=document.customer,
            description=f"Payment of {invoice.number}",
        )
        hold.status = "captured"  # fsm-bypass: Locked ledger CharField; no protected FSM field
        hold.invoice = invoice
        hold.payment = payment
        hold.save(update_fields=["status", "invoice", "payment"])
        payments.append(payment)
    return payments


@transaction.atomic
def release_reservations(document: Any) -> int:
    document = type(document).objects.select_for_update().get(pk=document.pk)
    if document.payments.filter(payment_method="stripe", status__in=["pending", "succeeded"]).exists():
        raise ValidationError(_("The card payment must be resolved before releasing gift-card funds."))
    restored = 0
    for hold in document.gift_card_reservations.filter(status="reserved").order_by("gift_card_id", "pk"):
        card = GiftCard.objects.select_for_update().get(pk=hold.gift_card_id)
        card.reserved_cents -= hold.amount_cents
        card.save(update_fields=["reserved_cents", "updated_at"])
        hold.status = "released"  # fsm-bypass: Locked ledger CharField; no protected FSM field
        hold.save(update_fields=["status"])
        restored += hold.amount_cents
    return restored


def release_expired_reservations() -> int:
    """Return abandoned proforma holds, retaining unresolved gateway attempts."""
    from django.db.models import Q  # noqa: PLC0415

    from apps.billing.proforma_models import ProformaInvoice  # noqa: PLC0415

    ids = list(
        ProformaInvoice.objects.filter(
            Q(valid_until__lt=timezone.now()) | Q(status__in=["expired", "cancelled"]),
            gift_card_reservations__status="reserved",
        )
        .exclude(status="converted")
        .values_list("pk", flat=True)
        .distinct()
    )
    released = 0
    for document_id in ids:
        with transaction.atomic():
            document = ProformaInvoice.objects.select_for_update().get(pk=document_id)
            if document.status == "converted" or (
                not document.is_expired and document.status not in {"expired", "cancelled"}
            ):
                continue
            if document.payments.filter(payment_method="stripe", status__in=["pending", "succeeded"]).exists():
                continue
            released += release_reservations(document)
    return released


@transaction.atomic
def pay_document(  # noqa: PLR0913  # Signed actor supplements the immutable payment identity
    code: str, document: Any, customer: Any, key: str, amount_cents: int | None = None, *, actor: User | None = None
) -> dict[str, Any]:
    from apps.billing.invoice_models import Invoice  # noqa: PLC0415
    from apps.billing.payment_convergence import PaymentSuccessService  # noqa: PLC0415
    from apps.billing.proforma_service import ProformaPaymentService  # noqa: PLC0415

    document = type(document).objects.select_for_update().get(pk=document.pk)
    hold = reserve_value(code, document, customer, key, amount_cents, actor=actor)
    if isinstance(document, Invoice):
        payments = capture_reservations(document, document)
        for payment in payments:
            result = PaymentSuccessService.converge_local_paid_document(payment.pk)
            if result.is_err():
                raise ValidationError(result.unwrap_err())
        document.refresh_from_db()
        due = document.get_remaining_amount()
    else:
        due = cash_due(document)
        if due == 0:
            result = ProformaPaymentService.record_payment_and_convert(
                str(document.pk), 0, "other", reference="Gift-card payment"
            )
            if result.is_err():
                raise ValidationError(result.unwrap_err())
    return {"success": True, "applied_cents": hold.amount_cents, "cash_due_cents": due}
