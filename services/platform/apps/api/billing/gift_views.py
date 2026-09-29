"""Signed, customer-owned gift purchases; bearer codes have a separate POST action."""

from typing import Any, cast

from django.core.exceptions import ValidationError
from django.http import HttpRequest
from django.utils import timezone
from django.utils.translation import gettext as _
from rest_framework import serializers, status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from apps.api.secure_auth import BILLING_ROLES, require_customer_role_in
from apps.audit.services import AuditService
from apps.billing.bank_transfer import bank_transfer_instructions
from apps.billing.currency_policy import SellingCurrencyChangedError, get_selling_currency_policy
from apps.customers.models import Customer
from apps.promotions.gift_cards import GiftRecipient, create_public_purchase, start_funding
from apps.promotions.gift_purchase_policy import gift_purchase_options
from apps.promotions.models import GiftCardPurchase
from apps.users.models import User


class RecipientSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False, allow_blank=True, default="")
    name = serializers.CharField(required=False, allow_blank=True, default="", max_length=200)
    message = serializers.CharField(required=False, allow_blank=True, default="", max_length=2000)


class PurchaseSerializer(serializers.Serializer):
    amount_cents = serializers.IntegerField(min_value=100, max_value=100_000_000)
    currency = serializers.ChoiceField(choices=("RON", "EUR", "USD"))
    currency_revision = serializers.IntegerField(min_value=1)
    idempotency_key = serializers.CharField(max_length=100)
    payment_method = serializers.ChoiceField(choices=("stripe", "bank"))
    recipient = RecipientSerializer(required=False, default=dict)
    is_gift = serializers.BooleanField()

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        if set(self.initial_data).intersection({"coupon_code", "coupon_codes", "gift_code", "gift_codes"}):
            raise serializers.ValidationError(_("Gift cards must be paid by card or bank transfer."))
        return attrs


class PurchaseActionSerializer(serializers.Serializer):
    purchase_id = serializers.UUIDField()


class PurchasePageSerializer(serializers.Serializer):
    page = serializers.IntegerField(min_value=1, default=1)


def _response(payload: dict[str, Any], response_status: int = status.HTTP_200_OK) -> Response:
    response = Response(payload, status=response_status)
    response["Cache-Control"] = "private, no-store"
    response["Pragma"] = "no-cache"
    response["Referrer-Policy"] = "no-referrer"
    return response


def _error(message: str, response_status: int = status.HTTP_400_BAD_REQUEST) -> Response:
    return _response({"success": False, "error": message}, response_status)


def _owned_purchase(request: HttpRequest, customer: Customer) -> GiftCardPurchase | None:
    serializer = PurchaseActionSerializer(data=getattr(request, "data", {}))
    serializer.is_valid(raise_exception=True)
    return (
        GiftCardPurchase.objects.select_related("gift_card", "funding_payment", "funding_attempt")
        .filter(
            pk=serializer.validated_data["purchase_id"],
            customer=customer,
        )
        .first()
    )


def _purchase_data(purchase: GiftCardPurchase) -> dict[str, Any]:
    from apps.promotions.gift_delivery import purchase_delivery_summary  # noqa: PLC0415  # ADR-0007

    card = purchase.gift_card
    delivery = purchase_delivery_summary(purchase)
    return {
        "id": str(purchase.pk),
        "created_at": purchase.created_at.isoformat(),
        "status": purchase.status,
        "currency_code": card.currency_id,
        "amount_cents": card.initial_value_cents,
        "payment_method": purchase.funding_payment.payment_method,
        "receipt_number": purchase.receipt_number,
        "recipient_email": card.recipient_email if purchase.is_gift else purchase.buyer_email,
        "recipient_name": card.recipient_name if purchase.is_gift else purchase.buyer_name,
        "is_gift": purchase.is_gift,
        "delivery_status": delivery["status"],
        "deliveries": delivery["deliveries"],
        "delivery_queued": delivery["is_queued"],
        "resend_available_at": delivery["resend_available_at"],
        "current_balance_cents": card.current_balance_cents,
        "available_balance_cents": card.available_balance_cents,
        "reserved_cents": card.reserved_cents,
        "refund_held_cents": card.refund_held_cents,
        "spending_frozen": card.spending_frozen_at is not None,
        "can_reveal": purchase.can_reveal_code,
        "can_resend": delivery["can_resend"],
        **_funding_data(purchase),
    }


def _funding_data(purchase: GiftCardPurchase) -> dict[str, Any]:
    from apps.promotions.gift_funding import UNBOUND_RETRY_WINDOW  # noqa: PLC0415  # ADR-0007

    payment = purchase.funding_payment
    attempt = getattr(purchase, "funding_attempt", None)
    funding_status = attempt.status if attempt else payment.status
    unbound_expired = bool(
        attempt
        and not attempt.gateway_intent_id
        and attempt.first_submitted_at
        and timezone.now() - attempt.first_submitted_at >= UNBOUND_RETRY_WINDOW
    )
    needs_review = not purchase.funded_at and (funding_status == "needs_review" or unbound_expired)
    closed = not purchase.funded_at and (funding_status == "canceled" or payment.status != "pending")
    open_payment = not purchase.funded_at and not closed and not needs_review
    return {
        "funding_status": funding_status,
        "payment_closed": bool(closed),
        "funding_needs_review": bool(needs_review),
        "can_pay": bool(
            open_payment and payment.payment_method == "stripe" and funding_status not in {"processing", "succeeded"}
        ),
        "can_refresh": bool(
            open_payment and (payment.payment_method == "bank" or (attempt is not None and attempt.gateway_intent_id))
        ),
    }


def _details(purchase: GiftCardPurchase) -> dict[str, Any]:
    bank = (
        bank_transfer_instructions(purchase.funding_payment.currency_id)
        if (purchase.funding_payment.payment_method == "bank")
        else None
    )
    return {"success": True, "purchase": _purchase_data(purchase), "bank_details": bank}


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_customer_role_in(*BILLING_ROLES)
def catalog(request: HttpRequest, customer: Customer) -> Response:
    policy = get_selling_currency_policy()
    options = gift_purchase_options(policy.currency_code)
    return _response(
        {
            "success": True,
            **policy.as_dict(),
            "sales_enabled": options["sales_enabled"],
            "denominations": options["denominations_cents"],
            "payment_methods": options["payment_methods"],
        }
    )


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_customer_role_in(*BILLING_ROLES)
def purchases(request: HttpRequest, customer: Customer) -> Response:
    serializer = PurchasePageSerializer(data=getattr(request, "data", {}))
    serializer.is_valid(raise_exception=True)
    page = serializer.validated_data["page"]
    page_size = 50
    rows = list(
        GiftCardPurchase.objects.filter(customer=customer)
        .select_related(
            "gift_card",
            "funding_payment",
            "funding_attempt",
        )
        .prefetch_related("deliveries")
        .order_by("-created_at", "-pk")[(page - 1) * page_size : page * page_size + 1]
    )
    return _response(
        {
            "success": True,
            "purchases": [_purchase_data(row) for row in rows[:page_size]],
            "page": page,
            "has_next": len(rows) > page_size,
        }
    )


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_customer_role_in(*BILLING_ROLES)
def create(request: HttpRequest, customer: Customer) -> Response:
    serializer = PurchaseSerializer(data=getattr(request, "data", {}))
    serializer.is_valid(raise_exception=True)
    data = serializer.validated_data
    try:
        purchase = create_public_purchase(
            customer,
            data["amount_cents"],
            data["idempotency_key"],
            policy_revision=data["currency_revision"],
            currency_code=data["currency"],
            method=data["payment_method"],
            recipient=cast(GiftRecipient, data["recipient"]),
            is_gift=data["is_gift"],
            actor=cast(User, getattr(request, "_customer_user", None)),
        )
    except SellingCurrencyChangedError as exc:
        return _response(
            {
                "success": False,
                "error": "; ".join(exc.messages),
                "code": "currency_changed",
                **get_selling_currency_policy().as_dict(),
            },
            status.HTTP_409_CONFLICT,
        )
    except ValidationError as exc:
        return _error("; ".join(exc.messages))
    return _response({"success": True, "purchase": _purchase_data(purchase)}, status.HTTP_201_CREATED)


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_customer_role_in(*BILLING_ROLES)
def detail(request: HttpRequest, customer: Customer) -> Response:
    purchase = _owned_purchase(request, customer)
    if purchase is None:
        return _error(_("Gift-card purchase not found."), status.HTTP_404_NOT_FOUND)
    return _response(_details(purchase))


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_customer_role_in(*BILLING_ROLES)
def funding(request: HttpRequest, customer: Customer) -> Response:
    purchase = _owned_purchase(request, customer)
    if purchase is None:
        return _error(_("Gift-card purchase not found."), status.HTTP_404_NOT_FOUND)
    if purchase.funding_payment.payment_method == "bank":
        return _response(_details(purchase))
    try:
        return _response(start_funding(purchase))
    except ValidationError as exc:
        return _error("; ".join(exc.messages))


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_customer_role_in(*BILLING_ROLES)
def refresh(request: HttpRequest, customer: Customer) -> Response:
    from apps.promotions.gift_funding import refresh_funding  # noqa: PLC0415  # ADR-0007

    purchase = _owned_purchase(request, customer)
    if purchase is None:
        return _error(_("Gift-card purchase not found."), status.HTTP_404_NOT_FOUND)
    if purchase.funding_payment.payment_method == "stripe":
        try:
            result = refresh_funding(purchase.pk)
        except ValidationError as exc:
            return _error("; ".join(exc.messages))
        if not result.get("success"):
            return _error(
                str(result.get("error") or _("Payment verification is temporarily unavailable.")),
                status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        purchase.refresh_from_db()
    return _response(_details(purchase))


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_customer_role_in(*BILLING_ROLES)
def reveal(request: HttpRequest, customer: Customer) -> Response:
    purchase = _owned_purchase(request, customer)
    if purchase is None:
        return _error(_("Gift-card purchase not found."), status.HTTP_404_NOT_FOUND)
    if not purchase.can_reveal_code:
        return _error(_("The code is available after verified payment while the card has usable value."))
    AuditService.log_simple_event(
        "gift_card_code_revealed",
        content_object=purchase.gift_card,
        user=cast(User, getattr(request, "_customer_user", None)),
        description="Buyer revealed the purchased gift-card code",
        metadata={"purchase_id": str(purchase.pk)},
    )
    return _response({"success": True, "code": purchase.gift_card.code})


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_customer_role_in(*BILLING_ROLES)
def resend(request: HttpRequest, customer: Customer) -> Response:
    from apps.promotions.gift_delivery import queue_purchase_delivery  # noqa: PLC0415  # ADR-0007

    purchase = _owned_purchase(request, customer)
    if purchase is None:
        return _error(_("Gift-card purchase not found."), status.HTTP_404_NOT_FOUND)
    if not purchase.can_reveal_code:
        return _error(_("Gift-card delivery is available after verified payment while the card has usable value."))
    try:
        queue_purchase_delivery(purchase.pk, resend=True)
    except ValidationError as exc:
        return _error("; ".join(exc.messages))
    AuditService.log_simple_event(
        "gift_card_delivery_requested",
        content_object=purchase.gift_card,
        user=cast(User, getattr(request, "_customer_user", None)),
        description="Buyer requested gift-card delivery",
        metadata={"purchase_id": str(purchase.pk)},
    )
    return _response({"success": True})
