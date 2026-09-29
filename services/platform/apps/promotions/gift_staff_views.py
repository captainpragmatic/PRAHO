"""Deliberate staff actions on a gift purchase's original funding and saved code."""

from decimal import Decimal
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID, uuid4

from django import forms
from django.contrib import messages
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext as _
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_POST

from apps.audit.services import AuditService
from apps.common.decorators import staff_required_strict

from .gift_delivery import purchase_delivery_summary, queue_purchase_delivery
from .gift_refunds import record_bank_refund, refresh_refund, refund_purchase
from .models import GiftCard, GiftCardFundingRefund, GiftCardPurchase
from .presentation import staff_context

if TYPE_CHECKING:
    from apps.users.models import User

_SESSION_FORMS = "gift_refund_forms"
_MAX_FORMS = 20


class GiftRefundForm(forms.Form):
    amount = forms.DecimalField(label=_("Refund amount"), min_value=Decimal("0.01"), max_digits=12, decimal_places=2)
    reason = forms.ChoiceField(
        label=_("Reason"),
        choices=(
            ("requested_by_customer", _("Requested by customer")),
            ("duplicate", _("Duplicate payment")),
            ("fraudulent", _("Fraudulent payment")),
        ),
    )
    request_key = forms.UUIDField(widget=forms.HiddenInput)


def _refund_form(request: HttpRequest, card: GiftCard) -> GiftRefundForm:
    key = str(uuid4())
    saved = dict(list(request.session.get(_SESSION_FORMS, {}).items())[-(_MAX_FORMS - 1) :])
    saved[key] = {"card_id": str(card.pk)}
    request.session[_SESSION_FORMS] = saved
    return GiftRefundForm(initial={"request_key": key, "reason": "requested_by_customer"})


def gift_staff_context(request: HttpRequest, card: GiftCard, form: GiftRefundForm | None = None) -> dict[str, Any]:
    purchase = GiftCardPurchase.objects.select_related("funding_payment").filter(gift_card=card).first()
    financial = bool(getattr(request.user, "can_manage_financial_data", False))
    context: dict[str, Any] = {
        "gift_purchase": purchase,
        "gift_financial": financial,
        "can_reveal": financial and card.is_valid and card.available_balance_cents > 0,
    }
    if purchase:
        purchase.gift_card = card
        context["delivery"] = purchase_delivery_summary(purchase)
        context["funding_refunds"] = purchase.funding_refunds.order_by("-created_at")
        if financial and purchase.funded_at and not card.spending_frozen_at and card.available_balance_cents > 0:
            context["refund_form"] = form if form is not None else _refund_form(request, card)
    # Keep an invalid or uncertain submitted form available for the same-key retry.
    if form is not None:
        context["refund_form"] = form
    return context


def _detail_response(
    request: HttpRequest,
    card: GiftCard,
    context: dict[str, Any] | None = None,
    *,
    form: GiftRefundForm | None = None,
    status: int = 200,
) -> HttpResponse:
    card.refresh_from_db()
    context = staff_context(
        request,
        {
            "gift_card": card,
            "transactions": card.transactions.select_related("order", "customer", "created_by").order_by("-created_at"),
            **gift_staff_context(request, card, form),
            **(context or {}),
        },
    )
    response = render(request, "promotions/admin/gift_card_detail.html", context, status=status)
    response["Referrer-Policy"] = "same-origin"
    return response


def _accept_refund_key(request: HttpRequest, card: GiftCard, form: GiftRefundForm) -> bool:
    saved = dict(request.session.get(_SESSION_FORMS, {}))
    key = str(form.cleaned_data["request_key"])
    issued = saved.get(key)
    payload = {"amount_cents": int(form.cleaned_data["amount"] * 100), "reason": form.cleaned_data["reason"]}
    if not isinstance(issued, dict) or issued.get("card_id") != str(card.pk):
        return False
    if issued.get("payload") not in (None, payload):
        return False
    issued["payload"] = payload
    saved[key] = issued
    request.session[_SESSION_FORMS] = saved
    # Persist the immutable request before provider I/O, including on a later 5xx.
    request.session.save()
    return True


def _request_refund(request: HttpRequest, card: GiftCard, purchase: GiftCardPurchase) -> HttpResponse:
    form = GiftRefundForm(request.POST)
    if not form.is_valid():
        return _detail_response(request, card, form=form, status=400)
    if not _accept_refund_key(request, card, form):
        return _detail_response(
            request,
            card,
            form=form,
            status=409,
            context={
                "gift_error": _(
                    "This refund form expired or was submitted with different details. Reload the gift card to start a new request."
                )
            },
        )
    try:
        refund = refund_purchase(
            purchase.pk,
            int(form.cleaned_data["amount"] * 100),
            str(form.cleaned_data["request_key"]),
            actor=cast("User", request.user),
            reason=form.cleaned_data["reason"],
        )
    except ValidationError as exc:
        return _detail_response(request, card, {"gift_error": "; ".join(exc.messages)}, form=form, status=400)
    if refund.status == "succeeded":
        messages.success(request, _("The original payment refund is confirmed."))
    elif refund.status == "awaiting_bank_transfer":
        messages.info(request, _("Refund value is held. Return the money by bank transfer, then record its reference."))
    else:
        messages.info(request, _("The refund request is recorded. Check its status before requesting another refund."))
    return redirect("promotions:gift_card_detail", pk=card.pk)


def _existing_refund_action(
    request: HttpRequest,
    purchase: GiftCardPurchase,
    action: str,
    refund_id: UUID | None,
) -> None:
    refund = get_object_or_404(GiftCardFundingRefund, pk=refund_id, purchase=purchase)
    if action == "refund_bank_confirm":
        refund = record_bank_refund(
            refund.pk,
            reference=request.POST.get("reference", ""),
            actor=cast("User", request.user),
        )
        messages.success(request, _("The completed bank refund has been recorded."))
    else:
        refund = refresh_refund(refund.pk)
        messages.info(request, _("Refund status checked. Review the recorded result below."))
    AuditService.log_simple_event(
        "gift_card_refund_reviewed",
        content_object=refund,
        user=cast("User", request.user),
        description="Financial staff reviewed an original-payment gift refund",
        metadata={"purchase_id": str(purchase.pk), "action": action, "status": refund.status},
    )


@transaction.non_atomic_requests
@never_cache
@staff_required_strict
@require_POST
@csrf_protect
def gift_card_action(
    request: HttpRequest,
    pk: UUID,
    action: str,
    refund_id: UUID | None = None,
) -> HttpResponse:
    if not getattr(request.user, "can_manage_financial_data", False):
        raise PermissionDenied
    card = get_object_or_404(GiftCard.objects.select_related("currency"), pk=pk)
    if action == "reveal":
        with transaction.atomic():
            card = GiftCard.objects.select_for_update().get(pk=pk)
            if not card.is_valid or card.available_balance_cents <= 0:
                return _detail_response(
                    request, card, {"gift_error": _("This gift card is unavailable for use.")}, status=400
                )
            AuditService.log_simple_event(
                "gift_card_code_revealed",
                content_object=card,
                user=cast("User", request.user),
                description="Financial staff revealed a gift-card code",
                metadata={"gift_card_id": str(card.pk)},
            )
            return _detail_response(request, card, {"revealed_code": card.code})
    purchase = get_object_or_404(GiftCardPurchase, gift_card=card)
    if action == "refund":
        return _request_refund(request, card, purchase)
    try:
        if action == "resend":
            queue_purchase_delivery(purchase.pk, resend=True)
            AuditService.log_simple_event(
                "gift_card_delivery_requested",
                content_object=card,
                user=cast("User", request.user),
                description="Financial staff requested gift-card delivery",
                metadata={"purchase_id": str(purchase.pk)},
            )
            messages.success(request, _("Delivery requested using the same saved gift card code."))
        else:
            _existing_refund_action(request, purchase, action, refund_id)
    except ValidationError as exc:
        return _detail_response(request, card, {"gift_error": "; ".join(exc.messages)}, status=400)
    return redirect("promotions:gift_card_detail", pk=card.pk)
