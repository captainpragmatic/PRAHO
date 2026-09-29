"""Gift purchase pages. Business state and payment verification remain on the Platform."""

import hashlib
import json
from http import HTTPStatus
from typing import Any
from uuid import UUID, uuid4

from django.contrib import messages
from django.http import HttpRequest, HttpResponse, HttpResponseNotFound
from django.shortcuts import redirect, render
from django.utils.translation import gettext as _
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_POST

from apps.api_client.services import PlatformAPIError
from apps.common.decorators import require_billing_access

from .forms import GiftCardPurchaseForm
from .services import GiftCardPurchaseService
from .views import _recurring_session_ids

_SESSION_FORMS = "gift_purchase_forms"
_MAX_FORMS = 10


def _catalog(service: GiftCardPurchaseService) -> dict[str, Any]:
    catalog = service.call("catalog")
    if (
        not isinstance(catalog.get("sales_enabled"), bool)
        or catalog.get("selling_currency") not in {"RON", "EUR", "USD"}
        or type(catalog.get("currency_revision")) is not int
        or catalog["currency_revision"] < 1
        or not isinstance(catalog.get("denominations"), list)
        or not all(type(value) is int and value > 0 for value in catalog["denominations"])
        or not isinstance(catalog.get("payment_methods"), list)
        or not all(value in {"stripe", "bank"} for value in catalog["payment_methods"])
    ):
        raise PlatformAPIError("Gift card catalog is unavailable")
    if catalog["sales_enabled"] and (not catalog["denominations"] or not catalog["payment_methods"]):
        raise PlatformAPIError("Gift card catalog is incomplete")
    return catalog


def _new_form(request: HttpRequest, service: GiftCardPurchaseService, catalog: dict[str, Any]) -> GiftCardPurchaseForm:
    key = str(uuid4())
    saved = dict(request.session.get(_SESSION_FORMS, {}))
    # Keep recent tabs and uncertain retries without growing the session indefinitely.
    saved = dict(list(saved.items())[-(_MAX_FORMS - 1) :])
    saved[key] = {"customer_id": service.customer_id, "catalog": catalog}
    request.session[_SESSION_FORMS] = saved
    return GiftCardPurchaseForm(
        catalog=catalog,
        initial={
            "idempotency_key": key,
            "currency": catalog["selling_currency"],
            "currency_revision": catalog["currency_revision"],
            "delivery": "for_me",
        },
    )


def _index_response(
    request: HttpRequest, service: GiftCardPurchaseService, context: dict[str, Any], status: int = 200
) -> HttpResponse:
    try:
        page = max(1, int(request.GET.get("page", "1")))
    except ValueError:
        page = 1
    try:
        result = service.call("purchases", {"page": page})
        context["purchases"] = result["purchases"]
        context["previous_page"] = page - 1 if page > 1 else None
        context["next_page"] = page + 1 if result.get("has_next") else None
    except (PlatformAPIError, KeyError):
        context["history_error"] = _("Your gift card history is temporarily unavailable. Try again shortly.")
    return render(request, "billing/gift_cards.html", context, status=status)


def _fresh_index(
    request: HttpRequest, service: GiftCardPurchaseService, *, notice: str = "", status: int = 200
) -> HttpResponse:
    context: dict[str, Any] = {"notice": notice}
    try:
        context["catalog"] = _catalog(service)
        if context["catalog"]["sales_enabled"]:
            context["form"] = _new_form(request, service, context["catalog"])
    except PlatformAPIError:
        context["catalog_error"] = _("Gift card purchases are temporarily unavailable. Try again shortly.")
    return _index_response(request, service, context, status)


@never_cache
@require_GET
@require_billing_access()
def gift_cards(request: HttpRequest) -> HttpResponse:
    identity = _recurring_session_ids(request)
    if identity is None:
        return redirect("/login/")
    return _fresh_index(request, GiftCardPurchaseService(*identity))


def _create_error_response(
    request: HttpRequest, service: GiftCardPurchaseService, form: GiftCardPurchaseForm, error: PlatformAPIError
) -> HttpResponse:
    if (error.response_data or {}).get("code") == "currency_changed":
        return _fresh_index(
            request,
            service,
            notice=_("The selling currency or prices changed. Review the new amount and submit again to continue."),
            status=409,
        )
    status = HTTPStatus.SERVICE_UNAVAILABLE
    message = _(
        "We could not confirm this purchase. Retry this same form to check it safely, or check your purchase history."
    )
    if error.status_code in {HTTPStatus.BAD_REQUEST, HTTPStatus.FORBIDDEN, HTTPStatus.CONFLICT}:
        status = HTTPStatus(error.status_code)
        message = _("The purchase was not accepted. Review its details or start a new purchase with the current offer.")
    elif error.is_rate_limited:
        status = HTTPStatus.TOO_MANY_REQUESTS
        message = _("Too many requests. Wait briefly, then retry this same purchase.")
    form.add_error(None, message)
    response = _index_response(request, service, {"form": form, "catalog": form.catalog}, status=status)
    if error.retry_after:
        response["Retry-After"] = str(error.retry_after)
    return response


def _validate_retry(request: HttpRequest, form: GiftCardPurchaseForm, issued: dict[str, Any]) -> bool:
    fingerprint = hashlib.sha256(json.dumps(form.purchase_payload(), sort_keys=True).encode()).hexdigest()
    if issued.get("fingerprint") not in (None, fingerprint):
        form.add_error(
            None, _("This purchase was already submitted with different details. Start a new purchase to change it.")
        )
        return False
    saved = dict(request.session.get(_SESSION_FORMS, {}))
    issued["fingerprint"] = fingerprint
    saved[str(form.cleaned_data["idempotency_key"])] = issued
    request.session[_SESSION_FORMS] = saved
    # SessionMiddleware does not persist 5xx responses. Save before the API call so an
    # uncertain timeout cannot turn a retry into a differently configured purchase.
    request.session.save()
    return True


@never_cache
@require_POST
@require_billing_access()
def gift_card_create(request: HttpRequest) -> HttpResponse:
    identity = _recurring_session_ids(request)
    if identity is None:
        return redirect("/login/")
    service = GiftCardPurchaseService(*identity)
    key = request.POST.get("idempotency_key", "")
    saved = dict(request.session.get(_SESSION_FORMS, {}))
    issued = saved.get(key)
    if not isinstance(issued, dict) or issued.get("customer_id") != service.customer_id:
        return _fresh_index(
            request, service, notice=_("Review the current offer before buying a gift card."), status=400
        )
    form = GiftCardPurchaseForm(request.POST, catalog=issued["catalog"])
    if not form.is_valid() or not _validate_retry(request, form, issued):
        return _index_response(request, service, {"form": form, "catalog": form.catalog}, status=400)
    try:
        result = service.call("create", form.purchase_payload())
        purchase_id = UUID(str(result.get("purchase", {}).get("id")))
    except PlatformAPIError as error:
        return _create_error_response(request, service, form, error)
    except (TypeError, ValueError):
        return _create_error_response(request, service, form, PlatformAPIError("Purchase confirmation is incomplete"))
    return redirect("billing:gift_card_detail", purchase_id=purchase_id)


def _detail_response(
    request: HttpRequest,
    service: GiftCardPurchaseService,
    purchase_id: UUID,
    context: dict[str, Any] | None = None,
    status: int = 200,
) -> HttpResponse:
    context = context or {}
    if "purchase" not in context:
        try:
            context.update(service.call("detail", {"purchase_id": str(purchase_id)}))
        except PlatformAPIError as error:
            if error.status_code in {HTTPStatus.NOT_FOUND, HTTPStatus.FORBIDDEN}:
                return HttpResponseNotFound(_("Gift card purchase not found."))
            context["error"] = _("This purchase is temporarily unavailable. Try again shortly.")
            status = 503
    context["purchase_id"] = purchase_id
    return render(request, "billing/gift_card_detail.html", context, status=status)


@never_cache
@require_GET
@require_billing_access()
def gift_card_detail(request: HttpRequest, purchase_id: UUID) -> HttpResponse:
    identity = _recurring_session_ids(request)
    if identity is None:
        return redirect("/login/")
    return _detail_response(request, GiftCardPurchaseService(*identity), purchase_id)


def _action_error_response(
    request: HttpRequest,
    service: GiftCardPurchaseService,
    purchase_id: UUID,
    action: str,
    error: PlatformAPIError,
) -> HttpResponse:
    if error.status_code in {HTTPStatus.NOT_FOUND, HTTPStatus.FORBIDDEN}:
        return HttpResponseNotFound(_("Gift card purchase not found."))
    message = _("This action could not be confirmed. Check the purchase status before trying again.")
    status = HTTPStatus.SERVICE_UNAVAILABLE
    if error.status_code in {HTTPStatus.BAD_REQUEST, HTTPStatus.CONFLICT}:
        status = HTTPStatus(error.status_code)
        message = (
            _("Wait a few minutes before sending again, and check that this gift card is still available.")
            if action == "resend"
            else _("This action is unavailable. Review the purchase status below before trying again.")
        )
    elif error.is_rate_limited:
        status = HTTPStatus.TOO_MANY_REQUESTS
        message = _("Too many requests. Wait briefly, then try again.")
    response = _detail_response(request, service, purchase_id, {"error": message}, status=status)
    if error.retry_after:
        response["Retry-After"] = str(error.retry_after)
    return response


@never_cache
@require_POST
@require_billing_access()
def gift_card_action(request: HttpRequest, purchase_id: UUID, action: str) -> HttpResponse:
    if action not in {"funding", "refresh", "reveal", "resend"}:
        return HttpResponseNotFound()
    identity = _recurring_session_ids(request)
    if identity is None:
        return redirect("/login/")
    service = GiftCardPurchaseService(*identity)
    context: dict[str, Any] = {}
    try:
        result = service.call(action, {"purchase_id": str(purchase_id)})
        if action == "resend":
            messages.success(request, _("Delivery requested. The same gift card code will be sent again."))
            return redirect("billing:gift_card_detail", purchase_id=purchase_id)
        if action == "refresh":
            context.update(result)
        elif action == "reveal":
            context["revealed_code"] = result.get("code", "")
        elif action == "funding":
            if result.get("status") == "processing":
                context["notice"] = _("Payment is processing. Check its status shortly.")
            elif result.get("status") in {
                "requires_payment_method",
                "requires_confirmation",
                "requires_action",
            } and result.get("client_secret"):
                context["payment"] = {
                    "client_secret": result["client_secret"],
                    "public_key": service.stripe_public_key(),
                }
    except PlatformAPIError as error:
        return _action_error_response(request, service, purchase_id, action, error)
    return _detail_response(request, service, purchase_id, context)
