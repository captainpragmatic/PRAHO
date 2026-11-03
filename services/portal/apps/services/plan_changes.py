"""Session-bound Portal checkout; Platform owns all commercial and payment state."""

from uuid import UUID, uuid4

from django import forms
from django.http import HttpRequest, HttpResponse, HttpResponseNotFound
from django.shortcuts import redirect, render
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.utils.translation import gettext as _
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from apps.api_client.services import PlatformAPIClient, PlatformAPIError
from apps.common.decorators import require_billing_access

from .views import _get_session_identity


class PlanQuoteForm(forms.Form):
    target_product_id = forms.UUIDField(widget=forms.HiddenInput)
    submission_id = forms.UUIDField(widget=forms.HiddenInput)
    expected_limit_revision = forms.IntegerField(min_value=1, widget=forms.HiddenInput)


class PlanAcceptanceForm(forms.Form):
    quote_fingerprint = forms.RegexField(regex=r"^[a-f0-9]{64}$", widget=forms.HiddenInput)
    accept_zero_due = forms.BooleanField(required=False)


class PlanChangeClient:
    def __init__(self, customer_id: int, user_id: int, service_id: int) -> None:
        self.customer_id, self.user_id, self.service_id = customer_id, user_id, service_id
        self.api = PlatformAPIClient()

    def call(self, action: str, data: dict[str, object] | None = None, *, change_id: UUID | None = None) -> object:
        if action not in {"options", "quote", "confirm", "payment-intent", "status", "cancel", "safety-refresh"}:
            raise ValueError("Unsupported plan change operation")
        bound = f"{change_id}/" if change_id is not None else ""
        response = self.api.post(
            f"/services/{self.service_id}/plan-changes/{bound}{action}/",
            data={**(data or {}), "customer_id": self.customer_id, "user_id": self.user_id},
        )
        if response.get("success") is not True:
            raise PlatformAPIError("Plan change unavailable")
        return response.get("data")


def _client(request: HttpRequest, service_id: int) -> PlanChangeClient | None:
    customer_id, user_id = _get_session_identity(request)
    return (
        PlanChangeClient(customer_id, user_id, service_id) if customer_id is not None and user_id is not None else None
    )


def _change(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or value.get("status") not in {
        "quoted",
        "awaiting_payment",
        "payment_in_flight",
        "scheduled",
        "applying_limits",
        "completed",
        "cancelled",
        "expired",
        "paid_review",
        "limits_attention",
    }:
        raise PlatformAPIError("Plan change state unavailable")
    if any(
        type(value.get(key)) is not int or value[key] < 0
        for key in ("net_cents", "tax_cents", "total_cents", "next_recurring_net_cents")
    ):
        raise PlatformAPIError("Plan change prices unavailable")
    if not isinstance(value.get("currency"), str) or not isinstance(value.get("periods"), list):
        raise PlatformAPIError("Plan change terms unavailable")
    return value


def _failed(request: HttpRequest, service_id: int, error: PlatformAPIError) -> HttpResponse:
    if error.status_code in {403, 404}:
        return HttpResponseNotFound(_("Plan change not found."))
    status = error.status_code if error.status_code in {400, 409, 429} else 503
    response = render(
        request,
        "services/plan_change.html",
        {
            "service_id": service_id,
            "error": _(
                "This action could not be confirmed. Refresh the plan change before trying again, or contact support."
            ),
        },
        status=status,
    )
    if error.retry_after:
        response["Retry-After"] = str(error.retry_after)
    return response


def _authority_open(change: dict[str, object]) -> bool:
    raw = change.get("authority_expires_at")
    deadline = parse_datetime(raw) if isinstance(raw, str) else None
    return deadline is not None and not timezone.is_naive(deadline) and timezone.now() < deadline


def _phase(change: dict[str, object]) -> str:
    state = change["status"]
    paid = change.get("payment_received") is True
    if state == "payment_in_flight":
        if change.get("payment_state") in {"review", "refused"} or not _authority_open(change):
            return _("This card payment needs staff review. Refresh its status or contact support.")
        if change.get("payment_state") in {"unknown", "submitting"}:
            return _("Payment status is uncertain. Refresh its status before taking another action.")
    if state == "applying_limits":
        return (
            _("Payment received. Your new limits are being applied.")
            if paid
            else _("Your accepted terms are recorded. Your new limits are being applied.")
        )
    if state == "limits_attention":
        return (
            _("Payment received. Applying your limits needs attention; your data is retained.")
            if paid
            else _("Your accepted terms are recorded. Applying your limits needs attention; your data is retained.")
        )
    if state == "paid_review":
        return (
            _("Payment received. Staff must review this change before the plan can be applied.")
            if paid
            else _("Staff must review this change before the plan can be applied.")
        )
    return {
        "quoted": _("Review your plan change"),
        "awaiting_payment": _("Awaiting payment"),
        "payment_in_flight": _("Check payment status before trying again"),
        "scheduled": _("Downgrade scheduled for the agreed renewal boundary"),
        "completed": _("Your accepted plan is active"),
        "cancelled": _("Plan change cancelled"),
        "expired": _("Plan change expired"),
    }[str(state)]


def _detail(request: HttpRequest, client: PlanChangeClient, change_id: UUID, *, payment: object = None) -> HttpResponse:
    change = _change(client.call("status", change_id=change_id))
    ready = change.get("payment_state") in {"reserved", "ready"}
    payable = (change["status"] == "awaiting_payment" and change.get("payment_state") in {None, "reserved"}) or (
        change["status"] == "payment_in_flight" and ready
    )
    can_pay = change.get("viewer_can_pay") is True and payable and _authority_open(change)
    return render(
        request,
        "services/plan_change.html",
        {
            "service_id": client.service_id,
            "change": change,
            "phase": _phase(change),
            "payment": payment if can_pay and change.get("payment_state") == "ready" else None,
            "can_pay": can_pay,
            "can_accept": change.get("viewer_can_accept") is True and change["status"] == "quoted",
            "can_cancel": change["status"] in {"quoted", "awaiting_payment", "payment_in_flight", "scheduled"},
        },
    )


@never_cache
@require_http_methods(["GET", "POST"])
@require_billing_access()
def plan_change_index(request: HttpRequest, service_id: int) -> HttpResponse:
    client = _client(request, service_id)
    if client is None:
        return redirect("/login/")
    try:
        if request.method == "POST":
            if request.POST.get("action") == "refresh-usage":
                client.call("safety-refresh")
                return redirect("services:change_plan", service_id=service_id)
            form = PlanQuoteForm(request.POST)
            if not form.is_valid():
                return render(
                    request,
                    "services/plan_change.html",
                    {"service_id": service_id, "error": _("Select an available plan and request a fresh quote.")},
                    status=400,
                )
            values = form.cleaned_data
            change = _change(
                client.call(
                    "quote",
                    {
                        "target_product_id": str(values["target_product_id"]),
                        "submission_id": str(values["submission_id"]),
                        "expected_limit_revision": values["expected_limit_revision"],
                    },
                )
            )
            return redirect("services:plan_change_detail", service_id=service_id, change_id=change["id"])
        data = client.call("options")
        if not isinstance(data, list) or any(not isinstance(row, dict) for row in data):
            raise PlatformAPIError("Plan choices unavailable")
        options = [
            {
                **row,
                "form": PlanQuoteForm(
                    initial={
                        "target_product_id": row["product_id"],
                        "submission_id": uuid4(),
                        "expected_limit_revision": row["expected_limit_revision"],
                    }
                ),
            }
            for row in data
        ]
        return render(request, "services/plan_change.html", {"service_id": service_id, "options": options})
    except PlatformAPIError as error:
        return _failed(request, service_id, error)


@never_cache
@require_GET
@require_billing_access()
def plan_change_detail(request: HttpRequest, service_id: int, change_id: UUID) -> HttpResponse:
    client = _client(request, service_id)
    if client is None:
        return redirect("/login/")
    try:
        return _detail(request, client, change_id)
    except PlatformAPIError as error:
        return _failed(request, service_id, error)


@never_cache
@require_POST
@require_billing_access()
def plan_change_action(request: HttpRequest, service_id: int, change_id: UUID, action: str) -> HttpResponse:
    client = _client(request, service_id)
    if client is None:
        return redirect("/login/")
    if action not in {"confirm", "payment-intent", "cancel", "refresh"}:
        return HttpResponseNotFound()
    try:
        payment = None
        if action != "refresh":
            form = PlanAcceptanceForm(request.POST)
            if not form.is_valid():
                return render(
                    request,
                    "services/plan_change.html",
                    {"service_id": service_id, "error": _("Refresh the quote before accepting this change.")},
                    status=400,
                )
            result = client.call(
                action,
                {
                    "quote_fingerprint": form.cleaned_data["quote_fingerprint"],
                    "accept_zero_due": form.cleaned_data["accept_zero_due"],
                },
                change_id=change_id,
            )
            if action == "payment-intent":
                if not isinstance(result, dict):
                    raise PlatformAPIError("Card checkout unavailable")
                payment = result if result.get("state") == "ready" and result.get("client_secret") else None
        return _detail(request, client, change_id, payment=payment)
    except PlatformAPIError as error:
        return _failed(request, service_id, error)
