"""Customer DNS management delegates authorization and durable changes to Platform."""

import json
from collections.abc import Callable
from functools import wraps
from typing import Any
from uuid import UUID

from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django.utils.cache import patch_cache_control
from django.utils.translation import gettext as _
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods

from apps.api_client.services import PlatformAPIError
from apps.common.decorators import _get_user_role_for_customer
from apps.services.services import services_api
from apps.services.views import _get_session_identity

from .forms import (
    ConfirmImportForm,
    DeleteRecordForm,
    DeleteZoneForm,
    RecordForm,
    RegistrarSwitchForm,
    RevisionForm,
    ZoneImportForm,
)
from .services import MAX_ZONE_FILE_BYTES, dns_api

TECH_ROLES = frozenset({"owner", "tech"})
MEMBER_ROLES = TECH_ROLES | {"billing", "viewer"}
MAX_POLLS = 12


def _failure(request: HttpRequest, code: int) -> HttpResponse:
    allowed = {400, 403, 404, 409, 429, 503}
    status = code if code in allowed else 503
    response = render(request, "dns/error.html", {"status": status}, status=status)
    if request.headers.get("HX-Request") == "true":
        # HTMX leaves 4xx/5xx bodies unswapped. Its existing event listener displays this
        # notice while preserving the form and the real failure status.
        response["HX-Trigger"] = json.dumps(
            {
                "showToast": {
                    "variant": "error",
                    "message": _(
                        "The DNS operation could not be completed. Reload the zone and review the current information."
                    ),
                }
            }
        )
    return response


def _access(*, write: bool = False) -> Callable[..., Any]:
    def decorate(view: Callable[..., HttpResponse]) -> Callable[..., HttpResponse]:
        @wraps(view)
        def wrapped(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
            customer_id, user_id = _get_session_identity(request)
            if customer_id is None or user_id is None:
                return HttpResponseRedirect("/login/")
            try:
                role = _get_user_role_for_customer(request, str(customer_id))
                if role not in (TECH_ROLES if write else MEMBER_ROLES):
                    response = _failure(request, 403)
                else:
                    response = view(request, customer_id, user_id, *args, can_edit=role in TECH_ROLES, **kwargs)
            except PlatformAPIError as error:
                response = _failure(request, error.status_code or 503)
            patch_cache_control(response, private=True, no_store=True)
            return response

        return wrapped

    return decorate


def _number(raw: str | None, *, default: int = 1, maximum: int = 100000) -> int:
    try:
        return min(maximum, max(default, int(raw or default)))
    except ValueError:
        return default


def _success(request: HttpRequest, zone_id: UUID | str) -> HttpResponse:
    url = reverse("dns:detail", args=[zone_id])
    if request.headers.get("HX-Request") == "true":
        return HttpResponse(status=200, headers={"HX-Redirect": url})
    return HttpResponseRedirect(url, status=303)


def _pagination(data: dict[str, Any]) -> dict[str, int | None]:
    page, pages = data["page"], data["pages"]
    return {"previous_page": page - 1 if page > 1 else None, "next_page": page + 1 if page < pages else None}


def _import_errors(zone: dict[str, Any]) -> list[dict[str, Any]]:
    explanations = {
        "unsupported_records": _("This zone includes record types that cannot be imported safely."),
        "provider_unrepresentable_record": _("The provider cannot preserve one or more records exactly."),
        "conflicting_rrset_ttl": _("Records in the same set have conflicting TTL values."),
        "ttl_out_of_range": _("A record's TTL must be between 60 and 86400 seconds."),
        "missing_apex_infrastructure": _("Include the original zone's SOA and apex NS records."),
        "out_of_zone_owner": _("A record name is outside this zone."),
        "canonical_zone_limit": _("The complete zone exceeds the supported export size."),
        "rrset_record_limit": _("A record set exceeds the supported limit of 128 values."),
    }
    return [
        {
            "line": error["line"],
            "message": explanations.get(error["code"], _("The zone file could not be imported safely.")),
        }
        for error in zone["errors"]
    ]


def _status_label(status: str) -> str:
    labels = {
        "pending_import": _("Import pending"),
        "awaiting_ns": _("Awaiting nameserver change"),
        "active": _("Active"),
        "deleting": _("Deletion in progress"),
        "deleted": _("Deleted"),
        "failed": _("Needs attention"),
    }
    return labels.get(status, _("Status unavailable"))


def _normalization_labels(zone: dict[str, Any]) -> list[dict[str, Any]]:
    labels = {
        "managed_frontend": _("Managed hosting records"),
        "duplicate_collapsed": _("Duplicate record removed"),
        "customer_record_change": _("DNS record changes"),
    }
    return [
        {**change, "label": labels.get(change["kind"], _("DNS record adjustment"))} for change in zone["normalizations"]
    ]


@require_http_methods(["GET"])
@_access()
def zone_list(request: HttpRequest, customer_id: int, user_id: int, *, can_edit: bool) -> HttpResponse:
    data = dns_api.zone_list(customer_id, user_id, page=_number(request.GET.get("page")))
    zones = [{**zone, "status_label": _status_label(zone["status"])} for zone in data["zones"]]
    return render(request, "dns/zone_list.html", {**data, "zones": zones, **_pagination(data), "can_edit": can_edit})


@require_http_methods(["GET", "POST"])
@csrf_protect
@_access(write=True)
def zone_import(
    request: HttpRequest, customer_id: int, user_id: int, service_id: int, *, can_edit: bool
) -> HttpResponse:
    service = services_api.get_service_detail(customer_id, user_id, service_id)
    if (
        not isinstance(service, dict)
        or not isinstance(service.get("domain"), str)
        or not isinstance(service.get("hosting"), dict)
        or not service["hosting"]
    ):
        return _failure(request, 404)
    data = request.POST.copy() if request.method == "POST" else None
    if data is not None:
        data["service_id"] = str(service_id)
    form = ZoneImportForm(data, request.FILES or None, initial={"service_id": service_id})
    if request.method == "POST" and form.is_valid():
        raw = form.cleaned_data["zone_file"].read(MAX_ZONE_FILE_BYTES + 1)
        zone = dns_api.import_zone(customer_id, user_id, service_id, raw)
        return _success(request, zone["id"])
    return render(
        request,
        "dns/zone_import.html",
        {"form": form, "service": service, "service_id": service_id},
        status=400 if request.method == "POST" else 200,
    )


@require_http_methods(["GET"])
@_access()
def zone_detail(request: HttpRequest, customer_id: int, user_id: int, zone_id: UUID, *, can_edit: bool) -> HttpResponse:
    zone = dns_api.zone_detail(customer_id, user_id, zone_id, page=_number(request.GET.get("page")))
    poll = _number(request.GET.get("poll"), default=0, maximum=MAX_POLLS)
    initial = {"expected_revision": zone["revision"], "manifest_digest": zone["manifest_digest"]}
    return render(
        request,
        "dns/zone_detail.html",
        {
            "zone": zone,
            "status_label": _status_label(zone["status"]),
            "normalizations": _normalization_labels(zone),
            "can_edit": can_edit,
            "import_errors": _import_errors(zone),
            "confirm_form": ConfirmImportForm(initial=initial),
            "revision_form": RevisionForm(initial=initial),
            "switch_form": RegistrarSwitchForm(initial=initial),
            "poll": poll + 1,
            "poll_again": zone["pending"] and poll < MAX_POLLS,
            **_pagination(zone),
        },
    )


@require_http_methods(["POST"])
@csrf_protect
@_access(write=True)
def zone_action(  # noqa: PLR0913  # Decorator supplies both authenticated identities and the role flag.
    request: HttpRequest, customer_id: int, user_id: int, zone_id: UUID, action: str, *, can_edit: bool
) -> HttpResponse:
    if action not in {"crosscheck", "confirm", "switch"}:
        return _failure(request, 404)
    forms = {"confirm": ConfirmImportForm, "switch": RegistrarSwitchForm, "crosscheck": RevisionForm}
    form = forms[action](request.POST)
    if not form.is_valid():
        return _failure(request, 400)
    payload = {key: value for key, value in form.cleaned_data.items() if key != "confirmed"}
    dns_api.zone_action(customer_id, user_id, zone_id, action, payload)
    return _success(request, zone_id)


@require_http_methods(["POST"])
@csrf_protect
@_access(write=True)
def zone_export(request: HttpRequest, customer_id: int, user_id: int, zone_id: UUID, *, can_edit: bool) -> HttpResponse:
    raw = dns_api.export_zone(customer_id, user_id, zone_id)
    return HttpResponse(
        raw,
        content_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="dns-zone.txt"', "X-Content-Type-Options": "nosniff"},
    )


@require_http_methods(["GET", "POST"])
@csrf_protect
@_access(write=True)
def zone_delete(request: HttpRequest, customer_id: int, user_id: int, zone_id: UUID, *, can_edit: bool) -> HttpResponse:
    zone = dns_api.zone_detail(customer_id, user_id, zone_id)
    initial = {"expected_revision": zone["revision"], "export_digest": zone["export_digest"]}
    form = DeleteZoneForm(request.POST if request.method == "POST" else None, initial=initial)
    if request.method == "POST" and form.is_valid():
        if (
            form.cleaned_data["export_digest"] != zone["export_digest"]
            or form.cleaned_data["expected_revision"] != zone["revision"]
        ):
            return _failure(request, 409)
        dns_api.zone_action(customer_id, user_id, zone_id, "delete", {key: form.cleaned_data[key] for key in initial})
        return _success(request, zone_id)
    return render(
        request, "dns/zone_delete.html", {"zone": zone, "form": form}, status=400 if request.method == "POST" else 200
    )


@require_http_methods(["GET", "POST"])
@csrf_protect
@_access(write=True)
def zone_record(  # noqa: PLR0913  # Decorator supplies both authenticated identities and the role flag.
    request: HttpRequest,
    customer_id: int,
    user_id: int,
    zone_id: UUID,
    record_id: UUID | None = None,
    *,
    can_edit: bool,
) -> HttpResponse:
    zone = dns_api.zone_detail(customer_id, user_id, zone_id)
    initial: dict[str, Any] = {"expected_revision": zone["revision"], "name": zone["name"], "ttl": 300}
    if record_id:
        data = dns_api.record_detail(customer_id, user_id, zone_id, record_id)
        if data["record"]["managed"]:
            return _failure(request, 409)
        initial.update(data["record"], expected_revision=data["revision"])
    form = RecordForm(request.POST if request.method == "POST" else None, initial=initial)
    if request.method == "POST" and form.is_valid():
        dns_api.change_record(customer_id, user_id, zone_id, record_id, form.payload())
        return _success(request, zone_id)
    return render(
        request,
        "dns/record_form.html",
        {"zone": zone, "form": form, "record_id": record_id},
        status=400 if request.method == "POST" else 200,
    )


@require_http_methods(["GET", "POST"])
@csrf_protect
@_access(write=True)
def record_delete(  # noqa: PLR0913  # Decorator supplies both authenticated identities and the role flag.
    request: HttpRequest, customer_id: int, user_id: int, zone_id: UUID, record_id: UUID, *, can_edit: bool
) -> HttpResponse:
    data = dns_api.record_detail(customer_id, user_id, zone_id, record_id)
    record = data["record"]
    if record["managed"]:
        return _failure(request, 409)
    form = DeleteRecordForm(
        request.POST if request.method == "POST" else None, initial={"expected_revision": data["revision"]}
    )
    if request.method == "POST" and form.is_valid():
        dns_api.change_record(
            customer_id,
            user_id,
            zone_id,
            record_id,
            {"expected_revision": form.cleaned_data["expected_revision"], "delete": True},
        )
        return _success(request, zone_id)
    return render(
        request,
        "dns/record_delete.html",
        {"zone_id": zone_id, "record": record, "form": form},
        status=400 if request.method == "POST" else 200,
    )
