"""Customer DNS observations are read from Platform, never probed during a page request."""

from http import HTTPStatus
from typing import Any

from django.http import HttpRequest, HttpResponse, HttpResponseForbidden, HttpResponseRedirect
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils.cache import patch_cache_control
from django.utils.dateparse import parse_datetime
from django.utils.translation import gettext as _
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods

from apps.api_client.services import PlatformAPIError
from apps.common.decorators import _get_user_role_for_customer

from .services import services_api
from .views import _get_session_identity

TECH_ROLES = frozenset({"owner", "tech"})
MAX_DNS_POLLS = 12


def _components(status: dict[str, Any]) -> list[dict[str, str]]:
    labels = {
        "apex": _("Website"),
        "www": _("www"),
        "caa": _("Certificate authority policy"),
        "dnssec": _("DNSSEC delegation"),
        "mx": _("Mail routing"),
    }
    messages = {
        "healthy": _("The observed DNS matches the expected configuration."),
        "broken": _("These DNS records need attention."),
        "unknown": _("This check is not confirmed yet."),
        "not_applicable": _("No change is required for this check."),
    }
    codes = {
        "address_mismatch": _("DNS points to another destination."),
        "routing_missing": _("This name has no usable website address."),
        "routing_mixed_addresses": _("DNS mixes this hosting destination with another address."),
        "stray_aaaa": _("An IPv6 record points away from your hosting."),
        "external_origin_unverified": _("DNS uses another service or a proxy whose hosting origin is not confirmed."),
        "caa_unknown_critical": _("A critical CAA property prevents certificate issuance."),
        "caa_excludes_letsencrypt": _("CAA does not allow Let's Encrypt to issue a certificate."),
        "caa_parameters_unverified": _("Issuer-specific CAA restrictions need further confirmation."),
        "dnssec_ds_key_mismatch": _("The registrar's DS record does not match the nameserver keys."),
        "dnssec_ds_key_consistent": _("Delegation keys match; DNSSEC signatures were not checked."),
        "dnssec_unsigned": _("No DNSSEC delegation is configured."),
        "external_mail": _("External mail delivery is unchanged."),
        "null_mx": _("This domain declares that it does not accept mail."),
        "implicit_external_mail": _("Hosted mail has not been enabled."),
        "mixed_null_mx": _("MX records mix a no-mail declaration with mail servers."),
    }
    results = status.get("components")
    rows = []
    for name, label in labels.items():
        value = results.get(name) if isinstance(results, dict) else None
        if not isinstance(value, dict):
            continue
        raw_state, raw_code = value.get("state"), value.get("code")
        state = raw_state if isinstance(raw_state, str) else "unknown"
        code = raw_code if isinstance(raw_code, str) else ""
        rows.append(
            {
                "name": label,
                "state": str(state),
                "message": codes.get(code, messages.get(state, messages["unknown"])),
            }
        )
    return rows


def _context(request: HttpRequest, service_id: int, status: dict[str, Any], *, can_recheck: bool) -> dict[str, Any]:
    try:
        poll = min(MAX_DNS_POLLS, max(0, int(request.GET.get("poll", "0"))))
    except ValueError:
        poll = 0
    checked = status.get("checked_at")
    try:
        checked_at = parse_datetime(checked) if isinstance(checked, str) else None
    except ValueError:
        checked_at = None
    stale = status.get("stale") is True
    components = status.get("components")
    maintenance = isinstance(components, dict) and any(
        isinstance(item, dict) and item.get("code") == "maintenance" for item in components.values()
    )
    state = "maintenance" if maintenance else "unknown" if stale else status.get("state", "unknown")
    account_name = status.get("account_name")
    instructions = status.get("instructions")
    records = []
    if isinstance(instructions, list):
        records = [
            {"type": item["type"], "name": item["name"], "value": account_name}
            for item in instructions[:8]
            if isinstance(item, dict)
            and isinstance(item.get("type"), str)
            and item.get("type") in {"CNAME", "ALIAS"}
            and isinstance(item.get("name"), str)
            and item.get("value") == account_name
        ]
    return {
        "service_id": service_id,
        "dns_state": state,
        "dns_stale": stale,
        "dns_pending": status.get("pending") is True,
        "dns_checked_at": checked_at,
        "dns_account_name": status.get("account_name"),
        "dns_hosting": {"account_name": account_name, "records": records} if account_name else None,
        "dns_components": [] if stale else _components(status),
        "can_recheck_dns": can_recheck and state not in {"unavailable", "maintenance", "not_applicable"},
        "dns_poll": poll + 1,
        "dns_poll_again": status.get("pending") is True and poll < MAX_DNS_POLLS,
    }


@require_http_methods(["GET", "POST"])
@csrf_protect
def service_dns(request: HttpRequest, service_id: int) -> HttpResponse:
    customer_id, user_id = _get_session_identity(request)
    if not customer_id or not user_id:
        return redirect("/login/")
    try:
        role = _get_user_role_for_customer(request, str(customer_id))
        if request.method == "POST" and role not in TECH_ROLES:
            return HttpResponseForbidden(_("You do not have permission to recheck DNS."))
        status = (
            services_api.recheck_service_dns(customer_id, user_id, service_id)
            if request.method == "POST"
            else services_api.get_service_dns_status(customer_id, user_id, service_id)
        )
        context = _context(request, service_id, status, can_recheck=role in TECH_ROLES)
        code = 202 if request.method == "POST" else 200
        if request.method == "POST" and request.headers.get("HX-Request") != "true":
            return HttpResponseRedirect(reverse("services:dns", args=[service_id]), status=303)
    except PlatformAPIError as error:
        if error.status_code == HTTPStatus.FORBIDDEN:
            return HttpResponseForbidden(_("You do not have permission to access these DNS checks."))
        context = _context(request, service_id, {"state": "unavailable"}, can_recheck=False)
        code = 200 if request.headers.get("HX-Request") == "true" else 503
    template = (
        "services/partials/dns_status_card.html"
        if request.headers.get("HX-Request") == "true"
        else "services/service_dns.html"
    )
    response = render(request, template, context, status=code)
    patch_cache_control(response, private=True, no_store=True)
    return response
