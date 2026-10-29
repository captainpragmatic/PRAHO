"""Staff diagnostics read bounded stored observations; requests never query DNS."""

import json
from typing import TYPE_CHECKING, cast

from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.paginator import Paginator
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext as _
from django.views.decorators.http import require_POST

from .hosted_domain_dns_models import HostedDomainDnsStatus
from .hosted_domain_dns_service import request_recheck
from .virtualmin_models import VirtualminAccount
from .virtualmin_views import is_staff_or_superuser

if TYPE_CHECKING:
    from apps.users.models import User


@login_required
@user_passes_test(is_staff_or_superuser)
def dns_failures(request: HttpRequest) -> HttpResponse:
    state = request.GET.get("state", "broken")
    if state not in {"broken", "unknown", "all"}:
        state = "broken"
    rows = HostedDomainDnsStatus.objects.select_related("account", "account__service__customer")
    if state != "all":
        rows = rows.filter(healthy=False) if state == "broken" else rows.filter(healthy__isnull=True)
    page = Paginator(rows.order_by("checked_at", "account_id"), 25).get_page(request.GET.get("page"))
    return render(
        request,
        "provisioning/virtualmin/dns_failures.html",
        {
            "page_title": _("Recorded DNS issues"),
            "dns_page": page,
            "selected_state": state,
            "dns_state_options": [
                {"value": "broken", "label": _("Recorded problems")},
                {"value": "unknown", "label": _("Not confirmed")},
                {"value": "all", "label": _("All recorded results")},
            ],
        },
    )


@login_required
@user_passes_test(is_staff_or_superuser)
@require_POST
def recheck_dns(request: HttpRequest, account_id: str) -> HttpResponse:
    account = get_object_or_404(VirtualminAccount, pk=account_id)
    result = request_recheck(account, actor=cast("User", request.user))
    if result.is_ok():
        messages.success(request, _("A background DNS check was requested."))
    else:
        messages.warning(request, _("A DNS check cannot be requested for this account right now."))
    return redirect("provisioning:virtualmin_account_detail", account_id=account.pk)


def stored_evidence(account: VirtualminAccount) -> str:
    row = HostedDomainDnsStatus.objects.filter(account=account).first()
    if row is None:
        return ""
    results = dict(row.results) if isinstance(row.results, dict) else {"results": row.results}
    components = results.pop("components", None)
    # Every component's state and code come first: jsonb returns keys shorter-first and nested evidence
    # can be long, so the bound below must only ever cut details, never a code staff act on.
    summary = (
        {name: {"state": part.get("state"), "code": part.get("code")} for name, part in components.items()}
        if isinstance(components, dict) and all(isinstance(part, dict) for part in components.values())
        else {}
    )
    ordered: dict[str, object] = {"component_codes": summary} if summary else {}
    if components is not None:
        ordered["components"] = components
    ordered.update((key, value) for key, value in results.items() if key not in ordered)
    return json.dumps(ordered, ensure_ascii=False, indent=2)[:12000]
