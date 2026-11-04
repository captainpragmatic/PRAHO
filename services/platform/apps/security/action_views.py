"""HTTP actions persist audited intent; background tasks own every remote operation."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast
from uuid import UUID

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.paginator import Paginator
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext as _
from django.utils.translation import gettext_lazy
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from . import action_services, replication
from .action_forms import ActionHistoryFilter, ActionReasonForm, AllowlistForm, BanForm, CoverageForm, ReasonForm
from .models import SecurityActionRequest, SecurityAllowlist, SecurityDecision, SecuritySource
from .permissions import can_manage_security, can_revoke_security, can_view_security

if TYPE_CHECKING:
    from django.forms import Form

    from apps.users.models import User

STATUS_LABELS = {
    "pending": gettext_lazy("Pending"),
    "issued": gettext_lazy("Pending"),
    "dispatching": gettext_lazy("Dispatched"),
    "unknown": gettext_lazy("Unknown"),
    "succeeded": gettext_lazy("Verified"),
    "complete": gettext_lazy("Complete"),
    "partial": gettext_lazy("Partial"),
    "rejected": gettext_lazy("Rejected"),
    "superseded": gettext_lazy("Superseded"),
    "expired": gettext_lazy("Expired"),
}
EVIDENCE_LABELS = {
    "decision_present": gettext_lazy("Decision confirmed in the local API"),
    "decision_absent": gettext_lazy("Intended decision confirmed inactive"),
    "allowlist_matches": gettext_lazy("Complete staff allowlist confirmed"),
    "no_receipt": gettext_lazy("No receipt; application remains uncertain"),
    "mutation_uncertain": gettext_lazy("The dispatched operation may have applied"),
    "pending_create": gettext_lazy("Waiting for an earlier create to reconcile or expire"),
    "operation_pending": gettext_lazy("Host operation is still pending"),
    "reconciliation_unavailable": gettext_lazy("Read-only reconciliation is unavailable"),
    "simulation": gettext_lazy("Simulation refuses new bans"),
    "protected_overlap": gettext_lazy("Overlaps an inventory protected network"),
    "allowlisted_overlap": gettext_lazy("Overlaps a staff protected network"),
    "clock_unqualified": gettext_lazy("The target clock is unqualified"),
    "scenario_not_approved": gettext_lazy("Scenario sharing is not approved"),
    "source_loop": gettext_lazy("Copying back to the original installation is refused"),
    "immutable_conflict": gettext_lazy("Recorded operation identity conflicts with this payload"),
    "revision_conflict": gettext_lazy("A conflicting revision is already recorded"),
    "allowlist_conflict": gettext_lazy("The staff allowlist changed"),
    "expired": gettext_lazy("The fixed expiry has passed"),
    "revoked": gettext_lazy("A recorded revocation suppresses this create"),
    "newer_revision": gettext_lazy("A newer revision superseded this operation"),
    "capacity": gettext_lazy("The qualified decision capacity was reached"),
}


def _actor(request: HttpRequest, *, revoke: bool = False) -> User:
    actor = cast("User", request.user)
    if not (can_revoke_security(actor) if revoke else can_manage_security(actor)):
        raise PermissionDenied
    return actor


def _page(
    request: HttpRequest,
    form: Form,
    copy: tuple[str, str],
    *,
    status: int = 200,
    subject: SecuritySource | SecurityDecision | None = None,
) -> HttpResponse:
    title, explanation = copy
    withdraw = ReasonForm() if isinstance(form, CoverageForm) else None
    if withdraw is not None:
        withdraw.fields["reason"].widget.attrs["id"] = "id_withdraw_reason"
    return render(
        request,
        "security/action_form.html",
        {
            "page_title": title,
            "action_title": title,
            "explanation": explanation,
            "form": form,
            "source": subject if isinstance(subject, SecuritySource) else None,
            "decision": subject if isinstance(subject, SecurityDecision) else None,
            "actions_enabled": getattr(settings, "PRAHO_CROWDSEC_ACTIONS_ENABLED", False),
            "withdraw_form": withdraw,
        },
        status=status,
    )


@login_required
@require_http_methods(["GET", "POST"])
def ban_create(request: HttpRequest) -> HttpResponse:
    actor = _actor(request)
    form = BanForm(request.POST if request.method == "POST" else None)
    if request.method == "POST" and form.is_valid():
        try:
            address = cast("str", form.cleaned_data["address"])
            action = action_services.issue_ban(
                actor=actor,
                reason=form.cleaned_data["reason"],
                idempotency_key=form.cleaned_data["idempotency_key"],
                source_ids=[source.pk for source in form.cleaned_data["sources"]],
                scope="range" if "/" in address else "ip",
                value=address,
                duration_seconds=form.cleaned_data["duration_seconds"],
            )
            return redirect("security:action-detail", action_id=action.pk)
        except ValidationError as error:
            form.add_error(None, "; ".join(error.messages))
    return _page(
        request,
        form,
        (
            _("Create manual ban"),
            _(
                "New bans require fresh enforcing sources and qualified clocks. Portal targets keep a fixed expiry of at most five minutes; node targets allow at most four hours."
            ),
        ),
        status=400 if request.method == "POST" else 200,
    )


@login_required
@require_http_methods(["GET", "POST"])
def decision_revoke(request: HttpRequest, decision_id: UUID) -> HttpResponse:
    actor = _actor(request, revoke=True)
    decision = get_object_or_404(SecurityDecision.objects.select_related("source"), pk=decision_id)
    form = ActionReasonForm(request.POST if request.method == "POST" else None)
    if request.method == "POST" and form.is_valid():
        try:
            action = action_services.issue_revoke(
                actor=actor,
                reason=form.cleaned_data["reason"],
                idempotency_key=form.cleaned_data["idempotency_key"],
                decision_id=decision.pk,
            )
            return redirect("security:action-detail", action_id=action.pk)
        except ValidationError as error:
            form.add_error(None, "; ".join(error.messages))
    return _page(
        request,
        form,
        (
            _("Revoke decision and PRAHO replicas"),
            _(
                "Revocation suppresses this original decision and its PRAHO copies. A delayed earlier create keeps revocation uncertain until reconciled or expired. Verified LAPI removal does not immediately prove packet-filter removal."
            ),
        ),
        subject=decision,
        status=400 if request.method == "POST" else 200,
    )


@login_required
@require_http_methods(["GET", "POST"])
def allowlist_edit(request: HttpRequest, source_id: UUID) -> HttpResponse:
    actor = _actor(request)
    source = get_object_or_404(SecuritySource, pk=source_id)
    desired = SecurityAllowlist.objects.filter(source=source).first()
    form = AllowlistForm(
        request.POST if request.method == "POST" else None,
        initial={
            "cidrs": "\n".join(desired.cidrs) if desired else "",
            "expected_revision": desired.revision if desired else 0,
        },
    )
    if request.method == "POST" and form.is_valid():
        try:
            action = action_services.replace_allowlist(
                actor=actor,
                reason=form.cleaned_data["reason"],
                idempotency_key=form.cleaned_data["idempotency_key"],
                source_id=source.pk,
                cidrs=form.cleaned_data["cidrs"],
                expected_revision=form.cleaned_data["expected_revision"],
            )
            return redirect("security:action-detail", action_id=action.pk)
        except ValidationError as error:
            form.add_error(None, "; ".join(error.messages))
    return _page(
        request,
        form,
        (
            _("Replace staff allowlist"),
            _(
                "Submit the complete desired staff list. Inventory protections stay fixed. Allowing an address may remove an overlapping broader CIDR ban and unblock other addresses in that range; review the per-target result before claiming removal."
            ),
        ),
        subject=source,
        status=400 if request.method == "POST" else 200,
    )


@login_required
@require_http_methods(["GET", "POST"])
def coverage_edit(request: HttpRequest, source_id: UUID) -> HttpResponse:
    actor = _actor(request)
    source = get_object_or_404(SecuritySource, pk=source_id)
    form = CoverageForm(request.POST if request.method == "POST" else None)
    if request.method == "POST" and form.is_valid():
        try:
            replication.approve_coverage(
                actor=actor,
                reason=form.cleaned_data["reason"],
                source_id=source.pk,
                scenarios=form.cleaned_data["scenarios"],
                evidence_digest=form.cleaned_data["evidence_digest"],
                native_evidence=form.cleaned_data["native_evidence"],
                administrative_ssh=form.cleaned_data["administrative_ssh"],
            )
            return redirect("security:dashboard")
        except ValidationError as error:
            form.add_error(None, "; ".join(error.messages))
    return _page(
        request,
        form,
        (
            _("Approve qualified scenario sharing"),
            _(
                "Approve only the listed hostile scenarios supported by native acquisition and ingress evidence for this exact installation and configuration. Customer SFTP, Portal authentication, Webmin authentication and HTTP probing remain local."
            ),
        ),
        subject=source,
        status=400 if request.method == "POST" else 200,
    )


@login_required
@require_POST
def coverage_withdraw(request: HttpRequest, source_id: UUID) -> HttpResponse:
    actor = _actor(request)
    source = get_object_or_404(SecuritySource, pk=source_id)
    form = ReasonForm(request.POST)
    if form.is_valid():
        try:
            replication.withdraw_coverage(actor=actor, reason=form.cleaned_data["reason"], source_id=source.pk)
            return redirect("security:dashboard")
        except ValidationError as error:
            form.add_error(None, "; ".join(error.messages))
    return _page(
        request,
        form,
        (
            _("Withdraw scenario sharing approval"),
            _("Withdrawal prevents new copies. Existing local and copied decisions retain their fixed expiry."),
        ),
        subject=source,
        status=400,
    )


@login_required
@require_GET
def action_list(request: HttpRequest) -> HttpResponse:
    if not can_view_security(cast("User", request.user)):
        raise PermissionDenied
    form = ActionHistoryFilter(request.GET)
    rows = SecurityActionRequest.objects.order_by("-created_at", "pk")
    if not form.is_valid():
        rows = rows.none()
    elif state := form.cleaned_data.get("state"):
        rows = rows.filter(status=state)
    page = Paginator(rows, 25).get_page(request.GET.get("page"))
    summaries = [{"action": action, "label": STATUS_LABELS.get(action.status, gettext_lazy("Unknown"))} for action in page]
    return render(
        request,
        "security/action_list.html",
        {
            "page_title": _("Security actions"),
            "filters": form,
            "action_page": page,
            "summaries": summaries,
            "state": request.GET.get("state", ""),
        },
        status=200 if form.is_valid() else 400,
    )


@login_required
@require_GET
def action_detail(request: HttpRequest, action_id: UUID) -> HttpResponse:
    if not can_view_security(cast("User", request.user)):
        raise PermissionDenied
    action = get_object_or_404(
        SecurityActionRequest.objects.select_related("actor", "decision").prefetch_related("targets__source"),
        pk=action_id,
    )
    targets = [
        {
            "target": target,
            "label": STATUS_LABELS.get(target.state, gettext_lazy("Unknown")),
            "evidence_label": EVIDENCE_LABELS.get(
                str(target.evidence.get("evidence", "")), gettext_lazy("Awaiting a verified result")
            ),
        }
        for target in action.targets.all()
    ]
    return render(
        request,
        "security/action_detail.html",
        {
            "page_title": _("Security action result"),
            "action": action,
            "status_label": STATUS_LABELS.get(action.status, _("Unknown")),
            "targets": targets,
        },
    )
