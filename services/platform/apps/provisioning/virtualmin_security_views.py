"""Operator review of the exact observed node policy."""

from typing import TYPE_CHECKING, cast
from urllib.parse import urlencode
from uuid import UUID

from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.translation import gettext as _
from django.views.decorators.http import require_http_methods
from django_q.models import Task
from django_q.tasks import async_task

from apps.infrastructure.ansible_service import node_admin_allowed_cidrs
from apps.infrastructure.permissions import can_deploy_nodes, is_staff_or_superuser
from apps.ui.widgets import PRAHOCheckboxWidget, PRAHOTextAreaWidget

from .virtualmin_models import VirtualminServer
from .virtualmin_node_capability import destination_refusal
from .virtualmin_security_policy import selected_network_preparation

if TYPE_CHECKING:
    from apps.users.models import User


class SourceAcknowledgmentForm(forms.Form):
    review_id = forms.UUIDField(widget=forms.HiddenInput)
    reason = forms.CharField(
        label=_("Responsibility for retained services"),
        max_length=2000,
        widget=PRAHOTextAreaWidget(attrs={"rows": 3, "id": "id_source_security_reason"}),
    )
    acknowledged = forms.BooleanField(
        label=_(
            "I understand that hardening will be skipped, existing access and services remain, "
            "and this node is retained as a migration source."
        ),
        widget=PRAHOCheckboxWidget(attrs={"id": "id_source_security_acknowledged"}),
    )


class HardeningApprovalForm(forms.Form):
    review_id = forms.UUIDField(widget=forms.HiddenInput)
    reason = forms.CharField(
        label=_("Service evacuation and operator responsibility"),
        max_length=2000,
        widget=PRAHOTextAreaWidget(attrs={"rows": 3, "id": "id_hardening_security_reason"}),
    )
    acknowledged = forms.BooleanField(
        label=_(
            "I accept the listed access, firewall, package and service changes and their interruption. "
            "Mail, DNS and other affected services have been evacuated or may be stopped. "
            "I have the approved operator SSH key and understand the recovery limits."
        ),
        widget=PRAHOCheckboxWidget(attrs={"id": "id_hardening_security_acknowledged"}),
    )


class PolicyVerificationForm(forms.Form):
    reason = forms.CharField(
        label=_("Recovery actions and verification responsibility"),
        max_length=2000,
        widget=PRAHOTextAreaWidget(attrs={"rows": 3, "id": "id_verification_security_reason"}),
    )
    acknowledged = forms.BooleanField(
        label=_(
            "I confirmed that the failed attempt and its remote commands have stopped. "
            "Reinspect and verify the applied policy without replaying hardening."
        ),
        widget=PRAHOCheckboxWidget(attrs={"id": "id_verification_security_acknowledged"}),
    )


def _admission_context(server: VirtualminServer) -> dict[str, object]:
    refusal = destination_refusal(server)
    review = server.current_security_review
    preparation = (
        selected_network_preparation(
            review.evidence,
            server.security_policy_version,
            server.security_configuration_digest,
            node_admin_allowed_cidrs(),
        )
        if review
        else []
    )
    if review and review.policy_version != server.security_policy_version:
        preparation = [str(_("Inspect again for current NAT, forwarding and topology evidence."))]
    return {
        "verification_stale": server.security_state == "verified_web" and refusal is not None,
        "legacy_admitted": server.security_state == "unreviewed"
        and server.legacy_security_admission
        and refusal is None,
        "admission_warning": refusal,
        "network_preparation": preparation,
        "network_ready": review is not None and not preparation,
    }


@login_required
@require_http_methods(["GET", "POST"])
def node_security(request: HttpRequest, server_id: UUID) -> HttpResponse:
    if not is_staff_or_superuser(cast("User", request.user)):
        raise PermissionDenied(_("Staff access is required."))
    server = get_object_or_404(VirtualminServer, pk=server_id)
    actor = cast("User", request.user)
    form: forms.Form = SourceAcknowledgmentForm(initial={"review_id": server.current_security_review_id})
    apply_form: forms.Form = HardeningApprovalForm(initial={"review_id": server.current_security_review_id})
    verify_form: forms.Form = PolicyVerificationForm()
    decision_form: forms.Form = form
    task_name = f"node-security:{server.pk}:{actor.pk}"
    if request.method == "POST":
        action = request.POST.get("action")
        if action not in {"inspect", "acknowledge", "apply", "verify"}:
            return HttpResponse(_("Invalid security action."), status=400, content_type="text/plain; charset=utf-8")
        if action != "inspect":
            if not can_deploy_nodes(actor):
                return HttpResponse(
                    _("Deployment permission is required."), status=403, content_type="text/plain; charset=utf-8"
                )
            decision_form = (
                HardeningApprovalForm(request.POST) if action == "apply" else SourceAcknowledgmentForm(request.POST)
            )
            if action == "verify":
                decision_form = PolicyVerificationForm(request.POST)
                verify_form = decision_form
            if action == "apply":
                apply_form = decision_form
            elif action == "acknowledge":
                form = decision_form
            if not decision_form.is_valid():
                return render(
                    request,
                    "provisioning/virtualmin/security.html",
                    {
                        "server": server,
                        "review": server.current_security_review,
                        "form": form,
                        "apply_form": apply_form,
                        "verify_form": verify_form,
                        "can_decide": True,
                        **_admission_context(server),
                    },
                    status=400,
                )
        if action == "inspect" or decision_form.is_valid():
            task_id = async_task(
                "apps.provisioning.virtualmin_security_tasks.review_node_security",
                str(server.pk),
                str(actor.pk),
                action,
                str(decision_form.cleaned_data["review_id"]) if action in {"apply", "acknowledge"} else "",
                decision_form.cleaned_data["reason"] if action != "inspect" else "",
                task_name=task_name,
                timeout=4200 if action == "apply" else 180,
            )
            messages.info(request, _("Node security action queued. Refresh this page for the result."))
            path = reverse("provisioning:node_security", args=[server.pk])
            return redirect(f"{path}?{urlencode({'task': task_id})}")
    task = Task.objects.filter(pk=request.GET.get("task"), name=task_name).first() if request.GET.get("task") else None
    return render(
        request,
        "provisioning/virtualmin/security.html",
        {
            "server": server,
            "review": server.current_security_review,
            "form": form,
            "apply_form": apply_form,
            "verify_form": verify_form,
            "task": task,
            "can_decide": can_deploy_nodes(actor),
            **_admission_context(server),
        },
    )
