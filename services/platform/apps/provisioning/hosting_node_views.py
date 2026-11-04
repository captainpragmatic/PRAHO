"""Explicit operator review, independent quota adoption and customer mail handover."""

from typing import TYPE_CHECKING, cast
from uuid import UUID

from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext as _
from django.views.decorators.http import require_http_methods
from django_q.models import Task
from django_q.tasks import async_task

from apps.infrastructure.permissions import can_deploy_nodes

from .hosting_node_bundle import helper_bundle
from .hosting_node_execution import normalized_operator_emails
from .hosting_node_policy import node_hosting_readiness, notification_handover_refusal
from .hosting_node_policy_models import NodeHostingPolicy, NodeHostingReview
from .virtualmin_models import VirtualminServer

if TYPE_CHECKING:
    from apps.users.models import User


class HostingPolicyApprovalForm(forms.Form):
    action = forms.ChoiceField(
        choices=[
            ("prepare_helpers", _("Prepare inspection helpers without changing quotas or mail")),
            ("adopt_quota", _("Adopt verified native quotas")),
            ("requalify_quota", _("Requalify an adopted node after reboot while preserving account holds")),
            ("handover_mail", _("Hand customer notifications to Platform")),
            ("reconcile", _("Reconcile held operation")),
        ]
    )
    review_id = forms.UUIDField(required=False, widget=forms.HiddenInput)
    helper_bundle_digest = forms.CharField(required=False, widget=forms.HiddenInput)
    reason = forms.CharField(max_length=2000, widget=forms.Textarea(attrs={"rows": 3}))
    operator_emails = forms.CharField(
        required=False,
        label=_("Additional operator alert recipients"),
        help_text=_(
            "Comma-separated operator addresses to preserve during notification handover. Customer operational recipients are removed."
        ),
    )
    acknowledged = forms.BooleanField(label=_("I reviewed this inventory and accept this specific policy change."))

    def clean_operator_emails(self) -> list[str]:
        return normalized_operator_emails(
            [value.strip() for value in self.cleaned_data["operator_emails"].split(",") if value.strip()]
        )


def _queue_review(
    request: HttpRequest, server: VirtualminServer, action: str, payload: dict[str, object] | None = None
) -> None:
    def committed() -> None:
        task_id = async_task(
            "apps.provisioning.hosting_node_tasks.review_node_hosting",
            str(server.pk),
            str(request.user.pk),
            action,
            payload,
        )
        request.session["node_hosting_task_" + server.pk.hex] = str(task_id)
        request.session.save()

    transaction.on_commit(committed)


@login_required
@require_http_methods(["GET", "POST"])
def node_hosting_policy(request: HttpRequest, server_id: UUID) -> HttpResponse:
    if not can_deploy_nodes(cast("User", request.user)):
        raise PermissionDenied(_("Deployment permission is required."))
    server = get_object_or_404(VirtualminServer, pk=server_id)
    review = NodeHostingReview.objects.filter(server=server).order_by("-created_at").first()
    bundle_digest = helper_bundle()["helper_bundle_digest"]
    form = HostingPolicyApprovalForm(
        initial={"review_id": review.pk if review else None, "helper_bundle_digest": bundle_digest}
    )
    if request.method == "POST":
        action = request.POST.get("action")
        if action == "inspect":
            _queue_review(request, server, "inspect")
            messages.info(
                request, _("Read-only native inventory queued. Import and inspection change no caps or warnings.")
            )
            return redirect("provisioning:node_hosting_policy", server_id=server.pk)
        form = HostingPolicyApprovalForm(request.POST)
        if form.is_valid():
            values = form.cleaned_data.copy()
            if values["action"] == "handover_mail" and (refusal := notification_handover_refusal(server)):
                form.add_error("action", refusal)
            else:
                _queue_review(
                    request,
                    server,
                    values["action"],
                    {
                        "review_id": str(values["review_id"] or ""),
                        "reason": values["reason"],
                        "operator_emails": values["operator_emails"],
                        "helper_bundle_digest": values["helper_bundle_digest"],
                    },
                )
                messages.info(
                    request,
                    _("Reviewed hosting policy operation queued; current ownership remains until native proof."),
                )
                return redirect("provisioning:node_hosting_policy", server_id=server.pk)
    return render(
        request,
        "provisioning/virtualmin/hosting_policy.html",
        {
            "server": server,
            "review": review,
            "readiness": node_hosting_readiness(server),
            "policy": NodeHostingPolicy.objects.filter(server=server).first(),
            "form": form,
            "helper_bundle_digest": bundle_digest,
            "handover_refusal": notification_handover_refusal(server),
            "last_task": Task.objects.filter(pk=request.session.get("node_hosting_task_" + server.pk.hex)).first(),
        },
    )
