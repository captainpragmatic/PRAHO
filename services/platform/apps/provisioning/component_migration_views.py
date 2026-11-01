"""Staff preview and explicit consent for selected imported website migrations."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast
from urllib.parse import urlencode
from uuid import UUID

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext as _
from django.views.decorators.http import require_http_methods
from django_q.models import Task
from django_q.tasks import async_task

from apps.infrastructure.permissions import can_deploy_nodes

from .component_migration_forms import ComponentApprovalForm, ComponentSelectionForm, SourceReleaseForm
from .component_migration_manifest import ComponentManifest
from .component_migration_models import ComponentMigrationReview, SourceServiceObligation
from .component_migration_service import COMPONENT_POLICY_VERSION, MAX_COMPONENT_REVIEW_AGE_SECONDS
from .virtualmin_models import VirtualminAccount
from .virtualmin_node_capability import destination_refusal
from .virtualmin_security import connection_identity

if TYPE_CHECKING:
    from apps.users.models import User


def _review(account: VirtualminAccount, requested: str | None, task: Task | None) -> ComponentMigrationReview | None:
    identifier = requested
    if not identifier and task is not None and task.success and isinstance(task.result, dict):
        identifier = task.result.get("review_id")
    if not identifier:
        return account.component_reviews.select_related("source_server", "target_server").first()
    try:
        review_id = UUID(identifier)
    except (ValueError, TypeError, AttributeError) as error:
        raise Http404 from error
    return get_object_or_404(
        ComponentMigrationReview.objects.select_related("source_server", "target_server"), pk=review_id, account=account
    )


def _readiness(review: ComponentMigrationReview | None) -> tuple[bool, list[str]]:
    if review is None:
        return False, []
    latest = ComponentMigrationReview.objects.filter(
        account_id=review.account_id, source_server_id=review.source_server_id, target_server_id=review.target_server_id
    ).first()
    age = (timezone.now() - review.created_at).total_seconds()
    if (
        latest is None
        or latest.pk != review.pk
        or not 0 <= age <= MAX_COMPONENT_REVIEW_AGE_SECONDS
        or review.policy_version != COMPONENT_POLICY_VERSION
        or review.account.server_id != review.source_server_id
        or review.source_identity != connection_identity(review.source_server)
        or review.target_identity != connection_identity(review.target_server)
        or review.target_server.security_state != "verified_web"
        or destination_refusal(review.target_server) is not None
    ):
        return False, [str(_("This preview is stale or superseded. Inspect the current source and target again."))]
    try:
        ComponentManifest.parse(review.manifest).assert_ready()
    except ValidationError as error:
        return False, error.messages
    return not hasattr(review, "approval"), []


def _task_redirect(account_id: UUID, task_id: str) -> HttpResponse:
    path = reverse("provisioning:component_migration", args=[account_id])
    return redirect(f"{path}?{urlencode({'task': task_id})}")


def _queue_release(
    request: HttpRequest, account: VirtualminAccount, actor: User, task_name: str, form: SourceReleaseForm
) -> HttpResponse | None:
    if not form.is_valid():
        return None
    obligation = get_object_or_404(
        SourceServiceObligation, pk=form.cleaned_data["obligation_id"], migration__account=account
    )
    task_id = async_task(
        "apps.provisioning.component_migration_tasks.release_component_source",
        str(account.pk),
        str(obligation.pk),
        str(actor.pk),
        form.cleaned_data["backup_handoff"],
        task_name=task_name,
        timeout=360,
    )
    messages.info(request, _("Retained source absence verification and backup handoff recording are queued."))
    return _task_redirect(account.pk, task_id)


def _obligation_rows(account: VirtualminAccount, bound: SourceReleaseForm) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    obligations = SourceServiceObligation.objects.filter(migration__account=account).select_related(
        "source_server", "backup_responsible", "release"
    )
    for obligation in obligations:
        form = (
            bound
            if bound.is_bound and str(bound.data.get("obligation_id")) == str(obligation.pk)
            else SourceReleaseForm(initial={"obligation_id": obligation.pk})
        )
        form.auto_id = f"source-release-{obligation.pk}-%s"
        rows.append({"obligation": obligation, "form": form})
    return rows


@login_required
@require_http_methods(["GET", "POST"])
def component_migration(request: HttpRequest, account_id: UUID) -> HttpResponse:
    actor = cast("User", request.user)
    if not actor.is_active or not actor.is_staff_user or not can_deploy_nodes(actor):
        raise PermissionDenied(_("An active staff operator with deployment permission is required."))
    account = get_object_or_404(VirtualminAccount.objects.select_related("server"), pk=account_id)
    action = request.POST.get("action") if request.method == "POST" else None
    task_name = f"component-migration:{account.pk}:{actor.pk}"
    form = ComponentSelectionForm(request.POST if action == "inspect" else None, account=account)
    approval_form = ComponentApprovalForm(request.POST if action == "accept" else None)
    release_form = SourceReleaseForm(request.POST if action == "release" else None)
    task = Task.objects.filter(pk=request.GET.get("task"), name=task_name).first() if request.GET.get("task") else None
    review = _review(account, request.GET.get("review"), task)
    if review is not None and not form.is_bound:
        facts = ComponentManifest.parse(review.manifest).as_json()
        form.initial.update(
            {
                "target_server": review.target_server_id,
                "application_paths": "\n".join(
                    row["relative"] for row in facts["paths"] if row["purpose"] == "application"
                ),
                "configuration_paths": "\n".join(
                    row["relative"] for row in facts["paths"] if row["purpose"] == "configuration"
                ),
                "upload_paths": "\n".join(row["relative"] for row in facts["paths"] if row["purpose"] == "uploads"),
                "databases": "\n".join(row["name"] for row in facts["databases"]),
            }
        )
    status = 200
    if request.method == "POST":
        if action == "release" and (response := _queue_release(request, account, actor, task_name, release_form)):
            return response
        if action == "inspect" and form.is_valid():
            task_id = async_task(
                "apps.provisioning.component_migration_tasks.inspect_component_migration",
                str(account.pk),
                str(form.cleaned_data["target_server"].pk),
                str(actor.pk),
                form.selection(),
                task_name=task_name,
                timeout=360,
            )
            messages.info(request, _("Read-only component inspection queued. Refresh for the current preview."))
            return _task_redirect(account.pk, task_id)
        if action == "accept" and approval_form.is_valid():
            review = get_object_or_404(
                ComponentMigrationReview, pk=approval_form.cleaned_data["review_id"], account=account
            )
            ready, _errors = _readiness(review)
            if ready:
                task_id = async_task(
                    "apps.provisioning.component_migration_tasks.accept_component_migration",
                    str(account.pk),
                    str(review.pk),
                    str(actor.pk),
                    approval_form.cleaned_data["reason"],
                    approval_form.cleaned_data["backup_responsibility"],
                    task_name=task_name,
                    timeout=600,
                )
                messages.info(request, _("Fresh verification and the accepted component migration are queued."))
                return _task_redirect(account.pk, task_id)
            approval_form.add_error(
                None, _("This preview requires preparation or has already been accepted. Inspect again.")
            )
        if action not in {"inspect", "accept", "release"}:
            return HttpResponse(
                _("Invalid component migration action."), status=400, content_type="text/plain; charset=utf-8"
            )
        status = 400
    ready, readiness_errors = _readiness(review)
    if not approval_form.is_bound:
        approval_form = ComponentApprovalForm(initial={"review_id": review.pk if review else None})
    migration = (
        account.migrations.filter(contract="imported_web")
        .select_related("source_server", "target_server", "component_source_obligation")
        .first()
    )
    return render(
        request,
        "provisioning/virtualmin/components/review.html",
        {
            "account": account,
            "form": form,
            "approval_form": approval_form,
            "review": review,
            "facts": review.manifest if review else None,
            "ready": ready,
            "readiness_errors": readiness_errors,
            "task": task,
            "migration": migration,
            "component_management": True,
            "obligation_rows": _obligation_rows(account, release_form),
            "release_form": release_form,
        },
        status=status,
    )
