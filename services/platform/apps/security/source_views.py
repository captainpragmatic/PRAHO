"""Administrator source enrollment persists intent without issuing RPCs."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast
from uuid import UUID

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext as _
from django.views.decorators.http import require_http_methods, require_POST

from .models import SecuritySource
from .permissions import can_manage_security
from .services import enroll_source, reconfigure_source, retire_source
from .source_forms import SourceEnrollmentForm, SourceReasonForm

if TYPE_CHECKING:
    from apps.users.models import User


def _admin(request: HttpRequest) -> User:
    actor = cast("User", request.user)
    if not can_manage_security(actor):
        raise PermissionDenied
    return actor


def _render(request: HttpRequest, form: SourceEnrollmentForm, source: SecuritySource | None, *, status: int = 200, retire_form: SourceReasonForm | None = None) -> HttpResponse:
    return render(request, "security/source_form.html", {
        "page_title": _("Security source"), "form": form, "source": source,
        "retire_form": retire_form or SourceReasonForm(initial={"generation": source.generation if source else 1}),
    }, status=status)


@login_required
@require_http_methods(["GET", "POST"])
def source_edit(request: HttpRequest, source_id: UUID | None = None) -> HttpResponse:
    actor = _admin(request)
    source = get_object_or_404(SecuritySource, pk=source_id) if source_id else None
    form = SourceEnrollmentForm(request.POST if request.method == "POST" else None, source=source)
    if request.method == "POST" and form.is_valid():
        try:
            config = form.configuration()
            reason = cast("str", form.cleaned_data["reason"])
            if source is None:
                enroll_source(config, actor, reason=reason)
            else:
                reconfigure_source(source.pk, config, actor, reason=reason, expected_generation=cast("int", form.cleaned_data["generation"]))
            return redirect("security:dashboard")
        except ValidationError as error:
            form.add_error(None, "; ".join(error.messages))
    return _render(request, form, source, status=400 if request.method == "POST" else 200)


@login_required
@require_POST
def source_retire(request: HttpRequest, source_id: UUID) -> HttpResponse:
    actor = _admin(request)
    source = get_object_or_404(SecuritySource, pk=source_id)
    form = SourceReasonForm(request.POST)
    if form.is_valid():
        try:
            retire_source(source.pk, actor, reason=cast("str", form.cleaned_data["reason"]), expected_generation=cast("int", form.cleaned_data["generation"]))
            return redirect("security:dashboard")
        except ValidationError as error:
            form.add_error(None, "; ".join(error.messages))
    return _render(request, SourceEnrollmentForm(source=source), source, status=400, retire_form=form)
