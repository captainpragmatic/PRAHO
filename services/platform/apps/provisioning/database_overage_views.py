"""Staff page for a service's database over-allowance episodes: what happened, and extend or waive."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from django.contrib import messages
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.paginator import Paginator
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext as _
from django.views.decorators.http import require_http_methods

from apps.common.decorators import staff_required_strict

from .database_overage_attention import episodes_needing_attention
from .database_overage_models import DatabaseOverageEpisode, EpisodeState
from .database_overage_staff import MAX_EXTENSION_DAYS, MIN_EXTENSION_DAYS, extend_episode, waive_episode
from .hosting_limit_override_service import can_override_hosting_resources
from .service_models import Service

if TYPE_CHECKING:
    from apps.users.models import User

ATTENTION_PAGE_SIZE = 25


def _act(request: HttpRequest, episodes: list[DatabaseOverageEpisode], user: User) -> str:
    """The action on the episode the form was shown for, at the revision it was shown at."""
    action, reason = request.POST.get("action"), request.POST.get("reason", "")
    shown = next((episode for episode in episodes if str(episode.pk) == request.POST.get("episode")), None)
    try:
        revision = int(request.POST.get("revision", ""))
    except ValueError:
        revision = -1
    if shown is None or shown.state == EpisodeState.CLOSED:
        raise ValidationError(_("This episode changed since the page was shown. Review it again."))
    if action == "extend":
        try:
            days = int(request.POST.get("days", ""))
        except ValueError as error:
            raise ValidationError(_("Enter a whole number of days.")) from error
        extend_episode(shown.pk, user=user, days=days, reason=reason, expected_revision=revision)
        return _("Deadline extended. A hold, if any, is being released for the write window.")
    if action == "waive":
        waive_episode(shown.pk, user=user, reason=reason, expected_revision=revision)
        return _("Waived. A hold, if any, is being released.")
    raise ValidationError(_("Unknown action."))


@staff_required_strict
@require_http_methods(["GET", "POST"])
def service_database_overage(request: HttpRequest, pk: int) -> HttpResponse:
    user = cast("User", request.user)
    can_act = can_override_hosting_resources(user)  # any staff member reads; administrators and managers act
    if request.method == "POST" and not can_act:
        raise PermissionDenied(_("Administrator or manager authority is required for database over-allowance actions."))
    service = get_object_or_404(Service.objects.select_related("customer"), pk=pk)
    if not user.can_access_customer(service.customer):
        raise PermissionDenied
    episodes = list(DatabaseOverageEpisode.objects.filter(service=service).order_by("-opened_at")[:6])
    current = next((episode for episode in episodes if episode.state != EpisodeState.CLOSED), None)
    error = ""
    if request.method == "POST":
        try:
            messages.success(request, _act(request, episodes, user))
            return redirect("provisioning:service_database_overage", pk=service.pk)
        except ValidationError as refusal:
            error = " ".join(refusal.messages)
    return render(
        request,
        "provisioning/service_database_overage.html",
        {
            "service": service,
            "current": current,
            "notices": list(current.notices.order_by("created_at")) if current else [],
            "history": [episode for episode in episodes if episode is not current],
            "error": error,
            "can_act": can_act,
            "min_days": MIN_EXTENSION_DAYS,
            "max_days": MAX_EXTENSION_DAYS,
        },
        # htmx swaps only successful responses, so an htmx form gets its refusal with a 200 to show it
        status=400 if error and not request.headers.get("HX-Request") else 200,
    )


@staff_required_strict
@require_http_methods(["GET"])
def database_overage_attention(request: HttpRequest) -> HttpResponse:
    """Every episode staff must look at, each linked to its service's page; any staff member may read it."""
    page = Paginator(episodes_needing_attention(), ATTENTION_PAGE_SIZE).get_page(request.GET.get("page"))
    return render(request, "provisioning/database_overage_attention.html", {"page": page, "episodes": page.object_list})
