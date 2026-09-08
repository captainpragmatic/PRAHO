"""Staff-only node drain controls."""

from typing import TYPE_CHECKING, cast

from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext as _
from django.views.decorators.http import require_http_methods

if TYPE_CHECKING:
    from apps.users.models import User

from .virtualmin_drain_service import NodeDrainService
from .virtualmin_migration_models import NodeDrain
from .virtualmin_models import VirtualminServer
from .virtualmin_views import is_staff_or_superuser


@login_required
@user_passes_test(is_staff_or_superuser)
@require_http_methods(["GET", "POST"])
def node_drain(request: HttpRequest, server_id: str) -> HttpResponse:
    server = get_object_or_404(VirtualminServer, pk=server_id)
    if request.method == "POST":
        action = request.POST.get("action")
        user = cast("User", request.user)
        if action == "start":
            result = NodeDrainService.start_drain(server, initiated_by=user)
        elif action in {"cancel", "finalize"}:
            drain = get_object_or_404(NodeDrain, pk=request.POST.get("drain_id"), server=server)
            if action == "finalize":
                if request.POST.get("routing_confirmed") != "on":
                    return HttpResponse(_("Confirm routing before finalizing."), status=400)
                result = NodeDrainService.finalize_drain(drain, confirmed_by=user)
            else:
                result = NodeDrainService.cancel_drain(drain)
        else:
            return HttpResponse(_("Invalid drain action."), status=400)
        if result.is_ok():
            messages.success(request, _("Drain request accepted. Refresh this page for progress."))
        else:
            messages.error(request, result.unwrap_err())
        return redirect("provisioning:node_drain", server_id=server.pk)
    return render(request, "provisioning/virtualmin/drain.html", {"server": server, "drain": server.drains.first()})
