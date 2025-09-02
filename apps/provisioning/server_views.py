# ===============================================================================
# SERVER INFRASTRUCTURE VIEWS - SERVER MANAGEMENT AND MONITORING
# ===============================================================================

from django.http import HttpRequest, HttpResponse
from django.shortcuts import render

from apps.common.decorators import staff_required_strict

from .service_models import Server


@staff_required_strict
def server_list(request: HttpRequest) -> HttpResponse:
    """🖥️ Display server infrastructure"""
    servers = Server.objects.all().order_by("name")

    context = {
        "servers": servers,
        "active_servers": servers.filter(status="active").count(),
        "total_servers": servers.count(),
    }

    return render(request, "provisioning/server_list.html", context)