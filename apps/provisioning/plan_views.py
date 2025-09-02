# ===============================================================================
# SERVICE PLAN VIEWS - HOSTING PLAN MANAGEMENT
# ===============================================================================

from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render

from .service_models import ServicePlan


@login_required
def plan_list(request: HttpRequest) -> HttpResponse:
    """📋 Display available hosting plans"""
    plans = ServicePlan.objects.filter(is_active=True).order_by("price_monthly")

    context = {
        "plans": plans,
    }

    return render(request, "provisioning/plan_list.html", context)
