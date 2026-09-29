# ===============================================================================
# SERVICE PLAN VIEWS - HOSTING PLAN MANAGEMENT
# ===============================================================================

from django.contrib.auth.decorators import login_required
from django.db.models import OuterRef, Subquery
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render

from .service_models import ServicePlan, ServicePlanPrice


@login_required
def plan_list(request: HttpRequest) -> HttpResponse:
    """📋 Display available hosting plans"""
    from apps.billing.currency_policy import get_selling_currency_policy  # noqa: PLC0415  # ADR-0007

    policy = get_selling_currency_policy()
    prices = ServicePlanPrice.objects.filter(
        service_plan_id=OuterRef("pk"),
        currency_id=policy.currency_code,
        is_active=True,
    )
    plans = (
        ServicePlan.objects.filter(is_active=True)
        .annotate(
            selling_monthly_price_cents=Subquery(prices.values("monthly_price_cents")[:1]),
        )
        .order_by("selling_monthly_price_cents", "name")
    )

    context = {
        "plans": plans,
        "selling_currency": policy.currency_code,
    }

    return render(request, "provisioning/plan_list.html", context)
