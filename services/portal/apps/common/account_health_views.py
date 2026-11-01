"""Customer-scoped browser refresh for the persistent account-status region."""

from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET
from django.views.decorators.vary import vary_on_cookie

from apps.common.account_health import get_account_health
from apps.services.views import _get_session_identity


@never_cache
@vary_on_cookie
@require_GET
def account_status_banner_partial(request: HttpRequest) -> HttpResponse:
    """Browser GET has no identity query: Platform reads remain signed customer POSTs."""
    customer_id, user_id = _get_session_identity(request)
    if not customer_id or not user_id:
        if request.headers.get("HX-Request") == "true":
            return HttpResponse(
                status=401, headers={"HX-Redirect": "/login/"}, content_type="text/plain; charset=utf-8"
            )
        return redirect("/login/")
    return render(
        request,
        "components/account_status_content.html",
        {
            "account_banner": get_account_health(request),
            "maintenance_unavailable": getattr(request, "maintenance_unavailable", False),
        },
    )
