"""Views reachable only through the portal E2E URL configuration."""

from django.conf import settings
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import render
from django.views.decorators.http import require_GET


@require_GET
def csp_violation_positive_control(request: HttpRequest) -> HttpResponse:
    """Render one deliberate inline-handler violation for the browser oracle."""
    if not settings.E2E_TEST_ROUTES_ENABLED:
        raise Http404("E2E test routes are disabled.")

    return render(request, "e2e/csp_violation_positive_control.html")
