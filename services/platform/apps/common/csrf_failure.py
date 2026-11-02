"""The answer to a refused CSRF token: reload the page.

The usual cause is a stale tab. The token a page carries stops working when the secret rotates (someone signs in
again in another tab), and only a fresh page has a new one. `X-CSRF-Failure: reload` tells the page's scripts this is
that case and not a refused permission: the htmx error handler and `platformFetch` show the guidance and never
replay the request.
"""

from __future__ import annotations

import logging

from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.translation import gettext as _

logger = logging.getLogger(__name__)

RELOAD_HEADER = "X-CSRF-Failure"


def csrf_failure(request: HttpRequest, reason: str = "") -> HttpResponse:
    logger.warning("⚠️ [CSRF] Refused %s %s: %s", request.method, request.path, reason)
    message = _("This page has expired. Please reload the page and try again.")
    if request.headers.get("HX-Request") == "true" or "application/json" in request.headers.get("Accept", ""):
        response = HttpResponse(message, status=403, content_type="text/plain; charset=utf-8")
    else:
        # Back to the page the form was on; never the refused URL itself (a POST-only action, or logout).
        referer = request.headers.get("Referer", "")
        safe = url_has_allowed_host_and_scheme(
            referer, allowed_hosts={request.get_host()}, require_https=request.is_secure()
        )
        back = referer if referer and safe else reverse("dashboard")
        response = render(request, "errors/csrf_failure.html", {"message": message, "back_url": back}, status=403)
    response[RELOAD_HEADER] = "reload"
    return response
