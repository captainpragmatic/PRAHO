"""One answer for a request refused because the shared counter store is unavailable (#554).

Every store-failure arm fails closed. Before this module each arm also chose its own shape - 503 JSON from
the checkout replay lookup, a 500 from `confirm_payment`, a 503 JSON or a redirect from the auth limiter -
and the Portal's client code branches on the shape. The contract is now:

* A caller that reads JSON (HTMX, XHR, a JSON-only ``Accept``, or an endpoint that only speaks JSON) gets
  HTTP 503 with ``Retry-After`` and ``{"success": false, "error": <message>, "retry_after": <seconds>}``.
* A browser navigation gets the same message as an error notice and a redirect to the page the request
  can be retried from. Which page is the only per-site choice.
"""

from __future__ import annotations

from django.contrib import messages
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect
from django.utils.cache import add_never_cache_headers
from django.utils.translation import gettext as _

STORE_UNAVAILABLE_STATUS = 503
STORE_UNAVAILABLE_RETRY_AFTER_SECONDS = 60


def wants_json(request: HttpRequest) -> bool:
    """Whether the caller reads a JSON body rather than following a redirect."""
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return True
    if request.headers.get("HX-Request"):
        return True
    accept = request.headers.get("Accept", "")
    return "application/json" in accept and "text/html" not in accept


def store_unavailable_message() -> str:
    return _("Service temporarily unavailable. Please try again later.")


def store_unavailable_json() -> JsonResponse:
    """The JSON half of the contract, for endpoints whose callers never navigate."""
    retry_after = STORE_UNAVAILABLE_RETRY_AFTER_SECONDS
    response = JsonResponse(
        {"success": False, "error": store_unavailable_message(), "retry_after": retry_after},
        status=STORE_UNAVAILABLE_STATUS,
    )
    response["Retry-After"] = str(retry_after)
    add_never_cache_headers(response)
    return response


def store_unavailable_response(request: HttpRequest, redirect_to: str) -> HttpResponse:
    """JSON for JSON callers; otherwise an error notice and a redirect to ``redirect_to``."""
    if wants_json(request):
        return store_unavailable_json()
    messages.error(request, store_unavailable_message())
    return redirect(redirect_to)
