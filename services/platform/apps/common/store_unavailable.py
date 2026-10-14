"""The Platform's answer when the shared counter store cannot be reached.

One 503 for every layer that counts requests (the HMAC middleware, DRF throttles, the login
peek). The Portal reads a 401 as "the secret or the clock is wrong" and a 429 as "this customer
is throttled"; neither is what happened when the store is down.
"""

from __future__ import annotations

from django.http import JsonResponse

# Within the portal's immediate-retry cap (PLATFORM_API_MAX_RETRY_WAIT_SECONDS, 2.5 s), so a brief
# store outage is absorbed by one retry instead of failing the page.
STORE_UNAVAILABLE_RETRY_AFTER_SECONDS = 2

STORE_UNAVAILABLE_ERROR = "Platform temporarily unavailable"


def store_unavailable_body() -> dict[str, object]:
    return {"success": False, "error": STORE_UNAVAILABLE_ERROR, "status": 503}


def store_unavailable_response() -> JsonResponse:
    response = JsonResponse(store_unavailable_body(), status=503)
    response["Retry-After"] = str(STORE_UNAVAILABLE_RETRY_AFTER_SECONDS)
    return response
