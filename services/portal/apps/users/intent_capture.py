"""Where the visitor came from and what they came to buy, kept in the session (apps.common.intent).

The operator's site links to registration with the product, period and domain the visitor chose.
That intent goes with the registration to Platform, and comes back with its details when the link
is confirmed, on whichever device. The first UTM tags and referring site of a visit are kept for
every order the account places.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode, urlsplit

from django.http import HttpRequest
from django.urls import reverse

from apps.common.intent import ATTRIBUTION_KEYS, INTENT_KEYS, clean_intent
from apps.users.constants import ATTRIBUTION_SESSION_KEY, REGISTRATION_INTENT_SESSION_KEY

_UTM_KEYS = tuple(key for key in ATTRIBUTION_KEYS if key.startswith("utm_"))
_RESUMED_KEYS = ("period", "domain", "domain_mode")


def capture_first_touch(request: HttpRequest) -> None:
    """Keep the visit's first UTM tags and referring site; later pages change nothing.

    A page with neither writes nothing, so a plain visit creates no session.
    """
    if ATTRIBUTION_SESSION_KEY in request.session:
        return
    raw = {key: request.GET.get(key, "") for key in _UTM_KEYS}
    referrer = request.META.get("HTTP_REFERER", "")
    if referrer and urlsplit(referrer).hostname != request.get_host().split(":")[0]:
        raw["referrer"] = referrer  # Another site's: links within the portal are not a source
    attribution = clean_intent(raw, ATTRIBUTION_KEYS)
    if attribution:
        request.session[ATTRIBUTION_SESSION_KEY] = attribution


def capture_intent(request: HttpRequest) -> None:
    """Keep the product, period and domain a link to registration names (the latest link wins)."""
    intent = clean_intent({key: request.GET[key] for key in INTENT_KEYS if key in request.GET}, INTENT_KEYS)
    if intent:
        request.session[REGISTRATION_INTENT_SESSION_KEY] = intent


def registration_intent(request: HttpRequest) -> dict[str, str]:
    """What goes with the registration: the intent and the visit's attribution."""
    return {
        **request.session.get(REGISTRATION_INTENT_SESSION_KEY, {}),
        **request.session.get(ATTRIBUTION_SESSION_KEY, {}),
    }


def order_attribution(request: HttpRequest) -> dict[str, str]:
    return dict(request.session.get(ATTRIBUTION_SESSION_KEY) or {})


def resume_after_confirmation(request: HttpRequest, intent: Any) -> str | None:
    """Where to go after signing in to resume the registered intent, or None.

    The confirming device may never have seen the visit, so it also takes the attribution the
    registration carried, unless it has its own.
    """
    intent = clean_intent(intent if isinstance(intent, dict) else {})
    attribution = {key: value for key, value in intent.items() if key in ATTRIBUTION_KEYS}
    if attribution and not request.session.get(ATTRIBUTION_SESSION_KEY):
        request.session[ATTRIBUTION_SESSION_KEY] = attribution
    request.session.pop(REGISTRATION_INTENT_SESSION_KEY, None)
    product = intent.get("product")
    if not product:
        return None
    query = urlencode({key: intent[key] for key in _RESUMED_KEYS if key in intent})
    path = reverse("orders:product_detail", args=[product])
    return f"{path}?{query}" if query else path
