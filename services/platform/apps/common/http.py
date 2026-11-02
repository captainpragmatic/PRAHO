"""Response helpers: downloads, and redirects that htmx follows as a full page.

A download carries someone's data (an invoice, an export, an attachment). `private, no-store` keeps
it out of shared and browser caches, and Django's `content_disposition_header` adds `filename*`
for a name outside Latin-1, which a hand-built `filename="..."` header garbles.

An htmx request that should land on another page gets HX-Redirect rather than a 302: htmx follows a
302 inside the XHR and swaps the whole next page into its target, and the address bar stays put.
"""

from __future__ import annotations

from django.http import HttpRequest, HttpResponse, HttpResponseBase
from django.shortcuts import redirect
from django.utils.http import content_disposition_header


def mark_download[ResponseT: HttpResponseBase](response: ResponseT, filename: str) -> ResponseT:
    """Make ``response`` a private, uncached attachment named ``filename``."""
    # Only an inline disposition with no filename gives None; an attachment always has a value.
    response["Content-Disposition"] = content_disposition_header(True, filename) or "attachment"
    response["Cache-Control"] = "private, no-store"
    return response


def hx_redirect(url: str) -> HttpResponse:
    """An empty answer telling htmx to navigate to ``url`` as a full page."""
    response = HttpResponse()
    response["HX-Redirect"] = url
    return response


def page_redirect(request: HttpRequest, url: str) -> HttpResponse:
    """Go to ``url``: htmx gets HX-Redirect, a plain request a 302."""
    if request.headers.get("HX-Request") == "true":
        return hx_redirect(url)
    return redirect(url)
