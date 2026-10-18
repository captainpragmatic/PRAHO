"""Download responses: an RFC 6266 filename that survives any characters, and never cached.

A download carries someone's data (an invoice, an export, an attachment). `private, no-store` keeps
it out of shared and browser caches, and Django's `content_disposition_header` adds `filename*`
for a name outside Latin-1, which a hand-built `filename="..."` header garbles.
"""

from __future__ import annotations

from django.http import HttpResponseBase
from django.utils.http import content_disposition_header


def mark_download[ResponseT: HttpResponseBase](response: ResponseT, filename: str) -> ResponseT:
    """Make ``response`` a private, uncached attachment named ``filename``."""
    # Only an inline disposition with no filename gives None; an attachment always has a value.
    response["Content-Disposition"] = content_disposition_header(True, filename) or "attachment"
    response["Cache-Control"] = "private, no-store"
    return response
