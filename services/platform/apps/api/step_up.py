"""The identity check a sensitive customer action needs within the last 300 seconds (ADR-0017).

Login counts as a check. A guarded view calls ``step_up_refusal`` after its own owner and role
checks and before it writes anything.
"""

from __future__ import annotations

from django.http import HttpRequest
from django.utils import timezone
from rest_framework.response import Response

from apps.users import portal_sessions


def step_up_refusal(request: HttpRequest) -> Response | None:
    """The refusal for a request that may not act yet, or None when it may.

    A request with no bound session is refused as an ended one, whatever ``PORTAL_SESSION_REQUIRED``
    says, so a guarded action is never reachable without a session. A session not checked in the
    last 300 seconds gets ``reauth_required``, which the portal answers by asking for the password.
    """
    row = getattr(request, "portal_session", None)
    if row is None:
        return portal_sessions.session_refused()
    if portal_sessions.recently_reauthenticated(row, timezone.now()):
        return None
    response = Response({"success": False, "code": "reauth_required"}, status=403)
    response["Cache-Control"] = "no-store"
    return response
