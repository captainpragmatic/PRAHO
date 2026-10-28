"""Portal side of customer view (ADR-0065): redeem the one-time code, and leave.

Platform's staff page posts the code here in a request body. The browser session is replaced by the
scoped session Platform opens; it holds no credential of the customer, only the id of that session.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime

from django.conf import settings
from django.db import DatabaseError, InterfaceError
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.middleware.csrf import rotate_token
from django.shortcuts import render
from django.utils.translation import gettext as _
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.views.decorators.http import require_POST

from apps.api_client.services import PlatformAPIError, api_client
from apps.common import counters, request_context
from apps.common.rate_limiting import _client_ip_is_distinguishable
from apps.common.request_ip import get_safe_client_ip
from apps.common.store_unavailable import wants_json

logger = logging.getLogger(__name__)

CODE = re.compile(r"[A-Za-z0-9_-]{43}")
MAX_REDEEM_BYTES = 2048
REDEEM_LIMIT = 10  # per client address per minute, as on Platform


def _answer(request: HttpRequest, status: int, error: str, message: str) -> HttpResponse:
    """A page for the staff member's browser (the handoff is a navigation), JSON for a script."""
    headers = {"Cache-Control": "no-store"}
    if wants_json(request):
        return JsonResponse({"error": error}, status=status, headers=headers)
    page = render(request, "users/customer_view_unavailable.html", {"message": message}, status=status)
    page["Cache-Control"] = "no-store"
    return page


def _refused(request: HttpRequest, status: int = 403) -> HttpResponse:
    return _answer(
        request,
        status,
        "customer_view_forbidden",
        _(
            "This customer view cannot be opened. Open it again from the staff console; a link works once, for one minute."
        ),
    )


def _unavailable(request: HttpRequest) -> HttpResponse:
    response = _answer(
        request,
        503,
        "Customer view unavailable",
        _("The customer view could not be opened just now. Try again shortly."),
    )
    response["Retry-After"] = "5"
    return response


def _end_current_platform_session(request: HttpRequest) -> None:
    """End whatever session this browser held on Platform; an already-ended one is the goal."""
    session_id, user_id = request.session.get("portal_session_id"), request.session.get("user_id")
    if session_id and user_id:
        try:
            api_client.end_session(int(user_id), str(session_id))
        except (PlatformAPIError, ValueError, TypeError):
            logger.warning("⚠️ [CustomerView] Displaced session not ended on Platform; it ends at its deadline")
    request_context.forget_rejection()


@csrf_exempt  # a cross-site POST from Platform's page by design; the exact Origin check replaces CSRF
@never_cache
@require_POST
def redeem(request: HttpRequest) -> HttpResponse:
    origin = str(settings.PLATFORM_PUBLIC_ORIGIN).rstrip("/")
    if not settings.CUSTOMER_VIEW_ENABLED or not origin or request.headers.get("Origin") != origin:
        logger.warning("⚠️ [CustomerView] Redemption refused: feature off or wrong origin")
        return _refused(request)
    if (
        len(request.body) > MAX_REDEEM_BYTES
        or set(request.POST) != {"code"}
        or len(request.POST.getlist("code")) != 1
        or CODE.fullmatch(request.POST["code"]) is None
    ):
        return _refused(request, 400)
    client_ip = get_safe_client_ip(request)
    try:
        # Per address only when addresses can be told apart; one shared bucket would let anyone lock staff out.
        if (
            _client_ip_is_distinguishable()
            and counters.increment(f"customer-view-redeem:{client_ip}", 60) > REDEEM_LIMIT
        ):
            limited = _answer(request, 429, "Too many attempts", _("Too many attempts. Wait a minute and try again."))
            limited["Retry-After"] = "60"
            return limited
        # Unbound: the code is exchanged for itself, never as the session this browser held before.
        with request_context.bound(None, None):
            data = api_client.redeem_customer_view(request.POST["code"], client_ip)
        if "session_auth_hash" in data:
            raise ValueError("a customer view never carries a credential of the customer")
        session_id = str(data["session_id"])
        expires_at = datetime.fromisoformat(str(data["session_expires_at"]))
        user, customer = data["user"], data["customer"]
    except PlatformAPIError as exc:
        return _refused(request) if exc.status_code in (400, 403) else _unavailable(request)
    except (DatabaseError, InterfaceError, KeyError, TypeError, ValueError):
        logger.exception("🔥 [CustomerView] Redemption answer unusable")
        return _unavailable(request)

    _end_current_platform_session(request)
    request.session.flush()
    rotate_token(request)
    request.session.update(
        {
            "user_id": user["id"],
            "email": user["email"],
            "customer_id": customer["id"],
            "active_customer_id": customer["id"],
            "selected_customer_id": customer["id"],
            "selected_customer_name": customer["name"],
            "selected_customer_role": customer["role"],
            "portal_session_id": session_id,
            "customer_view": True,
            "customer_view_customer_id": customer["id"],
            "customer_view_customer_name": customer["name"],
            "customer_view_staff_label": data.get("staff_label", ""),
            "customer_view_expires_at": expires_at.isoformat(),
        }
    )
    # The cookie ends with the browser: closing it never reopens the customer's portal.
    request.session.set_expiry(0)
    logger.info("✅ [CustomerView] Customer view opened")
    return HttpResponse(status=303, headers={"Location": "/dashboard/", "Cache-Control": "no-store"})


@csrf_protect
@never_cache
@require_POST
def leave(request: HttpRequest) -> HttpResponse:
    """Leave the customer view: end the scoped session on Platform and forget it here."""
    if not request.session.get("customer_view"):
        return _refused(request)
    _end_current_platform_session(request)
    request.session.flush()
    rotate_token(request)
    return HttpResponse(
        status=303, headers={"Location": "/login/", "Cache-Control": "no-store", "Clear-Site-Data": '"cache"'}
    )
