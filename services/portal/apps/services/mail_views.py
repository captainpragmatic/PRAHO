"""Read-only mail section; fixed public text never renders worker errors or credentials."""

from http import HTTPStatus
from typing import Any

from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.utils.cache import patch_cache_control
from django.utils.dateparse import parse_datetime
from django.utils.translation import gettext as _
from django.views.decorators.http import require_GET

from apps.api_client.services import PlatformAPIError
from apps.common.rate_limit_feedback import get_retry_after_from_error

from .mail_status import PublicMailStatus
from .services import services_api
from .views import _get_session_identity


def _context(status: PublicMailStatus) -> dict[str, Any]:
    context: dict[str, Any] = {"mail_status": status}
    operation = status["operation"]
    if operation is not None:
        context["mail_intent"] = {
            "enable": _("Hosted-mail enrollment"),
            "disable": _("Return to external mail"),
        }.get(operation["intent"], _("Mail request"))
        context["mail_progress"] = {
            "queued": _("Your request is recorded and waiting for processing."),
            "running": _("Your request is being processed."),
            "awaiting_dns": _("Your request is waiting for DNS verification."),
            "needs_review": _("Staff review is required before this request can continue."),
            "completed": _("The latest request completed."),
            "failed": _("The latest request did not complete."),
            "cancelled": _("The latest request was cancelled."),
        }.get(operation["status"], _("The request status is not confirmed."))
        if (
            operation["intent"] == "enable"
            and operation["status"] == "cancelled"
            and operation["error_code"] == "mail_prerequisites_expired"
        ):
            context["mail_progress"] = _(
                "Setup prerequisites were not ready within 24 hours, so this request was cancelled. "
                "You can request enrollment again."
            )
        context["mail_updated_at"] = parse_datetime(operation["updated_at"]) if operation["updated_at"] else None
    return context


@require_GET
def service_mail_status(request: HttpRequest, service_id: int) -> HttpResponse:
    customer_id, user_id = _get_session_identity(request)
    if not customer_id or not user_id:
        return redirect("/login/")
    code = HTTPStatus.OK
    retry_after = None
    try:
        context = _context(services_api.get_service_mail_status(customer_id, user_id, service_id))
    except PlatformAPIError as error:
        retry_after = get_retry_after_from_error(error)
        context = {"mail_error": "unavailable"}
        if error.status_code in {HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN}:
            context["mail_error"] = "forbidden"
            code = HTTPStatus.FORBIDDEN
        elif error.status_code == HTTPStatus.NOT_FOUND:
            context["mail_error"] = "not_found"
            code = HTTPStatus.NOT_FOUND
        elif request.headers.get("HX-Request") != "true":
            code = HTTPStatus.TOO_MANY_REQUESTS if error.is_rate_limited else HTTPStatus.SERVICE_UNAVAILABLE
    response = render(request, "services/partials/mail_status.html", context, status=code)
    if retry_after is not None:
        response["Retry-After"] = str(retry_after)
    patch_cache_control(response, private=True, no_store=True)
    return response
