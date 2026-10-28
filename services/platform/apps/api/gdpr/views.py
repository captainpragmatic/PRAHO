"""
GDPR API views for Portal-to-Platform communication.

Endpoints:
- POST /api/gdpr/cookie-consent/ — Record cookie consent (user_id optional)
- POST /api/gdpr/consent-history/ — Get consent history (user_id required)
- POST /api/gdpr/data-export/ — Request GDPR data export (user_id required)
"""

import logging
import uuid
from typing import Any

from django.db import transaction
from django.db.models import F
from django.http import HttpResponse
from django_q.tasks import async_task
from rest_framework.decorators import api_view, authentication_classes, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response

from apps.api.secure_auth import (
    _uniform_error_response,
    require_portal_service_authentication,
)
from apps.audit.export_files import read_export_file
from apps.audit.models import DataExport
from apps.audit.services import AuditService, ComplianceEventRequest, GDPRConsentService, GDPRExportService
from apps.common.encryption import DecryptionError
from apps.common.http import mark_download
from apps.common.performance.rate_limiting import BurstRateThrottle, CustomerRateThrottle
from apps.users.mfa import staff_must_enrol
from apps.users.models import User
from apps.users.security_notices import notify_data_export_requested

logger = logging.getLogger(__name__)

# Throttling note (#277): these HMAC service endpoints add CustomerRateThrottle +
# BurstRateThrottle. Both return None for verified portal-service traffic (which sets
# request._portal_authenticated), so legitimate signed calls are unaffected, but they
# key ANONYMOUS traffic by safe client IP. DRF runs throttles before
# @require_portal_service_authentication rejects an unsigned request, so without a
# fallback the pre-auth path would be an unthrottled endpoint-layer surface.


@api_view(["POST"])
@authentication_classes([])  # No DRF authentication - HMAC handled by middleware + secure_auth
@permission_classes([AllowAny])  # No DRF permissions - auth handled by @require_portal_service_authentication
@throttle_classes([CustomerRateThrottle, BurstRateThrottle])  # #277: IP-limit unsigned traffic; None for signed
@require_portal_service_authentication
def cookie_consent_api(request: Request, request_data: dict[str, Any]) -> Response:
    """
    Record cookie consent from Portal visitors (anonymous or authenticated).

    Accepts: cookie_id, status, functional, analytics, marketing,
             ip_address, user_agent, user_id (optional)
    """
    cookie_id = request_data.get("cookie_id", "")
    status = request_data.get("status", "")

    if not cookie_id or not status:
        return _uniform_error_response("Missing required fields: cookie_id, status", 400)

    result = GDPRConsentService.record_cookie_consent(
        cookie_id=cookie_id,
        status=status,
        functional=bool(request_data.get("functional", False)),
        analytics=bool(request_data.get("analytics", False)),
        marketing=bool(request_data.get("marketing", False)),
        ip_address=request_data.get("ip_address"),
        user_agent=request_data.get("user_agent", ""),
        user_id=request_data.get("user_id"),
        language=str(request_data.get("language") or ""),
    )

    if result.is_err():
        logger.error(f"🔥 [GDPR API] Cookie consent failed: {result.unwrap_err()}")
        return Response({"success": False, "error": "Failed to record consent"}, status=500)

    consent = result.unwrap()
    return Response({"success": True, "consent_id": str(consent.id)})


@api_view(["POST"])
@authentication_classes([])  # No DRF authentication - HMAC handled by middleware + secure_auth
@permission_classes([AllowAny])  # No DRF permissions - auth handled by @require_portal_service_authentication
@throttle_classes([CustomerRateThrottle, BurstRateThrottle])  # #277: IP-limit unsigned traffic; None for signed
@require_portal_service_authentication
def consent_history_api(request: Request, request_data: dict[str, Any]) -> Response:
    """
    Get consent history for an authenticated user.
    Returns both ComplianceLog entries and CookieConsent records.
    """
    user_id = request_data.get("user_id")
    if user_id is None:
        return _uniform_error_response("user_id is required", 400)

    try:
        user = User.objects.get(id=int(user_id), is_active=True)
    except (User.DoesNotExist, ValueError, TypeError):
        return _uniform_error_response()
    # Named by the signed body, not through secure_auth: the staff 2FA policy applies here too.
    if staff_must_enrol(user):
        return _uniform_error_response("Authentication required", 401)

    consent_history = GDPRConsentService.get_consent_history(user)
    cookie_history = GDPRConsentService.get_cookie_consent_history(user)

    return Response(
        {
            "success": True,
            "consent_history": consent_history,
            "cookie_consent_history": cookie_history,
        }
    )


# An export larger than this is not sent through the portal: the portal holds a response in
# memory while it relays it. Such an export is downloaded from Platform by staff.
EXPORT_API_MAX_BYTES = 20 * 1024 * 1024


@api_view(["POST"])
@authentication_classes([])  # No DRF authentication - HMAC handled by middleware + secure_auth
@permission_classes([AllowAny])  # No DRF permissions - auth handled by @require_portal_service_authentication
@throttle_classes([CustomerRateThrottle, BurstRateThrottle])  # #277: IP-limit unsigned traffic; None for signed
@require_portal_service_authentication
def data_export_api(request: Request, request_data: dict[str, Any]) -> Response:
    """
    GDPR data export (Article 15 - Right of access, Article 20 - Right to data portability).

    action="status": return recent exports for user.
    action="request" (default): create a new export request.
    """
    user_id = request_data.get("user_id")
    if user_id is None:
        return _uniform_error_response("user_id is required", 400)

    try:
        user = User.objects.get(id=int(user_id), is_active=True)
    except (User.DoesNotExist, ValueError, TypeError):
        return _uniform_error_response()
    # Named by the signed body, not through secure_auth: the staff 2FA policy applies here too.
    if staff_must_enrol(user):
        return _uniform_error_response("Authentication required", 401)

    action = request_data.get("action", "request")

    if action == "status":
        exports = GDPRExportService.get_user_exports(user)
        for entry in exports:
            # Not offered through the portal, which would only get a 413; staff hand these over.
            entry["too_large"] = (entry["file_size"] or 0) > EXPORT_API_MAX_BYTES
            entry["downloadable"] = entry["downloadable"] and not entry["too_large"]
        return Response({"success": True, "exports": exports})

    ip_address = request_data.get("ip_address")
    # A repeat request returns the export already pending; only the request that created it queues
    # it, so repeated clicks do not each queue a job (process_pending_data_exports covers a lost one).
    pending_before = set(DataExport.objects.filter(requested_by=user, status="pending").values_list("pk", flat=True))
    result = GDPRExportService.create_data_export_request(user, request_ip=ip_address)

    if result.is_err():
        logger.error(f"🔥 [GDPR API] Data export request failed: {result.unwrap_err()}")
        return Response({"success": False, "error": "Failed to create export request"}, status=500)

    export_request = result.unwrap()
    if export_request.status == "pending" and export_request.pk not in pending_before:
        # Generated by the task queue, not in this request: an export can take longer than the
        # portal waits. A message lost on the way is picked up by process_pending_data_exports.
        export_id = str(export_request.id)
        transaction.on_commit(lambda: async_task("apps.audit.tasks.process_data_export_task", export_id))
        notify_data_export_requested(user)
    return Response(
        {
            "success": True,
            "export_id": str(export_request.id),
            "status": export_request.status,
        }
    )


@api_view(["POST"])
@authentication_classes([])  # No DRF authentication - HMAC handled by middleware + secure_auth
@permission_classes([AllowAny])  # No DRF permissions - auth handled by @require_portal_service_authentication
@throttle_classes([CustomerRateThrottle, BurstRateThrottle])  # #277: IP-limit unsigned traffic; None for signed
@require_portal_service_authentication
def data_export_download_api(request: Request, request_data: dict[str, Any], export_id: uuid.UUID) -> Response:
    """The decrypted file of the signed-in person's own GDPR export, for the portal to relay.

    Only an export the person requested, still inside its download window and with its file, is
    returned. Anything else, including a file that is gone or will not decrypt, gets the uniform
    error. The download is counted and logged only once the file has been read.
    """
    user_id = request_data.get("user_id")
    try:
        user = User.objects.get(id=int(str(user_id)), is_active=True)
    except (User.DoesNotExist, ValueError, TypeError):
        return _uniform_error_response()
    # Named by the signed body, not through secure_auth: the staff 2FA policy applies here too.
    if staff_must_enrol(user):
        return _uniform_error_response("Authentication required", 401)

    export = DataExport.objects.filter(pk=export_id, requested_by_id=user.id).first()
    if export is None or not export.is_downloadable:
        return _uniform_error_response("Export not available", 404)
    if (export.file_size or 0) > EXPORT_API_MAX_BYTES:
        return _uniform_error_response("Export too large to download here; contact support", 413)

    try:
        content = read_export_file(export).encode("utf-8")
    except (OSError, DecryptionError):
        logger.error(f"🔥 [GDPR API] Export {export.id} could not be read", exc_info=True)
        # A completed export with no readable file would be handed back by every new request
        # until it expires; failing it lets the next request generate a fresh one.
        DataExport.objects.filter(pk=export.pk).update(
            status="failed", error_message="Export file missing or unreadable"
        )
        return _uniform_error_response("Export not available", 404)

    DataExport.objects.filter(pk=export.pk).update(download_count=F("download_count") + 1)
    AuditService.log_compliance_event(
        ComplianceEventRequest(
            compliance_type="gdpr_consent",
            reference_id=f"export_download_{export.id}",
            description="GDPR export downloaded through the portal",
            user=user,
            status="success",
            evidence={"export_id": str(export.id), "file_size": len(content)},
            metadata={"ip_address": request_data.get("ip_address")},
        )
    )
    response = HttpResponse(content, content_type="application/json")
    mark_download(response, f"gdpr-export-{export.id}.json")
    return response
