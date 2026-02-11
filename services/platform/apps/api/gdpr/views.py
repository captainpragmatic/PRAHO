"""
GDPR API views for Portal-to-Platform communication.

Endpoints:
- POST /api/gdpr/cookie-consent/ — Record cookie consent (user_id optional)
- POST /api/gdpr/consent-history/ — Get consent history (user_id required)
- POST /api/gdpr/data-export/ — Request GDPR data export (user_id required)
"""

import logging
from typing import Any

from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response

from apps.api.secure_auth import (
    _uniform_error_response,
    require_portal_service_authentication,
)
from apps.audit.services import GDPRConsentService, GDPRExportService
from apps.users.models import User

logger = logging.getLogger(__name__)


@api_view(['POST'])
@authentication_classes([])  # No DRF authentication - HMAC handled by middleware + secure_auth
@permission_classes([AllowAny])  # No DRF permissions - auth handled by @require_portal_service_authentication
@require_portal_service_authentication
def cookie_consent_api(request: Request, request_data: dict[str, Any]) -> Response:
    """
    Record cookie consent from Portal visitors (anonymous or authenticated).

    Accepts: cookie_id, status, functional, analytics, marketing,
             ip_address, user_agent, user_id (optional)
    """
    cookie_id = request_data.get('cookie_id', '')
    status = request_data.get('status', '')

    if not cookie_id or not status:
        return _uniform_error_response("Missing required fields: cookie_id, status", 400)

    result = GDPRConsentService.record_cookie_consent(
        cookie_id=cookie_id,
        status=status,
        functional=bool(request_data.get('functional', False)),
        analytics=bool(request_data.get('analytics', False)),
        marketing=bool(request_data.get('marketing', False)),
        ip_address=request_data.get('ip_address'),
        user_agent=request_data.get('user_agent', ''),
        user_id=request_data.get('user_id'),
    )

    if result.is_err():
        logger.error(f"🔥 [GDPR API] Cookie consent failed: {result.error}")
        return Response({'success': False, 'error': 'Failed to record consent'}, status=500)

    consent = result.unwrap()
    return Response({'success': True, 'consent_id': str(consent.id)})


@api_view(['POST'])
@authentication_classes([])  # No DRF authentication - HMAC handled by middleware + secure_auth
@permission_classes([AllowAny])  # No DRF permissions - auth handled by @require_portal_service_authentication
@require_portal_service_authentication
def consent_history_api(request: Request, request_data: dict[str, Any]) -> Response:
    """
    Get consent history for an authenticated user.
    Returns both ComplianceLog entries and CookieConsent records.
    """
    user_id = request_data.get('user_id')
    if user_id is None:
        return _uniform_error_response("user_id is required", 400)

    try:
        user = User.objects.get(id=int(user_id), is_active=True)
    except (User.DoesNotExist, ValueError, TypeError):
        return _uniform_error_response()

    consent_history = GDPRConsentService.get_consent_history(user)
    cookie_history = GDPRConsentService.get_cookie_consent_history(user)

    return Response({
        'success': True,
        'consent_history': consent_history,
        'cookie_consent_history': cookie_history,
    })


@api_view(['POST'])
@authentication_classes([])  # No DRF authentication - HMAC handled by middleware + secure_auth
@permission_classes([AllowAny])  # No DRF permissions - auth handled by @require_portal_service_authentication
@require_portal_service_authentication
def data_export_api(request: Request, request_data: dict[str, Any]) -> Response:
    """
    GDPR data export (Article 20 - Right to data portability).

    action="status": return recent exports for user.
    action="request" (default): create a new export request.
    """
    user_id = request_data.get('user_id')
    if user_id is None:
        return _uniform_error_response("user_id is required", 400)

    try:
        user = User.objects.get(id=int(user_id), is_active=True)
    except (User.DoesNotExist, ValueError, TypeError):
        return _uniform_error_response()

    action = request_data.get('action', 'request')

    if action == 'status':
        exports = GDPRExportService.get_user_exports(user)
        return Response({'success': True, 'exports': exports})

    ip_address = request_data.get('ip_address')
    result = GDPRExportService.create_data_export_request(user, request_ip=ip_address)

    if result.is_err():
        logger.error(f"🔥 [GDPR API] Data export request failed: {result.error}")
        return Response({'success': False, 'error': 'Failed to create export request'}, status=500)

    export_request = result.unwrap()
    return Response({
        'success': True,
        'export_id': str(export_request.id),
        'status': export_request.status,
    })
