"""
Common views for Portal service.
Cookie consent proxy, cookie policy page.
"""

import json
import logging
import uuid

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_POST

from apps.api_client.services import PlatformAPIClient, PlatformAPIError
from apps.common.request_ip import get_safe_client_ip

logger = logging.getLogger(__name__)

api_client = PlatformAPIClient()


@require_POST
@csrf_protect
def cookie_consent_view(request: HttpRequest) -> HttpResponse:
    """
    Proxy cookie consent to Platform GDPR API.
    Accepts JSON body with consent preferences from the banner.
    """
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

    # Read or generate cookie_id for anonymous visitors
    cookie_id = request.COOKIES.get('cookie_consent_id', '')
    if not cookie_id:
        cookie_id = str(uuid.uuid4())

    # Build payload for Platform GDPR API
    consent_data = {
        'cookie_id': cookie_id,
        'status': data.get('status', 'customized'),
        'functional': bool(data.get('functional', False)),
        'analytics': bool(data.get('analytics', False)),
        'marketing': bool(data.get('marketing', False)),
        'ip_address': get_safe_client_ip(request),
        'user_agent': request.META.get('HTTP_USER_AGENT', '')[:500],
    }

    # Include user_id from session if authenticated
    user_id = request.session.get('user_id')
    if user_id:
        consent_data['user_id'] = user_id

    try:
        result = api_client.submit_cookie_consent(consent_data)
        success = result.get('success', False)
    except PlatformAPIError:
        logger.warning("⚠️ [Portal Cookie] Platform API unavailable, consent saved client-side only")
        success = False

    response = JsonResponse({'success': success})

    # Set cookie_consent_id for anonymous tracking across sessions
    if not request.COOKIES.get('cookie_consent_id'):
        response.set_cookie(
            'cookie_consent_id',
            cookie_id,
            max_age=365 * 24 * 60 * 60,
            httponly=True,
            samesite='Lax',
        )

    return response


def cookie_policy_view(request: HttpRequest) -> HttpResponse:
    """
    Cookie policy page - public, no auth required.
    Lists all cookie categories with name, purpose, duration, provider.
    """
    return render(request, 'legal/cookie_policy.html')
