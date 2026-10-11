"""
Legal pages views for GDPR compliance.
Privacy Policy, Terms of Service, Cookie Policy, and Data Processors.

Note: Cookie consent banner + proxy endpoint moved to Portal.
The cookie_policy view here remains for staff reference (cross-linked
from privacy_policy.html, terms_of_service.html, etc.).
Cookie consent recording is now via Portal → Platform GDPR API
(see apps/api/gdpr/views.py).
"""

import logging
from datetime import UTC, date, datetime

from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.urls import reverse
from django.utils.translation import gettext as _

from apps.common.legal import TERMS_OF_SERVICE_VERSION

# A calendar date: shown as the same day in every timezone. The portal's page states the same one.
PRIVACY_POLICY_DATE = date(2024, 12, 27)

logger = logging.getLogger(__name__)


def privacy_policy(request: HttpRequest) -> HttpResponse:
    """GDPR-compliant Privacy Policy page. The text is shared with the portal's /privacy-policy/ page."""
    dashboard = reverse("audit:gdpr_dashboard")
    signed_in = request.user.is_authenticated
    context = {
        "last_updated": PRIVACY_POLICY_DATE,
        "effective_date": PRIVACY_POLICY_DATE,
        "rights_url": dashboard if signed_in else f"{reverse('users:login')}?next={dashboard}",
        "rights_label": _("Go to GDPR Dashboard") if signed_in else _("Login to Access GDPR Dashboard"),
    }
    return render(request, "legal/privacy_policy.html", context)


def terms_of_service(request: HttpRequest) -> HttpResponse:
    """Terms of Service page. The text is shared with the portal's /terms/ page."""
    effective_date = date.fromisoformat(TERMS_OF_SERVICE_VERSION)  # A calendar date, in every timezone
    context = {
        "last_updated": effective_date,
        "effective_date": effective_date,
        "terms_version": TERMS_OF_SERVICE_VERSION,
    }
    return render(request, "legal/terms_of_service.html", context)


def cookie_policy(request: HttpRequest) -> HttpResponse:
    """
    Cookie Policy page (staff reference).

    The interactive cookie consent banner is on Portal. This page remains
    on Platform so that cross-references from other legal templates
    (privacy policy, terms of service, etc.) resolve correctly.
    """
    context = {
        "last_updated": datetime(2024, 12, 27, tzinfo=UTC),
    }
    return render(request, "legal/cookie_policy.html", context)


def data_processors(request: HttpRequest) -> HttpResponse:
    """Third-party data processors disclosure page."""
    context = {
        "last_updated": datetime(2024, 12, 27, tzinfo=UTC),
    }
    return render(request, "legal/data_processors.html", context)
