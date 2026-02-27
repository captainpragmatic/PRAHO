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
from datetime import UTC, datetime

from django.http import HttpRequest, HttpResponse
from django.shortcuts import render

logger = logging.getLogger(__name__)


def privacy_policy(request: HttpRequest) -> HttpResponse:
    """GDPR-compliant Privacy Policy page."""
    context = {
        "last_updated": datetime(2024, 12, 27, tzinfo=UTC),
        "effective_date": datetime(2024, 12, 27, tzinfo=UTC),
    }
    return render(request, "legal/privacy_policy.html", context)


def terms_of_service(request: HttpRequest) -> HttpResponse:
    """Terms of Service page."""
    context = {
        "last_updated": datetime(2024, 12, 27, tzinfo=UTC),
        "effective_date": datetime(2024, 12, 27, tzinfo=UTC),
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
