"""Render the portal's final error response without request context processors."""

import logging

from django.conf import settings
from django.http import HttpRequest, HttpResponse, HttpResponseServerError
from django.template.loader import render_to_string
from django.utils.html import format_html
from django.utils.translation import gettext as _

from apps.common import localisation_services

logger = logging.getLogger(__name__)


def server_error(request: HttpRequest) -> HttpResponse:
    """Keep the public support address available even when error rendering fails."""
    try:
        company = localisation_services.get_company_identity()
    except Exception:
        logger.exception("🔥 [Portal] Company identity unavailable while rendering the server error")
        company = dict(settings.COMPANY_IDENTITY_DEFAULTS)

    try:
        # A 500 response must not rerun context processors that may have caused the error.
        return HttpResponseServerError(render_to_string("500.html", {"company": company}))
    except Exception:
        logger.exception("🔥 [Portal] Server error template failed; returning the minimal support page")

    address = company["email_support"]
    return HttpResponseServerError(
        format_html(
            '<h1>{}</h1><p>{}: <a href="mailto:{}">{}</a></p>',
            _("Server Error"),
            _("Contact Support"),
            address,
            address,
        )
    )
