"""The legal pages are the portal's; these staff-side addresses send visitors there (ADR-0058)."""

from __future__ import annotations

import logging
from collections.abc import Callable

from django.core.exceptions import ImproperlyConfigured
from django.http import Http404, HttpRequest, HttpResponseRedirect

logger = logging.getLogger(__name__)


def _portal_page(path: str) -> Callable[[HttpRequest], HttpResponseRedirect]:
    def view(request: HttpRequest) -> HttpResponseRedirect:
        from apps.users.services import portal_public_origin  # noqa: PLC0415  # ADR-0007

        try:
            return HttpResponseRedirect(portal_public_origin() + path)
        except ImproperlyConfigured as exc:
            logger.warning("⚠️ [Legal] portal.public_base_url is not set; %s has nowhere to go", path)
            raise Http404 from exc

    return view


privacy_policy = _portal_page("/privacy-policy/")
terms_of_service = _portal_page("/terms/")
cookie_policy = _portal_page("/cookie-policy/")
