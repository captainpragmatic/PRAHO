"""
Common app configuration for PRAHO Platform
Shared utilities, types, and middleware.
"""

import logging
import socket

from django.apps import AppConfig
from django.conf import settings

logger = logging.getLogger(__name__)


class CommonConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.common"
    verbose_name = "Common Utilities"

    def ready(self) -> None:
        _validate_internal_service_domains()


def _validate_internal_service_domains() -> None:
    """Warn at startup if INTERNAL_SERVICE_ALLOWED_DOMAINS contains unreachable hosts."""
    domains: list[str] = getattr(settings, "INTERNAL_SERVICE_ALLOWED_DOMAINS", [])
    if not domains:
        return

    for domain in domains:
        try:
            socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except (socket.gaierror, OSError):
            logger.warning(
                "⚠️ [OutboundHTTP] INTERNAL_SERVICE_ALLOWED_DOMAINS contains "
                "unreachable host: %s — inter-service requests to this host will fail",
                domain,
            )
