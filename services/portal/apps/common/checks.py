"""Deploy-time system checks for the portal common app."""

from __future__ import annotations

from collections.abc import Iterable

from django.apps import AppConfig
from django.conf import settings
from django.core.checks import CheckMessage, Error, Tags, Warning, register  # noqa: A004


@register(Tags.security, deploy=True)
def check_trusted_proxy_list(app_configs: Iterable[AppConfig] | None, **kwargs: object) -> list[CheckMessage]:
    """Require proxy trust outside debug mode so client IP limits remain usable."""
    if getattr(settings, "IPWARE_TRUSTED_PROXY_LIST", []):
        return []

    message_class = Warning if settings.DEBUG else Error
    return [
        message_class(
            "IPWARE_TRUSTED_PROXY_LIST is empty. Behind a reverse proxy, all clients appear as the same IP.",
            hint="Set PORTAL_TRUSTED_PROXY_CIDRS to the trusted reverse proxy CIDRs.",
            id="portal.W001" if settings.DEBUG else "portal.E001",
        )
    ]
