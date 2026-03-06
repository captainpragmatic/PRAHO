"""Deploy-time system checks for the portal common app."""

from __future__ import annotations

from typing import Any

from django.conf import settings
from django.core.checks import CheckMessage, Tags, Warning, register  # noqa: A004


@register(Tags.security, deploy=True)
def check_trusted_proxy_list(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    """Warn if IPWARE_TRUSTED_PROXY_LIST is empty in non-debug mode."""
    warnings: list[CheckMessage] = []
    if not settings.DEBUG and not getattr(settings, "IPWARE_TRUSTED_PROXY_LIST", []):
        warnings.append(
            Warning(
                "IPWARE_TRUSTED_PROXY_LIST is empty in non-debug mode. "
                "Behind a load balancer, all clients will appear as the same IP.",
                id="portal.W001",
            )
        )
    return warnings
