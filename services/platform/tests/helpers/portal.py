"""The portal URL staff store; without one, tests use the test settings' PORTAL_DOMAIN."""

from __future__ import annotations

from django.core.cache import cache

from apps.settings.models import SystemSetting


def set_portal_origin(origin: str) -> None:
    """Store the portal URL as staff would; blank stores an empty row, which inherits PORTAL_DOMAIN."""
    SystemSetting.objects.update_or_create(
        key="portal.public_base_url",
        defaults={
            "name": "Portal URL",
            "category": "platform",
            "data_type": "string",
            "value": origin,
            "default_value": "",
        },
    )
    cache.clear()
