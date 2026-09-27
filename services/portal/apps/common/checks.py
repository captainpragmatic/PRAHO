"""Deploy-time system checks for the portal common app."""

from __future__ import annotations

from collections.abc import Iterable

from django.apps import AppConfig
from django.conf import settings
from django.core.checks import CheckMessage, Error, Tags, Warning, register  # noqa: A004
from django.db import Error as DatabaseError
from django.db import connections, router
from django.utils.translation import gettext as _

from apps.common.models import Counter


@register(Tags.database, deploy=True)
def check_counter_table(app_configs: Iterable[AppConfig] | None, **kwargs: object) -> list[CheckMessage]:
    """Require the counter table at deployment while allowing initial migrations."""
    alias = router.db_for_write(Counter)
    try:
        with connections[alias].cursor() as cursor:
            cursor.execute("SELECT 1 FROM common_counters LIMIT 1")
    except DatabaseError:
        return [
            Error(
                _("The Portal counter store is unavailable."),
                hint=_("Run migrate sessions --noinput and migrate common --noinput on the Portal database."),
                obj=alias,
                id="portal.E002",
            )
        ]
    return []


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
