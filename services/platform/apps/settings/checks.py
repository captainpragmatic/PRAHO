"""Read-only deployment checks for the stored company identity.

Database access is explicit: ``migrate`` and ``check --database default`` select it, ordinary
checks and imports stay offline, and a schema without the settings table is skipped.
"""

from __future__ import annotations

from collections.abc import Sequence

from django.conf import settings
from django.core import checks
from django.db import DatabaseError, InterfaceError, connections, router

# Public contacts customers see before staff configure their own (legal pages, the portal). The legal
# name needs no check: unset, it is the seller name that production requires.
PLACEHOLDER_IDENTITY_KEYS = ("company.email_support", "company.email_privacy")


@checks.register("company_identity", checks.Tags.database)
def check_company_identity_placeholders(
    *, databases: Sequence[str] | None = None, **_kwargs: object
) -> list[checks.CheckMessage]:
    """Warn outside DEBUG while the shipped example identity is still in use."""
    from apps.settings.catalog import CATALOG_BY_KEY  # noqa: PLC0415  # registry is ready before checks run
    from apps.settings.models import SystemSetting  # noqa: PLC0415
    from apps.settings.services import SettingsService  # noqa: PLC0415  # read-only: stored rows, no cache

    alias = router.db_for_read(SystemSetting)
    if settings.DEBUG or not databases or alias not in databases:
        return []
    try:
        with connections[alias].cursor() as cursor:
            if SystemSetting._meta.db_table not in connections[alias].introspection.table_names(cursor):
                return []
        unchanged = [
            key
            for key in PLACEHOLDER_IDENTITY_KEYS
            if (stored := SettingsService.get_stored_setting(key)) is None
            or str(stored) == str(CATALOG_BY_KEY[key].default)
        ]
    except (DatabaseError, InterfaceError):
        return []
    if not unchanged:
        return []
    return [
        checks.Warning(
            f"The example company contacts are still configured: {', '.join(unchanged)}.",
            hint="Set your support and privacy emails in Settings → Company & Identity.",
            id="settings.W001",
        )
    ]
