"""System check: audit writes that failed and were swallowed (ADR-0016)."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from django.apps import AppConfig
from django.core.checks import CheckMessage, Tags, Warning, register  # noqa: A004  # Django's own name
from django.db import DatabaseError
from django.utils.translation import gettext as _

from apps.common import audit_failures


@register(Tags.database)
def check_audit_write_failures(
    app_configs: Iterable[AppConfig] | None, databases: Sequence[str] | None = None, **kwargs: Any
) -> list[CheckMessage]:
    """Warn when audit writes failed and were skipped: the trail has holes the logs explain."""
    if not databases:
        return []  # Only when the database is asked about: a check must not query unmigrated tables
    try:
        failed = audit_failures.count()
    except DatabaseError:
        return []
    if not failed:
        return []
    return [
        Warning(
            _("%(count)d audit writes failed and were skipped in the last 30 days.") % {"count": failed},
            hint=_("The actions went ahead without their audit event. Search the logs for 'Failed to log event'."),
            id="audit.W001",
        )
    ]
