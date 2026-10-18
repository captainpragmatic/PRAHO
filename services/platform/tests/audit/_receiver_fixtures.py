"""Receivers for the audit-coverage detector's own tests: one module, three behaviours."""

from __future__ import annotations

from typing import Any

from apps.audit.services import AuditService


def _record(instance: Any) -> None:
    AuditService.log_event  # noqa: B018  # the name is what the detector looks for


def audits_directly(sender: Any, instance: Any, **kwargs: Any) -> None:
    AuditService.log_event  # noqa: B018


def audits_through_a_helper(sender: Any, instance: Any, **kwargs: Any) -> None:
    _record(instance)


def only_invalidates_a_cache(sender: Any, instance: Any, **kwargs: Any) -> None:
    # AuditService is only mentioned in this comment, and the module above imports it.
    instance.refresh_from_db()


def loops_through_itself(sender: Any, instance: Any, **kwargs: Any) -> None:
    loops_through_itself(sender, instance)
