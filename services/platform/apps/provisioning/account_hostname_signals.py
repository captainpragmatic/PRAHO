"""Audit the account-hostname lifecycle (ADR-0061): a label assigned, a name retired.

Rows are never deleted (`ProtectedLabelError`), so there is no delete event.
"""

from __future__ import annotations

import logging
from typing import Any

from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver

from apps.audit.services import AuditEventData, AuditService, actor_context
from apps.audit.switches import audit_signals_disabled
from apps.common.transactions import best_effort_atomic

from .account_hostname_models import AccountHostname

logger = logging.getLogger(__name__)


def _log(instance: AccountHostname, event_type: str, description: str) -> None:
    if audit_signals_disabled():
        return
    # A failed audit write never undoes the hostname change; its own savepoint keeps the transaction usable.
    with best_effort_atomic(logger=logger, scope="Account hostnames", message="Account hostname audit failed"):
        AuditService.log_event(
            AuditEventData(
                event_type=event_type,
                content_object=instance,
                new_values={
                    "fqdn": instance.fqdn,
                    "account_id": str(instance.account_id) if instance.account_id else None,
                    "target_server_id": str(instance.target_server_id) if instance.target_server_id else None,
                    "retired_at": instance.retired_at.isoformat() if instance.retired_at else None,
                },
                description=description,
            ),
            context=actor_context(),
        )


@receiver(pre_save, sender=AccountHostname)
def remember_account_hostname_retirement(
    sender: type[AccountHostname], instance: AccountHostname, **kwargs: Any
) -> None:
    """Record whether this save retires the name: the stored row was live and this one is retired."""
    update_fields = kwargs.get("update_fields")
    if update_fields is not None and "retired_at" not in update_fields:
        instance._retires_now = False  # type: ignore[attr-defined]  # retired_at is not written by this save
        return
    was_retired = (
        instance.pk is not None and AccountHostname.objects.filter(pk=instance.pk, retired_at__isnull=False).exists()
    )
    instance._retires_now = instance.retired_at is not None and not was_retired  # type: ignore[attr-defined]  # per-save flag read by post_save


@receiver(post_save, sender=AccountHostname)
def audit_account_hostname_saved(
    sender: type[AccountHostname], instance: AccountHostname, created: bool, **kwargs: Any
) -> None:
    if created:
        _log(instance, "account_hostname_assigned", f"Account hostname {instance.fqdn} assigned")
    if getattr(instance, "_retires_now", False):
        _log(instance, "account_hostname_retired", f"Account hostname {instance.fqdn} retired")
