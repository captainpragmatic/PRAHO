"""Audit the account-hostname lifecycle (ADR-0061): a label assigned, a name retired, a row deleted."""

from __future__ import annotations

import logging
from typing import Any

from django.conf import settings
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from apps.audit.services import AuditContext, AuditEventData, AuditService
from apps.common.transactions import best_effort_atomic

from .account_hostname_models import AccountHostname

logger = logging.getLogger(__name__)


def _log(instance: AccountHostname, event_type: str, description: str) -> None:
    if getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
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
            context=AuditContext(actor_type="system"),
        )


@receiver(post_save, sender=AccountHostname)
def audit_account_hostname_saved(
    sender: type[AccountHostname], instance: AccountHostname, created: bool, **kwargs: Any
) -> None:
    update_fields = kwargs.get("update_fields")
    if created:
        _log(instance, "account_hostname_assigned", f"Account hostname {instance.fqdn} assigned")
    elif instance.retired_at is not None and (update_fields is None or "retired_at" in update_fields):
        _log(instance, "account_hostname_retired", f"Account hostname {instance.fqdn} retired")


@receiver(post_delete, sender=AccountHostname)
def audit_account_hostname_deleted(sender: type[AccountHostname], instance: AccountHostname, **kwargs: Any) -> None:
    _log(instance, "account_hostname_deleted", f"Account hostname {instance.fqdn} deleted")
