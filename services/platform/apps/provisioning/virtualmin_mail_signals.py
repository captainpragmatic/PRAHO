"""Audit persisted hosted-mail decisions without copying native credentials or lease heartbeats."""

from __future__ import annotations

from typing import Any

from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver

from apps.audit.services import AuditService
from apps.audit.switches import audit_signals_disabled

from .virtualmin_mail_models import VirtualminMailConfiguration, VirtualminMailOperation

_OPERATION_STATE = ("status", "checkpoint", "error_code")


@receiver(pre_save, sender=VirtualminMailConfiguration)
def remember_mail_mode(
    sender: type[VirtualminMailConfiguration], instance: VirtualminMailConfiguration, **kwargs: Any
) -> None:
    instance.__dict__["_mail_previous_mode"] = (
        sender.objects.filter(pk=instance.pk).values_list("mode", flat=True).first()
    )


@receiver(post_save, sender=VirtualminMailConfiguration)
def audit_mail_mode(
    sender: type[VirtualminMailConfiguration],
    instance: VirtualminMailConfiguration,
    created: bool,
    raw: bool = False,
    **kwargs: Any,
) -> None:
    if raw or audit_signals_disabled():
        return
    written = sender.objects.filter(pk=instance.pk).values_list("mode", flat=True).get()
    previous = instance.__dict__.get("_mail_previous_mode")
    if not created and written == previous:
        return
    AuditService.log_simple_event(
        "configuration_changed",
        content_object=instance,
        actor_type="system",
        description="Hosted mail mode recorded",
        old_values={"mode": previous} if previous is not None else {},
        new_values={"mode": written, "account_id": str(instance.account_id)},
        metadata={"component": "hosting_mail"},
    )


@receiver(pre_save, sender=VirtualminMailOperation)
def remember_mail_operation(
    sender: type[VirtualminMailOperation], instance: VirtualminMailOperation, **kwargs: Any
) -> None:
    instance.__dict__["_mail_previous_operation"] = (
        sender.objects.filter(pk=instance.pk).values(*_OPERATION_STATE).first()
    )


@receiver(post_save, sender=VirtualminMailOperation)
def audit_mail_operation(
    sender: type[VirtualminMailOperation],
    instance: VirtualminMailOperation,
    created: bool,
    raw: bool = False,
    **kwargs: Any,
) -> None:
    if raw or audit_signals_disabled():
        return
    written = sender.objects.filter(pk=instance.pk).values(*_OPERATION_STATE).get()
    previous = instance.__dict__.get("_mail_previous_operation")
    if not created and written == previous:
        return
    AuditService.log_simple_event(
        "configuration_changed",
        content_object=instance,
        user=instance.requested_by if created else None,
        actor_type="user" if created else "system",
        description="Hosted mail owner intent recorded" if created else "Hosted mail operation progressed",
        old_values=previous or {},
        new_values={
            **written,
            "configuration_id": str(instance.configuration_id),
            "intent": instance.intent,
            "requested_by_id": str(instance.requested_by_id),
            "requested_customer_id": str(instance.requested_customer_id),
            "consent_digest": instance.consent_digest,
            "target_generation": instance.target_generation,
        },
        metadata={"component": "hosting_mail"},
    )
