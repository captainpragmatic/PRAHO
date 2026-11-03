"""Audit notice ownership without fiscal identity, rendered mail or payment secrets."""

from typing import Any

from django.db.models.signals import post_save
from django.dispatch import receiver

from apps.audit.services import AuditService
from apps.audit.switches import audit_signals_disabled

from .plan_change_models import PlanChange
from .plan_change_notice_models import PlanChangeNotice
from .plan_change_notices import publish_plan_change_notice


@receiver(post_save, sender=PlanChange)
def publish_plan_change_phase(sender: type[PlanChange], instance: PlanChange, created: bool, **kwargs: Any) -> None:
    fields = kwargs.get("update_fields")
    if fields and set(fields) <= {"next_reconcile_at", "updated_at"}:
        return
    phases = {
        "scheduled": "scheduled",
        "completed": "completed",
        "limits_attention": "attention",
        "paid_review": "attention",
    }
    phase = phases.get(instance.status)
    if instance.status == "awaiting_payment" and instance.proforma_id is not None:
        phase = "proforma"
    if phase is not None:
        publish_plan_change_notice(instance, phase)


@receiver(post_save, sender=PlanChangeNotice)
def audit_plan_change_notice(
    sender: type[PlanChangeNotice], instance: PlanChangeNotice, created: bool, **kwargs: Any
) -> None:
    if not audit_signals_disabled():
        AuditService.log_simple_event(
            "create" if created else "update",
            content_object=instance,
            description="Hosting plan phase delivery ownership",
            new_values={
                "change_id": str(instance.change_id),
                "phase": instance.phase,
                "state": instance.state,
                "email_log_id": str(instance.email_log_id) if instance.email_log_id else None,
                "refusal_reason": instance.refusal_reason,
            },
        )
