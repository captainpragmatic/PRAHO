"""Audit durable checkout ownership without exposing provider request secrets."""

from typing import Any

from django.db.models.signals import post_save
from django.dispatch import receiver

from apps.audit.services import AuditService
from apps.audit.switches import audit_signals_disabled

from .plan_change_payment_models import PlanChangePaymentAttempt


@receiver(post_save, sender=PlanChangePaymentAttempt)
def audit_plan_change_payment_attempt(
    sender: type[PlanChangePaymentAttempt], instance: PlanChangePaymentAttempt, created: bool, **kwargs: Any
) -> None:
    if not audit_signals_disabled():
        AuditService.log_simple_event(
            "create" if created else "update",
            content_object=instance,
            description="Standalone plan payment submission ownership",
            new_values={
                "change_id": str(instance.change_id),
                "payment_id": instance.payment_id,
                "state": instance.state,
                "payload_hash": instance.payload_hash,
                "provider_status": instance.provider_status,
                "submission_count": instance.submission_count,
                "gateway_intent_id": instance.gateway_intent_id,
            },
        )
