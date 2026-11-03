"""Audit financial review facts without copying customer or provider payloads."""

from django.db.models.signals import post_save
from django.dispatch import receiver

from apps.audit.services import AuditService
from apps.audit.switches import audit_signals_disabled

from .payment_models import Payment
from .plan_change_review_models import PlanChangeReviewEvent
from .plan_change_review_service import record_payment_review, record_refund_review
from .refund_models import Refund


@receiver(post_save, sender=Payment)
def journal_plan_payment_review(sender: type[Payment], instance: Payment, using: str, **kwargs: object) -> None:
    if not kwargs.get("raw"):
        record_payment_review(instance, using=using)


@receiver(post_save, sender=Refund)
def journal_plan_refund_review(sender: type[Refund], instance: Refund, using: str, **kwargs: object) -> None:
    if not kwargs.get("raw"):
        record_refund_review(instance, using=using)


@receiver(post_save, sender=PlanChangeReviewEvent)
def audit_plan_change_review_event(
    sender: type[PlanChangeReviewEvent],
    instance: PlanChangeReviewEvent,
    created: bool,
    **kwargs: object,
) -> None:
    if not audit_signals_disabled():
        AuditService.log_simple_event(
            "create" if created else "update",
            content_object=instance,
            description="Hosting plan financial review journal",
            new_values={
                "fact_key": instance.fact_key,
                "source_kind": instance.source_kind,
                "source_id": instance.source_id,
                "reason": instance.reason,
                "customer_id": instance.customer_id,
                "payment_id": instance.payment_id,
                "invoice_id": instance.invoice_id,
                "proforma_id": instance.proforma_id,
                "reviewed_changes": instance.reviewed_changes,
                "processed_at": instance.processed_at.isoformat() if instance.processed_at else None,
                "refusal_code": instance.refusal_code,
            },
        )
