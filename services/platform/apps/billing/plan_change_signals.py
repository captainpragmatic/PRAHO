"""Audit commercial acceptance without copying fiscal or card data."""

from typing import Any

from django.db.models.signals import post_save
from django.dispatch import receiver

from apps.audit.services import AuditService
from apps.audit.switches import audit_signals_disabled

from .plan_change_models import PlanChange, PlanChangeInterval


@receiver(post_save, sender=PlanChange)
def audit_plan_change(sender: type[PlanChange], instance: PlanChange, created: bool, **kwargs: Any) -> None:
    fields = kwargs.get("update_fields")
    if not created and fields and set(fields) <= {"next_reconcile_at", "updated_at"}:
        return  # Technical reconciliation scheduling does not repeat the commercial acceptance audit.
    if not audit_signals_disabled():
        AuditService.log_simple_event(
            "create" if created else "update",
            content_object=instance,
            description="Commercial hosting plan change",
            new_values={
                "service_id": instance.service_id,
                "subscription_id": str(instance.subscription_id),
                "customer_id": instance.customer_id,
                "requested_by_id": instance.requested_by_id,
                "submission_id": str(instance.submission_id),
                "status": instance.status,
                "from_product_id": str(instance.from_product_id),
                "to_product_id": str(instance.to_product_id),
                "expected_limit_revision": instance.expected_limit_revision,
                "currency": instance.currency_id,
                "net_cents": instance.net_cents,
                "tax_cents": instance.tax_cents,
                "total_cents": instance.total_cents,
                "effective_at": instance.effective_at.isoformat(),
                "request_fingerprint": instance.request_fingerprint,
                "proforma_id": str(instance.proforma_id) if instance.proforma_id else None,
                "invoice_id": str(instance.invoice_id) if instance.invoice_id else None,
                "limit_application_id": str(instance.limit_application_id) if instance.limit_application_id else None,
                "review_reason": instance.review_reason,
            },
        )


@receiver(post_save, sender=PlanChangeInterval)
def audit_plan_change_interval(
    sender: type[PlanChangeInterval], instance: PlanChangeInterval, created: bool, **kwargs: Any
) -> None:
    if not audit_signals_disabled():
        AuditService.log_simple_event(
            "create" if created else "update",
            content_object=instance,
            description="Immutable plan-change interval allocation",
            new_values={
                "change_id": str(instance.change_id),
                "ordinal": instance.ordinal,
                "period_start": instance.period_start.isoformat(),
                "period_end": instance.period_end.isoformat(),
                "slice_start": instance.slice_start.isoformat(),
                "base_net_cents": instance.base_net_cents,
                "prior_supplement_cents": instance.prior_supplement_cents,
                "net_cents": instance.net_cents,
                "current_slice": instance.current_slice,
                "evidence": instance.evidence,
            },
        )
