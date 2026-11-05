"""One durable urgent staff obligation for a failed, due scheduled downgrade."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext as _

if TYPE_CHECKING:
    from apps.customers.models import Customer
    from apps.provisioning.service_models import Service

    from .plan_change_models import PlanChange
    from .subscription_models import Subscription


def escalate_scheduled_attention(
    change: PlanChange,
    customer: Customer,
    subscription: Subscription,
    service: Service,
    *,
    at: datetime | None = None,
) -> bool:
    """Caller owns the existing document→Customer→Subscription→Service→change context.

    The event and technical marker commit together. A failed audit INSERT must
    leave the marker unset so the ordinary operation sweep can recover it.
    """
    from apps.audit.services import AuditContext, AuditEventData, AuditService  # noqa: PLC0415 -- Staff queue boundary.

    if not transaction.get_connection(change._state.db).in_atomic_block:
        raise RuntimeError("Plan-change escalation requires the locked commercial context")
    now = timezone.now() if at is None else at
    if timezone.is_naive(now):
        raise ValueError("Plan-change escalation requires a timezone-aware instant")
    if (
        change.direction != "downgrade"
        or change.status != "limits_attention"
        or change.confirmed_at is None
        or change.committed_at is None
        or change.effective_at > now
        or change.staff_escalated_at is not None
        or service.pk != change.service_id
        or subscription.pk != change.subscription_id
        or customer.pk != change.customer_id
        or service.customer_id != customer.pk
        or subscription.customer_id != customer.pk
        or subscription.service_id != service.pk
        or customer.anonymized_at is not None
        or customer.deleted_at is not None
    ):
        return False
    AuditService.log_event(
        AuditEventData(
            event_type="hosting_plan_change_attention",
            content_object=change,
            description=_("Scheduled downgrade limits need staff review."),
            new_values={
                "plan_change_id": str(change.pk),
                "service_id": service.pk,
                "customer_id": customer.pk,
                "subscription_id": str(subscription.pk),
                "effective_at": change.effective_at.isoformat(),
                "target_plan_id": change.to_plan_id,
                "agreed_period_price_cents": change.target_period_price_cents,
            },
        ),
        AuditContext(actor_type="system", metadata={"source_app": "billing", "operational_event": True}),
    )
    change.staff_escalated_at = now
    change.save(update_fields=["staff_escalated_at", "updated_at"])
    return True
