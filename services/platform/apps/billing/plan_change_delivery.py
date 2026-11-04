"""Final plan-change mail authority checks, with no locks spanning provider I/O."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from django.db import transaction
from django.utils import timezone

from apps.notifications.delivery import mark_permanent

from .plan_change_lifecycle import _cancel_context
from .plan_change_notice_models import PlanChangeNotice
from .plan_change_notices import OPERATIONAL_PHASES, notice_refusal

if TYPE_CHECKING:
    from apps.notifications.models import EmailLog


def _valid_claim(log: EmailLog, token: UUID | None) -> bool:
    return bool(
        token is not None
        and log.claim_token == token
        and log.status == "sending"
        and log.lease_until is not None
        and log.lease_until > timezone.now()
    )


def plan_change_dispatch_allowed(email_log_id: str, claim_token: UUID | None) -> bool:
    """The stored recipient and phase must still be current immediately before send."""

    from apps.customers.models import Customer  # noqa: PLC0415  # ADR-0007: runtime model.
    from apps.notifications.models import EmailLog  # noqa: PLC0415  # ADR-0007: runtime model.

    try:
        log_id = UUID(email_log_id)
    except ValueError:
        return False
    hint = PlanChangeNotice.objects.filter(email_log_id=log_id).values("pk", "change_id").first()
    if hint is None:
        with transaction.atomic():
            log = EmailLog.objects.select_for_update(of=("self",)).filter(pk=email_log_id).first()
            if log is None or log.template_key not in {f"plan_change_{phase}" for phase in OPERATIONAL_PHASES}:
                return True
            if _valid_claim(log, claim_token):
                mark_permanent(log, "plan_change_notice_missing")
            return False
    with _cancel_context(hint["change_id"]) as change:
        notice = PlanChangeNotice.objects.select_for_update(of=("self",)).get(pk=hint["pk"])
        log = EmailLog.objects.select_for_update(of=("self",)).get(pk=email_log_id)
        if not _valid_claim(log, claim_token) or notice.email_log_id != log.pk:
            return False
        customer = Customer.all_objects.get(pk=change.customer_id)
        reason = notice_refusal(change, notice.phase, customer)
        if notice.state != "linked" or log.customer_id != change.customer_id:
            reason = reason or "plan_change_delivery_owner_changed"
        if log.to_addr.strip().casefold() != customer.primary_email.strip().casefold():
            reason = reason or "plan_change_recipient_changed"
        expected_template = f"plan_change_{notice.phase}" if notice.phase in OPERATIONAL_PHASES else notice.phase
        if log.template_key != expected_template:
            reason = reason or "plan_change_template_changed"
        if reason:
            mark_permanent(log, reason)
            notice.refusal_reason = reason
            notice.save(update_fields=["refusal_reason", "updated_at"])
            return False
        return True
