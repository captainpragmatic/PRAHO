"""Durable maintenance notices reuse the normal mail claims, retry budget and provider path."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING
from uuid import UUID

from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from apps.common.localisation import format_localised_date, resolve_display
from apps.common.localisation_services import get_localisation_defaults, user_localisation_preferences
from apps.customers.services import get_customer_locale
from apps.infrastructure.node_maintenance_audience import is_unstarted_not_run, not_run_service_ids
from apps.infrastructure.node_maintenance_models import (
    NodeMaintenanceAudience,
    NodeMaintenanceDelivery,
    NodeMaintenanceWindow,
)
from apps.notifications.services import EmailService, EmailSuppressionService

if TYPE_CHECKING:
    from apps.customers.models import Customer

MAINTENANCE_TEMPLATE_KEYS = frozenset({"maintenance_scheduled", "maintenance_completed", "maintenance_correction"})
QUIET_DURATION = timedelta(minutes=5)
NOTICE_LEAD = timedelta(hours=48)


def _preference_allows(customer: Customer) -> bool:
    from apps.notifications.models import EmailPreference  # noqa: PLC0415

    preference = EmailPreference.objects.filter(customer=customer).first()
    return (preference or EmailPreference(customer=customer)).can_receive("maintenance")


def _current_audience(window: NodeMaintenanceWindow, event: str) -> dict[int, list[int]]:
    from apps.provisioning.service_models import Service  # noqa: PLC0415
    from apps.provisioning.virtualmin_models import VirtualminAccount  # noqa: PLC0415

    service_ids = (
        (
            not_run_service_ids(window)
            if is_unstarted_not_run(window)
            else window.audience.filter(provenance="execution").values_list("service_id_snapshot", flat=True)
        )
        if event == "completed"
        else VirtualminAccount.objects.filter(server_id=window.node_id).values_list("service_id", flat=True)
    )
    result: dict[int, list[int]] = {}
    for service_id, customer_id in (
        Service.objects.filter(pk__in=service_ids).order_by("pk").values_list("pk", "customer_id")
    ):
        result.setdefault(customer_id, []).append(service_id)
    if event == "correction":
        # Moving to another node does not erase an earlier announcement to the same owner.
        # A former owner receives only a generic withdrawal, never the new owner's details.
        for previous in window.deliveries.filter(first_dispatch_claimed_at__isnull=False).exclude(
            revision=window.revision
        ):
            current_ids = Service.objects.filter(
                pk__in=previous.selected_service_ids, customer_id=previous.customer_id_snapshot
            ).values_list("pk", flat=True)
            for service_id in current_ids:
                selected = result.setdefault(previous.customer_id_snapshot, [])
                if service_id not in selected:
                    selected.append(service_id)
    return result


def _snapshot(
    window: NodeMaintenanceWindow, kind: str, *, customer: Customer, withdrawal: bool = False
) -> dict[str, object]:
    if withdrawal:
        return {
            "withdrawal": True,
            "event_label": "An earlier maintenance announcement has been withdrawn.",
            "customer_note": "The earlier announcement no longer applies to your account.",
            "public_outcome": "",
        }
    labels = {
        "scheduled": "Emergency maintenance for your hosting"
        if window.kind == "emergency"
        else "Scheduled maintenance for your hosting",
        "completed": "Maintenance outcome for your hosting",
        "correction": "Your hosting maintenance announcement changed",
    }
    membership = (
        customer.memberships.filter(is_primary=True, is_active=True, user__is_active=True)
        .select_related("user__profile")
        .first()
    )
    display = resolve_display(
        get_localisation_defaults(), user_localisation_preferences(membership.user) if membership else None
    )
    return {
        "withdrawal": False,
        "event_label": labels[kind],
        "customer_note": window.customer_note,
        "public_outcome": window.public_outcome,
        "starts_at": window.starts_at.isoformat(),
        "ends_at": window.ends_at.isoformat(),
        "timezone": window.policy_timezone,
        "status": window.status,
        "expects_downtime": window.expects_downtime,
        "expected_downtime_minutes": window.expected_downtime_minutes,
        "completion_source": window.completion_source,
        "kind": window.kind,
        "is_emergency": window.kind == "emergency",
        "display_starts_at": format_localised_date(window.starts_at, display, "datetime"),
        "display_ends_at": format_localised_date(window.ends_at, display, "datetime"),
        "display_timezone": display.timezone,
    }


def _link_due_intent(window: NodeMaintenanceWindow, intent: NodeMaintenanceDelivery) -> None:
    """Caller holds Window then Delivery. Log publication and typed link commit together."""
    from apps.customers.models import Customer  # noqa: PLC0415

    if intent.phase != "pending" or intent.email_log_id or intent.due_at > timezone.now():
        return
    current_ids = _current_audience(window, intent.kind).get(intent.customer_id_snapshot, [])
    if not current_ids and intent.kind != "correction":
        intent.refuse("no_affected_services")
        intent.save()
        return
    intent.selected_service_ids = current_ids
    customer = Customer.objects.filter(pk=intent.customer_id).first() if intent.customer_id is not None else None
    reason = "customer_unavailable" if customer is None else ""
    if customer is not None and not _preference_allows(customer):
        reason = "maintenance_opt_out"
    if customer is not None and not customer.primary_email:
        reason = reason or "no_recipient_address"
    if reason:
        intent.refuse(reason)
        intent.save()
        return
    assert customer is not None
    intent.public_snapshot = _snapshot(
        window, intent.kind, customer=customer, withdrawal=intent.kind == "correction" and not current_ids
    )
    result = EmailService.send_template_email(
        template_key=f"maintenance_{intent.kind}",
        recipient=customer.primary_email,
        context=dict(intent.public_snapshot),
        locale=get_customer_locale(customer),
        customer=customer,
        async_send=True,
        require_async=True,
    )
    if result.email_log_id:
        intent.email_log_id = UUID(result.email_log_id)
        intent.link()
    else:
        # Configuration/render/suppression refusal has no transport log to retry.
        intent.refusal_reason = (result.error or "email_not_queued")[:255]
        intent.due_at = timezone.now() + timedelta(minutes=15)
    intent.save()


def publish_window_notices(window: NodeMaintenanceWindow, event: str) -> int:
    """Publish revision-scoped intentions; corrections take precedence for prior recipients."""
    from apps.customers.models import Customer  # noqa: PLC0415

    quiet = (
        window.kind != "emergency"
        and not window.expects_downtime
        and window.ends_at - window.starts_at < QUIET_DURATION
    )
    if event == "completed" and window.kind != "emergency" and not window.was_overrun and window.status != "failed":
        return 0
    audience = _current_audience(window, event)
    # Preserve independent planned membership, including later arrivals and opt-outs.
    # This does not promote anyone to an executed audience.
    for selected in audience.values():
        for service_id in selected:
            NodeMaintenanceAudience.objects.get_or_create(
                window=window,
                service_id_snapshot=service_id,
                defaults={"service_id": service_id, "provenance": "scheduled"},
            )
    announced = (
        set(
            window.deliveries.filter(first_dispatch_claimed_at__isnull=False)
            .exclude(revision=window.revision)
            .values_list("customer_id_snapshot", flat=True)
        )
        if event == "correction"
        else set()
    )
    if event == "correction":
        for previous in (
            window.deliveries.select_for_update(of=("self",))
            .exclude(revision=window.revision)
            .filter(phase__in=("pending", "linked"))
        ):
            previous.supersede()
            previous.save()
    corrected = (
        set(
            window.deliveries.filter(revision=window.revision, kind="correction").values_list(
                "customer_id_snapshot", flat=True
            )
        )
        if event == "scheduled"
        else set()
    )
    created_count = 0
    for customer_id in sorted(set(audience) | announced):
        if customer_id in corrected:
            continue  # The correction remains this recipient's single notice for this revision.
        correction = event == "correction" and customer_id in announced
        if not correction and (quiet or window.status == "cancelled"):
            continue
        kind = "correction" if correction else ("scheduled" if event == "correction" else event)
        selected_ids = audience.get(customer_id, [])
        customer = Customer.objects.filter(pk=customer_id).first()
        if customer is None:
            continue
        intent, created = NodeMaintenanceDelivery.objects.get_or_create(
            window=window,
            revision=window.revision,
            customer_id_snapshot=customer_id,
            kind=kind,
            channel="email",
            defaults={
                "customer": customer,
                "selected_service_ids": selected_ids,
                "public_snapshot": _snapshot(
                    window, kind, customer=customer, withdrawal=correction and not selected_ids
                ),
                "due_at": max(timezone.now(), window.starts_at - NOTICE_LEAD)
                if kind == "scheduled" and window.kind != "emergency"
                else timezone.now(),
            },
        )
        if created and not _preference_allows(customer):
            intent.refuse("maintenance_opt_out")
            intent.save()
        created_count += int(created)
        _link_due_intent(window, intent)
    return created_count


def dispatch_due_notices(*, window_ids: list[str] | None = None) -> int:
    """Unlinked configuration retries reuse an intent; mail transport retries reuse its log."""
    count = 0
    windows = NodeMaintenanceWindow.objects.filter(
        Q(status="scheduled") | Q(deliveries__phase="pending", deliveries__due_at__lte=timezone.now())
    ).distinct()
    if window_ids is not None:
        windows = windows.filter(pk__in=window_ids)
    for window_id in windows.values_list("pk", flat=True):
        with transaction.atomic():
            window = NodeMaintenanceWindow.objects.select_for_update(of=("self",)).get(pk=window_id)
            if window.status == "scheduled":
                count += publish_window_notices(window, "scheduled")
            for intent in window.deliveries.select_for_update(of=("self",)).filter(
                revision=window.revision, phase="pending", due_at__lte=timezone.now()
            ):
                _link_due_intent(window, intent)
    return count


def _event_refusal(window: NodeMaintenanceWindow, intent: NodeMaintenanceDelivery) -> str | None:
    if window.revision != intent.revision or intent.phase not in {"linked", "dispatching"}:
        return "obsolete_maintenance_revision"
    if intent.kind == "completed" and window.status not in {"completed", "failed"}:
        return "maintenance_outcome_not_final"
    if (
        intent.kind == "scheduled"
        and window.status != "scheduled"
        and not (window.kind == "emergency" and window.status in {"running", "overran"})
    ):
        return "maintenance_notice_obsolete"
    # A current-revision correction remains required if work starts or finishes
    # while its normal transport retries. Moves/cancellations invalidate it by
    # revision above; current recipient, ownership and claim checks still apply.
    return None


def _unlinked_dispatch_allowed(log_id: UUID, claim_token: UUID | None) -> bool:
    from apps.notifications.models import EmailLog  # noqa: PLC0415

    with transaction.atomic():
        log = EmailLog.objects.select_for_update().filter(pk=log_id).first()
        if log is None or log.template_key not in MAINTENANCE_TEMPLATE_KEYS:
            return True
        from apps.notifications.delivery import mark_permanent  # noqa: PLC0415  # Existing transport policy

        if claim_token is not None and log.claim_token == claim_token and log.status == "sending":
            mark_permanent(log, "maintenance_intent_missing")
        return False


def _service_scope_refusal(window: NodeMaintenanceWindow, intent: NodeMaintenanceDelivery) -> str | None:
    from apps.provisioning.service_models import Service  # noqa: PLC0415
    from apps.provisioning.virtualmin_models import VirtualminAccount  # noqa: PLC0415

    selected_ids = intent.selected_service_ids
    owned_ids = set(
        Service.objects.filter(pk__in=selected_ids, customer_id=intent.customer_id_snapshot).values_list(
            "pk", flat=True
        )
    )
    if owned_ids != set(selected_ids) or (not selected_ids and intent.public_snapshot.get("withdrawal") is not True):
        return "maintenance_service_ownership_changed"
    if intent.kind == "scheduled" and window.kind != "emergency":
        placed_ids = set(
            VirtualminAccount.objects.filter(server_id=window.node_id, service_id__in=selected_ids).values_list(
                "service_id", flat=True
            )
        )
        if placed_ids != set(selected_ids):
            return "maintenance_service_placement_changed"
    return None


def maintenance_dispatch_allowed(email_log_id: str, claim_token: UUID | None) -> bool:
    """Recheck at the final provider boundary; no row lock spans provider I/O."""
    from apps.customers.models import Customer  # noqa: PLC0415
    from apps.notifications.models import EmailLog  # noqa: PLC0415

    try:
        log_id = UUID(email_log_id)
    except ValueError:
        return False
    hint = NodeMaintenanceDelivery.objects.filter(email_log_id=log_id).values("pk", "window_id").first()
    if hint is None:
        return _unlinked_dispatch_allowed(log_id, claim_token)
    with transaction.atomic():
        window = NodeMaintenanceWindow.objects.select_for_update(of=("self",)).get(pk=hint["window_id"])
        intent = NodeMaintenanceDelivery.objects.select_for_update(of=("self",)).get(pk=hint["pk"])
        log = EmailLog.objects.select_for_update().get(pk=email_log_id)
        if (
            claim_token is None
            or log.claim_token != claim_token
            or log.status != "sending"
            or log.lease_until is None
            or log.lease_until <= timezone.now()
            or intent.email_log_id != log.pk
        ):
            return False
        reason = _event_refusal(window, intent)
        customer = Customer.objects.filter(pk=intent.customer_id).first() if intent.customer_id is not None else None
        if customer is None or log.customer_id != intent.customer_id:
            reason = reason or "maintenance_customer_changed"
        elif not _preference_allows(customer):
            reason = reason or "maintenance_opt_out"
        elif log.to_addr.strip().casefold() != customer.primary_email.strip().casefold():
            reason = reason or "maintenance_recipient_changed"
        if log.template_key != f"maintenance_{intent.kind}":
            reason = reason or "maintenance_template_changed"
        if EmailSuppressionService.is_suppressed(log.to_addr):
            reason = reason or "maintenance_recipient_suppressed"
        reason = reason or _service_scope_refusal(window, intent)
        if reason:
            from apps.notifications.delivery import mark_permanent  # noqa: PLC0415  # Existing transport policy

            mark_permanent(log, reason)
            if intent.phase in {"pending", "linked", "dispatching"}:
                intent.refuse(reason)
            else:
                intent.refusal_reason = reason
        else:
            intent.claim_dispatch()
        intent.save()
        return reason is None
