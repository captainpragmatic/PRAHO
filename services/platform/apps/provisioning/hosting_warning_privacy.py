"""Shared grouping/final-send authority for every persisted hosting warning version."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from django.core.exceptions import ObjectDoesNotExist

from .hosting_limit_models import ServiceHostingLimits
from .hosting_node_policy import platform_notifications_owned
from .hosting_warning_models import HostingWarningIntent
from .hosting_warning_observation import recipient_hash
from .hosting_warning_policy import WarningLevel, WarningScope
from .hosting_warning_selectors import warning_resource_data
from .hosting_warning_state import scope_from_snapshot, state_from_snapshot
from .service_models import Service
from .virtualmin_models import VirtualminAccount

if TYPE_CHECKING:
    from apps.customers.models import Customer


@dataclass
class WarningAudience:
    services: dict[int, Service]
    accounts: dict[UUID, VirtualminAccount]
    limits: dict[int, ServiceHostingLimits]
    node_mail: dict[UUID, bool] = field(default_factory=dict)
    optional_mail: dict[int, bool] = field(default_factory=dict)
    raises: dict[int, dict[str, object] | None] = field(default_factory=dict)
    desired: dict[int, dict[str, int] | None] = field(default_factory=dict)


def pending_desired_limits(limits: ServiceHostingLimits | None) -> dict[str, int] | None:
    """Closed resource-only context from the existing batch, with no financial claim."""
    if (
        limits is None
        or limits.operational_revision is None
        or limits.revision <= limits.operational_revision
        or limits.disk_allowance_mib is None
        or limits.bandwidth_allowance_mib is None
    ):
        return None
    return {
        "base_revision": limits.revision,
        "operational_revision": limits.operational_revision,
        "disk_mib": limits.disk_allowance_mib,
        "bandwidth_mib": limits.bandwidth_allowance_mib,
    }


def load_warning_audience(intents: list[HostingWarningIntent], *, at: datetime | None = None) -> WarningAudience:
    from django.utils import timezone  # noqa: PLC0415 -- Runtime snapshot instant.

    from .hosting_limit_selectors import (  # noqa: PLC0415 -- Exact batch proof; no native I/O.
        prime_current_verification,
    )
    from .hosting_raise_service import (  # noqa: PLC0415 -- Public batch DTO.
        prime_hosting_raises,
        service_raise_public_state,
    )

    service_ids = {item.service_id_snapshot for item in intents}
    audience = WarningAudience(
        services={row.pk: row for row in Service.objects.filter(pk__in=service_ids).select_related("hosting_limits")},
        accounts={
            row.pk: row
            for row in VirtualminAccount.objects.filter(
                pk__in={item.state.account_id for item in intents},
            ).select_related("usage_state", "server__hosting_policy")
        },
        limits={row.service_id: row for row in ServiceHostingLimits.objects.filter(service_id__in=service_ids)},
    )
    instant = at or timezone.now()
    records = list(audience.services.values())
    prime_current_verification(records, {row.service_id: row for row in audience.accounts.values()}, at=instant)
    prime_hosting_raises(records, at=instant)
    for service in records:
        audience.desired[service.pk] = pending_desired_limits(audience.limits.get(service.pk))
        state = service_raise_public_state(service, at=instant)
        audience.raises[service.pk] = (
            None
            if state is None
            else {
                "state": state.state,
                "revision": state.revision,
                "extra_mib": state.extra_mib,
                "expires_at": state.expires_at.isoformat(),
            }
        )
    return audience


def intent_refusal(
    intent: HostingWarningIntent,
    customer: Customer,
    audience: WarningAudience,
    at: datetime,
) -> str | None:
    """A critical notice bypasses only optional consent; all hard authority stays current."""
    if reason := _customer_refusal(intent, customer, at):
        return reason
    service = audience.services.get(intent.service_id_snapshot)
    account = audience.accounts.get(intent.state.account_id)
    if service is None or account is None or service.customer_id != customer.pk or account.service_id != service.pk:
        return "warning_ownership_changed"
    if service.status != "active" or account.status != "active":
        return "warning_service_inactive"
    if reason := _usage_refusal(intent, account, service, audience, at):
        return reason
    if account.server_id not in audience.node_mail:
        audience.node_mail[account.server_id] = platform_notifications_owned(account.server)
    return (
        _recipient_refusal(intent, customer, audience)
        if audience.node_mail[account.server_id]
        else "warning_native_mail_not_handed_over"
    )


def _customer_refusal(intent: HostingWarningIntent, customer: Customer, at: datetime) -> str | None:
    if intent.due_at > at:
        return "warning_not_due"
    if (
        customer.pk != intent.customer_id_snapshot
        or customer.status != "active"
        or customer.anonymized_at
        or customer.deleted_at
    ):
        return "warning_customer_unavailable"
    if not customer.primary_email or recipient_hash(customer.primary_email) != intent.recipient_hash:
        return "warning_recipient_changed"
    return None


def _usage_refusal(
    intent: HostingWarningIntent,
    account: VirtualminAccount,
    service: Service,
    audience: WarningAudience,
    at: datetime,
) -> str | None:
    try:
        usage = account.usage_state
        scope = scope_from_snapshot(intent.scope_snapshot)
        episode = next(
            item
            for item in state_from_snapshot(intent.state.policy_state).episodes
            if int(item.threshold) == intent.threshold
        )
    except (ObjectDoesNotExist, ValueError, StopIteration):
        return "warning_scope_unknown"
    if usage.owner_scope != intent.owner_scope or (usage.service_id_snapshot, usage.customer_id_snapshot) != (
        service.pk,
        service.customer_id,
    ):
        return "warning_ownership_changed"
    if not episode.latched or episode.generation != intent.generation:
        return "warning_episode_superseded"
    current = warning_resource_data(service, usage, intent.state, audience.limits.get(service.pk), at)
    if (
        scope.resource != intent.resource
        or scope.service_id != service.pk
        or scope.customer_id != service.customer_id
        or scope.owner_scope != usage.owner_scope
    ):
        return "warning_scope_changed"
    return _condition_refusal(intent, scope, current)


def _condition_refusal(intent: HostingWarningIntent, scope: WarningScope, current: dict[str, object]) -> str | None:
    start = scope.period_start.isoformat() if scope.period_start else None
    end = scope.period_end.isoformat() if scope.period_end else None
    if intent.resource == "bandwidth" and (
        current["period_start"],
        current["period_end"],
        current["period_timezone"],
    ) != (start, end, scope.period_timezone):
        return "warning_period_changed"
    if current["availability"] not in {"fresh", "partial"}:
        return "warning_usage_unavailable"
    if current["condition"] != intent.threshold:
        return "warning_condition_changed"
    return None


def _recipient_refusal(intent: HostingWarningIntent, customer: Customer, audience: WarningAudience) -> str | None:
    from apps.notifications.models import EmailPreference  # noqa: PLC0415 -- Current policy, never a cached allow.
    from apps.notifications.services import EmailSuppressionService  # noqa: PLC0415

    critical = intent.threshold == WarningLevel.CRITICAL
    if not critical:
        # A new audience is loaded under the Customer lock both at grouping and
        # final dispatch. Public quota-preference writers take that same lock.
        if customer.pk not in audience.optional_mail:
            preference = EmailPreference.objects.filter(customer_id=customer.pk).first() or EmailPreference(
                customer=customer
            )
            audience.optional_mail[customer.pk] = preference.can_receive("quota_warnings")
        if not audience.optional_mail[customer.pk]:
            return "warning_optional_opt_out"
    if EmailSuppressionService.is_suppressed(customer.primary_email, essential=critical):
        return "warning_recipient_suppressed"
    return None


TRANSIENT_REFUSALS = frozenset(
    {"warning_usage_unavailable", "warning_native_mail_not_handed_over", "warning_scope_unknown", "warning_not_due"}
)
