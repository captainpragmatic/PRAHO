"""Database-only current binding for base-only safety snapshots (PR2 contract)."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from django.core.exceptions import ValidationError

from apps.infrastructure.node_maintenance_gate import maintenance_refusal

from .hosting_limit_models import ServiceHostingLimits
from .hosting_node_policy import current_quota_identity, managed_quota_refusal
from .hosting_node_policy_models import NodeHostingPolicy
from .service_models import Service
from .virtualmin_models import VirtualminAccount, VirtualminServer
from .virtualmin_security import connection_identity

SAFETY_SCHEMA = 1
SAFETY_TTL = timedelta(minutes=5)
SAFETY_PROBE_MAX_AGE = timedelta(seconds=60)
SAFETY_BUDGET = timedelta(minutes=4)


def current_safety_scope(service_id: int) -> dict[str, Any] | None:
    """PR3 must replace the explicit zero-overlay identity before enabling raises.

    Overlay revision must then remain monotonic across expiry; old zero-overlay
    jobs and results cannot be interpreted as current after that revision changes.
    """
    try:
        return _current_safety_scope(service_id)
    except (VirtualminAccount.DoesNotExist, VirtualminServer.DoesNotExist, ValidationError):
        return None


def _current_safety_scope(service_id: int) -> dict[str, Any] | None:  # noqa: PLR0911 -- Read-only privacy/lifecycle/node/assignment refusals remain explicit.
    from apps.customers.models import Customer  # noqa: PLC0415 -- Read only; no Customer/financial locks.

    from .hosting_limit_execution import _account_busy  # noqa: PLC0415 -- Same lifecycle exclusions, read only.

    service = Service.objects.filter(pk=service_id).first()
    if service is None or service.status not in {"active", "suspended"}:
        return None
    customer = Customer.all_objects.filter(pk=service.customer_id).first()
    if customer is None or customer.deleted_at or customer.anonymized_at or customer.status != "active":
        return None
    account = VirtualminAccount.objects.filter(service_id=service.pk).first()
    if account is None or account.status not in {"active", "suspended"} or account.restore_hold:
        return None
    server = VirtualminServer.objects.get(pk=account.server_id)
    if (
        server.status != "active"
        or server.is_draining
        or managed_quota_refusal(server) is not None
        or maintenance_refusal(server.pk) is not None
        or _account_busy(account)
    ):
        return None
    limits = ServiceHostingLimits.objects.filter(service_id=service.pk).first()
    policy = NodeHostingPolicy.objects.filter(server=server).first()
    if limits is None or policy is None:
        return None
    try:
        native_identity = current_quota_identity(server)
    except (ValidationError, VirtualminServer.DoesNotExist):
        return None
    return {
        "schema": SAFETY_SCHEMA,
        "service_id": service.pk,
        "customer_id": service.customer_id,
        "account_id": str(account.pk),
        "server_id": str(server.pk),
        "connection_identity": connection_identity(server),
        "node_policy_revision": policy.revision,
        "native_identity": native_identity,
        "domain": account.domain,
        "username": account.virtualmin_username,
        "quota_generation": account.quota_generation,
        "chain_epoch": account.chain_epoch,
        "base_revision": limits.revision,
        "assigned_plan_id": limits.assigned_plan_id,
        "service_plan_id": service.service_plan_id,
        "operational_revision": limits.operational_revision,
        "overlay_revision": 0,
        "overlay_expires_at": None,
    }
