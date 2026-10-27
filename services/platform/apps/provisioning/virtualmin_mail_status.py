"""Database-only public PRAHO mail intent and recorded-verification projection.

External mode describes PRAHO enrollment, never observed MX or native mail state.
Current verification describes the bounded stored receipt, not service availability.
No read repairs, enrollment creation, native observation or DNS work occur here.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, TypedDict

from apps.common.types import Err, Ok, Result, validate_domain_name

from .account_hostname_models import AccountHostname
from .service_models import Service
from .virtualmin_mail_models import VirtualminMailConfiguration, VirtualminMailOperation
from .virtualmin_models import VirtualminAccount

if TYPE_CHECKING:
    from apps.users.models import User

_CHECKPOINTS = {"": "not_started", "claimed": "claimed", "preflight": "preflight", "native_inflight": "native_inflight"}
_ERRORS = frozenset(
    {
        "mail_native_outcome_unknown",
        "mail_execution_interrupted",
        "mail_native_preparation_failed",
        "mail_execution_ownership_expired",
        "mail_execution_state_uncertain",
        "mail_execution_forbidden",
        "mail_generation_changed",
        "mail_account_unavailable",
        "mail_hosting_held",
        "mail_operation_active",
        "mail_mode_conflict",
        "mail_execution_invalid_consent",
        "mail_prerequisites_expired",
    }
)


class PublicMailOperation(TypedDict):
    intent: str
    status: str
    checkpoint: str
    error_code: str
    created_at: str | None
    updated_at: str | None
    resume_after: str | None


class PublicMailStatus(TypedDict):
    version: int
    applicability: str
    mode: str
    enrolled: bool | None
    verification: str
    verified_at: str | None
    account_name: str | None
    client_ports: dict[str, int]
    verified_login: str | None
    requires_owner_consent: bool
    operation: PublicMailOperation | None


def _authorized(customer_id: int, actor: User | None) -> bool:
    from apps.users.models import CustomerMembership  # noqa: PLC0415  # ADR-0007: fresh authorization at the read seam.

    return bool(
        actor is not None
        and actor.pk is not None
        and CustomerMembership.objects.filter(
            customer_id=customer_id,
            customer__status="active",
            customer__deleted_at__isnull=True,
            user_id=actor.pk,
            user__is_active=True,
            is_active=True,
        ).exists()
    )


def _date(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _account_name(account: VirtualminAccount | None) -> str | None:
    if account is None:
        return None
    name = AccountHostname.objects.filter(
        account_id=account.pk, target_server_id=account.server_id, retired_at__isnull=True
    ).first()
    if name is None:
        return None
    valid = validate_domain_name(name.fqdn)
    return str(valid.unwrap()) if valid.is_ok() else None


def _operation(configuration: VirtualminMailConfiguration | None, customer_id: int) -> PublicMailOperation | None:
    if configuration is None:
        return None
    operation = (
        VirtualminMailOperation.objects.filter(configuration_id=configuration.pk, requested_customer_id=customer_id)
        .only("intent", "status", "checkpoint", "error_code", "created_at", "updated_at", "resume_after")
        .order_by("-created_at", "-pk")
        .first()
    )
    if operation is None:
        return None
    return {
        "intent": operation.intent if operation.intent in {"enable", "disable"} else "unknown",
        "status": operation.status if operation.status in VirtualminMailOperation.Status.values else "unknown",
        "checkpoint": _CHECKPOINTS.get(operation.checkpoint, "unknown"),
        "error_code": operation.error_code
        if operation.error_code == "" or operation.error_code in _ERRORS
        else "mail_operation_unrecognized",
        "created_at": _date(operation.created_at),
        "updated_at": _date(operation.updated_at),
        "resume_after": _date(operation.resume_after),
    }


def _status(account: VirtualminAccount | None, customer_id: int) -> PublicMailStatus:
    configuration = VirtualminMailConfiguration.objects.filter(account_id=account.pk).first() if account else None
    mode = configuration.mode if configuration is not None else "external"
    if mode not in {"external", "hosted"}:
        mode = "unknown"
    verification = "unverified"
    if configuration is not None and mode == "hosted":
        verification = "current" if configuration.has_current_readiness() else "stale"
    return {
        "version": 1,
        "applicability": "applicable" if account is not None else "not_applicable",
        "mode": mode,
        "enrolled": mode == "hosted" if mode != "unknown" else None,
        "verification": verification,
        "verified_at": _date(configuration.verified_at) if configuration is not None else None,
        "account_name": _account_name(account),
        "client_ports": {"imap_tls": 993, "pop3_tls": 995, "submission_tls": 465} if account is not None else {},
        # The configuration's Unix owner is not an observed native mail login.
        "verified_login": None,
        "requires_owner_consent": True,
        "operation": _operation(configuration, customer_id),
    }


def cached_mail_status(service_id: int, *, customer_id: int, actor: User | None) -> Result[PublicMailStatus, str]:
    """Any active hosting-view member can read their current tenant's immutable public projection."""
    if not _authorized(customer_id, actor):
        return Err("mail_status_forbidden")
    if not Service.objects.filter(pk=service_id, customer_id=customer_id).exists():
        return Err("mail_status_not_found")
    account = VirtualminAccount.objects.filter(service_id=service_id).first()
    status = _status(account, customer_id)
    # A transfer, account relink or revocation during the read invalidates the loaded snapshot.
    if not Service.objects.filter(pk=service_id, customer_id=customer_id).exists() or (
        account is not None and not VirtualminAccount.objects.filter(pk=account.pk, service_id=service_id).exists()
    ):
        return Err("mail_status_not_found")
    return Ok(status) if _authorized(customer_id, actor) else Err("mail_status_forbidden")
