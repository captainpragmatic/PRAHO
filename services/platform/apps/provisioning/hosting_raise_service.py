"""Reviewed, versioned temporary disk relief; no financial or native-row locks."""

from __future__ import annotations

import hashlib
import json
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Literal
from uuid import UUID

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.db.models import Sum
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .hosting_limit_execution_models import HostingLimitExecution
from .hosting_limit_models import HostingLimitApplication, ServiceHostingLimits
from .hosting_limit_policy import BYTES_PER_MIB, OVERLAY_QUOTA_PROTOCOL, effective_disk_limit
from .hosting_raise_models import ServiceHostingRaise
from .hosting_raise_policy import DEFAULT_RAISE_DURATION, RaiseTerms, maximum_raise_mib, validate_raise_duration
from .service_models import Service
from .virtualmin_models import VirtualminAccount

if TYPE_CHECKING:
    from apps.users.models import User

_RAISE_WRITE = ContextVar("hosting_raise_write", default=False)


def raise_write_allowed() -> bool:
    return _RAISE_WRITE.get()


def _save_raise(row: ServiceHostingRaise) -> None:
    token = _RAISE_WRITE.set(True)
    try:
        row.save()
    finally:
        _RAISE_WRITE.reset(token)


def current_raise_terms(service_id: int, owner_id: int, *, at: datetime | None = None) -> RaiseTerms:
    row = ServiceHostingRaise.objects.filter(service_id=service_id).first()
    return raise_terms_for(row, owner_id, at=at or timezone.now())


def raise_terms_for(row: ServiceHostingRaise | None, owner_id: int, *, at: datetime) -> RaiseTerms:
    """Pure batch counterpart; persistent revision and expiry survive inactive state."""
    if row is None:
        return RaiseTerms()
    active = row.status == "active" and row.owner_id == owner_id and row.expires_at > at
    return RaiseTerms(row.revision, row.extra_mib if active else 0, row.expires_at)


def application_raise_refusal(application: HostingLimitApplication, service: Service) -> str | None:
    expected = current_raise_terms(service.pk, service.customer_id)
    if (application.overlay_revision, application.overlay_extra_mib, application.overlay_expires_at) != (
        expected.revision,
        expected.extra_mib,
        expected.expires_at,
    ):
        return "A newer hosting allowance supersedes this native application."
    if application.overlay_extra_mib:
        from apps.tickets.models import Ticket  # noqa: PLC0415 -- Recheck accepted human authority before native write.
        from apps.users.models import User  # noqa: PLC0415

        authority = application.authority
        actor = User.objects.filter(pk=authority.get("staff_user_id"), is_active=True).first()
        if authority.get("kind") in {"temporary_raise_grant", "temporary_raise_extension"} and (
            actor is None
            or not (actor.is_superuser or actor.staff_role in {"admin", "manager"})
            or not Ticket.objects.filter(pk=authority.get("ticket_id"), customer_id=service.customer_id).exists()
        ):
            return "The temporary resource grant no longer has its reviewed staff and ticket authority."
    return None


def compose_assignment_raise(service: Service, assigned_mib: int | None) -> RaiseTerms:
    """Caller holds Service; preserve fixed R, clamp to the accepted new base."""
    row = ServiceHostingRaise.objects.filter(service=service).first()
    if row is None:
        return RaiseTerms()
    now = timezone.now()
    bound = maximum_raise_mib(assigned_mib)
    changed = False
    if row.owner_id != service.customer_id:
        row.owner_id, row.extra_mib, row.status = service.customer_id, 0, "revoked"
        changed = True
    elif row.status == "active" and row.expires_at <= now:
        row.status = "expired"
        changed = True
    elif row.status == "active" and row.extra_mib > bound:
        row.extra_mib = bound
        if not bound:
            row.status = "revoked"
        changed = True
    if changed:
        row.revision += 1
        _save_raise(row)
    return current_raise_terms(service.pk, service.customer_id, at=now)


def is_preauthorized_raise_expiry(application: HostingLimitApplication, service: Service) -> bool:
    from .hosting_raise_expiry import (  # noqa: PLC0415 -- Historical authority is separate from fresh native state.
        operational_expiry_authorized,
    )

    return operational_expiry_authorized(application, service)


def _application(  # noqa: PLR0913 -- Complete immutable accepted authority.
    service: Service,
    limits: ServiceHostingLimits,
    row: ServiceHostingRaise,
    *,
    reason: str,
    authority: dict[str, str],
    submission_id: UUID,
) -> HostingLimitApplication:
    terms = current_raise_terms(service.pk, service.customer_id)
    return HostingLimitApplication.objects.create(
        service=service,
        revision=limits.revision,
        submission_id=submission_id,
        expected_plan_id=limits.assigned_plan_id,
        target_plan_id=limits.assigned_plan_id,
        disk_allowance_mib=limits.disk_allowance_mib,
        bandwidth_allowance_mib=limits.bandwidth_allowance_mib,
        policy_version=limits.policy_version,
        reason=reason,
        authority={
            **authority,
            "customer_id": str(service.customer_id),
            "first_granted_at": row.first_granted_at.isoformat(),
        },
        **terms.application_fields(),
    )


def _validate_raise_safety(service: Service, limits: ServiceHostingLimits, extra_mib: int) -> None:
    from apps.billing.plan_change_safety import current_safety_snapshot  # noqa: PLC0415 -- Exact DB-only observation.
    from apps.settings.services import SettingsService  # noqa: PLC0415

    if (
        limits.operational_revision != limits.revision
        or limits.applied_revision != limits.revision
        or limits.verified_at is None
        or not limits.verified_receipt
    ):
        raise ValidationError(_("Verify the current purchased base before requesting a new temporary allowance."))
    snapshot = current_safety_snapshot(service)
    account = VirtualminAccount.objects.filter(service=service, quota_managed=True).first()
    target = effective_disk_limit(limits.disk_allowance_mib, extra_mib=extra_mib)
    if (
        snapshot is None
        or account is None
        or target is None
        or snapshot.capacity_baseline_kib is None
        or snapshot.quota_protocol != OVERLAY_QUOTA_PROTOCOL
        or snapshot.used_bytes > target * BYTES_PER_MIB
    ):
        raise ValidationError(
            _("Refresh verified native safety and protocol 2 helpers before requesting temporary resources.")
        )
    positive = max(0, target * BYTES_PER_MIB - snapshot.capacity_baseline_kib * 1024)
    reserved = (
        HostingLimitExecution.objects.filter(
            job__server_id=account.server_id, reservation_released_at__isnull=True
        ).aggregate(total=Sum("reserved_bytes"))["total"]
        or 0
    )
    reserve = SettingsService.get_integer_setting("virtualmin.disk_free_reserve_mb", 1024)
    if reserve < 0 or (positive and snapshot.available_bytes < positive + reserved + reserve * BYTES_PER_MIB):
        raise ValidationError(_("Refresh sufficient unreserved node capacity before requesting temporary resources."))


def _raise_reviewer(service: Service, actor_id: int, ticket_id: int) -> User:
    from apps.customers.models import Customer  # noqa: PLC0415 -- Current privacy, no financial locks.
    from apps.tickets.models import Ticket  # noqa: PLC0415
    from apps.users.models import User  # noqa: PLC0415

    actor = User.objects.get(pk=actor_id)
    if not actor.is_active or not (actor.is_superuser or actor.staff_role in {"admin", "manager"}):
        raise PermissionDenied(_("Administrator or manager authority is required for a temporary resource raise."))
    customer = Customer.all_objects.filter(pk=service.customer_id).first()
    if (
        customer is None
        or customer.status != "active"
        or customer.deleted_at
        or customer.anonymized_at
        or service.status != "active"
    ):
        raise ValidationError(_("Temporary resources require the active service's current customer."))
    if not Ticket.objects.filter(pk=ticket_id, customer_id=service.customer_id).exists():
        raise ValidationError(_("Select a support ticket belonging to this service's customer."))
    return actor


def grant_hosting_raise(  # noqa: PLR0913 -- Explicit staff, ticket, versions, expiry and idempotency authority.
    *,
    user: User,
    service: Service,
    extra_mib: int,
    ticket_id: int,
    reason: str,
    expected_base_revision: int,
    expected_overlay_revision: int,
    submission_id: UUID,
    expires_at: datetime | None = None,
) -> HostingLimitApplication:
    """Accept a pending fixed-R overlay under Service only; the native lane verifies it.

    Every positive application still takes fresh capacity/reservations in the
    Account→Servers→Service worker. Acceptance never advertises verified capacity.
    """
    from apps.settings.services import SettingsService  # noqa: PLC0415

    if type(extra_mib) is not int or extra_mib <= 0 or not reason.strip():
        raise ValidationError(_("Give a positive integer disk raise and an explicit reason."))
    if type(expected_base_revision) is not int or type(expected_overlay_revision) is not int:
        raise ValidationError(_("Load the current base and temporary resource versions first."))
    if expires_at is not None and (not isinstance(expires_at, datetime) or timezone.is_naive(expires_at)):
        raise ValidationError(_("Select an exact expiry with a timezone."))
    request_hash = hashlib.sha256(
        json.dumps(
            {
                "actor": user.pk,
                "owner": service.customer_id,
                "extra": extra_mib,
                "ticket": ticket_id,
                "reason": reason,
                "base": expected_base_revision,
                "overlay": expected_overlay_revision,
                "expiry": expires_at.isoformat() if expires_at is not None else None,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    with transaction.atomic():
        locked = Service.objects.select_for_update(of=("self",), no_key=True).get(pk=service.pk)
        if locked.customer_id != service.customer_id:
            raise ValidationError(_("The service's owner changed. Reload and review the current customer."))
        actor = _raise_reviewer(locked, user.pk, ticket_id)
        previous = HostingLimitApplication.objects.filter(service=locked, submission_id=submission_id).first()
        if previous is not None:
            if previous.authority.get("raise_request_hash") != request_hash:
                raise ValidationError(_("This submission was already used for different temporary resource terms."))
            return previous
        if not SettingsService.get_boolean_setting("provisioning.hosting_raises_enabled", False):
            raise ValidationError(
                _("New temporary hosting raises are disabled until rollout qualification is complete.")
            )
        limits = ServiceHostingLimits.objects.get(service=locked)
        row = ServiceHostingRaise.objects.filter(service=locked).first()
        if limits.revision != expected_base_revision or (row.revision if row else 0) != expected_overlay_revision:
            raise ValidationError(_("The base allowance or temporary resources changed. Reload before retrying."))
        if extra_mib > maximum_raise_mib(limits.disk_allowance_mib):
            raise ValidationError(_("Temporary disk resources are limited to one quarter of the allowance or 5 GiB."))
        _validate_raise_safety(locked, limits, extra_mib)
        now = timezone.now()
        expiry = expires_at or now + DEFAULT_RAISE_DURATION
        active = (
            row is not None and row.status == "active" and row.owner_id == locked.customer_id and row.expires_at > now
        )
        first = row.first_granted_at if active and row is not None else now
        try:
            validate_raise_duration(first, expiry, now)
        except ValueError as error:
            raise ValidationError(_("A temporary raise must expire within seven days of its first grant.")) from error
        if active and row is not None and (row.extra_mib != extra_mib or expiry <= row.expires_at):
            raise ValidationError(_("An active raise can only extend its expiry, with the same fixed disk amount."))
        row = row or ServiceHostingRaise(service=locked)
        row.revision = expected_overlay_revision + 1
        row.owner_id, row.extra_mib = locked.customer_id, extra_mib
        row.first_granted_at, row.expires_at, row.status = first, expiry, "active"
        _save_raise(row)
        limits.verified_at = None
        limits.save(update_fields=["verified_at", "updated_at"])
        return _application(
            locked,
            limits,
            row,
            reason=reason,
            submission_id=submission_id,
            authority={
                "kind": "temporary_raise_extension" if active else "temporary_raise_grant",
                "staff_user_id": str(actor.pk),
                "ticket_id": str(ticket_id),
                "raise_request_hash": request_hash,
                "preauthorized_expiry": "acknowledged",
            },
        )


def expire_hosting_raise(service_id: int) -> HostingLimitApplication | None:
    with transaction.atomic():
        service = Service.objects.select_for_update(of=("self",), no_key=True).get(pk=service_id)
        row = ServiceHostingRaise.objects.filter(
            service=service, status__in=("active", "revoked"), expires_at__lte=timezone.now()
        ).first()
        if row is None:
            return None
        revoked = row.status == "revoked"
        row.revision += 1
        row.status = "expired"
        _save_raise(row)
        limits = ServiceHostingLimits.objects.get(service=service)
        limits.verified_at = None
        limits.save(update_fields=["verified_at", "updated_at"])
        from .hosting_raise_expiry import (  # noqa: PLC0415 -- Pin historical operational base.
            create_expiry_cleanup,
            has_expiry_consent,
        )

        if revoked and not has_expiry_consent(service, row):
            # A deadline is a fact; another owner does not inherit the original
            # customer's native mutation authority. Retain unverified state.
            return None
        return create_expiry_cleanup(service, limits, row)


def expire_hosting_raises() -> int:
    due = list(
        ServiceHostingRaise.objects.filter(status__in=("active", "revoked"), expires_at__lte=timezone.now())
        .order_by("expires_at")
        .values_list("service_id", flat=True)[:100]
    )
    return sum(expire_hosting_raise(service_id) is not None for service_id in due)


@dataclass(frozen=True)
class RaisePublicState:
    state: Literal["requested", "verified", "expired_attention", "expired"]
    extra_mib: int
    expires_at: datetime
    revision: int


def raise_public_state(service_id: int, at: datetime | None = None) -> RaisePublicState | None:
    service = Service.objects.select_related("hosting_limits").filter(pk=service_id).first()
    if service is None:
        return None
    from .hosting_limit_selectors import prime_current_verification  # noqa: PLC0415 -- Shared exact receipt proof.

    account = VirtualminAccount.objects.select_related("server__hosting_policy").filter(service=service).first()
    prime_current_verification([service], {service.pk: account} if account else {}, at=at)
    prime_hosting_raises([service], at=at)
    return service_raise_public_state(service, at=at)


def raise_public_state_for(
    service: Service, row: ServiceHostingRaise | None, *, at: datetime | None = None
) -> RaisePublicState | None:
    """Pure presentation for loaded rows; only exact primed proof may claim capacity."""
    if row is None or row.service_id != service.pk or row.owner_id != service.customer_id:
        return None
    now = at or timezone.now()
    terms = raise_terms_for(row, service.customer_id, at=now)
    limits = service._state.fields_cache.get("hosting_limits")
    current = bool(
        service.__dict__.get("_hosting_operational_verified")
        and service.__dict__.get("_hosting_current_overlay_terms") == terms
        and limits is not None
        and limits.applied_overlay_revision == row.revision
    )
    active = row.status == "active" and row.expires_at > now
    state: Literal["requested", "verified", "expired_attention", "expired"] = (
        "verified" if active and current else "requested" if active else "expired" if current else "expired_attention"
    )
    return RaisePublicState(state, row.extra_mib, row.expires_at, row.revision)


def prime_hosting_raises(services: list[Service], *, at: datetime | None = None) -> None:
    """At most one overlay query; reuse rows loaded by current-verification batches."""
    missing = [service for service in services if "_hosting_raise_row" not in service.__dict__]
    rows = (
        {
            row.service_id: row
            for row in ServiceHostingRaise.objects.filter(service_id__in=[service.pk for service in missing])
        }
        if missing
        else {}
    )
    for service in missing:
        service.__dict__["_hosting_raise_row"] = rows.get(service.pk)
    for service in services:
        service.__dict__["_hosting_raise_public_state"] = raise_public_state_for(
            service, service.__dict__["_hosting_raise_row"], at=at
        )


def service_raise_public_state(service: Service, *, at: datetime | None = None) -> RaisePublicState | None:
    """Batch consumers prime first; unprimed detail consumers get one bounded read."""
    if "_hosting_raise_row" not in service.__dict__:
        prime_hosting_raises([service], at=at)
    return raise_public_state_for(service, service.__dict__["_hosting_raise_row"], at=at)
