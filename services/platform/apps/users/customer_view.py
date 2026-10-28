"""Customer view: a staff member's scoped, read-only portal session as one customer member (ADR-0065).

A grant is 32 random bytes, stored only as a SHA-256 digest, valid for 60 seconds and consumed once.
Consuming it opens a ``PortalSession`` of the ``customer_view`` tier for the target member, limited
to 30 minutes and 10 idle minutes. Every request made in it re-reads the authority that allowed it
(``nonlive_reason``), without locks, so a revoked staff role, a changed credential, a deactivated
membership or the end of the staff console session ends the view at its next request.

Only ``issue`` and ``consume`` lock rows, and only for their own short transactions: users in
primary-key order, then the customer, then the membership, then the grant.
"""

from __future__ import annotations

import hashlib
import logging
import re
import secrets
from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.contrib.auth import SESSION_KEY
from django.contrib.sessions.models import Session
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.db.models import Q
from django.urls import reverse
from django.utils import timezone
from django.utils.crypto import constant_time_compare
from django.utils.translation import gettext as _

from apps.audit.session_digest import session_key_digest

from .models import CustomerMembership, CustomerViewGrant, PortalSession, User

if TYPE_CHECKING:
    from datetime import datetime

    from django.http import HttpRequest

    from apps.customers.models import Customer

logger = logging.getLogger(__name__)

STAFF_ROLES = frozenset({"admin", "support"})
CUSTOMER_STATUSES = frozenset({"active"})  # PRAHO customers start as "prospect"; see ADR-0065
REASON_CATEGORIES = frozenset(value for value, _label in CustomerViewGrant.REASON_CHOICES)
MIN_REASON, MAX_REASON, MAX_TICKET_REFERENCE = 10, 500, 100
HOURLY_LIMIT = 20
GRANT_TTL = timedelta(seconds=60)
ABSOLUTE_TIMEOUT = timedelta(minutes=30)
IDLE_TIMEOUT = timedelta(minutes=10)
CODE_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")
# Set on the staff console session when its login completed the second factor.
MFA_LOGIN_MARKER = "mfa_verified_at"


class CustomerViewBlocked(PermissionDenied):
    """A refusal staff can act on: what is missing, and where to fix it."""

    def __init__(self, code: str, message: str, remedy_url: str = "") -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.remedy_url = remedy_url


@dataclass(frozen=True)
class IssuedGrant:
    grant_id: Any
    code: str = field(repr=False)


def enabled() -> bool:
    return bool(getattr(settings, "CUSTOMER_VIEW_ENABLED", False))


def _digest(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def _staff_session_live(staff: User, session_key: str, now: datetime) -> bool:
    """The staff console session that issued the view is still open, for this staff member, after MFA."""
    session = Session.objects.filter(session_key=session_key, expire_date__gt=now).first()
    if session is None:
        return False
    data = session.get_decoded()
    return str(data.get(SESSION_KEY)) == str(staff.pk) and bool(data.get(MFA_LOGIN_MARKER))


def staff_blockers(
    staff: User, session_key: str, now: datetime | None = None, *, issuing: bool = True
) -> list[CustomerViewBlocked]:
    """Why this staff member cannot open a customer view now; empty when they can.

    The hourly quota counts grants being issued; redeeming one or using an open view never does.
    """
    now = now or timezone.now()
    blockers: list[CustomerViewBlocked] = []
    if not enabled():
        blockers.append(CustomerViewBlocked("disabled", _("Customer view is turned off for this deployment.")))
    if not staff.is_active or staff.staff_role not in STAFF_ROLES:
        blockers.append(CustomerViewBlocked("staff_role", _("Only administrators and support staff can do this.")))
    if not staff.two_factor_enabled:
        blockers.append(
            CustomerViewBlocked(
                "staff_mfa", _("Set up two-factor authentication first."), reverse("users:mfa_method_selection")
            )
        )
    elif not _staff_session_live(staff, session_key, now):
        blockers.append(
            CustomerViewBlocked(
                "staff_login_mfa",
                _("Sign out and sign in again with your second factor: this session did not use it."),
                reverse("users:logout"),
            )
        )
    recent = (
        CustomerViewGrant.objects.filter(staff=staff, created_at__gt=now - timedelta(hours=1)).count() if issuing else 0
    )
    if recent >= HOURLY_LIMIT:
        blockers.append(
            CustomerViewBlocked("rate_limited", _("You opened 20 customer views in the last hour. Try again later."))
        )
    return blockers


def target_refusal(target: User, customer: Customer) -> str:
    """Why this member's portal cannot be opened, or an empty string."""
    if customer.status not in CUSTOMER_STATUSES or getattr(customer, "deleted_at", None) is not None:
        return _("Only an active customer's portal can be opened.")
    if not target.is_active or target.is_staff_user:
        return _("Only an active customer member who is not staff can be viewed.")
    if not CustomerMembership.objects.filter(user=target, customer=customer, is_active=True).exists():
        return _("This person is not an active member of this customer.")
    return ""


def _lock_authority(staff_id: int, target_id: int, customer_id: int) -> tuple[User, User, Customer]:
    """Lock users in primary-key order, then the customer and the membership (one order everywhere)."""
    from apps.customers.models import Customer  # noqa: PLC0415  # ADR-0007: cross-app, deferred

    users = {
        user.pk: user
        for user in User.objects.select_for_update(no_key=True, of=("self",))
        .select_related("credential_version")
        .filter(pk__in={staff_id, target_id})
        .order_by("pk")
    }
    customer = Customer.objects.select_for_update(no_key=True).get(pk=customer_id)
    list(
        CustomerMembership.objects.select_for_update(no_key=True)
        .filter(user_id=target_id, customer_id=customer_id)
        .order_by("pk")
    )
    return users[staff_id], users[target_id], customer


def _audit(event_type: str, *, staff: User | None, target: User | None, metadata: dict[str, Any]) -> None:
    from apps.audit.services import AuditService  # noqa: PLC0415  # ADR-0007: cross-app, deferred

    AuditService.log_simple_event(
        event_type,
        user=staff,
        actor_type="user" if staff is not None else "system",
        content_object=target,
        metadata=metadata,
    )


def _grant_metadata(grant: CustomerViewGrant) -> dict[str, Any]:
    return {
        "customer_id": str(grant.customer_id),
        "grant_id": str(grant.pk),
        "reason_category": grant.reason_category,
        "reason": grant.reason,
        "ticket_reference": grant.ticket_reference,
    }


def issue(  # noqa: PLR0913  # the staff form's fields
    request: HttpRequest,
    *,
    target_id: int,
    customer_id: int,
    reason: str,
    reason_category: str,
    ticket_reference: str = "",
) -> IssuedGrant:
    """Issue a grant, or raise CustomerViewBlocked. Every refusal is audited after the rollback."""
    from apps.customers.models import Customer  # noqa: PLC0415  # ADR-0007: cross-app, deferred

    staff = request.user
    if not isinstance(staff, User) or staff.pk is None:
        raise CustomerViewBlocked("staff_role", _("Only administrators and support staff can do this."))
    session_key = str(request.session.session_key or "")
    reason = reason.strip() if isinstance(reason, str) else ""
    try:
        if not MIN_REASON <= len(reason) <= MAX_REASON or reason_category not in REASON_CATEGORIES:
            raise CustomerViewBlocked(
                "reason", _("Choose a reason category and describe the reason in 10 to 500 characters.")
            )
        if len(ticket_reference) > MAX_TICKET_REFERENCE:
            raise CustomerViewBlocked("reason", _("Keep the ticket reference within 100 characters."))
        with transaction.atomic():
            staff, target, customer = _lock_authority(staff.pk, target_id, customer_id)
            if blockers := staff_blockers(staff, session_key):
                raise blockers[0]
            if staff.pk == target.pk or (refusal := target_refusal(target, customer)):
                raise CustomerViewBlocked("target", refusal or _("You cannot view your own account."))
            code = secrets.token_urlsafe(32)
            grant = CustomerViewGrant.objects.create(
                code_digest=_digest(code),
                staff=staff,
                target=target,
                customer=customer,
                staff_session_key=session_key,
                staff_credential_snapshot=staff.get_session_auth_hash(),
                target_credential_snapshot=target.get_session_auth_hash(),
                reason_category=reason_category,
                reason=reason,
                ticket_reference=ticket_reference,
                expires_at=timezone.now() + GRANT_TTL,
            )
            _audit("customer_view_issued", staff=staff, target=target, metadata=_grant_metadata(grant))
            return IssuedGrant(grant.pk, code)
    except (CustomerViewBlocked, User.DoesNotExist, Customer.DoesNotExist, KeyError) as exc:
        blocked = (
            exc
            if isinstance(exc, CustomerViewBlocked)
            else CustomerViewBlocked("target", _("Choose an active member of this customer."))
        )
        with transaction.atomic():
            _audit(
                "customer_view_issue_denied",
                staff=request.user if isinstance(request.user, User) else None,
                target=User.objects.filter(pk=target_id).first(),
                metadata={"customer_id": str(customer_id), "refusal": blocked.code, "reason_category": reason_category},
            )
        raise blocked from exc


def consume(code: object) -> PortalSession:
    """Redeem a code once and open the customer view; PermissionDenied for anything else."""
    if not enabled() or not isinstance(code, str) or CODE_PATTERN.fullmatch(code) is None:
        raise PermissionDenied("customer_view_forbidden")
    candidate = CustomerViewGrant.objects.filter(code_digest=_digest(code)).first()
    if candidate is None:
        raise PermissionDenied("customer_view_forbidden")
    with transaction.atomic():
        staff, target, customer = _lock_authority(candidate.staff_id, candidate.target_id, candidate.customer_id)
        grant = CustomerViewGrant.objects.select_for_update().get(pk=candidate.pk)
        now = timezone.now()
        if (
            staff_blockers(staff, grant.staff_session_key, now, issuing=False)
            or target_refusal(target, customer)
            or not constant_time_compare(grant.staff_credential_snapshot, staff.get_session_auth_hash())
            or not constant_time_compare(grant.target_credential_snapshot, target.get_session_auth_hash())
        ):
            raise PermissionDenied("customer_view_forbidden")
        claimed = CustomerViewGrant.objects.filter(
            pk=grant.pk, consumed_at__isnull=True, voided_at__isnull=True, expires_at__gt=now
        ).update(consumed_at=now)
        if not claimed:
            raise PermissionDenied("customer_view_forbidden")
        row = PortalSession.objects.create(
            user=target,
            tier=PortalSession.TIER_CUSTOMER_VIEW,
            credential_snapshot=target.get_session_auth_hash(),
            staff_credential_snapshot=staff.get_session_auth_hash(),
            viewed_as_customer_by=staff,
            customer_view_customer=customer,
            customer_view_grant=grant,
            last_seen_at=now,
            idle_deadline=now + IDLE_TIMEOUT,
            expires_at=now + ABSOLUTE_TIMEOUT,
        )
        _audit(
            "customer_view_started",
            staff=staff,
            target=target,
            metadata={**_grant_metadata(grant), "portal_session": session_key_digest(str(row.pk))},
        )
    return row


def audit_refused_redemption(code: object) -> None:
    """Record a refused redemption after its transaction rolled back. Never raises."""
    if not isinstance(code, str) or CODE_PATTERN.fullmatch(code) is None:
        return
    try:
        with transaction.atomic():
            grant = (
                CustomerViewGrant.objects.select_related("staff", "target").filter(code_digest=_digest(code)).first()
            )
            if grant is None:
                return
            if grant.consumed_at is not None:
                why = "reused"
            elif grant.voided_at is not None:
                why = "voided"
            elif grant.expires_at <= timezone.now():
                why = "expired"
            else:
                why = "authority"
            _audit(
                "customer_view_denied",
                staff=grant.staff,
                target=grant.target,
                metadata={**_grant_metadata(grant), "operation": "redeem", "refusal": why},
            )
    except Exception:
        logger.exception("🔥 [CustomerView] Refused redemption not audited")


def nonlive_reason(row: PortalSession, now: datetime | None = None) -> str:
    """Why a customer view may no longer be used, or an empty string. Reads only; takes no locks."""
    now = now or timezone.now()
    staff = row.viewed_as_customer_by
    grant = row.customer_view_grant
    customer = row.customer_view_customer
    if not enabled():
        return "disabled"
    if staff is None or grant is None or customer is None:
        return "authority_changed"
    if staff_blockers(staff, grant.staff_session_key, now, issuing=False):
        return "authority_changed"
    if not constant_time_compare(row.staff_credential_snapshot, staff.get_session_auth_hash()):
        return "credentials_changed"
    if target_refusal(row.user, customer):
        return "authority_changed"
    return ""


def end_customer_view(row: PortalSession, reason: str, *, only_if_expired: bool = False) -> bool:
    """End one customer view once, with its audit event in the same transaction.

    only_if_expired re-checks the deadlines in the update itself, so a request that renewed the
    view after the caller read it keeps it.
    """
    with transaction.atomic():
        now = timezone.now()
        rows = PortalSession.objects.filter(pk=row.pk, tier=PortalSession.TIER_CUSTOMER_VIEW, revoked_at__isnull=True)
        if only_if_expired:
            rows = rows.filter(Q(expires_at__lte=now) | Q(idle_deadline__lte=now))
        changed = rows.update(revoked_at=now, revoke_reason=reason)
        if changed:
            row.revoked_at, row.revoke_reason = now, reason
            _audit(
                "customer_view_ended",
                staff=row.viewed_as_customer_by,
                target=row.user,
                metadata={
                    "customer_id": str(row.customer_view_customer_id),
                    "grant_id": str(row.customer_view_grant_id),
                    "portal_session": session_key_digest(str(row.pk)),
                    "end_reason": reason,
                },
            )
    return bool(changed)


def sweep(now: datetime | None = None) -> int:
    """End customer views that can no longer be used and void stale grants; one failure never undoes the rest."""
    now = now or timezone.now()
    ended = 0
    live = PortalSession.objects.filter(tier=PortalSession.TIER_CUSTOMER_VIEW, revoked_at__isnull=True)
    for row in live.select_related("user", "viewed_as_customer_by", "customer_view_grant", "customer_view_customer"):
        try:
            with transaction.atomic():
                expired = row.expires_at <= now or row.idle_deadline <= now
                why = "expired" if expired else nonlive_reason(row, now)
                if why and end_customer_view(row, why, only_if_expired=expired):
                    ended += 1
        except Exception:
            logger.exception("🔥 [CustomerView] Sweep could not end a customer view")
    CustomerViewGrant.objects.filter(consumed_at__isnull=True, voided_at__isnull=True, expires_at__lte=now).update(
        voided_at=now
    )
    return ended
