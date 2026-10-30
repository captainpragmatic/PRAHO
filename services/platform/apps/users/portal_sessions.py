"""Customer portal sessions, owned and enforced by Platform (ADR-0017 section 5).

Login opens a row. The portal sends the row's id in the signed body of every request it makes for
that customer, and ``PortalServiceHMACMiddleware`` resolves it before any view runs. A row is live
while it is not revoked, both deadlines are in the future, the user is active, and its credential
snapshot still matches the user's session hash. Every password or second-factor change moves that
hash, so it ends every other session of the user at their next request. The few portal endpoints
where customers change their own credentials re-stamp only the calling session (``restamp``).

Each tier's lifetimes come from ``session_policy``; a row whose tier the policy does not know ends.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from django.conf import settings
from django.db import transaction
from django.db.models import Q
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils import timezone
from django.utils.crypto import constant_time_compare

from apps.audit.session_digest import session_key_digest

from . import session_policy
from .models import PortalSession, User

logger = logging.getLogger(__name__)

# Interactive activity extends the idle deadline at most this often, so a busy page costs one
# write a minute, not one per request.
TOUCH_INTERVAL = timedelta(seconds=60)
SWEEP_RETENTION = timedelta(days=1)
# A sensitive action needs a password (and second factor) check this recent; login counts as one.
STEP_UP_WINDOW = timedelta(seconds=300)
SWEEP_BATCH = 500

REASON_LOGOUT = "logout"
REASON_CREDENTIALS = "credentials_changed"
REASON_OPERATOR = "operator"
REASON_POLICY = "policy"  # the tier is unknown, or no longer allowed for this person


@dataclass(frozen=True)
class SessionDeadlines:
    session_id: str
    tier: str
    idle_deadline: datetime
    expires_at: datetime

    def as_payload(self) -> dict[str, str]:
        return {
            "session_id": self.session_id,
            "session_tier": self.tier,
            "session_idle_deadline": self.idle_deadline.isoformat(),
            "session_expires_at": self.expires_at.isoformat(),
        }


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16] if value else ""


def _audit(event_type: str, row: PortalSession, *, description: str, reason: str = "") -> None:
    from apps.audit.services import AuditService  # noqa: PLC0415  # ADR-0007: cross-app, deferred

    metadata = {"portal_session": session_key_digest(str(row.pk)), "tier": row.tier}
    if reason:
        metadata["reason"] = reason
    AuditService.log_simple_event(
        event_type,
        user=row.user,
        content_object=row.user,
        description=description,
        metadata=metadata,
    )


def deadlines(row: PortalSession) -> SessionDeadlines:
    return SessionDeadlines(str(row.pk), row.tier, row.idle_deadline, row.expires_at)


def open_session(user: User, *, remember_me: bool = False, ip: str = "", user_agent: str = "") -> PortalSession:
    """Open a session for a login that has just passed every check, in the tier it may have, and audit it."""
    now = timezone.now()
    tier = session_policy.tier_for(user, remember_me=remember_me)
    life = session_policy.TIERS[tier]
    with transaction.atomic():
        row = PortalSession.objects.create(
            user=user,
            tier=tier,
            credential_snapshot=user.get_session_auth_hash(),
            last_seen_at=now,
            idle_deadline=now + life.idle,
            expires_at=now + life.absolute,
            reauth_at=now,
            ip_digest=_digest(ip),
            ua_digest=_digest(user_agent),
            ua_label=user_agent[:80],
        )
        _audit("login_success", row, description="Portal session opened")
    return row


def _parse_id(raw: object) -> uuid.UUID | None:
    if not isinstance(raw, str) or len(raw) != 36:  # noqa: PLR2004  # canonical UUID text only
        return None
    try:
        parsed = uuid.UUID(raw)
    except ValueError:
        return None
    return parsed if str(parsed) == raw else None


def _live(now: datetime) -> Q:
    return Q(revoked_at__isnull=True, expires_at__gt=now, idle_deadline__gt=now)


def _snapshot_matches(row: PortalSession, user: User) -> bool | None:
    """True for the current hash, None for a ``SECRET_KEY_FALLBACKS`` hash, False otherwise."""
    if constant_time_compare(row.credential_snapshot, user.get_session_auth_hash()):
        return True
    if any(constant_time_compare(row.credential_snapshot, h) for h in user.get_session_auth_fallback_hash()):
        return None
    return False


def resolve(raw_session_id: object, user_id: int, *, interactive: bool) -> PortalSession | None:
    """The live session a signed request names, or None. Never raises for a bad id.

    A row whose snapshot no longer matches is ended here, so the refusal is recorded once and the
    row cannot come back if the hash ever matched again.
    """
    session_id = _parse_id(raw_session_id)
    if session_id is None:
        return None
    now = timezone.now()
    row = (
        PortalSession.objects.select_related(
            "user",
            "user__credential_version",
            "viewed_as_customer_by",
            "viewed_as_customer_by__credential_version",
            "customer_view_grant",
            "customer_view_customer",
        )
        .filter(_live(now), pk=session_id, user_id=user_id, user__is_active=True)
        .first()
    )
    if row is None:
        return None
    match = _snapshot_matches(row, row.user)
    if match is False:
        end(row, REASON_CREDENTIALS)
        return None
    life = session_policy.lifetimes(row.tier)
    if life is None or (row.tier == PortalSession.TIER_REMEMBER and row.user.is_staff_user):
        # Ended, never raised: a 500 here is an outage the portal would fail open on.
        end(row, REASON_POLICY)
        return None
    scoped = row.tier == PortalSession.TIER_CUSTOMER_VIEW
    if scoped:
        from .customer_view import nonlive_reason  # noqa: PLC0415  # customer_view imports this module

        if why := nonlive_reason(row, now):
            end(row, why)
            return None
    if match is None and not scoped:
        # Signed under a retired key: promote, unless the row changed meanwhile.
        current = row.user.get_session_auth_hash()
        PortalSession.objects.filter(_live(now), pk=row.pk, credential_snapshot=row.credential_snapshot).update(
            credential_snapshot=current
        )
        row.credential_snapshot = current
    if interactive and now - row.last_seen_at >= TOUCH_INTERVAL:
        idle = min(now + life.idle, row.expires_at)
        # In SQL, so it holds against concurrent touches: at most one a minute, never backwards.
        touched = PortalSession.objects.filter(_live(now), pk=row.pk, last_seen_at__lte=now - TOUCH_INTERVAL).update(
            last_seen_at=now, idle_deadline=idle
        )
        if touched:
            row.last_seen_at, row.idle_deadline = now, idle
    return row


def end(row: PortalSession, reason: str) -> bool:
    """End one session once; the first caller records the reason and the audit event."""
    if row.tier == PortalSession.TIER_CUSTOMER_VIEW:
        from .customer_view import end_customer_view  # noqa: PLC0415  # import cycle

        return end_customer_view(row, reason)
    now = timezone.now()
    with transaction.atomic():
        changed = PortalSession.objects.filter(pk=row.pk, revoked_at__isnull=True).update(
            revoked_at=now, revoke_reason=reason
        )
        if changed:
            row.revoked_at, row.revoke_reason = now, reason
            _audit(
                "logout_manual" if reason == REASON_LOGOUT else "session_terminated",
                row,
                description="Portal session ended",
                reason=reason,
            )
    return bool(changed)


def restamp(row: PortalSession | None, *, old_hash: str, new_hash: str) -> bool:
    """Keep the calling session across its own credential change.

    Call inside the transaction that holds the user row lock and writes the credential. The update
    applies only to a live row still bound to the pre-change hash, so it never revives an ended
    row and never carries a session across a change someone else made.
    """
    if row is None or old_hash == new_hash:
        return False
    return bool(
        PortalSession.objects.filter(_live(timezone.now()), pk=row.pk, credential_snapshot=old_hash).update(
            credential_snapshot=new_hash
        )
    )


def recently_reauthenticated(row: PortalSession, now: datetime) -> bool:
    """True when the session's last identity check is at most STEP_UP_WINDOW old, and not in the future."""
    if row.reauth_at is None:
        return False
    return timedelta(0) <= now - row.reauth_at <= STEP_UP_WINDOW


def still_live(row: PortalSession, user: User) -> bool:
    """Whether a session read under its row lock is live for this user's current credentials."""
    now = timezone.now()
    return (
        row.user_id == user.pk
        and user.is_active
        and row.revoked_at is None
        and row.expires_at > now
        and row.idle_deadline > now
        and _snapshot_matches(row, user) is not False
    )


def record_step_up(row: PortalSession, *, confirmed: bool) -> None:
    """Audit an identity check made in this session, which the audit names by its digest only."""
    if confirmed:
        _audit("step_up_confirmed", row, description="Identity confirmed for sensitive actions")
    else:
        _audit("step_up_failed", row, description="Identity check for sensitive actions failed")


def mark_reauth(row: PortalSession) -> datetime | None:
    """Record a passed identity check on a live session, and return its new window; an ended one is never marked."""
    now = timezone.now()
    marked = PortalSession.objects.filter(_live(now), pk=row.pk).update(reauth_at=now)
    if not marked:
        return None
    row.reauth_at = now
    return now


def step_up_stamp(row: PortalSession) -> str:
    """The window a login or identity check opened, as the portal must echo it to act in it."""
    return row.reauth_at.isoformat() if row.reauth_at is not None else ""


def window_open(row: PortalSession, echoed: object, now: datetime) -> bool:
    """Whether a request may act in the session's 300 s window (ADR-0017 section 7).

    Read from the row as it is now, not as the request bound it: a check made meanwhile replaces the
    window. The request must echo exactly that window, which only the browser that opened it holds,
    so a request that loaded the session before the person confirmed cannot act in what they opened.
    """
    current = PortalSession.objects.filter(_live(now), pk=row.pk).values_list("reauth_at", flat=True).first()
    if current is None or not isinstance(echoed, str):
        return False
    try:
        echoed_at = datetime.fromisoformat(echoed)
    except ValueError:
        return False
    return echoed_at == current and timedelta(0) <= now - current <= STEP_UP_WINDOW


def sweep_expired(*, now: datetime | None = None) -> int:
    """Delete rows a day past their end, in batches. Liveness never depends on this running."""
    cutoff = (now or timezone.now()) - SWEEP_RETENTION
    stale = Q(revoked_at__lt=cutoff) | Q(expires_at__lt=cutoff) | Q(idle_deadline__lt=cutoff)
    deleted = 0
    while True:
        ids = list(PortalSession.objects.filter(stale).values_list("pk", flat=True)[:SWEEP_BATCH])
        if not ids:
            return deleted
        deleted += PortalSession.objects.filter(pk__in=ids).delete()[0]


def required() -> bool:
    return bool(getattr(settings, "PORTAL_SESSION_REQUIRED", False))


def session_refused() -> JsonResponse:
    """The refusal the portal treats as authoritative: it ends the browser session at once.

    The same body as the validation endpoint's uniform error, so a missing, unknown, ended or
    rebound session is never mistaken for an outage by the portal's fail-open breaker.
    """
    response = JsonResponse({"active": False, "error": "Session validation failed"}, status=401)
    response["Cache-Control"] = "no-store"
    response["Pragma"] = "no-cache"
    return response


def bind_request(request: HttpRequest, data: dict[str, object]) -> HttpResponse | None:
    """Resolve the session a verified portal request names; a response means refuse it.

    Runs in ``PortalServiceHMACMiddleware`` for every verified ``/api/`` request, so views that
    read the signed ``user_id`` themselves are bound exactly like the decorated ones. A request
    that names no user (login, registration, reset, anonymous consent) carries no session.
    """
    from apps.common.portal_hmac import parse_signed_user_id  # noqa: PLC0415  # ADR-0007: cross-app

    user_id = parse_signed_user_id(data.get("user_id"))
    raw_session_id = data.get("session_id")
    if user_id is None:
        # A session without a user to bind it to is a malformed request, never an anonymous one.
        return session_refused() if raw_session_id is not None else None
    if raw_session_id is None:
        return session_refused() if required() else None
    row = resolve(raw_session_id, user_id, interactive=data.get("interactive") is True)
    if row is None:
        return session_refused()
    request.portal_session = row  # type: ignore[attr-defined]  # read by the endpoints that end or re-stamp it
    request.portal_step_up_at = data.get("step_up_at")  # type: ignore[attr-defined]  # read by step_up_refusal
    if row.tier == PortalSession.TIER_CUSTOMER_VIEW:
        from apps.api.customer_view_policy import check  # noqa: PLC0415  # ADR-0007: cross-app, deferred

        return check(request, data, row)
    return None
