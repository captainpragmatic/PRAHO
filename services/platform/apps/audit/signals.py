"""
Comprehensive audit signals for PRAHO Platform
Implements industry-standard user action auditing (GDPR, ISO 27001, NIST, SOX, PCI DSS).
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import partial
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.db.models.signals import post_save, pre_delete, pre_save

# Bound directly (not via the transaction module attribute): tests elsewhere patch
# django.db.transaction.atomic through their own module's reference, which mutates the
# SHARED module attribute — this signal's savepoint must not be swept into assertions
# about other apps' transaction behavior.
from django.db.transaction import atomic, on_commit
from django.dispatch import Signal, receiver
from django.http import HttpRequest

from apps.common.request_ip import get_safe_client_ip
from apps.common.transactions import best_effort_atomic, swallow_application_errors
from apps.users.models import CustomerMembership, User, UserProfile

from .actor_context import current_actor
from .models import AuditEvent, ComplianceLog, audit_mutation_allowed
from .person_events import note_erasure_write
from .services import AuditContext, AuditEventData, AuditService
from .switches import audit_signals_disabled

if TYPE_CHECKING:
    from apps.customers.models import Customer

# Bumped when _calculate_event_hash changes shape, so old hashes are not compared against a new
# algorithm and misreported as tampering. Its presence also marks an event as belonging to the
# hashed era: a row without it predates #217 and is unverifiable rather than tampered.


@dataclass
class AuditEventCreationData:
    """Parameter object for audit event creation"""

    action: str
    user: User | None = None
    content_object: Any = None
    old_values: dict[str, Any] | None = None
    new_values: dict[str, Any] | None = None
    description: str = ""
    request: HttpRequest | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    actor_type: str = "user"


logger = logging.getLogger(__name__)

# ===============================================================================
# CUSTOM SIGNALS FOR BUSINESS-SPECIFIC USER ACTIONS
# ===============================================================================

# The one custom signal that is sent: the Portal's cookie-consent API raises it. The other
# eighteen (profile, privacy, API key, membership and context-switch signals) were never sent by
# any code, so their receivers audited nothing; they are gone rather than left to look like coverage.
cookie_consent_updated = Signal()


# ===============================================================================
# HELPER FUNCTIONS
# ===============================================================================


def _get_audit_context_from_request(request: HttpRequest | None, user: User | None = None) -> AuditContext:
    """Extract audit context from Django request"""
    if not request:
        return AuditContext(user=user)

    ip_address = get_safe_client_ip(request)

    return AuditContext(
        user=user or getattr(request, "user", None),
        ip_address=ip_address,
        user_agent=request.META.get("HTTP_USER_AGENT", ""),
        session_key=getattr(request.session, "session_key", None) if hasattr(request, "session") else None,
        request_id=getattr(request, "id", None),
    )


def _create_audit_event(  # Audit event creation requires comprehensive parameter set for full context capture  # audit trail fields  # noqa: PLR0913  # Business logic parameters
    event_data: AuditEventCreationData | Callable[[], AuditEventCreationData] | None = None,
    *,
    action: str | None = None,
    user: User | None = None,
    content_object: Any = None,
    old_values: dict[str, Any] | None = None,
    new_values: dict[str, Any] | None = None,
    description: str = "",
    request: HttpRequest | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    """
    Unified audit event creation with automatic categorization

    Supports both new dataclass API and legacy keyword arguments for backward compatibility.
    """
    with best_effort_atomic(logger=logger, scope="audit", message="_create_audit_event failed"):
        # Deferred fields and related objects must be read inside this event's savepoint.
        if callable(event_data):
            event_data = event_data()

        # Handle backward compatibility - convert keyword arguments to dataclass
        if event_data is None:
            if action is None:
                raise ValueError("Either event_data or action must be provided")
            event_data = AuditEventCreationData(
                action=action,
                user=user,
                content_object=content_object,
                old_values=old_values,
                new_values=new_values,
                description=description,
                request=request,
                metadata=metadata or {},
            )

        # Get context from request
        context = _get_audit_context_from_request(event_data.request, event_data.user)
        context.actor_type = event_data.actor_type

        # Add additional metadata
        if event_data.metadata:
            context.metadata.update(event_data.metadata)

        # Classification is the audit service's, from the action alone; the metadata only
        # records that a signal receiver wrote the event.
        context.metadata["audit_signal"] = True

        # Create event data
        audit_event_data = AuditEventData(
            event_type=event_data.action,
            content_object=event_data.content_object,
            old_values=event_data.old_values,
            new_values=event_data.new_values,
            description=event_data.description,
        )

        # Log the event
        AuditService.log_event(audit_event_data, context)

        logger.info(
            "✅ [Audit Signal] %s logged for %s",
            event_data.action,
            f"user {event_data.user.pk}" if event_data.user else "System",
        )


# ===============================================================================
# USER PROFILE & ACCOUNT MANAGEMENT SIGNALS
# ===============================================================================


# ===============================================================================
# CHANGE DETECTION AND ATTRIBUTION FOR MODEL RECEIVERS
# ===============================================================================

_PERSISTED_VALUES_ATTR = "_audit_persisted_values"

USER_AUDITED_FIELDS = (
    "email",
    "first_name",
    "last_name",
    "phone",
    "staff_role",
    "two_factor_enabled",
    "accepts_marketing",
)
PROFILE_AUDITED_FIELDS = (
    "preferred_language",
    "timezone",
    "email_notifications",
    "sms_notifications",
    "marketing_emails",
    "emergency_contact_name",
    "emergency_contact_phone",
)
MEMBERSHIP_AUDITED_FIELDS = ("role", "is_primary")

_AUDITED_FIELDS_BY_MODEL: dict[type, tuple[str, ...]] = {
    User: USER_AUDITED_FIELDS,
    UserProfile: PROFILE_AUDITED_FIELDS,
    CustomerMembership: MEMBERSHIP_AUDITED_FIELDS,
}


def _actor_event_fields() -> dict[str, Any]:
    """The user and actor type an event written by a receiver carries.

    A receiver sees the row that changed, not who changed it. The subject of an edit is the
    event's content object; its author is whoever is acting now, or the system when nobody is.
    """
    actor = current_actor()
    return {"user": actor, "actor_type": "user" if actor else "system"}


@receiver(pre_save, sender=User, dispatch_uid="audit_snapshot_user")
@receiver(pre_save, sender=UserProfile, dispatch_uid="audit_snapshot_user_profile")
@receiver(pre_save, sender=CustomerMembership, dispatch_uid="audit_snapshot_membership")
def snapshot_persisted_values(
    sender: Any, instance: Any, raw: bool = False, using: str | None = None, **kwargs: Any
) -> None:
    """Remember what the row holds now, so the post_save receiver can tell what this save changed.

    One read per save, on the signal's own database alias and in its own savepoint, so a failed
    read can never poison the caller's transaction. It replaces the previous save's snapshot,
    covers only the audited fields this save can touch (deferred fields were never loaded, and
    ``update_fields`` limits the rest), and is skipped for fixture loads and inserts.
    """
    setattr(instance, _PERSISTED_VALUES_ATTR, None)
    if raw or audit_signals_disabled() or instance._state.adding or instance.pk is None:
        return

    deferred = instance.get_deferred_fields()
    update_fields = kwargs.get("update_fields")
    fields = [
        name
        for name in _AUDITED_FIELDS_BY_MODEL[sender]
        if name not in deferred and (update_fields is None or name in update_fields)
    ]
    if not fields:
        return

    with best_effort_atomic(
        logger=logger, scope="audit", message=f"{sender.__name__} audit snapshot failed", using=using
    ):
        row = sender._base_manager.using(using).filter(pk=instance.pk).values(*fields).first()
        setattr(instance, _PERSISTED_VALUES_ATTR, row)


def _persisted_changes(instance: Any) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """(old, new) values of the audited fields this save changed, or None without a snapshot."""
    snapshot = getattr(instance, _PERSISTED_VALUES_ATTR, None)
    setattr(instance, _PERSISTED_VALUES_ATTR, None)
    if snapshot is None:
        return None
    old = {name: value for name, value in snapshot.items() if value != getattr(instance, name)}
    return old, {name: getattr(instance, name) for name in old}


def _changed_fields(
    instance: Any, fields: tuple[str, ...], update_fields: Any
) -> tuple[list[str], dict[str, Any], bool]:
    """(changed fields in declaration order, their old values, snapshot available).

    Without a snapshot the saved ``update_fields`` stand in, and no old values are known.
    """
    changes = _persisted_changes(instance)
    if changes is not None:
        old, _new = changes
        return [name for name in fields if name in old], old, True
    return [name for name in fields if update_fields and name in update_fields], {}, False


def _build_user_event(
    instance: User, kind: str, names: list[str], old: dict[str, Any], actor: dict[str, Any]
) -> AuditEventCreationData:
    """The event for one kind of change. Built inside the event's savepoint, never before it:
    a description may read a deferred field, and that read must not poison the caller."""
    old_of = {name: old[name] for name in names if name in old}
    if kind == "email_changed":
        return AuditEventCreationData(
            action="email_changed",
            content_object=instance,
            old_values=old_of,
            new_values={"email": instance.email},
            description="Email address changed",
            metadata={"security_sensitive": True, "requires_verification": True},
            **actor,
        )
    if kind == "name_changed":
        return AuditEventCreationData(
            action="name_changed",
            content_object=instance,
            old_values=old_of,
            new_values={name: getattr(instance, name) for name in names},
            description=f"Name changed to {instance.get_full_name()}",
            metadata={"identity_change": True},
            **actor,
        )
    if kind == "phone_updated":
        return AuditEventCreationData(
            action="phone_updated",
            content_object=instance,
            old_values=old_of,
            new_values={"phone": instance.phone},
            description="Phone number updated",
            metadata={"affects_2fa": True, "requires_verification": True},
            **actor,
        )
    if kind == "staff_role_changed":
        return AuditEventCreationData(
            action="staff_role_changed",
            content_object=instance,
            old_values=old_of,
            new_values={"staff_role": instance.staff_role},
            description=f"Staff role changed to {instance.staff_role}",
            metadata={"authorization_change": True},
            **actor,
        )
    if kind == "two_factor":
        return AuditEventCreationData(
            action="2fa_enabled" if instance.two_factor_enabled else "2fa_disabled",
            content_object=instance,
            old_values=old_of,
            new_values={"two_factor_enabled": instance.two_factor_enabled},
            description=f"2FA {'enabled' if instance.two_factor_enabled else 'disabled'}",
            metadata={"security_configuration": True},
            **actor,
        )
    return AuditEventCreationData(
        action="marketing_consent_granted" if instance.accepts_marketing else "marketing_consent_withdrawn",
        content_object=instance,
        old_values=old_of,
        new_values={"accepts_marketing": instance.accepts_marketing},
        description=f"Marketing consent {'granted' if instance.accepts_marketing else 'withdrawn'}",
        metadata={"gdpr_compliance": True, "consent_change": True},
        **actor,
    )


_USER_EVENT_KINDS: dict[str, str] = {
    "email": "email_changed",
    "first_name": "name_changed",
    "last_name": "name_changed",
    "phone": "phone_updated",
    "staff_role": "staff_role_changed",
    "two_factor_enabled": "two_factor",
    "accepts_marketing": "marketing_consent",
}


def _user_change_events(
    instance: User, changed: list[str], old: dict[str, Any]
) -> list[Callable[[], AuditEventCreationData]]:
    """One event per kind of change: both names changing is one name_changed, not two."""
    actor = _actor_event_fields()
    fields_by_kind: dict[str, list[str]] = {}
    for field_name in changed:
        fields_by_kind.setdefault(_USER_EVENT_KINDS[field_name], []).append(field_name)
    return [partial(_build_user_event, instance, kind, names, old, actor) for kind, names in fields_by_kind.items()]


@receiver(post_save, sender=User)
def audit_user_profile_changes(
    sender: type[User], instance: User, created: bool, raw: bool = False, **kwargs: Any
) -> None:
    """
    Audit User model changes for security and compliance

    Tracks the changes that affect security or privacy: email, name, phone, staff role, 2FA and
    marketing consent. The pre_save snapshot says what this save changed, so a full ``save()``
    is audited as precisely as an ``update_fields`` one, and a save that changed nothing audited
    writes nothing. The event's user is the actor; its content object is the changed account.
    """
    if created or raw or audit_signals_disabled():
        # New user creation is logged by the view, not here
        return

    with swallow_application_errors(logger=logger, scope="audit", message="audit_user_profile_changes failed"):
        changed, old, have_snapshot = _changed_fields(instance, USER_AUDITED_FIELDS, kwargs.get("update_fields"))
        if changed:
            for event in _user_change_events(instance, changed, old):
                _create_audit_event(event)
        elif not have_snapshot and not kwargs.get("update_fields"):
            # No snapshot and no field list: the change cannot be told, say only that the row was saved.
            _create_audit_event(
                AuditEventCreationData(
                    action="profile_updated",
                    content_object=instance,
                    description="User profile updated",
                    metadata={"general_update": True},
                    **_actor_event_fields(),
                )
            )


@receiver(post_save, sender=UserProfile)
def audit_user_profile_preferences(
    sender: type[UserProfile], instance: UserProfile, created: bool, raw: bool = False, **kwargs: Any
) -> None:
    """Audit UserProfile changes for preference tracking"""
    if created or raw or audit_signals_disabled():
        return

    with swallow_application_errors(logger=logger, scope="audit", message="audit_user_profile_preferences failed"):
        changed, old, have_snapshot = _changed_fields(instance, PROFILE_AUDITED_FIELDS, kwargs.get("update_fields"))
        actor = _actor_event_fields()
        emergency_fields = ("emergency_contact_name", "emergency_contact_phone")
        emergency_done = False

        for field_name in changed:
            if field_name in emergency_fields:
                if emergency_done:
                    continue
                emergency_done = True
            _create_audit_event(partial(_build_preference_event, instance, field_name, old, actor))

        if not changed and not have_snapshot and not kwargs.get("update_fields"):
            _create_audit_event(
                lambda: AuditEventCreationData(
                    action="profile_updated",
                    content_object=instance,
                    description="User profile preferences updated",
                    metadata={"preferences_update": True},
                    **actor,
                )
            )


def _build_preference_event(
    instance: UserProfile, field_name: str, old: dict[str, Any], actor: dict[str, Any]
) -> AuditEventCreationData:
    """The event for one changed preference, built inside its savepoint (see ``_build_user_event``)."""
    old_of = {name: old[name] for name in (field_name,) if name in old}
    if field_name == "preferred_language":
        return AuditEventCreationData(
            action="language_preference_changed",
            content_object=instance,
            old_values=old_of,
            new_values={field_name: instance.preferred_language},
            description=f"Language preference changed to {instance.preferred_language}",
            metadata={"preference_change": True},
            **actor,
        )
    if field_name == "timezone":
        return AuditEventCreationData(
            action="timezone_changed",
            content_object=instance,
            old_values=old_of,
            new_values={field_name: instance.timezone},
            description=f"Timezone changed to {instance.timezone}",
            metadata={"preference_change": True},
            **actor,
        )
    if field_name in ("email_notifications", "sms_notifications", "marketing_emails"):
        return AuditEventCreationData(
            action="notification_settings_changed",
            content_object=instance,
            old_values=old_of,
            new_values={field_name: getattr(instance, field_name)},
            description=f"Notification preference changed: {field_name}",
            metadata={"notification_change": True, "channel": field_name},
            **actor,
        )
    # Old and new values share the model's field names and hold only the changed halves.
    emergency_old = {name: old[name] for name in ("emergency_contact_name", "emergency_contact_phone") if name in old}
    return AuditEventCreationData(
        action="emergency_contact_updated",
        content_object=instance,
        old_values=emergency_old,
        new_values={name: getattr(instance, name) for name in emergency_old},
        description="Emergency contact information updated",
        metadata={"security_relevant": True},
        **actor,
    )


# ===============================================================================
# CUSTOMER RELATIONSHIP AUDITING
# ===============================================================================


@receiver(post_save, sender=CustomerMembership)
def audit_customer_membership_changes(
    sender: type[CustomerMembership],
    instance: CustomerMembership,
    created: bool,
    raw: bool = False,
    **kwargs: Any,
) -> None:
    """Audit customer membership changes for authorization tracking"""
    if raw or audit_signals_disabled():
        return

    audit_user: User | None = None
    audit_customer: Customer | None = None
    with best_effort_atomic(logger=logger, scope="Audit", message="Membership audit context failed"):
        audit_user = instance.user
        audit_customer = instance.customer
    if audit_user is None or audit_customer is None:
        return

    with swallow_application_errors(logger=logger, scope="audit", message="audit_customer_membership_changes failed"):
        actor = _actor_event_fields()
        if created:
            _create_audit_event(
                lambda: AuditEventCreationData(
                    action="customer_membership_created",
                    content_object=instance,
                    new_values={
                        "customer": str(audit_customer),
                        "role": instance.role,
                        "is_primary": instance.is_primary,
                    },
                    description=f"Customer membership created: {audit_user.email} → {audit_customer.company_name} ({instance.role})",
                    metadata={"authorization_change": True, "customer_id": str(audit_customer.id)},
                    **actor,
                )
            )
            return

        changed, old, have_snapshot = _changed_fields(instance, MEMBERSHIP_AUDITED_FIELDS, kwargs.get("update_fields"))
        if "role" in changed:
            _create_audit_event(
                lambda: AuditEventCreationData(
                    action="customer_role_changed",
                    content_object=instance,
                    old_values={"role": old["role"]} if "role" in old else None,
                    new_values={"role": instance.role},
                    description=f"Customer role changed to {instance.role}",
                    metadata={"authorization_change": True, "customer_id": str(audit_customer.id)},
                    **actor,
                )
            )

        if "is_primary" in changed and instance.is_primary:
            _create_audit_event(
                lambda: AuditEventCreationData(
                    action="primary_customer_changed",
                    content_object=instance,
                    old_values={"is_primary": old["is_primary"]} if "is_primary" in old else None,
                    new_values={"new_primary": str(audit_customer)},
                    description=f"Primary customer set to {audit_customer.company_name}",
                    metadata={"authorization_change": True, "customer_id": str(audit_customer.id)},
                    **actor,
                )
            )

        if not changed and not have_snapshot and not kwargs.get("update_fields"):
            # No snapshot and no field list: say only that the membership was saved.
            _create_audit_event(
                lambda: AuditEventCreationData(
                    action="customer_membership_updated",
                    content_object=instance,
                    description=f"Customer membership updated: {audit_user.email} → {audit_customer.company_name}",
                    metadata={"authorization_change": True, "customer_id": str(audit_customer.id)},
                    **actor,
                )
            )


@receiver(pre_delete, sender=CustomerMembership)
def audit_customer_membership_deletion(
    sender: type[CustomerMembership], instance: CustomerMembership, **kwargs: Any
) -> None:
    """Audit customer membership deletion"""
    if audit_signals_disabled():
        return

    with best_effort_atomic(logger=logger, scope="audit", message="audit_customer_membership_deletion failed"):
        actor = _actor_event_fields()
        _create_audit_event(
            lambda: AuditEventCreationData(
                action="customer_membership_deleted",
                content_object=instance,
                old_values={
                    "customer": str(instance.customer),
                    "role": instance.role,
                    "is_primary": instance.is_primary,
                },
                description=f"Customer membership removed: {instance.user.email} ← {instance.customer.company_name}",
                metadata={
                    "authorization_change": True,
                    "customer_id": str(instance.customer.id),
                    "access_revoked": True,
                },
                **actor,
            )
        )


# ===============================================================================
# CUSTOM SIGNAL HANDLERS FOR BUSINESS-SPECIFIC EVENTS
# ===============================================================================


@receiver(cookie_consent_updated)
def audit_cookie_consent_change(
    sender: Any,
    consent: Any,
    user: Any | None = None,
    ip_address: str | None = None,
    user_agent: str = "",
    **kwargs: Any,
) -> None:
    """
    Audit cookie consent changes — dual audit trail for GDPR compliance.

    Creates BOTH:
    1. AuditEvent — for security monitoring dashboards (category=privacy, severity=high)
    2. ComplianceLog — for GDPR Article 7 compliance reporting
    """
    from .services import (  # Circular: signals<->services  # noqa: PLC0415  # Deferred: avoids circular import
        AuditService,
        ComplianceEventRequest,
    )

    def build_event() -> AuditEventCreationData:
        categories_enabled = []
        if consent.functional_cookies:
            categories_enabled.append("functional")
        if consent.analytics_cookies:
            categories_enabled.append("analytics")
        if consent.marketing_cookies:
            categories_enabled.append("marketing")

        identifier = user.email if user else f"cookie:{consent.cookie_id[:8]}"

        return AuditEventCreationData(
            action="cookie_consent_updated",
            user=user,
            content_object=consent,
            new_values={
                "status": consent.status,
                "functional": consent.functional_cookies,
                "analytics": consent.analytics_cookies,
                "marketing": consent.marketing_cookies,
            },
            description=f"Cookie consent {consent.status} by {identifier}",
            metadata={
                "gdpr_compliance": True,
                "consent_version": consent.consent_version,
                "categories_enabled": categories_enabled,
                "source": "portal",
                "ip_address": ip_address,
                "is_anonymous": user is None,
            },
        )

    _create_audit_event(build_event)

    with best_effort_atomic(logger=logger, scope="Audit", message="Cookie compliance audit failed"):
        event_data = build_event()
        # Also log as compliance event for GDPR reporting
        compliance_request = ComplianceEventRequest(
            compliance_type="gdpr_consent",
            reference_id=f"cookie_consent_{consent.id}",
            description=event_data.description,
            user=user,
            status="success",
            evidence={
                "consent_status": consent.status,
                "categories_enabled": event_data.metadata["categories_enabled"],
                "consent_version": consent.consent_version,
                "cookie_id": consent.cookie_id,
            },
            metadata={"ip_address": ip_address, "user_agent": user_agent[:200] if user_agent else ""},
        )
        AuditService.log_compliance_event(compliance_request)


# ===============================================================================
# GENERIC FSM TRANSITION AUDIT (ADR-0034 / ADR-0016)
# ===============================================================================

# Senders whose transitions are ALREADY audited by their own status-diffing
# post_save handlers - a generic event here would double-write. Each entry is
# pinned by a one-event-per-transition test in tests/audit/test_audit_fsm_receiver.py.
FSM_AUDIT_SENDER_SKIPLIST: frozenset[str] = frozenset(
    {
        "orders.order",  # orders/signals.py order_status_changed
        "tickets.ticket",  # tickets/signals.py _handle_status_change
        "billing.payment",  # billing/signals.py _handle_payment_status_change
        "domains.domain",  # domains/signals.py domain_status_changed
    }
)


def audit_fsm_transition(sender: Any, instance: Any, name: str, source: str, target: str, **kwargs: Any) -> None:
    """Audit every django-fsm transition not covered by a model-specific handler.

    Caveat (django-fsm contract): the transition method mutates the in-memory field
    but does NOT save the instance - this event records that the transition was
    EXECUTED, not that it was persisted. `make lint-fsm` guards that call sites
    save after transitioning.

    Flag contract (mirrors billing/signals.py): DISABLE_AUDIT_SIGNALS is honored
    only under TESTING; in production the flag is a misconfiguration - log critical
    and audit anyway (W8).
    """
    if audit_signals_disabled():
        return

    label = f"{sender._meta.app_label}.{sender._meta.model_name}"
    if label in FSM_AUDIT_SENDER_SKIPLIST:
        return

    try:
        # Savepoint: a failed audit INSERT must not poison the caller's transaction.
        with atomic():
            AuditService.log_simple_event(
                event_type="status_changed",
                content_object=instance if instance.pk else None,
                description=f"{sender.__name__} {instance.pk or '(unsaved)'} transition {name}: {source} -> {target}",
                **_actor_event_fields(),
                old_values={"status": source},
                new_values={"status": target},
                metadata={"source_app": sender._meta.app_label, "fsm_transition": name},
            )
    except Exception as e:
        logger.error(f"🔥 [Audit FSM] Failed to audit transition {name} on {label}: {e}")


try:  # pragma: no cover - django-fsm is a hard dependency, guard mirrors app-load robustness
    from django_fsm.signals import post_transition

    post_transition.connect(audit_fsm_transition, dispatch_uid="audit_fsm_transition")
except ImportError:  # pragma: no cover
    logger.error("🔥 [Audit FSM] django-fsm not installed; FSM transitions are NOT audited")


# ===============================================================================
# AUDIT EVENT INTEGRITY HASH
# ===============================================================================


@receiver(pre_save, sender=AuditEvent)
def stamp_audit_event_integrity_hash(sender: Any, instance: AuditEvent, **kwargs: Any) -> None:
    """Stamp the tamper-detection MAC into metadata BEFORE the row is written (#313 point 4).

    _verify_hash_chain has always read metadata["integrity_hash"], but nothing ever wrote it, so
    the stored hash was always absent, the mismatch branch was unreachable, and every integrity
    check reported compliant no matter how the rows had been altered (#217).

    Previously this ran on post_save and issued a SECOND write (create, then UPDATE metadata),
    because the MAC covers id and timestamp and timestamp was auto_now_add — populated inside
    _save_table, after pre_save fires. AuditEvent.timestamp is now a plain default=timezone.now,
    so both values exist by the time this receiver runs and the stamp rides along on the INSERT.

    Why that matters beyond saving a write: with two writes there was a real window in which the
    row existed unstamped. A verifier reading during that window saw a row with no marker and
    classified it legacy/unverifiable, and a crash between the two writes left it that way
    permanently. One write means a row is never observable without its MAC.

    This receiver performs NO database access — it only mutates the in-memory instance — so it
    cannot mark the caller's connection needs_rollback, and needs no savepoint of its own.
    """
    if not instance._state.adding:
        # Audit events are append-only; re-hashing on update would launder a tampered row.
        return

    from .services import AuditIntegrityService  # noqa: PLC0415  # Deferred: avoids circular import

    # Reserved keys are the integrity and chain machinery's own: a caller cannot supply them (a forged
    # chain_link_quarantined would hide the event from chaining).
    base_metadata = (
        {k: v for k, v in instance.metadata.items() if k not in AuditIntegrityService.RESERVED_METADATA_KEYS}
        if isinstance(instance.metadata, dict)
        else {}
    )
    if getattr(settings, "AUDIT_CHAIN_ENABLED", False):
        base_metadata["chain_link_pending"] = True
    try:
        metadata = dict(base_metadata)
        metadata.update(AuditIntegrityService.integrity_stamp_marker(instance))
        instance.metadata = metadata
    except Exception as e:
        # An audit event that exists without a hash is far better than a lost audit event, so
        # the write proceeds regardless. Land the version marker alone so the verifier reports
        # this row as missing_integrity_hash (critical) — without it the row is byte-identical
        # to a pre-hashing legacy row and demotes to an info-level "unverifiable" finding,
        # which is precisely the low-visibility outcome #217 exists to eliminate.
        logger.error(f"🔥 [Audit Integrity] Failed to stamp integrity hash on event {instance.pk}: {e}")
        try:
            instance.metadata = {**base_metadata, "integrity_hash_version": AuditIntegrityService.HASH_VERSION}
        except Exception:
            logger.error(f"🔥 [Audit Integrity] Could not mark event {instance.pk} for critical follow-up")


@receiver(post_save, sender=AuditEvent, dispatch_uid="audit_note_erasure_write_event")
@receiver(post_save, sender=ComplianceLog, dispatch_uid="audit_note_erasure_write_compliance")
def note_erasure_writes(sender: Any, instance: AuditEvent | ComplianceLog, created: bool, **kwargs: Any) -> None:
    """While an erasure runs, record the rows it writes, for its final sweep."""
    if created:
        note_erasure_write(instance)


@receiver(post_save, sender=AuditEvent)
def append_audit_event_chain_link(sender: Any, instance: AuditEvent, created: bool, **kwargs: Any) -> None:
    """Link committed events; the INSERT already carries its durable pending marker."""
    if not created or not getattr(settings, "AUDIT_CHAIN_ENABLED", False):
        return
    alias = kwargs.get("using") or instance._state.db
    on_commit(partial(_link_committed_event, instance.pk, alias), using=alias, robust=True)


def _link_committed_event(event_id: Any, alias: str | None = None) -> bool:
    from .services import AuditIntegrityService, UnverifiableAuditEventError  # noqa: PLC0415  # Circular

    try:
        with atomic(using=alias):
            event = AuditEvent.objects.using(alias).filter(pk=event_id).first()
            if event is None:
                return True  # Rolled back or legitimately deleted; never resurrect evidence.
            AuditIntegrityService.append_chain_link(event)
            event.refresh_from_db()
            return not bool(event.metadata.get("chain_link_pending"))
    except UnverifiableAuditEventError:
        _quarantine_chain_link(event_id, alias)
        return False
    except Exception:
        logger.exception("[Audit Chain] Post-commit linking failed for event %s; recovery remains pending", event_id)
        return False


def _quarantine_chain_link(event_id: Any, alias: str | None) -> None:
    """Mark an event the chain refused, after the refusal rolled back: recovery skips it from now on.

    The marker is a reserved key, outside the MAC. The event stays pending, so the verifier keeps reporting
    it unlinked; only the recovery batch stops retrying it ahead of everything behind it.
    """
    try:
        with atomic(using=alias):
            event = AuditEvent.objects.using(alias).select_for_update().filter(pk=event_id).first()
            if event is None:
                return
            metadata = {**(event.metadata or {}), "chain_link_quarantined": True}
            with audit_mutation_allowed("chain_quarantine"):
                AuditEvent.objects.using(alias).filter(pk=event_id).update(metadata=metadata)
        logger.critical("[Audit Chain] Event %s does not verify; quarantined, recovery skips it", event_id)
    except Exception:
        logger.exception("[Audit Chain] Could not quarantine unverifiable event %s", event_id)


# ===============================================================================
# SIGNAL REGISTRATION HELPER
# ===============================================================================


def register_audit_signals() -> None:
    """Register all audit signals - called from apps.py"""
    logger.info("✅ [Audit Signals] Comprehensive audit signals registered")

    # The @receiver decorators automatically register the signals
    # This function exists for explicit registration if needed
