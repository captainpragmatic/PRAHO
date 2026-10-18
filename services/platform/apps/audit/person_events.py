"""Find a person's audit rows, and remove their identity from rows that must survive (GDPR Art. 17).

Erasure first captures who the person is: every email, name and phone they have had, and every
record that identifies them. It then finds the audit rows that concern them. Each row gets one of
two treatments:

- a full scrub, for the person's own events that no law requires keeping;
- identity removal, for rows that are someone else's evidence or a legal record. The person's
  identifiers go and the rest of the row stays.

The identifiers are captured before anything changes, because the erasure itself overwrites the
user's email and name.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from django.contrib.contenttypes.models import ContentType
from django.db.models import Q

if TYPE_CHECKING:
    from django.db.models import QuerySet

    from apps.audit.models import AuditEvent
    from apps.users.models import User

REMOVED = "[removed]"
# Network identity copied into metadata, which the column scrub alone would miss. It is the actor's.
_NETWORK_KEYS = frozenset({"ip_address", "user_agent", "user_agent_info", "client_ip"})
# Values erasure itself writes, and empty ones: matching them would touch other people's rows.
_PLACEHOLDERS = frozenset({"anonymized", "user", "anonymized user", "+40700000000", "0.0.0.0"})
_ANONYMIZED_EMAIL = re.compile(r"^anonymized_[0-9a-f]+@example\.com$")
# Shorter values (initials, empty names) would match unrelated text.
_MIN_IDENTIFIER_LENGTH = 3
# Where an audit row can name the person.
_TEXT_FIELDS = ("description", "metadata", "old_values", "new_values")
# The proof that a CNP was cleared must stay; it carries no identifier.
ERASURE_PROOF_ACTIONS = frozenset({"data_anonymization_completed"})


@dataclass(frozen=True)
class ErasureSubject:
    """Who is being erased, frozen before the erasure changes anything."""

    user_pk: int
    identifiers: frozenset[str]
    objects: frozenset[tuple[int, str]]
    customer_ids: frozenset[str]


def _keep(value: Any) -> str | None:
    text = str(value or "").strip()
    if len(text) < _MIN_IDENTIFIER_LENGTH or text.lower() in _PLACEHOLDERS or _ANONYMIZED_EMAIL.match(text.lower()):
        return None
    return text


def capture_subject(user: User) -> ErasureSubject:
    """Every identifier and record of `user`, including earlier emails and names."""
    from apps.audit.models import AuditEvent  # noqa: PLC0415  # Deferred: app registry
    from apps.billing.invoice_models import Invoice  # noqa: PLC0415  # Deferred: import cycle
    from apps.billing.payment_models import Payment  # noqa: PLC0415  # Deferred: import cycle
    from apps.billing.proforma_models import ProformaInvoice  # noqa: PLC0415  # Deferred: import cycle
    from apps.customers.contact_models import CustomerAddress  # noqa: PLC0415  # Deferred: import cycle
    from apps.customers.customer_models import Customer  # noqa: PLC0415  # Deferred: import cycle
    from apps.customers.profile_models import (  # noqa: PLC0415  # Deferred: import cycle
        CustomerBillingProfile,
        CustomerTaxProfile,
    )
    from apps.orders.models import Order  # noqa: PLC0415  # Deferred: import cycle
    from apps.provisioning.service_models import Service  # noqa: PLC0415  # Deferred: import cycle
    from apps.users.mfa import WebAuthnCredential  # noqa: PLC0415  # Deferred: import cycle
    from apps.users.models import APIToken, CustomerMembership, UserProfile  # noqa: PLC0415  # Deferred

    texts = [user.email, user.first_name, user.last_name, user.get_full_name(), getattr(user, "phone", "")]
    content_type = ContentType.objects.get_for_model(user)
    # Earlier values: a change event records only the new one, so every event about the account
    # is read, and the address the authentication log recorded for the person's own actions.
    texts.extend(
        str(email)
        for email in AuditEvent.objects.filter(user_id=user.pk, metadata__has_key="user_email").values_list(
            "metadata__user_email", flat=True
        )
    )
    for change in AuditEvent.objects.filter(content_type=content_type, object_id=str(user.pk)).only(
        "new_values", "old_values"
    ):
        for values in (change.new_values, change.old_values):
            if isinstance(values, dict):
                texts.extend(str(values.get(key) or "") for key in ("email", "first_name", "last_name", "phone"))
                texts.append(f"{values.get('first_name') or ''} {values.get('last_name') or ''}")

    owned = list(
        CustomerMembership.objects.filter(user=user, role="owner", customer__customer_type="individual").values_list(
            "customer_id", flat=True
        )
    )
    objects: set[tuple[int, str]] = set()

    def add(model: Any, pks: Any) -> None:
        type_id = ContentType.objects.get_for_model(model).pk
        objects.update((type_id, str(pk)) for pk in pks)

    add(type(user), [user.pk])
    add(UserProfile, UserProfile.objects.filter(user=user).values_list("pk", flat=True))
    add(CustomerMembership, CustomerMembership.objects.filter(user=user).values_list("pk", flat=True))
    add(WebAuthnCredential, WebAuthnCredential.objects.filter(user=user).values_list("pk", flat=True))
    add(APIToken, APIToken.objects.filter(user=user).values_list("pk", flat=True))
    add(Customer, Customer.all_objects.filter(pk__in=owned).values_list("pk", flat=True))
    for profile_model in (CustomerTaxProfile, CustomerBillingProfile, CustomerAddress):
        add(profile_model, profile_model.all_objects.filter(customer_id__in=owned).values_list("pk", flat=True))
    for record_model in (Invoice, ProformaInvoice, Order, Payment, Service):
        add(record_model, record_model._base_manager.filter(customer_id__in=owned).values_list("pk", flat=True))
    for customer in Customer.all_objects.filter(pk__in=owned):
        texts.extend([customer.name, customer.primary_email, getattr(customer, "primary_phone", "")])

    identifiers = frozenset(kept for kept in (_keep(text) for text in texts) if kept)
    return ErasureSubject(
        user_pk=user.pk,
        identifiers=identifiers,
        objects=frozenset(objects),
        customer_ids=frozenset(str(pk) for pk in owned),
    )


def _about_query(subject: ErasureSubject) -> Q:
    query = Q(pk__in=[])
    by_type: dict[int, list[str]] = {}
    for type_id, object_id in subject.objects:
        by_type.setdefault(type_id, []).append(object_id)
    for type_id, object_ids in by_type.items():
        query |= Q(content_type_id=type_id, object_id__in=object_ids)
    if subject.customer_ids:
        ids = sorted(subject.customer_ids)
        query |= Q(metadata__customer_id__in=ids + [int(pk) for pk in ids if pk.isdigit()])
    for field in ("metadata", "old_values", "new_values"):
        query |= Q(**{f"{field}__user_id": subject.user_pk}) | Q(**{f"{field}__user_id": str(subject.user_pk)})
    return query


def _mentions_query(subject: ErasureSubject, fields: tuple[str, ...] = _TEXT_FIELDS) -> Q:
    # A bounded text net: a row that only names the person's address is a candidate for identity
    # removal, not the person's own data (their note about someone else names them too). JSON
    # fields are searched as text: a security event can name the person only in its metadata.
    query = Q(pk__in=[])
    for identifier in subject.identifiers:
        if "@" in identifier:
            for name in fields:
                query |= Q(**{f"{name}__icontains": identifier})
    return query


def events_about(subject: ErasureSubject) -> QuerySet[AuditEvent]:
    """Rows whose object, values or text concern the person (not merely rows they acted in)."""
    from apps.audit.models import AuditEvent  # noqa: PLC0415  # Deferred: app registry

    return AuditEvent.objects.filter(_about_query(subject)).exclude(action__in=ERASURE_PROOF_ACTIONS)


def events_concerning(subject: ErasureSubject) -> QuerySet[AuditEvent]:
    """Every row about the person, naming them, or acted in by them."""
    from apps.audit.models import AuditEvent  # noqa: PLC0415  # Deferred: app registry

    return AuditEvent.objects.filter(
        _about_query(subject) | _mentions_query(subject) | Q(user_id=subject.user_pk)
    ).exclude(action__in=ERASURE_PROOF_ACTIONS)


def _replace(text: str, subject: ErasureSubject) -> str:
    # Whole words only: a first name such as "Ana" must not cut into "management".
    for identifier in sorted(subject.identifiers, key=len, reverse=True):
        text = re.sub(rf"(?<!\w){re.escape(identifier)}(?!\w)", REMOVED, text, flags=re.IGNORECASE)
    return text


def _scrub(value: Any, subject: ErasureSubject, *, network: bool, reserved: frozenset[str] = frozenset()) -> Any:
    # Only the person's own identifiers go: other people's values are their evidence.
    if isinstance(value, dict):
        scrubbed: dict[Any, Any] = {}
        for key, item in value.items():
            if key in reserved:
                scrubbed[key] = item
            elif network and key in _NETWORK_KEYS:
                continue
            else:
                scrubbed[key] = _scrub(item, subject, network=network)
        return scrubbed
    if isinstance(value, list):
        return [_scrub(item, subject, network=network) for item in value]
    if isinstance(value, str):
        return _replace(value, subject)
    return value


def remove_identity(event: AuditEvent, subject: ErasureSubject, *, removed_at: str) -> None:
    """Remove the person's identifiers from `event` and re-stamp it; the caller allows the mutation.

    The row stays the evidence it was. Its network identity and session go only when the person
    was the actor, or there was none: a staff member's IP on an action against the person is theirs.
    The row is never marked anonymized, so a later retention policy can still fully scrub it.
    """
    from apps.audit.services import AuditIntegrityService  # noqa: PLC0415  # Deferred: import cycle

    # A row with no actor (a failed login for the person's address) records the person's network.
    network = event.user_id in (subject.user_pk, None)
    if network:
        event.user = None
        event.ip_address = None
        event.user_agent = ""
        event.request_id = ""
        event.session_key = ""
    event.description = _replace(event.description or "", subject)
    event.old_values = _scrub(event.old_values, subject, network=network)
    event.new_values = _scrub(event.new_values, subject, network=network)
    metadata = event.metadata if isinstance(event.metadata, dict) else {}
    event.metadata = {
        **_scrub(metadata, subject, network=network, reserved=AuditIntegrityService.RESERVED_METADATA_KEYS),
        "identity_removed_at": removed_at,
    }
    event.metadata.update(AuditIntegrityService.integrity_stamp_marker(event))
    event.save()
