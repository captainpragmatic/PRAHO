"""Hosted-mail DNS publication seam; see docs/architecture/account-hostnames-mail-contracts.md §3.

Enrollment hands slot-scoped record changes to a publisher and observes agreement through it. The managed path
writes through a dedicated ``mail_records`` zone operation; the external path only observes the owner's records.
Until that outbox exists, every call refuses with a fixed code and changes nothing.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, Protocol, runtime_checkable
from uuid import UUID

from apps.common.types import Err, Result, Retriability

if TYPE_CHECKING:
    from .virtualmin_mail_dns import MailDnsRecord
    from .virtualmin_models import VirtualminAccount

type MailRecordSlot = Literal["dkim", "spf", "mx"]

_PENDING = "mail_contract_pending"


@dataclass(frozen=True)
class MailPublicationRequest:
    """One slot group of a confirmed plan, bound to its mail operation and plan digest."""

    mail_operation_id: UUID
    plan_sha256: str
    dns_plan: Mapping[str, object]
    slots: tuple[MailRecordSlot, ...]
    direction: Literal["apply", "remove"]


@dataclass(frozen=True)
class MailPublicationState:
    """Managed rows report ``submitted`` then ``agreed``; the external path reports ``waiting_owner`` with records."""

    state: Literal["submitted", "waiting_owner", "agreed"]
    zone_operation_id: UUID | None
    records: tuple[MailDnsRecord, ...]


@runtime_checkable
class MailDnsPublisher(Protocol):
    def submit(self, account: VirtualminAccount, request: MailPublicationRequest) -> Result[MailPublicationState, str]:
        """Idempotent on (mail_operation_id, slots, direction); provider I/O never runs inside a transaction."""
        ...

    def observe(self, account: VirtualminAccount, request: MailPublicationRequest) -> Result[MailPublicationState, str]:
        """Read-only agreement check of the requested slots."""
        ...


class _PendingPublisher:
    """Refuses every publication until the slot-scoped outbox exists."""

    def submit(self, account: VirtualminAccount, request: MailPublicationRequest) -> Result[MailPublicationState, str]:
        return Err(_PENDING, retriability=Retriability.NOT_RETRIABLE)

    def observe(self, account: VirtualminAccount, request: MailPublicationRequest) -> Result[MailPublicationState, str]:
        return Err(_PENDING, retriability=Retriability.NOT_RETRIABLE)


def mail_dns_publisher() -> MailDnsPublisher:
    """The publisher enrollment must use for every mail record write or observation."""
    return _PendingPublisher()
