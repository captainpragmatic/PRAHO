"""Hosted mailbox and local alias changes; see docs/architecture/account-hostnames-mail-contracts.md §4.

``apply_mail_mutation`` is the only entry point for creating or deleting mailboxes and aliases and for changing
passwords and quotas. Until the change model and native action exist, it refuses with a fixed code and stores nothing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal
from uuid import UUID

from apps.common.types import Err, Result, Retriability

if TYPE_CHECKING:
    from apps.users.models import User

    from .virtualmin_models import VirtualminAccount

_PENDING = "mail_contract_pending"


@dataclass(frozen=True)
class MailboxCreate:
    local_part: str
    password: str = field(repr=False)
    quota_mb: int | None = None


@dataclass(frozen=True)
class MailboxDelete:
    local_part: str


@dataclass(frozen=True)
class MailboxPassword:
    local_part: str
    password: str = field(repr=False)
    confirm_unlock: bool = False


@dataclass(frozen=True)
class MailboxQuota:
    local_part: str
    quota_mb: int | None


@dataclass(frozen=True)
class AliasCreate:
    """Targets are local parts of enabled local mailboxes; external and chained targets are refused."""

    local_part: str
    targets: tuple[str, ...]


@dataclass(frozen=True)
class AliasDelete:
    local_part: str


type MailMutation = MailboxCreate | MailboxDelete | MailboxPassword | MailboxQuota | AliasCreate | AliasDelete


@dataclass(frozen=True)
class MailMutationReceipt:
    change_id: UUID
    kind: str
    address: str
    status: Literal["pending", "applied"]


def apply_mail_mutation(
    account: VirtualminAccount, mutation: MailMutation, *, actor: User | None, submission_id: UUID | str
) -> Result[MailMutationReceipt, str]:
    """Admit one owner or tech mailbox change; the change is applied later by its own fenced worker."""
    return Err(_PENDING, retriability=Retriability.NOT_RETRIABLE)
