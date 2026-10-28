"""Node mail capability seam; see docs/architecture/account-hostnames-mail-contracts.md §5.

Enrollment reads whether a node can host mail from the database only, never from the node. The answer is derived
from completed ``configure_mail_node`` job cycles. Until those exist, the query refuses with a fixed code, so callers
treat the node as not ready.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from apps.common.types import Err, Result, Retriability

if TYPE_CHECKING:
    from .virtualmin_models import VirtualminServer

_PENDING = "mail_contract_pending"


@dataclass(frozen=True)
class NodeMailCapability:
    server_id: UUID
    configured: bool
    profile: str
    certificate_proven: bool
    certificate_not_after: datetime | None
    checked_at: datetime | None


def node_mail_capability(server: VirtualminServer) -> Result[NodeMailCapability, str]:
    """Database-only node mail readiness; an error means not ready, never a reason to contact the node."""
    return Err(_PENDING, retriability=Retriability.NOT_RETRIABLE)
