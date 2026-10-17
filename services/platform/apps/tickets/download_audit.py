"""Each ticket attachment download leaves an audit event, keyed by ids and never by filename.

A filename can carry a person's data, and the audit log outlives the ticket, so the event records
the attachment and ticket ids, the channel and the actor only. It is filed against the ticket, so
the ticket's own audit trail, export and erasure find it.
"""

from __future__ import annotations

from typing import Any

from apps.audit.services import AuditService
from apps.tickets.models import TicketAttachment


def audit_attachment_download(
    attachment: TicketAttachment, *, channel: str, user: Any | None = None, customer_id: int | None = None
) -> None:
    metadata: dict[str, Any] = {
        "attachment_id": attachment.pk,
        "ticket_id": str(attachment.ticket_id),
        "channel": channel,
    }
    if customer_id is not None:
        metadata["customer_id"] = customer_id
    AuditService.log_simple_event(
        "ticket_attachment_downloaded",
        user=user,
        content_object=attachment.ticket,
        description="Ticket attachment downloaded",
        metadata=metadata,
        actor_type="user" if user is not None else "api",
    )
