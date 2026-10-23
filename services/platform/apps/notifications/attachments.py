"""Email attachments by reference: what to attach, and how to make it again (#751 follow-up, H4).

A queued email stores no attachment bytes. It stores where each attachment comes from (a source type
and an id) and the SHA-256 of the bytes first sent; every send regenerates them from the source and
refuses if they differ, so a retry never sends a different document under the first one.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apps.notifications.models import EmailLog

# The most a regenerated set may weigh; over it the message is refused rather than sent incomplete.
MAX_REGENERATED_BYTES = 10 * 1024 * 1024


@dataclass(frozen=True)
class AttachmentRef:
    """An attachment named by its source, regenerated at send time."""

    source_type: str
    source_id: str


def _legal_document(source_id: str) -> tuple[str, bytes, str]:
    from apps.common.legal import LegalDocument  # noqa: PLC0415  # Deferred: common imports notifications

    return LegalDocument.objects.get(pk=source_id).attachment()


def _invoice_pdf(source_id: str) -> tuple[str, bytes, str]:
    from apps.billing.issuers.documents import get_invoice_pdf_bytes  # noqa: PLC0415  # Circular
    from apps.billing.models import Invoice  # noqa: PLC0415  # Circular

    invoice = Invoice.objects.get(pk=source_id)
    pdf = get_invoice_pdf_bytes(invoice)
    if pdf.is_err():
        raise ValueError(f"The PDF of {invoice.number} is not available: {pdf.unwrap_err()}")
    from apps.billing.invoice_models import DOCUMENT_KIND_CREDIT_NOTE  # noqa: PLC0415  # Circular

    prefix = "storno" if invoice.document_kind == DOCUMENT_KIND_CREDIT_NOTE else "invoice"
    return f"{prefix}_{invoice.number}.pdf", pdf.unwrap(), "application/pdf"


def _proforma_pdf(source_id: str) -> tuple[str, bytes, str]:
    from apps.billing.models import ProformaInvoice  # noqa: PLC0415  # Circular
    from apps.billing.proforma_service import generate_proforma_pdf  # noqa: PLC0415  # Circular

    proforma = ProformaInvoice.objects.get(pk=source_id)
    return f"proforma_{proforma.number}.pdf", generate_proforma_pdf(proforma), "application/pdf"


ATTACHMENT_SOURCES: dict[str, Callable[[str], tuple[str, bytes, str]]] = {
    "legal_document": _legal_document,
    "invoice_pdf": _invoice_pdf,
    "proforma_pdf": _proforma_pdf,
}


def content_sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


AttachmentInput = tuple[str, bytes, str] | AttachmentRef


@dataclass(frozen=True)
class ResolvedAttachment:
    """An attachment with its bytes in hand; `ref` is None for bytes with no source to make them again."""

    ref: AttachmentRef | None
    filename: str
    content: bytes
    mimetype: str

    @property
    def sha256(self) -> str:
        return content_sha256(self.content)

    def as_tuple(self) -> tuple[str, bytes, str]:
        return self.filename, self.content, self.mimetype


class AttachmentRefusedError(Exception):
    """A message cannot be sent with the attachments it was written with. `permanent`: never retry."""

    def __init__(self, reason: str, *, permanent: bool) -> None:
        super().__init__(reason)
        self.permanent = permanent


def _generate(ref: AttachmentRef) -> tuple[str, bytes, str]:
    source = ATTACHMENT_SOURCES.get(ref.source_type)
    if source is None:
        raise AttachmentRefusedError(f"Unknown attachment source {ref.source_type!r}", permanent=True)
    return source(ref.source_id)


def resolve_attachments(items: Sequence[AttachmentInput] | None) -> list[ResolvedAttachment]:
    """The attachments of a new message, each with its bytes. A source that fails raises."""
    resolved: list[ResolvedAttachment] = []
    for item in items or []:
        if isinstance(item, AttachmentRef):
            filename, content, mimetype = _generate(item)
            resolved.append(ResolvedAttachment(item, filename, content, mimetype))
        else:
            filename, content, mimetype = item
            resolved.append(ResolvedAttachment(None, filename, content, mimetype))
    return resolved


def regenerate_attachments(email_log: EmailLog) -> list[tuple[str, bytes, str]]:
    """The attachments of a stored message, made again from their sources and checked against the first send.

    Raises AttachmentRefusedError: permanent when the message can never be sent as written (attachments with
    no source, a changed document, a set over the size cap); not permanent when a source failed for now.
    """
    if (email_log.meta or {}).get("attachments_unrecoverable"):
        raise AttachmentRefusedError("Attachment not recoverable: it had no source to make it again", permanent=True)
    parts: list[tuple[str, bytes, str]] = []
    total = 0
    for stored in email_log.attachment_refs.order_by("position"):
        try:
            _filename, content, mimetype = _generate(AttachmentRef(stored.source_type, stored.source_id))
        except AttachmentRefusedError:
            raise
        except Exception as error:
            raise AttachmentRefusedError(f"Attachment source failed: {error}", permanent=False) from error
        if content_sha256(content) != stored.sha256:
            raise AttachmentRefusedError(
                f"Attachment {stored.filename} changed since the first send; send a new message", permanent=True
            )
        total += len(content)
        if total > MAX_REGENERATED_BYTES:
            raise AttachmentRefusedError("Attachments exceed the regenerated size cap", permanent=True)
        parts.append((stored.filename, content, mimetype))
    return parts
