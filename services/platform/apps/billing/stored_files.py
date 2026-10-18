"""Billing files: stored before their row names them, and kept while they are fiscal records.

Storage is not transactional. A writer stores the file, then saves the row that names it; if the
row save fails, it deletes the file it just stored, and a file it replaced is deleted only once the
replacement commits. The orphaned-media sweeper never touches billing prefixes, so these writers
own their own failures.

An issued invoice's documents, and an e-Factura document's XML and ANAF archive once the document
may have reached ANAF, are fiscal records: deleting their rows never deletes the files.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import TYPE_CHECKING

from django.core.files.storage import Storage
from django.db import transaction

if TYPE_CHECKING:
    from .efactura.models import EFacturaDocument
    from .invoice_models import Invoice

logger = logging.getLogger(__name__)

# Files stored inside the innermost delete_stored_files_on_failure() block.
_GUARDED: ContextVar[list[tuple[Storage, str]] | None] = ContextVar("billing_stored_files", default=None)

# Statuses in which the document may have reached ANAF; draft, queued and error never left PRAHO.
EFACTURA_UNSENT_STATUSES = frozenset({"draft", "queued", "error"})


def invoice_is_fiscal(invoice: Invoice) -> bool:
    """Whether an invoice's documents are fiscal records: it was issued, or is locked."""
    return invoice.locked_at is not None or invoice.status != "draft"


def efactura_document_is_fiscal(document: EFacturaDocument) -> bool:
    """Whether a document's XML and archive are fiscal records."""
    if document.status not in EFACTURA_UNSENT_STATUSES:
        return True
    from .invoice_models import Invoice  # noqa: PLC0415  # Deferred: invoice models import this module's callers

    # The row, not a cached instance: a cascade can delete a document whose invoice was loaded before it issued.
    invoice = Invoice.objects.filter(pk=document.invoice_id).only("locked_at", "status").first()
    return invoice is not None and invoice_is_fiscal(invoice)


def _delete(storage: Storage, name: str) -> None:
    try:
        storage.delete(name)
        logger.info("🗑️ [Billing] Deleted stored file %s", name)
    except Exception:
        logger.exception("🔥 [Billing] Could not delete stored file %s", name)


def delete_after_commit(storage: Storage, name: str | None) -> None:
    """Delete `name` once the current transaction commits; nothing if it rolls back."""
    if name:
        transaction.on_commit(lambda: _delete(storage, name), robust=True)


def record_stored_file(storage: Storage, stored: str, superseded: str | None, record: Callable[[], object]) -> None:
    """Save the row naming `stored`; delete `stored` if that fails, else delete `superseded` after commit."""
    try:
        record()
    except Exception:
        _delete(storage, stored)
        raise
    guarded = _GUARDED.get()
    if guarded is not None:
        guarded.append((storage, stored))
    if superseded and superseded != stored:
        delete_after_commit(storage, superseded)


@contextmanager
def delete_stored_files_on_failure() -> Iterator[None]:
    """Delete every file recorded inside this block if the block raises.

    Wrap a whole atomic block with it: when a later step raises, the transaction rolls back the row
    that named the file, and this deletes the file. Rollback has no hook of its own in Django.
    """
    stored: list[tuple[Storage, str]] = []
    token = _GUARDED.set(stored)
    try:
        yield
    except Exception:
        for storage, name in stored:
            _delete(storage, name)
        raise
    finally:
        _GUARDED.reset(token)
