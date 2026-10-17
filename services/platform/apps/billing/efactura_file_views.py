"""Staff download of an e-Factura document's stored XML and ANAF response archive.

These are fiscal records: the XML that was submitted and the ZIP ANAF returned. The view reads the
bytes once through the storage API, never a local path, so it works on an object store. It checks
them against the recorded SHA-256 and serves exactly those bytes, or refuses: a file that no longer
matches its hash is never handed out as the record. Every attempt is audited by document, invoice,
file kind and outcome, with no filename and no contents.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from dataclasses import dataclass
from typing import Any

from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.http import require_GET

from apps.audit.services import AuditService
from apps.common.decorators import billing_staff_required
from apps.common.http import mark_download

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _FileKind:
    field: str
    digest_field: str
    content_type: str
    filename_pattern: str


_KINDS = {
    "xml": _FileKind("xml_file", "xml_hash", "application/xml", "e_factura_{number}.xml"),
    "archive": _FileKind("response_archive", "response_archive_sha256", "application/zip", "anaf_{number}.zip"),
}


def _audit(request: HttpRequest, document: Any, kind: str, outcome: str) -> None:
    AuditService.log_simple_event(
        "efactura_file_downloaded",
        user=request.user,
        content_object=document,
        description="e-Factura file download",
        metadata={
            "document_id": str(document.pk),
            "invoice_id": document.invoice_id,
            "file_kind": kind,
            "outcome": outcome,
        },
    )


@billing_staff_required
@require_GET
def efactura_document_file(request: HttpRequest, pk: str, kind: str) -> HttpResponse:
    from apps.billing.efactura.models import EFacturaDocument  # noqa: PLC0415  # Deferred: avoids circular import

    spec = _KINDS.get(kind)
    if spec is None:
        raise Http404("Unknown file kind")
    document = get_object_or_404(EFacturaDocument.objects.select_related("invoice"), pk=pk)
    stored = getattr(document, spec.field)
    if not stored or not stored.name:
        _audit(request, document, kind, "missing")
        raise Http404("No stored file of this kind")

    try:
        with stored.open("rb") as handle:
            content = handle.read()
    except FileNotFoundError:
        _audit(request, document, kind, "missing")
        raise Http404("The stored file is gone") from None
    except (OSError, ValueError):
        logger.exception(f"🔥 [e-Factura] Could not read the stored {kind} for document {document.pk}")
        _audit(request, document, kind, "unavailable")
        return HttpResponse("The file store is unavailable.", status=503, content_type="text/plain")

    expected = getattr(document, spec.digest_field)
    if not expected or not hmac.compare_digest(hashlib.sha256(content).hexdigest(), expected):
        logger.error(f"🔥 [e-Factura] Stored {kind} for document {document.pk} does not match its recorded hash")
        _audit(request, document, kind, "integrity_failed")
        return HttpResponse("The stored file does not match its record.", status=409, content_type="text/plain")

    response = HttpResponse(content, content_type=spec.content_type)
    mark_download(response, spec.filename_pattern.format(number=document.invoice.number))
    _audit(request, document, kind, "served")
    return response
