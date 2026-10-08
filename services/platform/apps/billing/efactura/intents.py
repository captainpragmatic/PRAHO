"""Required issuance intent and bounded recovery, without ANAF I/O."""

from __future__ import annotations

import logging
from datetime import datetime, time, timedelta
from typing import TYPE_CHECKING

from django.db import models, transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext as _

from apps.billing.fiscal_identity import normalize_country_code
from apps.billing.issuers.policy import efactura_submission_denied_reason

from .models import EFacturaDocument, EFacturaDocumentType, EFacturaStatus
from .settings import ROMANIA_TIMEZONE, efactura_enabled, efactura_environment, ro_local_date
from .working_days import submission_deadline_datetime

if TYPE_CHECKING:
    from apps.billing.invoice_models import Invoice

logger = logging.getLogger(__name__)

LEGALLY_ISSUED_STATUSES = ("issued", "paid", "overdue", "void", "refunded", "partially_refunded")


def efactura_intent_required(invoice: Invoice) -> bool:
    """Automatic invoice recovery does not own the correction worker's credit notes."""
    from apps.billing.invoice_models import DOCUMENT_KIND_CREDIT_NOTE  # noqa: PLC0415

    return (
        efactura_enabled()
        and normalize_country_code(invoice.bill_to_country) == "RO"
        and efactura_submission_denied_reason(invoice) is None
        and invoice.document_kind != DOCUMENT_KIND_CREDIT_NOTE
    )


def ensure_efactura_intent(invoice: Invoice) -> EFacturaDocument | None:
    """Required transactional write: errors belong to the issuance caller."""
    if not efactura_intent_required(invoice):
        return None
    from .service import _document_type_for  # noqa: PLC0415  # Avoid the service/model import cycle.

    document, _created = EFacturaDocument.objects.get_or_create(
        invoice=invoice,
        defaults={
            "document_type": _document_type_for(invoice),
            "environment": efactura_environment().value,
            "status": EFacturaStatus.QUEUED.value,
        },
    )
    return document


def _unclaimed_documents() -> Q:
    """Neither active ownership nor any historical submission evidence may be repaired."""
    return Q(
        submission_claim_token__isnull=True,
        submission_claimed_at__isnull=True,
        submission_claim_expires_at__isnull=True,
        submitted_at__isnull=True,
        anaf_upload_index="",
    )


def _alert(invoice: Invoice, reason: str) -> None:
    from apps.audit.models import AuditAlert  # noqa: PLC0415  # ADR-0007

    description = (
        _("Invoice %(invoice)s has missed its submission window; review it before submitting to ANAF.")
        if reason == "submission_window_expired"
        else _(
            "Invoice %(invoice)s is held from automatic submission; review its issuer, country and correction owner."
        )
    ) % {"invoice": invoice.display_number}
    AuditAlert.objects.get_or_create(
        alert_type="compliance_violation",
        metadata__efactura_reconciliation=True,
        metadata__invoice_id=str(invoice.pk),
        metadata__reason=reason,
        defaults={
            "title": _("e-Factura reconciliation: %(invoice)s") % {"invoice": invoice.pk},
            "description": description,
            "severity": "high",
            "status": "active",
            "metadata": {
                "efactura_reconciliation": True,
                "invoice_id": str(invoice.pk),
                "reason": reason,
            },
        },
    )
    logger.warning("⚠️ [e-Factura] Invoice %s requires reconciliation: %s", invoice.pk, reason)


def _lookback_start(now: datetime, deadline_days: int) -> datetime:
    """Invert the existing working-day deadline, including weekends, holidays and DST."""
    candidate = datetime.combine(ro_local_date(now), time.min, tzinfo=ROMANIA_TIMEZONE)
    while submission_deadline_datetime(candidate, deadline_days) >= now:
        candidate -= timedelta(days=1)
    return candidate + timedelta(days=1)


@transaction.atomic
def _hold_queued_document(document: EFacturaDocument) -> bool:
    changed = EFacturaDocument.objects.filter(
        _unclaimed_documents(), pk=document.pk, status=EFacturaStatus.QUEUED.value
    ).update(  # fsm-bypass: conditional recovery; a concurrently acquired claim wins.
        status=EFacturaStatus.ERROR.value,
        last_error=_("Automatic e-Factura submission is held; review the reconciliation alert."),
        next_retry_at=None,
        updated_at=timezone.now(),
    )
    if changed:
        _alert(document.invoice, "submission_held")
    return bool(changed)


@transaction.atomic
def _reconcile_invoice(invoice: Invoice, *, expired: bool) -> str:
    """Repair only missing/unclaimed DRAFT intent; preserve every other state."""
    if not efactura_intent_required(invoice):
        return "unchanged"
    document = EFacturaDocument.objects.filter(invoice=invoice).first()
    if document is not None:
        repairable = EFacturaDocument.objects.filter(
            _unclaimed_documents(), pk=document.pk, status=EFacturaStatus.DRAFT.value
        ).exists()
        if not repairable:
            return "unchanged"
    if expired:
        _alert(invoice, "submission_window_expired")
        return "alerted"
    if document is None:
        ensure_efactura_intent(invoice)
        return "created"
    changed = EFacturaDocument.objects.filter(
        _unclaimed_documents(), pk=document.pk, status=EFacturaStatus.DRAFT.value
    ).update(  # fsm-bypass: compare-and-update preserves a claim acquired after the read.
        status=EFacturaStatus.QUEUED.value, updated_at=timezone.now()
    )
    return "promoted" if changed else "unchanged"


def reconcile_efactura_documents() -> dict[str, int]:
    """Daily, idempotent recovery; older orphans go to staff instead of the uploader."""
    from apps.billing.invoice_models import DOCUMENT_KIND_CREDIT_NOTE, Invoice  # noqa: PLC0415
    from apps.settings.services import SettingsService  # noqa: PLC0415

    results = {"created": 0, "promoted": 0, "held": 0, "alerted": 0, "unchanged": 0}
    if not efactura_enabled():
        return results

    # Also drain pre-existing held work, even when its invoice is outside the repair population.
    queued = EFacturaDocument.objects.filter(_unclaimed_documents(), status=EFacturaStatus.QUEUED.value).select_related(
        "invoice"
    )
    for document in queued.iterator():
        held = (
            document.document_type == EFacturaDocumentType.CREDIT_NOTE.value
            or document.invoice.document_kind == DOCUMENT_KIND_CREDIT_NOTE
            or normalize_country_code(document.invoice.bill_to_country) != "RO"
            or efactura_submission_denied_reason(document.invoice) is not None
        )
        if held and _hold_queued_document(document):
            results["held"] += 1

    now = timezone.now()
    deadline_days = SettingsService.get_integer_setting("billing.efactura_submission_deadline_days", 5)
    cutoff = _lookback_start(now, deadline_days)
    population: models.QuerySet[Invoice] = Invoice.objects.filter(
        issued_at__isnull=False,
        issued_at__lte=now,
        status__in=LEGALLY_ISSUED_STATUSES,
    )
    for invoice in population.filter(issued_at__gte=cutoff).iterator():
        results[_reconcile_invoice(invoice, expired=False)] += 1

    # Only older ORPHANS are inspected for alerts. No old invoice is queued.
    older_orphans = population.filter(issued_at__lt=cutoff).filter(
        Q(efactura_document__isnull=True)
        | Q(
            efactura_document__status=EFacturaStatus.DRAFT.value,
            efactura_document__submission_claim_token__isnull=True,
            efactura_document__submission_claimed_at__isnull=True,
            efactura_document__submission_claim_expires_at__isnull=True,
            efactura_document__submitted_at__isnull=True,
            efactura_document__anaf_upload_index="",
        )
    )
    for invoice in older_orphans.iterator():
        results[_reconcile_invoice(invoice, expired=True)] += 1
    logger.info("✅ [e-Factura] Reconciled document intent: %s", results)
    return results
