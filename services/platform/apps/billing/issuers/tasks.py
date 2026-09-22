"""Queued external issuance.

Issuance is queued rather than inline because a provider call must not sit inside
the transaction that converges a payment: the customer has paid, and their payment
must not be rolled back because an invoicing API was slow. Provisioning already
unblocks on payment rather than on issuance, so deferring costs nothing.
"""

from __future__ import annotations

import logging

from apps.common.types import Err

from .service import issue_invoice_externally

logger = logging.getLogger(__name__)


def issue_invoice_task(invoice_id: int) -> dict[str, object]:
    """Issue one invoice through its provider.

    Returns rather than raises on a refusal, so a failed issuance does not look like
    a crashed worker. An ambiguous outcome is reported as failure here too, but the
    ProviderIssuance row carries the distinction that matters: `outcome_unknown` has
    no path back to `claimed`, so no sweep can retry it.
    """
    result = issue_invoice_externally(invoice_id)
    if isinstance(result, Err):
        logger.warning(f"⚠️ [Issuance] Invoice {invoice_id} not issued: {result.error}")
        return {"invoice_id": invoice_id, "issued": False, "error": result.error}
    return {"invoice_id": invoice_id, "issued": True, "number": result.unwrap()}


def queue_invoice_issuance(invoice_id: int) -> str | None:
    """Enqueue issuance after the surrounding transaction commits.

    Falls back to running inline when the queue is unavailable, but only from a
    caller that is already outside a transaction — the service refuses otherwise,
    which is the guard rather than a comment.
    """
    try:
        from django_q.tasks import async_task  # noqa: PLC0415  # Optional at import time

        task_id: str = async_task(
            "apps.billing.issuers.tasks.issue_invoice_task",
            invoice_id,
            task_name=f"issue-invoice-{invoice_id}",
        )
    except Exception as exc:  # Queue unavailability must not lose the invoice
        logger.warning(f"⚠️ [Issuance] Could not queue invoice {invoice_id}: {exc}")
        return None
    return task_id


def sweep_pending_issuances(limit: int = 100) -> dict[str, int]:
    """Pick up issuances whose queue callback never ran.

    `on_commit` fires in-process: a crash between the conversion commit and the
    callback loses the enqueue but not the row, which is why the row is created in
    that transaction. This is the other half of that arrangement.

    Deliberately narrow: only `pending`. An abandoned `claimed` row is quarantined
    by the claim path itself, and `outcome_unknown` is never swept by anything.
    """
    from .models import IssuanceState, ProviderIssuance  # noqa: PLC0415

    pending = ProviderIssuance.objects.filter(
        state=IssuanceState.PENDING.value,
        invoice__number__isnull=True,
    ).order_by("created_at")[:limit]

    results = {"queued": 0, "skipped": 0}
    for issuance in pending:
        if queue_invoice_issuance(issuance.invoice_id):
            results["queued"] += 1
        else:
            results["skipped"] += 1
    return results
