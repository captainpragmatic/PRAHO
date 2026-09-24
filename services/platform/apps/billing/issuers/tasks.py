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

# Rotation state for `sweep_owed_reversals`; its docstring explains why it exists.
_REVERSAL_CURSOR_KEY = "billing:owed-reversal-sweep-cursor"


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
    from apps.billing.invoice_models import DOCUMENT_KIND_CREDIT_NOTE  # noqa: PLC0415  # ADR-0007

    from .models import MAX_SUBMISSIONS, IssuanceState, ProviderIssuance  # noqa: PLC0415

    # `pending` records that a provider call is owed, not WHICH one, so this dispatches
    # by document kind rather than filtering one out. Excluding credit notes stopped a
    # rate-gated reversal being POSTed to /invoice, but `sweep_owed_reversals` skips any
    # invoice that already has a reversal row - and a deferred storno always has one -
    # so the reversal was then recovered by neither sweep while the refund had moved.
    #
    # `failed` is included because `claim()` accepts it: a refusal earns REJECTED only
    # from a recognised refusal envelope, which is the classifier's guarantee that
    # nothing was created. The cap is what keeps a permanent validation error from
    # being resubmitted forever against a rate-limited third party.
    owed = (
        ProviderIssuance.objects.filter(
            state__in=(IssuanceState.PENDING.value, IssuanceState.FAILED.value),
            invoice__number__isnull=True,
            submissions__lt=MAX_SUBMISSIONS,
        )
        .select_related("invoice")
        .order_by("created_at")[:limit]
    )

    results = {"queued": 0, "skipped": 0, "exhausted": 0}
    for issuance in owed:
        invoice = issuance.invoice
        if invoice.document_kind == DOCUMENT_KIND_CREDIT_NOTE:
            # The reversal service is addressed by the ORIGINAL's id: it is the document
            # being reversed, and the credit note is what the call produces.
            if invoice.reverses_invoice_id is None:
                logger.error(
                    f"🔥 [Issuance] Credit note {invoice.pk} has no original to reverse; "
                    f"it cannot be recovered automatically."
                )
                results["skipped"] += 1
                continue
            queued = queue_invoice_storno(invoice.reverses_invoice_id)
        else:
            queued = queue_invoice_issuance(invoice.pk)
        results["queued" if queued else "skipped"] += 1

    exhausted = ProviderIssuance.objects.filter(
        state=IssuanceState.FAILED.value,
        invoice__number__isnull=True,
        submissions__gte=MAX_SUBMISSIONS,
    ).count()
    if exhausted:
        results["exhausted"] = exhausted
        logger.error(
            f"🔥 [Issuance] {exhausted} document(s) have spent their {MAX_SUBMISSIONS} "
            f"submission attempts and need an operator."
        )
    return results


def sweep_owed_reversals(limit: int = 100) -> dict[str, int]:
    """Pick up reversals whose queue callback never ran.

    Issuance survives a lost enqueue because its work row is written in the same
    transaction as the invoice, so a sweep can find it. A reversal has no such row:
    the credit note is created by the task itself, so an enqueue that fails leaves
    nothing behind at all - while the refund has already moved money, so the customer
    holds a full invoice with nothing reversing it and the books show revenue that was
    returned.

    No new state is needed to fix that, because the durable record already exists: a
    provider-issued invoice sitting in `refunded` with no reversal IS an outstanding
    correction. This reads that rather than inventing a second source of truth.

    Eligibility is deliberately not re-checked here. `issue_storno_for_invoice`
    settles it under lock, and a sweep that duplicated those rules is exactly how the
    two would drift apart.
    """
    from django.core.cache import cache  # noqa: PLC0415

    from apps.billing.invoice_models import DOCUMENT_KIND_INVOICE, ISSUER_BUILTIN, Invoice  # noqa: PLC0415

    candidates = Invoice.objects.filter(
        status="refunded",
        document_kind=DOCUMENT_KIND_INVOICE,
        reversals__isnull=True,
    ).exclude(issuer_provider=ISSUER_BUILTIN)

    # A refusal that can never succeed - an invoice refunded in instalments, say -
    # leaves that invoice a candidate forever. Always taking the lowest N primary keys
    # would let a handful of permanently stuck documents occupy every run while a
    # genuinely recoverable reversal behind them is never reached, and the money for
    # that one has already left. The cursor advances past whatever was examined and
    # wraps at the end, so every candidate is reached within a bounded number of runs.
    # Losing it to cache eviction only restarts the rotation, which is harmless, and
    # where the cache is a no-op the sweep simply degrades to always scanning from the
    # lowest key - correct, just not fair. Fairness only matters once candidates are
    # permanently stuck, which is itself the alarm condition.
    cursor = cache.get(_REVERSAL_CURSOR_KEY) or 0
    owed = list(candidates.filter(pk__gt=cursor).order_by("pk")[:limit])
    if not owed and cursor:
        owed = list(candidates.order_by("pk")[:limit])
    cache.set(_REVERSAL_CURSOR_KEY, owed[-1].pk if owed else 0, timeout=None)

    queued = 0
    for invoice in owed:
        if queue_invoice_storno(invoice.pk):
            queued += 1
        else:
            logger.error(
                f"🔥 [Storno] Reversal still cannot be queued for invoice {invoice.pk}; "
                f"the customer holds a refunded invoice with no credit note."
            )
    if owed:
        logger.info(f"🐢 [Storno] Swept {len(owed)} owed reversal(s); {queued} queued")
    return {"examined": len(owed), "queued": queued}


def issue_storno_task(invoice_id: int) -> dict[str, object]:
    """Reverse one provider-issued invoice."""
    from .service import issue_storno_for_invoice  # noqa: PLC0415

    result = issue_storno_for_invoice(invoice_id)
    if isinstance(result, Err):
        logger.warning(f"⚠️ [Storno] Invoice {invoice_id} not reversed: {result.error}")
        return {"invoice_id": invoice_id, "reversed": False, "error": result.error}
    return {"invoice_id": invoice_id, "reversed": True, "number": result.unwrap()}


def queue_invoice_storno(invoice_id: int) -> str | None:
    """Enqueue a reversal after the surrounding transaction commits."""
    try:
        from django_q.tasks import async_task  # noqa: PLC0415  # Optional at import time

        task_id: str = async_task(
            "apps.billing.issuers.tasks.issue_storno_task",
            invoice_id,
            task_name=f"storno-invoice-{invoice_id}",
        )
    except Exception as exc:
        logger.warning(f"⚠️ [Storno] Could not queue reversal for invoice {invoice_id}: {exc}")
        return None
    return task_id
