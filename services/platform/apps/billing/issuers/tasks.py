"""Queued external issuance.

Issuance is queued rather than inline because a provider call must not sit inside
the transaction that converges a payment: the customer has paid, and their payment
must not be rolled back because an invoicing API was slow. Provisioning already
unblocks on payment rather than on issuance, so deferring costs nothing.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from django.core.cache import cache
from django.db.models import Q

from apps.common.types import Err

from .service import issue_invoice_externally

logger = logging.getLogger(__name__)

# Rotation state for `sweep_pending_issuances`: a `(created_at, pk)` keyset rather than a single
# integer, because `ProviderIssuance.id` is a UUID and this sweep orders by `created_at`, so
# `pk__gt` alone is neither the ordering nor a complete resume point.
_PENDING_CURSOR_KEY = "billing:pending-issuance-sweep-cursor"


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


def _cursor_for(issuance: Any) -> list[str]:
    """Where the next run resumes: the last examined row's ordering key, as plain strings.

    Stored as text rather than as a datetime and a UUID so the value survives any cache
    backend's serialisation unchanged.
    """
    return [issuance.created_at.isoformat(), str(issuance.pk)]


def _resume_after(candidates: Any, cursor: Any) -> Any:
    """Everything ordered after the cursor, by `(created_at, pk)`.

    The second arm is what the tiebreaker is for: when a page ends between two rows sharing a
    timestamp, `created_at__gt` alone would step over the one that was never examined.
    """
    if not cursor:
        return candidates
    stamp, last_pk = cursor
    at = datetime.fromisoformat(stamp)
    return candidates.filter(Q(created_at__gt=at) | Q(created_at=at, pk__gt=last_pk))


def sweep_pending_issuances(limit: int = 100) -> dict[str, int]:
    """Pick up issuances whose queue callback never ran.

    `on_commit` fires in-process: a crash between the conversion commit and the
    callback loses the enqueue but not the row, which is why the row is created in
    that transaction. This is the other half of that arrangement.

    Narrow on purpose: `pending` and `failed` only. `outcome_unknown` is never swept by
    anything, and an expired `claimed` row is `sweep_abandoned_claims`' business - it used
    to say the claim path handled that, which was true only if some later attempt happened
    to reach `_claim` for the same invoice, and nothing guaranteed one ever would.
    """
    from apps.billing.fiscal_correction_worker import queue_fiscal_correction  # noqa: PLC0415
    from apps.billing.invoice_models import DOCUMENT_KIND_CREDIT_NOTE  # noqa: PLC0415  # ADR-0007

    from .models import MAX_SUBMISSIONS, IssuanceState, ProviderIssuance  # noqa: PLC0415

    # `pending` records that a provider call is owed, not WHICH one, so this dispatches
    # by document kind rather than filtering one out: a rate-gated reversal POSTed to /invoice
    # would mint a new document instead of reversing one. A reversal is resumed through the
    # fiscal correction it issues, which names exactly this document; the original's id did
    # not, once an original could carry more than one credit note.
    #
    # `failed` is included because `claim()` accepts it: a refusal earns REJECTED only
    # from a recognised refusal envelope, which is the classifier's guarantee that
    # nothing was created. The cap is what keeps a permanent validation error from
    # being resubmitted forever against a rate-limited third party.
    candidates = (
        ProviderIssuance.objects.filter(
            state__in=(IssuanceState.PENDING.value, IssuanceState.FAILED.value),
            invoice__number__isnull=True,
            submissions__lt=MAX_SUBMISSIONS,
        )
        .select_related("invoice")
        # `pk` is not decoration: two rows can share a `created_at`, and without a tiebreaker
        # the resume point below cannot tell which of them a page ended on.
        .order_by("created_at", "pk")
    )

    # A row that can never succeed - a credit note with no original to reverse, or one whose
    # enqueue keeps failing - stays a candidate forever. Always taking the oldest N would let a
    # handful of those occupy every run while a genuinely recoverable issuance behind them is
    # never reached, and that invoice has no legal number and no other automated path to one.
    # The cursor advances past whatever was examined and wraps at the end, so every candidate is
    # reached within a bounded number of runs. Losing the cursor to cache eviction restarts the
    # rotation, which is harmless, and where the cache is a no-op the sweep degrades to always scanning from the
    # oldest row - correct, just not fair. Fairness only matters once rows are permanently
    # stuck, which is itself the alarm condition.
    cursor = cache.get(_PENDING_CURSOR_KEY)
    owed = list(_resume_after(candidates, cursor)[:limit])
    if not owed and cursor:
        owed = list(candidates[:limit])
    # Set BEFORE the work, as the sibling does, so a crash part-way through still advances and
    # the same stuck row cannot be retried from the top of every run.
    cache.set(_PENDING_CURSOR_KEY, _cursor_for(owed[-1]) if owed else None, timeout=None)

    results = {"queued": 0, "skipped": 0, "exhausted": 0}
    for issuance in owed:
        invoice = issuance.invoice
        if invoice.document_kind == DOCUMENT_KIND_CREDIT_NOTE:
            # A reversal is resumed by the fiscal correction it issues: the correction's worker
            # finds this very document through its issuance and claims it again.
            if issuance.fiscal_correction_id is None:
                logger.error(
                    f"🔥 [Issuance] Credit note {invoice.pk} answers to no fiscal correction; "
                    f"it cannot be recovered automatically."
                )
                results["skipped"] += 1
                continue
            # `queue_fiscal_correction` never raises: a lost enqueue is the correction sweep's.
            queued: str | bool | None = queue_fiscal_correction(issuance.fiscal_correction_id)
        else:
            queued = queue_invoice_issuance(invoice.pk)
        results["queued" if queued else "skipped"] += 1

    # The sweep's own state set, not `FAILED` alone. `_finalize` is the only thing that
    # spends the budget and it always lands on a terminal state, so a capped row used to be
    # `failed` by construction. The old history's migration 0057 backfilled budgets spent
    # before the column existed, and `attempts` cannot say which state that spending ended in - so a capped
    # `pending` row became reachable for the first time. Read narrowly, this gauge answered
    # zero for it while `submissions__lt` kept the sweep off it and the reconciliation queue
    # listed it nowhere. Exhausted means the rows the sweep would take but for the cap.
    exhausted = ProviderIssuance.objects.filter(
        state__in=(IssuanceState.PENDING.value, IssuanceState.FAILED.value),
        invoice__number__isnull=True,
        submissions__gte=MAX_SUBMISSIONS,
    ).count()
    if exhausted:
        results["exhausted"] = exhausted
        # A gauge, not an event. This is a standing backlog, so raising it as an error on
        # every sweep run alarmed repeatedly about a condition that does not change between
        # runs and that nothing in this process can act on. It now has a screen and an
        # owner - the reconciliation queue - and the number is returned for whoever wants it.
        logger.warning(
            f"⚠️ [Issuance] {exhausted} document(s) awaiting an operator after spending "
            f"their {MAX_SUBMISSIONS} submission attempts; listed in the reconciliation queue."
        )
    return results


def sweep_abandoned_claims(limit: int = 100) -> dict[str, int]:
    """Route claims whose worker never reported back to a human.

    A worker that dies after committing `claimed` leaves a row that no sweep selects -
    they look at `pending` and `failed` - and that no screen lists, because the operator
    queue shows `outcome_unknown`. Quarantine happened only if another attempt for the
    same invoice later reached `_claim`, which depends on a redelivery that may never
    come and which `prepare` can fail before, returning an ordinary task result while the
    expired claim stays invisible. `ProviderIssuance.abandoned()` was written for exactly
    this case and had no caller.

    Never resubmits, and never will: a crash immediately before the POST and one
    immediately after the provider created the document leave identical durable state, so
    an expired lease is evidence of nothing. That uncertainty IS `outcome_unknown`, and
    only an operator who has checked the provider can resolve it.
    """
    from django.db import transaction  # noqa: PLC0415

    from .models import IssuanceState, ProviderIssuance  # noqa: PLC0415

    quarantined = 0
    for candidate in list(ProviderIssuance.abandoned().order_by("created_at")[:limit]):
        with transaction.atomic():
            issuance = ProviderIssuance.objects.select_for_update().get(pk=candidate.pk)
            # Re-read under the lock. Between the selection above and here a worker may
            # have finalised this attempt or renewed its lease, and whatever it decided
            # outranks a sweep that only knows the row looked stale a moment ago.
            if issuance.state != IssuanceState.CLAIMED.value or issuance.claim_is_live:
                continue
            issuance.mark_outcome_unknown(
                reason="A worker abandoned this claim mid-flight; the provider may hold a document."
            )
            issuance.save()
            # Worded to match `_claim`'s line for the identical quarantine: both call sites pass
            # the same `reason`, so they are one event, and a rollup alone cannot say WHICH
            # documents may exist at the provider - the only thing an operator can act on. The
            # aggregate below counts what THIS run quarantined, so it is a summary of these lines
            # rather than a standing backlog; it stays at warning because repeating the same
            # events at error level would only double the noise.
            logger.error(
                f"🔥 [Issuance] Invoice {issuance.invoice_id} had an abandoned claim; quarantined "
                f"for manual reconciliation rather than retried."
            )
            quarantined += 1

    if quarantined:
        logger.warning(
            f"⚠️ [Issuance] Quarantined {quarantined} abandoned claim(s) for manual "
            f"reconciliation; a document may exist at the provider for each."
        )
    return {"quarantined": quarantined}


def sweep_issued_settlements(limit: int = 100) -> dict[str, int]:
    """Recover committed issuance whose settlement callback was lost; never call the provider."""
    from django.db import transaction  # noqa: PLC0415
    from django.db.models import F, Sum  # noqa: PLC0415

    from apps.billing.invoice_models import DOCUMENT_KIND_INVOICE, ISSUER_BUILTIN, Invoice  # noqa: PLC0415

    from .models import IssuanceState  # noqa: PLC0415
    from .service import _settle_issued_document  # noqa: PLC0415

    candidates = (
        Invoice.objects.filter(
            document_kind=DOCUMENT_KIND_INVOICE,
            status__in=("issued", "overdue"),
            number__isnull=False,
            issued_at__isnull=False,
            provider_issuance__state=IssuanceState.ISSUED.value,
        )
        .exclude(issuer_provider=ISSUER_BUILTIN)
        .exclude(number="")
        .annotate(collected=Sum("payments__amount_cents", filter=Q(payments__status="succeeded"), default=0))
        .filter(Q(total_cents=0) | Q(collected__gte=F("total_cents")))
        .order_by("pk")
    )
    # Rotate past failed rows so a persistent failure cannot starve later invoices.
    cursor_key = "billing:issued-settlement-sweep-cursor"
    cursor = cache.get(cursor_key)
    owed = list((candidates.filter(pk__gt=cursor) if cursor is not None else candidates)[:limit])
    if not owed and cursor is not None:
        owed = list(candidates[:limit])
    cache.set(cursor_key, owed[-1].pk if owed else None, timeout=None)

    results = {"settled": 0, "failed": 0, "skipped": 0}
    for candidate in owed:
        with transaction.atomic():
            invoice = Invoice.objects.select_for_update().get(pk=candidate.pk)
            # Another worker may have settled it. Refunds may have reduced the balance.
            if invoice.status not in {"issued", "overdue"} or invoice.get_remaining_amount() > 0:
                results["skipped"] += 1
                continue
            settlement = _settle_issued_document(invoice.pk)
            results["failed" if settlement.is_err() else "settled"] += 1
    return results


def setup_issuance_scheduled_tasks() -> dict[str, str]:
    """Install settlement recovery even when no external provider is currently enabled."""
    from django_q.models import Schedule  # noqa: PLC0415

    _schedule, created = Schedule.objects.update_or_create(
        name="billing-issued-settlement-sweep",
        defaults={
            "func": "apps.billing.issuers.tasks.sweep_issued_settlements",
            "schedule_type": Schedule.MINUTES,
            "minutes": 5,
            "repeats": -1,
        },
    )
    logger.info("✅ [Issuance] Settlement recovery schedule configured")
    return {"issued_settlements": "created" if created else "already_exists"}
