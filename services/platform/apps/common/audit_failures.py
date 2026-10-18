"""Count the audit writes that failed and were swallowed (ADR-0016).

Audit writes are fail-open by design: a failed audit insert must never roll back the money-moving
transaction that caused it. The cost of that choice is a missed event, and a missed event nobody
hears about is a hole in the trail. ``AuditService.log_event`` marks the exception it re-raises;
the fail-open wrappers in ``apps.common.transactions`` count a marked exception once they have
rolled the failed write back. ``count()`` is what a health check reads.

The mark rides on the exception object, not on thread or request state, so an audit failure that
propagates to the caller is never counted, and an unrelated failure is never mistaken for one.
"""

from __future__ import annotations

import logging

from django.db import transaction

from apps.common import counters

logger = logging.getLogger(__name__)

AUDIT_WRITE_FAILURES_KEY = "audit_write_failures"
WINDOW_SECONDS = 30 * 24 * 3600  # the count covers the last thirty days from the first failure

_MARK = "_audit_write_failure"


def mark(error: BaseException) -> None:
    """Flag an exception as the failure of an audit write."""
    setattr(error, _MARK, True)


def is_marked(error: BaseException) -> bool:
    return bool(getattr(error, _MARK, False))


def record(error: BaseException) -> None:
    """Count a swallowed audit write failure, without ever failing the caller."""
    if not is_marked(error):
        return
    try:
        with transaction.atomic():
            counters.increment(AUDIT_WRITE_FAILURES_KEY, WINDOW_SECONDS)
    except Exception:
        logger.exception("🔥 [Audit] Could not count a failed audit write")


def count() -> int:
    """Audit writes that failed and were swallowed in the current window."""
    return counters.peek(AUDIT_WRITE_FAILURES_KEY)
