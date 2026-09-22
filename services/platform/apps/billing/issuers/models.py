"""Durable state for external issuance.

Only the pacing gate lives here so far. The attempt record (`ProviderIssuance`)
arrives in Phase 6 alongside the orchestration that writes and reconciles it.
"""

from __future__ import annotations

import hashlib
from datetime import timedelta
from typing import TYPE_CHECKING

from django.db import models, transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

if TYPE_CHECKING:
    from datetime import datetime


class SmartBillRateGate(models.Model):
    """Decides, for one API token, whether an outbound call may happen right now.

    SmartBill allows 30 calls per 10 seconds per token and **blocks the token for
    ten minutes** if that is exceeded. During an hourly recurring-billing run a
    ten-minute block is not a slowdown, it is an outage.

    Grant-or-defer, not reserve-and-hope. An earlier design handed out future
    timeslots and trusted the caller to wait; callers did not, so thirteen calls
    could fire at once while the schedule looked correct. `acquire()` therefore
    either grants permission *now* and advances the schedule, or refuses and says
    when to come back — refusing consumes nothing, so a deferred task cannot push
    itself further into the future each time it retries.

    A shared counter would not do: several Django-Q2 workers plus a staff member
    clicking "issue" can all read the same remaining count and all spend it. Here
    the second caller blocks on the row lock until the first has already advanced
    the schedule.
    """

    # One interval per call. 400ms is ~25 calls/10s, leaving headroom under 30 for
    # anything spending the same token outside this gate.
    INTERVAL = timedelta(milliseconds=400)

    # Fallback when a 429 arrives without a usable Retry-After: SmartBill documents
    # a ten-minute block, so assume the worst rather than probing and extending it.
    DEFAULT_BLOCK = timedelta(minutes=10)

    token_fingerprint = models.CharField(
        max_length=64,
        unique=True,
        help_text=_("SHA-256 of the API token. The token itself is never stored."),
    )
    next_allowed_at = models.DateTimeField(default=timezone.now)
    blocked_until = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("Set when the provider throttles us; suppresses every worker, not just one."),
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "billing_smartbill_rate_gates"
        verbose_name = _("SmartBill Rate Gate")
        verbose_name_plural = _("SmartBill Rate Gates")

    def __str__(self) -> str:
        return f"SmartBillRateGate({self.token_fingerprint[:12]}…)"

    @staticmethod
    def fingerprint(token: str) -> str:
        """Identify a token without storing it."""
        return hashlib.sha256(token.encode()).hexdigest()

    @classmethod
    def acquire(cls, token: str) -> datetime | None:
        """Grant permission to call now, or say when to try again.

        Returns `None` to proceed immediately. Returns a datetime to defer — and
        deliberately does NOT reserve that moment, so repeated deferrals cannot
        starve a task by pushing its slot ever further out.

        `durable=True` refuses to run inside an enclosing transaction (ADR-0045).
        That is the point: the schedule must commit before the network call, or an
        outer rollback would erase our record of a call the provider already saw,
        and the row lock would be held open across HTTP.
        """
        with transaction.atomic(durable=True):
            gate, _created = cls.objects.select_for_update().get_or_create(token_fingerprint=cls.fingerprint(token))
            # Sampled AFTER the lock: a timestamp read before waiting on the lock
            # can already be stale, which would let delayed workers burst together.
            now = timezone.now()

            if gate.blocked_until and gate.blocked_until > now:
                return gate.blocked_until
            if gate.next_allowed_at > now:
                return gate.next_allowed_at

            gate.next_allowed_at = now + cls.INTERVAL
            gate.save(update_fields=["next_allowed_at", "updated_at"])
            return None

    @classmethod
    def record_throttled(cls, token: str, retry_after_seconds: int | None = None) -> datetime:
        """Record that the provider throttled us, suppressing every worker.

        Returning `Retry-After` to the one caller that saw the 429 leaves the rest
        free to keep spending the same token, which is how a short throttle becomes
        the documented ten-minute block.
        """
        block_for = timedelta(seconds=retry_after_seconds) if retry_after_seconds else cls.DEFAULT_BLOCK
        with transaction.atomic(durable=True):
            gate, _created = cls.objects.select_for_update().get_or_create(token_fingerprint=cls.fingerprint(token))
            until = timezone.now() + block_for
            gate.blocked_until = max(until, gate.blocked_until) if gate.blocked_until else until
            gate.save(update_fields=["blocked_until", "updated_at"])
            return gate.blocked_until
