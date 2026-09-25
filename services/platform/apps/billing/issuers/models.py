"""Durable state for external issuance.

Only the pacing gate lives here so far. The attempt record (`ProviderIssuance`)
arrives in Phase 6 alongside the orchestration that writes and reconciles it.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Any, ClassVar

from django.db import models, transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django_fsm import FSMField, transition

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


class IssuanceState(StrEnum):
    """Where one external issuance attempt stands."""

    PENDING = "pending"
    """Recorded and committed; no provider call has been made."""

    CLAIMED = "claimed"
    """A worker holds a lease and is about to call, or is calling, the provider."""

    ISSUED = "issued"
    """The provider assigned a number and we recorded it."""

    FAILED = "failed"
    """The provider refused, provably creating nothing. Safe to correct and retry."""

    OUTCOME_UNKNOWN = "outcome_unknown"
    """A document MAY exist at the provider. Never retried automatically."""


# Three real submissions, then a human. A refusal is REJECTED only from a recognised
# refusal envelope, so retrying one is safe - but safe is not the same as likely to
# succeed, and a permanent validation error would otherwise be resubmitted forever
# against a rate-limited third party.
MAX_SUBMISSIONS = 3


class ProviderIssuance(models.Model):
    """The durable record of issuing one invoice through an external provider.

    It exists because SmartBill has no idempotency key and no way to find a
    document by our own reference. If we lose track of an attempt we cannot ask
    the provider what happened, so the record has to survive independently of the
    request that started it — written and committed BEFORE the call, not after.

    `outcome_unknown` is the state this model is really for. A timeout means the
    invoice may or may not exist, with a real number, addressed to a real customer,
    possibly already forwarded to ANAF. Automatically retrying that is how one
    order becomes two legally numbered invoices, and an invoice that is not last in
    its series can never be deleted — only cancelled or reversed. So it stops here
    and waits for a human.
    """

    CLAIM_LEASE = timedelta(minutes=10)

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    invoice = models.OneToOneField(
        "billing.Invoice",
        on_delete=models.CASCADE,
        related_name="provider_issuance",
    )
    provider = models.CharField(max_length=20)
    state = FSMField(
        max_length=20,
        choices=[(s.value, s.value) for s in IssuanceState],
        default=IssuanceState.PENDING.value,
        protected=True,
    )

    # Worker ownership: one lease, so two workers cannot both POST the same invoice.
    claim_token = models.UUIDField(null=True, blank=True)
    claimed_at = models.DateTimeField(null=True, blank=True)
    claim_expires_at = models.DateTimeField(null=True, blank=True)

    # Exactly what was sent, so a reconciling human can compare it to whatever the
    # provider shows them, and so a hash can prove the payload never changed.
    request_payload = models.JSONField(default=dict, blank=True)
    request_hash = models.CharField(max_length=64, blank=True)
    response = models.JSONField(default=dict, blank=True)

    provider_series = models.CharField(max_length=50, blank=True)
    provider_number = models.CharField(max_length=50, blank=True)
    provider_document_id = models.CharField(max_length=100, blank=True)

    # Forensic only. The provider's next-number counter before and after an
    # ambiguous attempt is evidence, never proof: the accountant can issue manually
    # in the web UI at any moment, so a moved counter does not establish ownership.
    observed_next_number_before = models.CharField(max_length=50, blank=True)
    observed_next_number_after = models.CharField(max_length=50, blank=True)

    attempts = models.PositiveIntegerField(default=0)
    # Counted separately from `attempts`, which increments on claim - before pacing -
    # so a deferral that sent nothing would consume a retry budget. This one advances
    # only where a reply came back, which is the only place we know a request left.
    submissions = models.PositiveIntegerField(default=0)
    last_error = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "billing_provider_issuances"
        verbose_name = _("Provider Issuance")
        verbose_name_plural = _("Provider Issuances")
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=["state", "created_at"]),
            models.Index(fields=["provider", "state"]),
        ]

    def __str__(self) -> str:
        return f"ProviderIssuance({self.provider}, {self.state}, invoice={self.invoice_id})"

    @property
    def needs_human_reconciliation(self) -> bool:
        return bool(self.state == IssuanceState.OUTCOME_UNKNOWN.value)

    @property
    def claim_is_live(self) -> bool:
        return bool(self.claim_expires_at and self.claim_expires_at > timezone.now())

    @transition(
        field=state,
        source=[IssuanceState.PENDING.value, IssuanceState.FAILED.value],
        target=IssuanceState.CLAIMED.value,
    )
    def claim(self, *, token: uuid.UUID, payload: dict[str, Any], payload_hash: str) -> None:
        """Take ownership and freeze the payload before any provider call.

        Committed before the network call, so a crash leaves evidence that an
        attempt began rather than silence.
        """
        now = timezone.now()
        self.claim_token = token
        self.claimed_at = now
        self.claim_expires_at = now + self.CLAIM_LEASE
        self.request_payload = payload
        self.request_hash = payload_hash
        self.attempts += 1
        self.last_error = ""

    @transition(field=state, source=IssuanceState.CLAIMED.value, target=IssuanceState.ISSUED.value)
    def mark_issued(self, *, series: str, number: str, document_id: str, response: dict[str, Any]) -> None:
        self.provider_series = series
        self.provider_number = number
        self.provider_document_id = document_id
        self.response = response
        self.claim_token = None
        self.claim_expires_at = None

    @transition(field=state, source=IssuanceState.CLAIMED.value, target=IssuanceState.FAILED.value)
    def mark_failed(self, *, error: str, response: dict[str, Any] | None = None) -> None:
        """The provider refused and provably created nothing, so this may be retried."""
        self.last_error = error
        self.response = response or {}
        self.claim_token = None
        self.claim_expires_at = None

    @transition(field=state, source=IssuanceState.CLAIMED.value, target=IssuanceState.PENDING.value)
    def release_unsent(self, *, reason: str) -> None:
        """Give the claim back, for the one case where nothing can have been sent.

        The rate gate refuses BEFORE any request leaves, so unlike an abandoned
        claim - where a crash before and after the POST look identical - this is the
        one moment we can prove the provider never heard from us. That proof is the
        entire justification for the only edge back to `pending`; do not reuse it for
        any failure that happens once a request is in flight, or a retry will create
        a second legally numbered document.
        """
        self.last_error = reason
        self.claim_token = None
        self.claim_expires_at = None

    @transition(
        field=state,
        source=[IssuanceState.CLAIMED.value, IssuanceState.PENDING.value],
        target=IssuanceState.OUTCOME_UNKNOWN.value,
    )
    def mark_outcome_unknown(self, *, reason: str, response: dict[str, Any] | None = None) -> None:
        """A document may exist at the provider. This is terminal without a human.

        Deliberately NOT retryable: `claim` has no path from here, so no scheduled
        sweep can resurrect it. Only an operator who has checked the provider and
        recorded what they found may move it on.
        """
        self.last_error = reason
        self.response = response or {}
        self.claim_token = None
        self.claim_expires_at = None

    @transition(
        field=state,
        source=IssuanceState.OUTCOME_UNKNOWN.value,
        target=IssuanceState.ISSUED.value,
    )
    def reconcile_as_issued(self, *, series: str, number: str, operator_note: str) -> None:
        """An operator checked the provider and identified the document.

        The ONLY edge out of `outcome_unknown`, and it exists exactly once: the
        provider offers no lookup by our reference, so identifying the document is a
        human judgement. Recording it as a transition rather than a field assignment
        means no other code path can reach `issued` from here by accident.
        """
        self.provider_series = series
        self.provider_number = number
        self.last_error = f"Reconciled by operator: {operator_note}"
        self.claim_token = None
        self.claim_expires_at = None

    @classmethod
    def abandoned(cls) -> models.QuerySet[ProviderIssuance]:
        """Claims whose worker died mid-flight and whose lease has expired.

        Named for what happens to them, not for a retry that must never occur: a
        crash immediately BEFORE the POST and one immediately AFTER the provider
        created the document leave identical durable state. Neither lease expiry nor
        worker death proves nothing was issued, so these are quarantined into
        `outcome_unknown` for a human rather than retried.

        `outcome_unknown` rows are excluded: they are already where these are going.
        """
        return cls.objects.filter(
            state=IssuanceState.CLAIMED.value,
            claim_expires_at__lt=timezone.now(),
        )
