"""Classifying what SmartBill actually told us.

This module exists because the obvious reading of a SmartBill response is wrong in
three separate ways, and each one can cost a duplicate fiscal invoice:

1. **The HTTP status is not the verdict.** A perfectly ordinary failure arrives as
   `200 OK` with a populated `errorText`. Code that branches on `response.ok`
   records a failed issuance as a success.

2. **The body is not always JSON.** A misspelled field name returns `500` with an
   HTML page. A parser that assumes JSON raises somewhere unhelpful.

3. **Failure is not one thing.** "The provider refused and created nothing" and
   "we never found out" demand opposite handling. Only the first may be retried.
   Getting this backwards turns one order into two legally numbered documents, and
   an invoice that is not last in its series can never be deleted, only reversed.

The published OpenAPI schema is also incomplete: a real `401` carries
`successfully`, `errorCode`, `key`, `id` and `documentNumber`, none of which appear
in it. Recorded live responses are the contract; the spec is a starting point.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from http import HTTPStatus
from typing import Any


class Verdict(Enum):
    """What a response proves about provider-side state."""

    SUCCESS = "success"
    """The document exists and we know its number."""

    REJECTED = "rejected"
    """The provider refused. Provably nothing was created; safe to fix and retry."""

    AMBIGUOUS = "ambiguous"
    """Unknown. A document MAY exist. Never retry automatically."""


@dataclass(frozen=True)
class SmartBillResponse:
    """A classified SmartBill reply."""

    verdict: Verdict
    status: int | None
    payload: dict[str, Any] = field(default_factory=dict)
    error_text: str = ""
    error_codes: tuple[str, ...] = ()
    retry_after_seconds: int | None = None
    raw_body: str = ""

    @property
    def is_success(self) -> bool:
        return self.verdict is Verdict.SUCCESS


def first_sentence(error_text: str) -> str:
    """Take the human cause out of an `errorText` that may carry HTML.

    SmartBill appends markup aimed at its own web UI — `<br/>` hints, `<b>` around
    document names, a hidden `<div id="moreErrorDetails">` with help text. The cause
    is always the leading plain text, so cut at the first tag rather than rendering
    or stripping markup we did not author.
    """
    return error_text.split("<", 1)[0].strip()


@dataclass(frozen=True)
class RawReply:
    """Everything observed about one HTTP exchange, before interpretation."""

    status: int | None
    body: str = ""
    parsed: dict[str, Any] | None = None
    retry_after: int | None = None
    transport_failed: bool = False
    is_write: bool = False


def classify(reply: RawReply) -> SmartBillResponse:  # noqa: C901, PLR0911  # A decision table: one branch per reply shape, one return per verdict. Splitting it scatters the money-safety reasoning across functions.
    """Decide what a reply proves, erring towards AMBIGUOUS whenever unsure.

    `is_write` is the important argument. On a read, a wrong verdict costs a retry
    of a GET. On a write, REJECTED is a licence to send the same POST again — and
    SmartBill has no idempotency key, so a wrong REJECTED creates a second legally
    numbered invoice which can never be deleted, only reversed, and may already be
    in SPV. Writes therefore earn REJECTED only from a *recognised* refusal
    envelope; everything else unknown is AMBIGUOUS.
    """
    status, body, parsed = reply.status, reply.body, reply.parsed
    retry_after, transport_failed, is_write = reply.retry_after, reply.transport_failed, reply.is_write

    # No reply at all: the request may or may not have been processed.
    if transport_failed or status is None:
        return SmartBillResponse(
            verdict=Verdict.AMBIGUOUS,
            status=status,
            raw_body=body,
            error_text="No usable reply from SmartBill; the document may or may not exist.",
        )

    # A rate limiter conventionally refuses before the request reaches invoicing
    # logic, so nothing would have been created - but SmartBill has not confirmed
    # that for write endpoints (question 5 in the outstanding support email), and
    # their limit is an account-level policy rather than an obvious edge throttle.
    # An unconfirmed assumption is not a recognised refusal envelope, so a write does
    # not get to replay on it. Our own gate defers before sending, so a 429 arriving
    # at all means pacing has already failed: a rare event, and cheap to reconcile by
    # hand compared with a duplicate fiscal invoice. Reads keep the cheap verdict.
    #
    # `error_codes` and `retry_after_seconds` are preserved deliberately - the client
    # keys throttle recording off the code, not the verdict, so the token is still
    # blocked for every worker either way.
    if status == HTTPStatus.TOO_MANY_REQUESTS:
        return SmartBillResponse(
            verdict=Verdict.AMBIGUOUS if is_write else Verdict.REJECTED,
            status=status,
            payload=parsed or {},
            error_text="Rate limit exceeded",
            error_codes=("rate_limit_exceeded",),
            retry_after_seconds=retry_after,
            raw_body=body,
        )

    # Any 5xx is unknown, including the documented HTML-body case for a misspelled
    # field. That case provably creates nothing, but it cannot be told apart from a
    # genuine server error *after* the document was written, and the two demand
    # opposite handling. A malformed request is a developer error caught in testing;
    # a duplicate invoice is a fiscal problem. Fail towards the cheap one.
    if status >= HTTPStatus.INTERNAL_SERVER_ERROR:
        return SmartBillResponse(
            verdict=Verdict.AMBIGUOUS,
            status=status,
            payload=parsed or {},
            error_text=f"SmartBill returned {status}; the document may or may not exist.",
            raw_body=body,
        )

    # An unparseable body below 500 is NOT proof the request never ran. A truncated
    # or intermediary-mangled reply can hide a completed write.
    if parsed is None:
        return SmartBillResponse(
            verdict=Verdict.AMBIGUOUS if is_write else Verdict.REJECTED,
            status=status,
            error_text=f"SmartBill returned an unparseable body with status {status}",
            raw_body=body,
        )

    # A recognised refusal envelope: the V3 shape, rejected before business logic.
    if isinstance(parsed.get("errors"), list) and parsed["errors"]:
        codes: list[str] = []
        messages: list[str] = []
        structured = False
        for entry in parsed["errors"]:
            if not isinstance(entry, dict):
                continue
            structured = True
            codes.append(str(entry.get("code", "")))
            param = entry.get("param")
            message = str(entry.get("message", ""))
            messages.append(f"{message} ({param})" if param else message)
        # A bare list of strings is failure-SHAPED, not a recognised envelope, so it
        # must not buy a write the right to replay.
        return SmartBillResponse(
            verdict=Verdict.REJECTED if (structured or not is_write) else Verdict.AMBIGUOUS,
            status=status,
            payload=parsed,
            error_text="; ".join(m for m in messages if m) or "Unrecognised error envelope",
            error_codes=tuple(c for c in codes if c),
            raw_body=body,
        )

    # The V1 rule: errorText is the verdict, whatever the status says. This is the
    # documented business-validation refusal, so it is a recognised envelope.
    error_text = str(parsed.get("errorText") or "").strip()
    if error_text:
        # …unless the same reply also carries issuance identifiers, which would be
        # contradictory. Contradiction must never authorise a replay.
        if is_write and str(parsed.get("number") or "").strip():
            return SmartBillResponse(
                verdict=Verdict.AMBIGUOUS,
                status=status,
                payload=parsed,
                error_text=f"Contradictory reply: errorText set but a number was returned ({first_sentence(error_text)})",
                raw_body=body,
            )
        return SmartBillResponse(
            verdict=Verdict.REJECTED,
            status=status,
            payload=parsed,
            error_text=first_sentence(error_text),
            raw_body=body,
        )

    # A 4xx carrying no refusal envelope is the ABSENCE of evidence, not evidence of
    # absence. 408 is the plainest case - the server timed out, possibly after writing
    # the document - and 409 and the intermediary-generated 4xx behave the same way.
    # Everything above this point that could name a reason has already returned, so
    # reaching here on a write means we cannot say what happened.
    if status >= HTTPStatus.BAD_REQUEST:
        return SmartBillResponse(
            verdict=Verdict.AMBIGUOUS if is_write else Verdict.REJECTED,
            status=status,
            payload=parsed,
            error_text=f"SmartBill returned {status} with no errorText",
            raw_body=body,
        )

    # Undocumented but observed live. It is evidence the call did not succeed; it is
    # NOT evidence that nothing was created, so on a write it denies SUCCESS without
    # granting the right to retry.
    if parsed.get("successfully") is False:
        return SmartBillResponse(
            verdict=Verdict.AMBIGUOUS if is_write else Verdict.REJECTED,
            status=status,
            payload=parsed,
            error_text=str(parsed.get("message") or "SmartBill reported the call was unsuccessful"),
            error_codes=(str(parsed.get("errorCode")),) if parsed.get("errorCode") else (),
            raw_body=body,
        )

    # SUCCESS must mean "the document exists and we know its number". A 200 with an
    # empty body satisfies no part of that.
    if is_write and not str(parsed.get("number") or "").strip():
        return SmartBillResponse(
            verdict=Verdict.AMBIGUOUS,
            status=status,
            payload=parsed,
            error_text="SmartBill returned no error and no document number",
            raw_body=body,
        )

    return SmartBillResponse(verdict=Verdict.SUCCESS, status=status, payload=parsed, raw_body=body)
