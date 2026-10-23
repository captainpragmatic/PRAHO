"""Durable delivery attempts and provider failure classification."""

from __future__ import annotations

import smtplib
from datetime import datetime, timedelta
from http import HTTPStatus
from typing import Any
from uuid import UUID, uuid4

from anymail.exceptions import (
    AnymailAPIError,
    AnymailConfigurationError,
    AnymailInvalidAddress,
    AnymailRecipientsRefused,
    AnymailSerializationError,
    AnymailUnsupportedFeature,
)
from django.core.mail import BadHeaderError
from django.db import transaction
from django.utils import timezone

from apps.notifications.models import EmailLog
from apps.notifications.services import validate_email_log_subject
from apps.settings.services import SettingsService, get_default_from_email

DEFAULT_MAX_RETRIES = 3
# How long a claim holds. The provider send is bounded well below it (EMAIL_TIMEOUT), and the worker
# renews it immediately before the provider call, so a live sender is never reclaimed.
CLAIM_LEASE = timedelta(minutes=10)
# A row left `sending` before claims had leases (or by a crash before its lease was written) counts as
# abandoned only this long after it was created.
UNLEASED_SENDING_GRACE = timedelta(minutes=15)
SMTP_PERMANENT_FAILURE = 500
RETRYABLE_CLIENT_STATUSES = {
    HTTPStatus.REQUEST_TIMEOUT,
    HTTPStatus.CONFLICT,
    HTTPStatus.TOO_EARLY,
    HTTPStatus.TOO_MANY_REQUESTS,
}
AWS_TRANSIENT_ERROR_CODES = {
    "Throttling",
    "ThrottlingException",
    "TooManyRequestsException",
    "RequestTimeout",
    "RequestTimeoutException",
    "ServiceUnavailable",
    "ServiceUnavailableException",
    "InternalFailure",
    "InternalError",
}


class InvalidRetryMetadataError(ValueError):
    """A corrupt row cannot safely decide its remaining attempt budget."""


def retry_index(row: EmailLog) -> int:
    response = row.provider_response or {}
    if not isinstance(response, dict):
        raise InvalidRetryMetadataError("Invalid email retry metadata")
    index: object = response.get("retry_count", 0)
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        raise InvalidRetryMetadataError("Invalid email retry counter")
    return max(index, row.delivery_attempts)


def max_retries() -> int:
    """The one retry budget: a message may be attempted `max_retries() + 1` times in all."""
    return max(0, SettingsService.get_integer_setting("notifications.email_max_retries", DEFAULT_MAX_RETRIES))


def retry_delay(attempts: int) -> timedelta:
    """The backoff before the next attempt, from settings.EMAIL_RETRY (the one place it is computed)."""
    from django.conf import settings  # noqa: PLC0415  # Read at call time; tests override it

    config = getattr(settings, "EMAIL_RETRY", {})
    base = config.get("RETRY_DELAY_SECONDS", 60)
    return timedelta(seconds=base * (2**attempts) if config.get("EXPONENTIAL_BACKOFF", True) else base)


def budget_spent(row: EmailLog) -> bool:
    return retry_index(row) >= max_retries() + 1


def _release(row: EmailLog) -> list[str]:
    row.claim_token = None
    row.lease_until = None
    return ["claim_token", "lease_until"]


def mark_permanent(row: EmailLog, reason: str) -> None:
    """A terminal failure. The caller holds the row lock (a status save keeps the audit signal)."""
    response = row.provider_response if isinstance(row.provider_response, dict) else {}
    row.status = "failed"
    row.provider_response = {**response, "final_error": reason, "permanent_failure": True}
    row.next_attempt_at = None
    row.save(update_fields=["status", "provider_response", "next_attempt_at", *_release(row)])


def mark_exhausted(row: EmailLog) -> None:
    """The retry budget is spent. The caller holds the row lock."""
    response = row.provider_response if isinstance(row.provider_response, dict) else {}
    row.status = "failed"
    row.provider_response = {**response, "final_error": "Email retry budget exhausted", "retry_exhausted": True}
    row.next_attempt_at = None
    row.save(update_fields=["status", "provider_response", "next_attempt_at", *_release(row)])


def claimable(row: EmailLog, now: datetime) -> bool:
    """Whether a worker may claim the row now: a due `queued` row, or a `sending` row nobody holds."""
    if row.status == "queued":
        return row.next_attempt_at is None or row.next_attempt_at <= now
    if row.status == "sending":
        if row.lease_until is not None:
            return row.lease_until < now
        return row.sent_at < now - UNLEASED_SENDING_GRACE
    return False  # sent, delivered, bounced, complained, failed: never sent again by a claim


def claim_delivery(
    email_log_id: str,
    subject: str | None = None,
    sender: str | None = None,
    supplied_retry: int = 0,
) -> tuple[EmailLog | None, dict[str, Any] | None]:
    """Claim the row for one send, or refuse. A claim writes a fresh `claim_token` and a lease.

    Every later write about this send (renewal, success, failure) must present that token: a worker
    whose lease expired and whose row another worker reclaimed writes nothing.
    """
    maximum = max_retries()
    with transaction.atomic():
        row = EmailLog.objects.select_for_update().filter(pk=email_log_id).first()
        if row is None:
            return None, {"success": False, "error": "EmailLog not found", "retry_scheduled": False}
        now = timezone.now()
        if not claimable(row, now):
            return row, {"success": False, "error": f"Not claimable: {row.status}", "retry_scheduled": False}
        try:
            if isinstance(supplied_retry, bool) or not isinstance(supplied_retry, int) or supplied_retry < 0:
                raise InvalidRetryMetadataError("Invalid email task retry counter")
            index = max(retry_index(row), supplied_retry)
        except InvalidRetryMetadataError as error:
            mark_permanent(row, str(error))
            return row, {"success": False, "error": str(error), "retry_scheduled": False}
        if (subject_error := validate_email_log_subject(row, row.subject if subject is None else subject)) is not None:
            return row, {"success": False, "error": subject_error, "retry_scheduled": False}
        if index >= maximum + 1:
            mark_exhausted(row)
            return row, {
                "success": False,
                "error": "Email retry budget exhausted",
                "retry_scheduled": False,
                "max_retries_exceeded": True,
            }
        row.from_addr = sender if sender is not None else row.from_addr or get_default_from_email()
        row.status = "sending"
        row.delivery_attempts = index + 1
        row.claim_token = uuid4()
        row.lease_until = now + CLAIM_LEASE
        row.next_attempt_at = None
        row.save(
            update_fields=["status", "from_addr", "delivery_attempts", "claim_token", "lease_until", "next_attempt_at"]
        )
        return row, None


def renew_claim(email_log_id: str, token: UUID | None) -> bool:
    """Immediately before the provider call: the claim is still ours, renewed. False: send nothing."""
    with transaction.atomic():
        row = EmailLog.objects.select_for_update().filter(pk=email_log_id).first()
        if row is None or token is None or row.status != "sending" or row.claim_token != token:
            return False
        row.lease_until = timezone.now() + CLAIM_LEASE
        row.save(update_fields=["lease_until"])
        return True


def record_success(email_log_id: str, token: UUID | None, *, provider_id: str, response: dict[str, Any]) -> bool:
    """The send this claim made was accepted. Nothing is written for a claim that is no longer ours.

    Delivery callbacks that arrived before the provider id was known are applied here, under the same lock.
    """
    from apps.notifications.services import apply_pending_delivery_events  # noqa: PLC0415  # Circular

    with transaction.atomic():
        row = EmailLog.objects.select_for_update().filter(pk=email_log_id).first()
        if row is None or token is None or row.status != "sending" or row.claim_token != token:
            return False
        row.status = "sent"
        row.sent_at = timezone.now()
        fields = ["status", "sent_at", *_release(row)]
        if provider_id:
            row.provider_id = provider_id
            fields.append("provider_id")
        if response:
            current = row.provider_response if isinstance(row.provider_response, dict) else {}
            row.provider_response = {**current, **response}
            fields.append("provider_response")
        row.save(update_fields=fields)
        if provider_id:
            apply_pending_delivery_events(row)
        return True


def permanent_provider_error(error: Exception) -> bool:
    if isinstance(
        error,
        (
            BadHeaderError,
            AnymailInvalidAddress,
            AnymailRecipientsRefused,
            AnymailSerializationError,
            AnymailUnsupportedFeature,
            AnymailConfigurationError,
            InvalidRetryMetadataError,
        ),
    ):
        return True
    if isinstance(error, smtplib.SMTPResponseException):
        return error.smtp_code >= SMTP_PERMANENT_FAILURE
    if isinstance(error, smtplib.SMTPRecipientsRefused):
        return bool(error.recipients) and all(
            code >= SMTP_PERMANENT_FAILURE for code, _message in error.recipients.values()
        )
    response = getattr(error, "response", None)
    if not isinstance(response, dict):
        response = getattr(error.__cause__, "response", None)
    details = response.get("Error") if isinstance(response, dict) else None
    code = details.get("Code") if isinstance(details, dict) else None
    code = code if isinstance(code, str) else None
    # SES can throttle with HTTP 400, so provider semantics take precedence.
    if code in AWS_TRANSIENT_ERROR_CODES:
        return False
    if code in {
        "MessageRejected",
        "MailFromDomainNotVerifiedException",
        "ConfigurationSetDoesNotExistException",
        "AccountSuspendedException",
        "SendingPausedException",
    }:
        return True
    status: object = getattr(error, "status_code", None)
    metadata = response.get("ResponseMetadata") if isinstance(response, dict) else None
    if status is None and isinstance(metadata, dict):
        status = metadata.get("HTTPStatusCode")
    return (
        isinstance(error, AnymailAPIError)
        and isinstance(status, int)
        and HTTPStatus.BAD_REQUEST <= status < HTTPStatus.INTERNAL_SERVER_ERROR
        and status not in RETRYABLE_CLIENT_STATUSES
    )


def record_sync_failure(email_log_id: str, error: Exception, token: UUID | None) -> None:
    """A synchronous send failed. It is not retried here: a retryable failure is left `failed`
    (the failed-email sweep may retry it asynchronously); a permanent one is marked permanent."""
    with transaction.atomic():
        row = EmailLog.objects.select_for_update().filter(pk=email_log_id).first()
        if row is None or token is None or row.status != "sending" or row.claim_token != token:
            return
        if permanent_provider_error(error):
            mark_permanent(row, str(error))
            return
        response = row.provider_response if isinstance(row.provider_response, dict) else {}
        row.status = "failed"
        row.provider_response = {**response, "error": str(error), "final_error": str(error)}
        row.save(update_fields=["status", "provider_response", *_release(row)])


def record_failure(email_log_id: str, error: Exception, token: UUID | None) -> tuple[EmailLog | None, bool]:
    """The send this claim made failed. (row, retry): nothing is written for a claim no longer ours."""
    maximum = max_retries()
    with transaction.atomic():
        row = EmailLog.objects.select_for_update().filter(pk=email_log_id).first()
        if row is None:
            return None, False
        if token is None or row.status != "sending" or row.claim_token != token:
            return row, False
        if permanent_provider_error(error):
            mark_permanent(row, str(error))
            return row, False
        response = row.provider_response if isinstance(row.provider_response, dict) else {}
        retry = row.delivery_attempts <= maximum
        row.status = "queued" if retry else "failed"
        # The due time is set in the same write, so no sweep sees a retryable row without one.
        row.next_attempt_at = timezone.now() + retry_delay(row.delivery_attempts) if retry else None
        row.provider_response = {
            **response,
            "retry_count": row.delivery_attempts,
            "final_error": str(error),
            "retry_exhausted": not retry,
        }
        row.save(update_fields=["status", "provider_response", "next_attempt_at", *_release(row)])
        return row, retry
