"""Durable delivery attempts and provider failure classification."""

from __future__ import annotations

import smtplib
from http import HTTPStatus
from typing import Any

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

from apps.notifications.models import EmailLog
from apps.notifications.services import validate_email_log_subject
from apps.settings.services import SettingsService, get_default_from_email

DEFAULT_MAX_RETRIES = 3
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


def mark_permanent(row: EmailLog, reason: str) -> None:
    response = row.provider_response if isinstance(row.provider_response, dict) else {}
    row.status = "failed"
    row.provider_response = {**response, "final_error": reason, "permanent_failure": True}
    row.save(update_fields=["status", "provider_response"])


def claim_delivery(
    email_log_id: str,
    subject: str,
    sender: str | None,
    supplied_retry: int,
) -> tuple[EmailLog | None, dict[str, Any] | None]:
    maximum = max(0, SettingsService.get_integer_setting("notifications.email_max_retries", DEFAULT_MAX_RETRIES))
    with transaction.atomic():
        row = EmailLog.objects.select_for_update().filter(pk=email_log_id).first()
        if row is None:
            return None, {"success": False, "error": "EmailLog not found", "retry_scheduled": False}
        try:
            if isinstance(supplied_retry, bool) or not isinstance(supplied_retry, int) or supplied_retry < 0:
                raise InvalidRetryMetadataError("Invalid email task retry counter")
            index = max(retry_index(row), supplied_retry)
        except InvalidRetryMetadataError as error:
            mark_permanent(row, str(error))
            return row, {"success": False, "error": str(error), "retry_scheduled": False}
        if (subject_error := validate_email_log_subject(row, subject)) is not None:
            return row, {"success": False, "error": subject_error, "retry_scheduled": False}
        if index >= maximum + 1:
            row.status = "failed"
            row.provider_response = {
                **(row.provider_response or {}),
                "final_error": "Email retry budget exhausted",
                "retry_exhausted": True,
            }
            row.save(update_fields=["status", "provider_response"])
            return row, {
                "success": False,
                "error": "Email retry budget exhausted",
                "retry_scheduled": False,
                "max_retries_exceeded": True,
            }
        row.from_addr = sender if sender is not None else row.from_addr or get_default_from_email()
        row.status = "sending"
        row.delivery_attempts = index + 1
        row.save(update_fields=["status", "from_addr", "delivery_attempts"])
        return row, None


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


def record_failure(email_log_id: str, error: Exception) -> tuple[EmailLog | None, bool]:
    maximum = max(0, SettingsService.get_integer_setting("notifications.email_max_retries", DEFAULT_MAX_RETRIES))
    with transaction.atomic():
        row = EmailLog.objects.select_for_update().filter(pk=email_log_id).first()
        if row is None:
            return None, False
        if permanent_provider_error(error):
            mark_permanent(row, str(error))
            return row, False
        response = row.provider_response if isinstance(row.provider_response, dict) else {}
        retry = row.delivery_attempts <= maximum
        row.status = "queued" if retry else "failed"
        row.provider_response = {
            **response,
            "retry_count": row.delivery_attempts,
            "final_error": str(error),
            "retry_exhausted": not retry,
        }
        row.save(update_fields=["status", "provider_response"])
        return row, retry
