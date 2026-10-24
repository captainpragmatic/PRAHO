"""A provider the operator must fix blocks sending; it does not kill the messages (#751 follow-up, M2).

Authentication, configuration and account errors (Anymail 401/403/404, SMTP 535, a misconfigured
backend, a suspended or paused SES account) were classed as permanent: every message sent while the
operator fixed a credential failed for good. They now leave the message queued with a long backoff,
give its attempt back, mark it blocked, and raise one staff alert per provider error per window. The
next attempt after the fix sends it. A message blocked for longer than the block limit is given up.
"""

from __future__ import annotations

import smtplib
from datetime import timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from anymail.exceptions import AnymailAPIError, AnymailConfigurationError
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
from django.test import TestCase
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.notifications.delivery import max_retries
from apps.notifications.models import EmailLog
from apps.notifications.services import EmailService
from apps.notifications.tasks import send_email_task

ALERT = "email_provider_blocked"


class SESError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": 400}}


def _api_error(status: int) -> AnymailAPIError:
    # As Anymail raises it: with the provider's HTTP response, which its message describes.
    response = SimpleNamespace(reason="Refused", text="{}", json=lambda: {"message": "Refused"})
    return AnymailAPIError(f"HTTP {status}", status_code=status, response=response)


def _wrapped(cause: Exception) -> AnymailAPIError:
    error = AnymailAPIError(str(cause))
    error.__cause__ = cause
    return error


def _ses_api_error(code: str, status: int) -> AnymailAPIError:
    return AnymailAPIError(code, response={"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}})


OPERATOR_ERRORS: dict[str, Any] = {
    "anymail 401": lambda: _api_error(401),
    "anymail 403": lambda: _api_error(403),
    "anymail 404": lambda: _api_error(404),
    "smtp 535": lambda: smtplib.SMTPAuthenticationError(535, b"Authentication failed"),
    "configuration": lambda: AnymailConfigurationError("Missing API key"),
    "ses suspended": lambda: SESError("AccountSuspendedException"),
    "ses paused": lambda: SESError("SendingPausedException"),
    # As Anymail's SES backend raises them: the HTTP status only in the boto response, none on the error.
    "ses missing configuration set": lambda: _ses_api_error("NotFoundException", 404),
    "ses credentials": lambda: _ses_api_error("AccessDeniedException", 403),
    # No AWS credentials at all: Anymail wraps botocore's error, with no response or status.
    "ses no credentials": lambda: _wrapped(NoCredentialsError()),
    "ses partial credentials": lambda: PartialCredentialsError(provider="env", cred_var="AWS_SECRET_ACCESS_KEY"),
}


def _queued(**fields: Any) -> EmailLog:
    row = EmailLog.objects.create(
        to_addr="customer@example.com", subject="Invoice", body_text="Body", status="queued", **fields
    )
    EmailLog.objects.filter(pk=row.pk).update(sent_at=timezone.now() - timedelta(minutes=11))
    row.refresh_from_db()
    return row


def _attempt(row: EmailLog, error: Exception | None) -> None:
    """Run the worker once, now due, with the provider failing with `error` (or accepting)."""
    EmailLog.objects.filter(pk=row.pk).update(next_attempt_at=None)

    def provider(message: Any, *args: Any, **kwargs: Any) -> int:
        if error is not None:
            raise error
        message.anymail_status = SimpleNamespace(message_id="pid-after-fix", status={"sent"}, esp_response={})
        return 1

    with patch("django.core.mail.EmailMessage.send", provider):
        send_email_task(str(row.pk))


class OperatorErrorTests(TestCase):
    def test_an_operator_error_leaves_the_message_queued_with_its_attempt_given_back(self) -> None:
        for label, make_error in OPERATOR_ERRORS.items():
            with self.subTest(error=label):
                row = _queued()

                _attempt(row, make_error())

                row.refresh_from_db()
                self.assertEqual(row.status, "queued", f"{label} is the operator's to fix, not the message's")
                self.assertEqual(row.delivery_attempts, 0, "the attempt is given back")
                self.assertIsNotNone(getattr(row, "operator_blocked_at", None))
                self.assertIsNot(row.provider_response.get("permanent_failure"), True)
                self.assertGreater(row.next_attempt_at, timezone.now() + timedelta(minutes=10), "a long backoff")

    def test_a_synchronous_send_blocked_by_the_operator_is_queued_for_later(self) -> None:
        with patch("django.core.mail.EmailMessage.send", side_effect=_api_error(401)):
            result = EmailService.send_email(to=["customer@example.com"], subject="Now", body_text="Body")

        row = EmailLog.objects.get(pk=result.email_log_id)
        self.assertEqual(row.status, "queued")
        self.assertIsNot(row.provider_response.get("permanent_failure"), True)

    def test_one_alert_per_provider_error_per_window(self) -> None:
        for _ in range(2):
            _attempt(_queued(), _api_error(401))
        _attempt(_queued(), smtplib.SMTPAuthenticationError(535, b"Authentication failed"))

        self.assertEqual(AuditEvent.objects.filter(action=ALERT).count(), 2, "one for the 401, one for the 535")


class OutageTests(TestCase):
    def test_an_outage_longer_than_the_retry_budget_still_delivers_once_fixed(self) -> None:
        row = _queued()
        for _ in range(max_retries() + 3):
            _attempt(row, _api_error(401))

        _attempt(row, None)

        row.refresh_from_db()
        self.assertEqual(row.status, "sent")
        self.assertIsNone(getattr(row, "operator_blocked_at", "missing"))

    def test_a_message_blocked_past_the_block_limit_is_given_up(self) -> None:
        from apps.notifications import delivery  # noqa: PLC0415

        limit = getattr(delivery, "OPERATOR_BLOCK_LIMIT", timedelta(days=3))
        row = _queued()
        EmailLog.objects.filter(pk=row.pk).update(sent_at=timezone.now() - limit - timedelta(hours=1))

        _attempt(row, _api_error(401))

        row.refresh_from_db()
        self.assertEqual(row.status, "failed")
        self.assertIs(row.provider_response.get("retry_exhausted"), True, "a block cannot keep a message forever")
