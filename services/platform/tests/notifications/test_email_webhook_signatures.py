"""SendGrid signs event webhooks with ECDSA over timestamp + body; its published key is public."""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.http import HttpRequest
from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings

from apps.notifications.webhooks import (
    MAILGUN_SIGNATURE_MAX_AGE_SECONDS,
    SENDGRID_SIGNATURE_MAX_AGE_SECONDS,
    SendGridWebhookView,
)

BODY = b'[{"email": "a@example.ro", "event": "bounce"}]'


def _key_pair() -> tuple[ec.EllipticCurvePrivateKey, str]:
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private, base64.b64encode(public).decode()


def _request(signature: str, timestamp: str) -> HttpRequest:
    return RequestFactory().post(
        "/webhooks/email/sendgrid/",
        BODY,
        content_type="application/json",
        HTTP_X_TWILIO_EMAIL_EVENT_WEBHOOK_SIGNATURE=signature,
        HTTP_X_TWILIO_EMAIL_EVENT_WEBHOOK_TIMESTAMP=timestamp,
    )


def _sign(private: ec.EllipticCurvePrivateKey, timestamp: str) -> str:
    return base64.b64encode(private.sign(timestamp.encode() + BODY, ec.ECDSA(hashes.SHA256()))).decode()


class SendGridSignatureTests(SimpleTestCase):
    def setUp(self) -> None:
        self.private, self.public = _key_pair()
        self.now = str(int(time.time()))

    def valid(self, signature: str, timestamp: str) -> bool:
        with override_settings(ANYMAIL={"SENDGRID_WEBHOOK_VERIFICATION_KEY": self.public}, DEBUG=False):
            return SendGridWebhookView()._validate_signature(_request(signature, timestamp))

    def test_a_delivery_sendgrid_signed_is_accepted(self) -> None:
        self.assertTrue(self.valid(_sign(self.private, self.now), self.now))

    def test_a_forgery_keyed_with_the_public_key_is_refused(self) -> None:
        forged = hmac.new(self.public.encode(), (self.now + BODY.decode()).encode(), hashlib.sha256).hexdigest()
        self.assertFalse(self.valid(forged, self.now))

    def test_another_key_or_a_stale_timestamp_is_refused(self) -> None:
        other, _public = _key_pair()
        self.assertFalse(self.valid(_sign(other, self.now), self.now))
        stale = str(int(time.time()) - SENDGRID_SIGNATURE_MAX_AGE_SECONDS - 5)
        self.assertFalse(self.valid(_sign(self.private, stale), stale))
        self.assertFalse(self.valid(_sign(self.private, self.now), "not-a-number"))


@override_settings(ANYMAIL={"MAILGUN_API_KEY": "mailgun-test-key"}, DEBUG=False)
class MailgunReplayTests(TestCase):
    """Mailgun's signature covers only timestamp and token: each token is applied once, while fresh."""

    KEY = "mailgun-test-key"

    def deliver(self, timestamp: str, token: str, recipient: str) -> int:
        from apps.notifications.webhooks import MailgunWebhookView  # noqa: PLC0415

        signature = hmac.new(self.KEY.encode(), f"{timestamp}{token}".encode(), hashlib.sha256).hexdigest()
        request = RequestFactory().post(
            "/webhooks/email/mailgun/",
            {
                "timestamp": timestamp,
                "token": token,
                "signature": signature,
                "event": "complained",
                "recipient": recipient,
            },
        )
        return MailgunWebhookView().post(request).status_code

    def suppressed(self, email: str) -> bool:
        from apps.notifications.services import EmailSuppressionService  # noqa: PLC0415

        return EmailSuppressionService.is_suppressed(email)

    def test_a_complaint_is_applied_and_its_token_cannot_carry_another(self) -> None:
        now = str(int(time.time()))
        self.assertEqual(self.deliver(now, "fresh-token", "ana@example.ro"), 200)
        self.assertTrue(self.suppressed("ana@example.ro"))
        # The signature does not cover the event: a replay could name anyone. It is answered 200 so
        # Mailgun stops retrying, and applies nothing.
        self.assertEqual(self.deliver(now, "fresh-token", "victim@example.ro"), 200)
        self.assertFalse(self.suppressed("victim@example.ro"))

    def test_a_failure_while_applying_the_event_leaves_the_token_redeliverable(self) -> None:
        now = str(int(time.time()))
        with patch(
            "apps.notifications.webhooks.EmailService.handle_delivery_event", side_effect=RuntimeError("worker stopped")
        ):
            self.assertEqual(self.deliver(now, "crash-token", "bob@example.ro"), 500)
        self.assertEqual(self.deliver(now, "crash-token", "bob@example.ro"), 200)
        self.assertTrue(self.suppressed("bob@example.ro"))

    def test_a_stale_timestamp_is_refused(self) -> None:
        stale = int(time.time()) - MAILGUN_SIGNATURE_MAX_AGE_SECONDS - 60
        self.assertEqual(self.deliver(str(stale), "old-token", "old@example.ro"), 403)
        self.assertFalse(self.suppressed("old@example.ro"))
