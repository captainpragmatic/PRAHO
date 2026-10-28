"""SendGrid signs event webhooks with ECDSA over timestamp + body; its published key is public."""

from __future__ import annotations

import base64
import hashlib
import hmac
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.http import HttpRequest
from django.test import RequestFactory, SimpleTestCase, override_settings

from apps.notifications.webhooks import SENDGRID_SIGNATURE_MAX_AGE_SECONDS, SendGridWebhookView

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


class MailgunReplayTests(SimpleTestCase):
    """Mailgun's signature covers only timestamp and token, so a token is good once and only while fresh."""

    KEY = "mailgun-test-key"

    def valid(self, timestamp: str, token: str) -> bool:
        from apps.notifications.webhooks import MailgunWebhookView  # noqa: PLC0415

        signature = hmac.new(self.KEY.encode(), f"{timestamp}{token}".encode(), hashlib.sha256).hexdigest()
        request = RequestFactory().post(
            "/webhooks/email/mailgun/", {"timestamp": timestamp, "token": token, "signature": signature}
        )
        with override_settings(
            ANYMAIL={"MAILGUN_API_KEY": self.KEY},
            DEBUG=False,
            CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "mailgun"}},
        ):
            return MailgunWebhookView()._validate_signature(request)

    def test_a_token_is_accepted_once(self) -> None:
        now = str(int(time.time()))
        self.assertTrue(self.valid(now, "fresh-token"))
        self.assertFalse(self.valid(now, "fresh-token"))

    def test_a_stale_timestamp_is_refused(self) -> None:
        self.assertFalse(self.valid(str(int(time.time()) - 3600), "old-token"))
