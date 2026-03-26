"""C3: SES webhook must verify SNS signatures before processing."""
from __future__ import annotations

import json

from django.http import HttpRequest
from django.test import RequestFactory, SimpleTestCase, override_settings

from apps.notifications.webhooks import SESWebhookView


class SESWebhookSignatureTests(SimpleTestCase):
    """C3: SES webhook must reject unsigned/invalid SNS notifications."""

    def setUp(self) -> None:
        self.factory = RequestFactory()
        self.view = SESWebhookView.as_view()

    def _make_sns_request(self, payload: dict[str, object]) -> HttpRequest:
        return self.factory.post(  # type: ignore[return-value]  # RequestFactory returns HttpRequest subtype
            "/webhooks/email/ses/",
            data=json.dumps(payload),
            content_type="application/json",
        )

    @override_settings(DEBUG=False)
    def test_unsigned_notification_rejected_in_production(self) -> None:
        """Notification without valid signature must be rejected with 403."""
        payload = {
            "Type": "Notification",
            "MessageId": "test-123",
            "Message": json.dumps({"notificationType": "Bounce"}),
            "Timestamp": "2026-03-26T10:00:00.000Z",
            "SignatureVersion": "1",
            "Signature": "",
            "SigningCertURL": "https://sns.us-east-1.amazonaws.com/cert.pem",
            "TopicArn": "arn:aws:sns:us-east-1:123456789:ses-notifications",
        }
        response = self.view(self._make_sns_request(payload))
        self.assertEqual(response.status_code, 403)

    @override_settings(DEBUG=False)
    def test_invalid_signing_cert_url_rejected(self) -> None:
        """SigningCertURL not from amazonaws.com must be rejected."""
        payload = {
            "Type": "Notification",
            "MessageId": "test-456",
            "Message": json.dumps({"notificationType": "Bounce"}),
            "Timestamp": "2026-03-26T10:00:00.000Z",
            "SignatureVersion": "1",
            "Signature": "dGVzdA==",
            "SigningCertURL": "https://evil.com/cert.pem",
            "TopicArn": "arn:aws:sns:us-east-1:123456789:ses-notifications",
        }
        response = self.view(self._make_sns_request(payload))
        self.assertEqual(response.status_code, 403)

    @override_settings(DEBUG=False)
    def test_http_signing_cert_url_rejected(self) -> None:
        """SigningCertURL using http:// (not https://) must be rejected."""
        payload = {
            "Type": "Notification",
            "MessageId": "test-789",
            "Message": json.dumps({"notificationType": "Bounce"}),
            "Timestamp": "2026-03-26T10:00:00.000Z",
            "SignatureVersion": "1",
            "Signature": "dGVzdA==",
            "SigningCertURL": "http://sns.us-east-1.amazonaws.com/cert.pem",
            "TopicArn": "arn:aws:sns:us-east-1:123456789:ses-notifications",
        }
        response = self.view(self._make_sns_request(payload))
        self.assertEqual(response.status_code, 403)

    @override_settings(DEBUG=False)
    def test_subscription_confirmation_also_validates(self) -> None:
        """SubscriptionConfirmation without valid signature must also be rejected."""
        payload = {
            "Type": "SubscriptionConfirmation",
            "MessageId": "test-sub-123",
            "Message": "Please confirm subscription",
            "SubscribeURL": "https://sns.us-east-1.amazonaws.com/confirm",
            "Timestamp": "2026-03-26T10:00:00.000Z",
            "SignatureVersion": "1",
            "Signature": "",
            "SigningCertURL": "https://sns.us-east-1.amazonaws.com/cert.pem",
            "TopicArn": "arn:aws:sns:us-east-1:123456789:ses-notifications",
        }
        response = self.view(self._make_sns_request(payload))
        self.assertEqual(response.status_code, 403)

    @override_settings(DEBUG=True)
    def test_unsigned_allowed_in_debug_mode(self) -> None:
        """In DEBUG mode, accept unsigned for dev convenience (matching other handlers)."""
        payload = {
            "Type": "Notification",
            "MessageId": "test-debug",
            "Message": json.dumps({
                "notificationType": "Delivery",
                "mail": {"messageId": "test-mail-id"},
                "delivery": {"recipients": ["test@example.com"]},
            }),
            "Timestamp": "2026-03-26T10:00:00.000Z",
        }
        response = self.view(self._make_sns_request(payload))
        self.assertIn(response.status_code, [200, 204])
