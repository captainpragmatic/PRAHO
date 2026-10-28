"""C3: SES webhook must verify SNS signatures before processing."""
from __future__ import annotations

import json
from unittest.mock import patch

from django.http import HttpRequest
from django.test import RequestFactory, TestCase, override_settings

from apps.notifications.webhooks import SESWebhookView

TOPIC_ARN = "arn:aws:sns:us-east-1:123456789:ses-notifications"


@override_settings(SES_SNS_TOPIC_ARNS=(TOPIC_ARN,))
class SESWebhookSignatureTests(TestCase):
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
            "MessageId": "11111111-1111-4111-8111-111111111111",
            "Message": json.dumps({"notificationType": "Bounce"}),
            "Timestamp": "2026-03-26T10:00:00.000Z",
            "SignatureVersion": "1",
            "Signature": "",
            "SigningCertURL": "https://sns.us-east-1.amazonaws.com/cert.pem",
            "TopicArn": TOPIC_ARN,
        }
        with patch("apps.notifications.webhooks.safe_request") as mock_fetch:
            response = self.view(self._make_sns_request(payload))
        self.assertEqual(response.status_code, 403)
        mock_fetch.assert_not_called()

    @override_settings(DEBUG=False)
    def test_invalid_signing_cert_url_rejected(self) -> None:
        """SigningCertURL not from amazonaws.com must be rejected."""
        payload = {
            "Type": "Notification",
            "MessageId": "22222222-2222-4222-8222-222222222222",
            "Message": json.dumps({"notificationType": "Bounce"}),
            "Timestamp": "2026-03-26T10:00:00.000Z",
            "SignatureVersion": "1",
            "Signature": "dGVzdA==",
            "SigningCertURL": "https://evil.com/cert.pem",
            "TopicArn": TOPIC_ARN,
        }
        with patch("apps.notifications.webhooks.safe_request") as mock_fetch:
            response = self.view(self._make_sns_request(payload))
        self.assertEqual(response.status_code, 403)
        mock_fetch.assert_not_called()

    @override_settings(DEBUG=False)
    def test_http_signing_cert_url_rejected(self) -> None:
        """SigningCertURL using http:// (not https://) must be rejected."""
        payload = {
            "Type": "Notification",
            "MessageId": "33333333-3333-4333-8333-333333333333",
            "Message": json.dumps({"notificationType": "Bounce"}),
            "Timestamp": "2026-03-26T10:00:00.000Z",
            "SignatureVersion": "1",
            "Signature": "dGVzdA==",
            "SigningCertURL": "http://sns.us-east-1.amazonaws.com/cert.pem",
            "TopicArn": TOPIC_ARN,
        }
        with patch("apps.notifications.webhooks.safe_request") as mock_fetch:
            response = self.view(self._make_sns_request(payload))
        self.assertEqual(response.status_code, 403)
        mock_fetch.assert_not_called()

    @override_settings(DEBUG=False)
    def test_subscription_confirmation_also_validates(self) -> None:
        """SubscriptionConfirmation without valid signature must also be rejected."""
        payload = {
            "Type": "SubscriptionConfirmation",
            "MessageId": "44444444-4444-4444-8444-444444444444",
            "Message": "Please confirm subscription",
            "SubscribeURL": "https://sns.us-east-1.amazonaws.com/confirm",
            "Token": "2336412f37fb687f5d51e6e2",
            "Timestamp": "2026-03-26T10:00:00.000Z",
            "SignatureVersion": "1",
            "Signature": "",
            "SigningCertURL": "https://sns.us-east-1.amazonaws.com/cert.pem",
            "TopicArn": TOPIC_ARN,
        }
        with patch("apps.notifications.webhooks.safe_request") as mock_fetch:
            response = self.view(self._make_sns_request(payload))
        self.assertEqual(response.status_code, 403)
        mock_fetch.assert_not_called()

    @override_settings(DEBUG=True)
    def test_unsigned_allowed_in_debug_mode(self) -> None:
        """In DEBUG mode, accept unsigned for dev convenience (matching other handlers)."""
        payload = {
            "Type": "Notification",
            "MessageId": "55555555-5555-4555-8555-555555555555",
            "Message": json.dumps({
                "notificationType": "Delivery",
                "mail": {"messageId": "test-mail-id"},
                "delivery": {"recipients": ["test@example.com"]},
            }),
            "Timestamp": "2026-03-26T10:00:00.000Z",
            "TopicArn": TOPIC_ARN,
        }
        response = self.view(self._make_sns_request(payload))
        self.assertIn(response.status_code, [200, 204])
