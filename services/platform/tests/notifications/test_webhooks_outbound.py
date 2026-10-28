"""Tests for SNS webhook confirmation migration to safe_request()."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from django.test import RequestFactory, TestCase, override_settings

from apps.common.outbound_http import OutboundSecurityError
from apps.notifications.webhooks import SESWebhookView

TOPIC_ARN = "arn:aws:sns:us-east-1:123456789:test"


@override_settings(SES_SNS_TOPIC_ARNS=(TOPIC_ARN,))
class SNSConfirmationOutboundTests(TestCase):
    """Verify SNS subscription confirmation uses safe_request() with SNS policy.

    These tests focus on SSRF protection in _handle_subscription_confirmation and
    run in DEBUG=True mode so that SNS signature verification is bypassed (the
    envelopes are complete, so structural validation and the topic allowlist still
    run). The signature check is tested in test_ses_webhook_signature.py and
    test_ses_webhook_hardening.py.
    """

    def setUp(self) -> None:
        self.factory = RequestFactory()
        self.view = SESWebhookView()

    def _make_confirmation_request(self, subscribe_url: str) -> MagicMock:
        data = {
            "Type": "SubscriptionConfirmation",
            "MessageId": "6f1c2a3e-4b5d-4c6e-8f70-1a2b3c4d5e6f",
            "Message": "You have chosen to subscribe to the topic.",
            "SubscribeURL": subscribe_url,
            "Token": "fixture-token",
            "Timestamp": "2026-10-28T10:00:00.000Z",
            "SignatureVersion": "1",
            "SigningCertURL": "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-abc.pem",
            "TopicArn": TOPIC_ARN,
        }
        return self.factory.post(
            "/webhooks/email/ses/",
            data=json.dumps(data),
            content_type="application/json",
        )

    @override_settings(DEBUG=True)
    @patch("apps.notifications.webhooks.safe_request")
    def test_uses_safe_request_for_confirmation(self, mock_safe_request: MagicMock) -> None:
        """SNS confirmation must use safe_request() not raw requests.get()."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_safe_request.return_value = mock_response

        url = "https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription&Token=abc"
        request = self._make_confirmation_request(url)
        self.view.post(request)

        mock_safe_request.assert_called_once()
        call_args = mock_safe_request.call_args
        self.assertEqual(call_args[0][0], "GET")
        self.assertEqual(call_args[0][1], url)

    @override_settings(DEBUG=True)
    @patch("apps.notifications.webhooks.safe_request")
    def test_sns_policy_allows_amazonaws(self, mock_safe_request: MagicMock) -> None:
        """SNS policy should allow amazonaws.com domains."""
        mock_safe_request.return_value = MagicMock(status_code=200)

        url = "https://sns.eu-west-1.amazonaws.com/?Action=ConfirmSubscription"
        request = self._make_confirmation_request(url)
        self.view.post(request)

        call_kwargs = mock_safe_request.call_args
        policy = call_kwargs[1].get("policy")
        if policy is not None:
            self.assertIn("amazonaws.com", policy.allowed_domains)

    @override_settings(DEBUG=True)
    @patch("apps.notifications.webhooks.safe_request")
    def test_non_aws_domain_rejected(self, mock_safe_request: MagicMock) -> None:
        """Non-AWS domains are rejected by the SubscribeURL host check before any request is made."""
        url = "https://evil.com/steal?token=abc"
        request = self._make_confirmation_request(url)
        with self.assertLogs("apps.notifications.webhooks", level="WARNING") as logs:
            response = self.view.post(request)

        self.assertEqual(response.status_code, 400)
        self.assertTrue(any("Rejected SubscribeURL" in line for line in logs.output), logs.output)
        mock_safe_request.assert_not_called()

    @override_settings(DEBUG=True)
    @patch("apps.notifications.webhooks.safe_request")
    def test_outbound_policy_rejection_is_a_400(self, mock_safe_request: MagicMock) -> None:
        """A SNS-shaped URL the outbound policy still refuses (for example a private resolution) is a 400."""
        mock_safe_request.side_effect = OutboundSecurityError("URL target resolves to blocked IP range")

        url = "https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription"
        with self.assertLogs("apps.notifications.webhooks", level="WARNING") as logs:
            response = self.view.post(self._make_confirmation_request(url))

        self.assertEqual(response.status_code, 400)
        self.assertTrue(any("blocked IP range" in line for line in logs.output), logs.output)
        mock_safe_request.assert_called_once()

    @override_settings(DEBUG=True)
    @patch("apps.notifications.webhooks.safe_request")
    def test_confirmation_policy_does_not_follow_redirects(self, mock_safe_request: MagicMock) -> None:
        mock_safe_request.return_value = MagicMock(status_code=200)
        url = "https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription"
        self.view.post(self._make_confirmation_request(url))

        policy = mock_safe_request.call_args[1]["policy"]
        self.assertFalse(policy.allow_redirects)
        self.assertEqual(policy.max_redirects, 0)
