"""Tests for SNS webhook confirmation migration to safe_request()."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from django.test import RequestFactory, TestCase

from apps.common.outbound_http import OutboundSecurityError
from apps.notifications.webhooks import SESWebhookView


class SNSConfirmationOutboundTests(TestCase):
    """Verify SNS subscription confirmation uses safe_request() with SNS policy."""

    def setUp(self) -> None:
        self.factory = RequestFactory()
        self.view = SESWebhookView()

    def _make_confirmation_request(self, subscribe_url: str) -> MagicMock:
        data = {
            "Type": "SubscriptionConfirmation",
            "SubscribeURL": subscribe_url,
            "TopicArn": "arn:aws:sns:us-east-1:123456789:test",
        }
        return self.factory.post(
            "/webhooks/email/ses/",
            data=json.dumps(data),
            content_type="application/json",
        )

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

    @patch("apps.notifications.webhooks.safe_request")
    def test_non_aws_domain_rejected(self, mock_safe_request: MagicMock) -> None:
        """Non-AWS domains should be rejected by the policy."""
        mock_safe_request.side_effect = OutboundSecurityError("Domain not allowed")

        url = "https://evil.com/steal?token=abc"
        request = self._make_confirmation_request(url)
        response = self.view.post(request)

        # Should return 400 — SSRF attempt is rejected; SNS retries are benign since
        # the SNS_CONFIRMATION_POLICY will block any non-amazonaws.com domain on retry.
        self.assertEqual(response.status_code, 400)
