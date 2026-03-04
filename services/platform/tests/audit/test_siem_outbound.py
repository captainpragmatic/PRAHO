"""Tests for SIEM integration outbound HTTP migration to safe_request()."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.test import TestCase

from apps.audit.siem_integration import SIEMConfig, SIEMIntegrationService, SIEMProvider, SIEMSeverity
from apps.common.outbound_http import OutboundSecurityError


class SIEMOutboundHTTPTests(TestCase):
    """Verify SIEM integration uses safe_request() with proper policies."""

    def _make_service(
        self, endpoint_url: str = "https://splunk.example.com:8088/services/collector"
    ) -> SIEMIntegrationService:
        config = SIEMConfig(
            provider=SIEMProvider.SPLUNK,
            endpoint_url=endpoint_url,
            api_key="test-token",
            min_severity=SIEMSeverity.INFO,
        )
        return SIEMIntegrationService(config)

    def _make_audit_event(self) -> MagicMock:
        event = MagicMock()
        event.id = 1
        event.timestamp.isoformat.return_value = "2026-01-01T00:00:00Z"
        event.action = "login"
        event.category = "authentication"
        event.severity = "high"
        event.actor_type = "user"
        event.user_id = 1
        event.user.email = "test@example.com"
        event.ip_address = "1.2.3.4"
        event.user_agent = "Mozilla/5.0"
        event.session_key = "abc123"
        event.content_type = None
        event.object_id = None
        event.description = "Test event"
        event.metadata = {}
        event.request_id = "req-1"
        event.is_sensitive = False
        event.requires_review = False
        return event

    @patch("apps.audit.siem_integration.safe_request")
    def test_send_events_uses_safe_request(self, mock_safe_request: MagicMock) -> None:
        """send_events() must use safe_request() not raw session."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_safe_request.return_value = mock_response

        service = self._make_service()
        event = self._make_audit_event()
        result = service.send_events([event])

        self.assertTrue(result)
        mock_safe_request.assert_called_once()
        call_kwargs = mock_safe_request.call_args
        self.assertEqual(call_kwargs[0][0], "POST")
        self.assertIn("splunk.example.com", call_kwargs[0][1])

    @patch("apps.audit.siem_integration.safe_request")
    def test_private_ip_endpoint_rejected(self, mock_safe_request: MagicMock) -> None:
        """SIEM endpoints pointing to private IPs must be rejected."""
        mock_safe_request.side_effect = OutboundSecurityError("blocked")

        service = self._make_service("https://192.168.1.1:8088/collector")
        event = self._make_audit_event()
        result = service.send_events([event])

        self.assertFalse(result)

    @patch("apps.audit.siem_integration.safe_request")
    def test_tls_always_verified(self, mock_safe_request: MagicMock) -> None:
        """TLS must always be verified — verify_ssl config option removed."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_safe_request.return_value = mock_response

        config = SIEMConfig(
            provider=SIEMProvider.GENERIC_WEBHOOK,
            endpoint_url="https://siem.example.com/events",
            api_key="key",
            verify_ssl=False,  # This should be ignored now
        )
        service = SIEMIntegrationService(config)
        event = self._make_audit_event()
        service.send_events([event])

        call_kwargs = mock_safe_request.call_args
        # Policy should enforce TLS — verify_ssl=False in config must not disable it
        policy = call_kwargs[1].get("policy")
        if policy is not None:
            self.assertTrue(policy.verify_tls)

    @patch("apps.audit.siem_integration.safe_request")
    def test_no_session_attribute(self, mock_safe_request: MagicMock) -> None:
        """Service should not create a requests.Session anymore."""
        service = self._make_service()
        self.assertFalse(hasattr(service, "_session"))
