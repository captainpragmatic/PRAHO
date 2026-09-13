"""BNR exchange-rate gateway: parsing, validation, and failure handling (#103)."""

from datetime import UTC, date, datetime
from decimal import Decimal
from unittest.mock import MagicMock, patch

from django.test import TestCase

from apps.audit.models import AuditEvent
from apps.billing.gateways.bnr_gateway import BNR_API_URL, BNRGateway
from apps.common.outbound_http import OutboundSecurityError

BNR_XML = b"""<?xml version="1.0" encoding="utf-8"?>
<DataSet xmlns="https://www.bnr.ro/xsd"
         xmlns:xsi="https://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="https://curs.bnr.ro/xsd/nbrfxrates.xsd">
  <Header>
    <Publisher>National Bank of Romania</Publisher>
    <PublishingDate>2026-09-11</PublishingDate>
    <MessageType>DR</MessageType>
  </Header>
  <Body>
    <Subject>Reference rates</Subject>
    <OrigCurrency>RON</OrigCurrency>
    <Cube date="2026-09-11">
      <Rate currency="EUR">5.2557</Rate>
      <Rate currency="USD">4.5316</Rate>
      <Rate currency="HUF" multiplier="100">1.4426</Rate>
      <Rate currency="JPY" multiplier="100">2.9409</Rate>
    </Cube>
  </Body>
</DataSet>
"""

# RO-local "today" comfortably after the 2026-09-11 publication.
_NOW = datetime(2026, 9, 12, 10, 0, tzinfo=UTC)


def _response(content: bytes = BNR_XML, status: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.content = content
    resp.raise_for_status.return_value = None
    return resp


class BNRGatewayTests(TestCase):
    @patch("apps.billing.gateways.bnr_gateway.safe_request")
    def test_parses_direction_and_multiplier(self, mock_req: MagicMock) -> None:
        mock_req.return_value = _response()
        result = BNRGateway.fetch_rates(["EUR", "USD", "HUF", "JPY"], now=_NOW)

        self.assertTrue(result.api_available)
        self.assertEqual(result.publication_date, date(2026, 9, 11))
        self.assertEqual(result.rates["EUR"], Decimal("5.2557"))
        self.assertEqual(result.rates["USD"], Decimal("4.5316"))
        self.assertEqual(result.rates["HUF"], Decimal("0.014426"))  # 1.4426 / 100
        self.assertEqual(result.rates["JPY"], Decimal("0.029409"))
        # One GET to the exact URL, redirects disabled by policy.
        mock_req.assert_called_once()
        self.assertEqual(mock_req.call_args.args[1], BNR_API_URL)
        self.assertFalse(mock_req.call_args.kwargs["policy"].allow_redirects)

    @patch("apps.billing.gateways.bnr_gateway.safe_request")
    def test_incomplete_feed_is_unavailable(self, mock_req: MagicMock) -> None:
        mock_req.return_value = _response(BNR_XML.replace(b'<Rate currency="USD">4.5316</Rate>', b""))
        result = BNRGateway.fetch_rates(["EUR", "USD"], now=_NOW)

        self.assertFalse(result.api_available)
        self.assertEqual(result.rates, {})
        self.assertIsNone(result.publication_date)

    @patch("apps.billing.gateways.bnr_gateway.safe_request")
    def test_future_publication_is_rejected(self, mock_req: MagicMock) -> None:
        mock_req.return_value = _response()
        # RO-local today is 2026-09-10 → the 2026-09-11 publication is in the future.
        result = BNRGateway.fetch_rates(["EUR"], now=datetime(2026, 9, 10, 6, 0, tzinfo=UTC))
        self.assertFalse(result.api_available)

    @patch("apps.billing.gateways.bnr_gateway.safe_request")
    def test_non_200_status_is_rejected_even_with_valid_body(self, mock_req: MagicMock) -> None:
        mock_req.return_value = _response(status=302)
        result = BNRGateway.fetch_rates(["EUR"], now=_NOW)
        self.assertFalse(result.api_available)

    @patch("apps.billing.gateways.bnr_gateway.safe_request")
    def test_malformed_xml_is_unavailable(self, mock_req: MagicMock) -> None:
        mock_req.return_value = _response(b"<not-a-bnr-feed/>")
        result = BNRGateway.fetch_rates(["EUR"], now=_NOW)
        self.assertFalse(result.api_available)

    @patch("apps.billing.gateways.bnr_gateway.safe_request")
    def test_security_error_propagates_and_is_audited(self, mock_req: MagicMock) -> None:
        mock_req.side_effect = OutboundSecurityError("blocked")
        with self.assertRaises(OutboundSecurityError):
            BNRGateway.fetch_rates(["EUR"], now=_NOW)
        self.assertTrue(AuditEvent.objects.filter(action="security_bnr_outbound_blocked").exists())
