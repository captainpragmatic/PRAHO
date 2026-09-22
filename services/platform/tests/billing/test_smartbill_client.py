"""SmartBill transport: policy, pacing, and how failures are classified."""

from __future__ import annotations

import base64
import json
from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.test import TransactionTestCase
from django.utils import timezone

from apps.billing.issuers.models import SmartBillRateGate
from apps.billing.issuers.smartbill.client import (
    SMARTBILL_POLICY,
    RateGateWait,
    SmartBillClient,
    SmartBillCredentials,
)
from apps.billing.issuers.smartbill.responses import Verdict

CREDS = SmartBillCredentials(
    email="api@example.invalid",
    token="tok-123",  # Fixture, not a credential
    cif="RO12345678",
    v3_token="sb_test_abc",  # Fixture, not a credential
)


def _response(status: int, body: str, headers: dict[str, str] | None = None) -> MagicMock:
    response = MagicMock()
    response.status_code = status
    response.text = body
    response.headers = headers or {}
    return response


class TransportPolicyTests(TransactionTestCase):
    def test_the_policy_is_pinned_to_smartbill(self) -> None:
        """SSRF policy: this client may not be pointed anywhere else."""
        self.assertEqual(SMARTBILL_POLICY.allowed_domains, frozenset({"smartbill.ro"}))
        self.assertTrue(SMARTBILL_POLICY.require_https)

    def test_the_policy_performs_no_transport_retries(self) -> None:
        """THE money-safety property of this layer.

        A `requests`-level retry would silently replay a POST whose response was
        merely lost, creating a second legally numbered invoice. Retry decisions
        belong to the caller, which can tell REJECTED from AMBIGUOUS.
        """
        self.assertEqual(SMARTBILL_POLICY.max_retries, 0)

    def test_every_call_goes_through_safe_request(self) -> None:
        with patch(
            "apps.billing.issuers.smartbill.client.safe_request",
            return_value=_response(200, json.dumps({"errorText": ""})),
        ) as request:
            SmartBillClient(CREDS).get_series()

        request.assert_called_once()
        self.assertIs(request.call_args.kwargs["policy"], SMARTBILL_POLICY)

    def test_v1_uses_basic_auth(self) -> None:
        with patch(
            "apps.billing.issuers.smartbill.client.safe_request",
            return_value=_response(200, json.dumps({"errorText": ""})),
        ) as request:
            SmartBillClient(CREDS).get_tax_rates()

        header = request.call_args.kwargs["headers"]["Authorization"]
        expected = base64.b64encode(b"api@example.invalid:tok-123").decode()
        self.assertEqual(header, f"Basic {expected}")

    def test_v3_uses_a_bearer_token_and_a_different_base(self) -> None:
        """V3 is read-only, and it is the only place `isReverseCharge` exists."""
        with patch(
            "apps.billing.issuers.smartbill.client.safe_request",
            return_value=_response(200, json.dumps({"items": []})),
        ) as request:
            SmartBillClient(CREDS).get_vat_rates_v3()

        self.assertEqual(request.call_args.kwargs["headers"]["Authorization"], "Bearer sb_test_abc")
        self.assertIn("/api/v3/companies/RO12345678/vat-rates", request.call_args.args[1])


class PacingTests(TransactionTestCase):
    def test_the_gate_is_consulted_before_the_request(self) -> None:
        with patch(
            "apps.billing.issuers.smartbill.client.safe_request",
            return_value=_response(200, json.dumps({"errorText": ""})),
        ):
            SmartBillClient(CREDS).get_series()

        self.assertEqual(SmartBillRateGate.objects.count(), 1)

    def test_a_deferred_call_never_reaches_the_network(self) -> None:
        """THE regression guard.

        An earlier design reserved a future slot then proceeded anyway if it was
        within five seconds, so thirteen requests could fire at once while the
        schedule looked correct. Any answer but "go now" must stop the call.
        """
        SmartBillRateGate.objects.create(
            token_fingerprint=SmartBillRateGate.fingerprint(CREDS.token),
            next_allowed_at=timezone.now() + timedelta(seconds=1),
        )

        with (
            patch("apps.billing.issuers.smartbill.client.safe_request") as request,
            self.assertRaises(RateGateWait),
        ):
            SmartBillClient(CREDS).get_series()

        request.assert_not_called()

    def test_a_second_immediate_call_is_deferred(self) -> None:
        """Back-to-back calls must not both go out."""
        client = SmartBillClient(CREDS)
        with patch(
            "apps.billing.issuers.smartbill.client.safe_request",
            return_value=_response(200, json.dumps({"errorText": ""})),
        ) as request:
            client.get_series()
            with self.assertRaises(RateGateWait):
                client.get_series()

        self.assertEqual(request.call_count, 1)

    def test_a_429_suppresses_every_worker(self) -> None:
        """Throttling is recorded centrally, not handed to one caller."""
        body = json.dumps({"errors": [{"code": "rate_limit_exceeded"}]})
        with patch(
            "apps.billing.issuers.smartbill.client.safe_request",
            return_value=_response(429, body, {"Retry-After": "300"}),
        ):
            SmartBillClient(CREDS).create_invoice({"companyVatCode": "RO1"})

        gate = SmartBillRateGate.objects.get(token_fingerprint=SmartBillRateGate.fingerprint(CREDS.token))
        self.assertIsNotNone(gate.blocked_until)

    def test_v3_is_paced_against_its_own_token(self) -> None:
        """V1 and V3 authenticate differently; pacing must follow the credential spent."""
        with patch(
            "apps.billing.issuers.smartbill.client.safe_request",
            return_value=_response(200, json.dumps({"items": []})),
        ):
            SmartBillClient(CREDS).get_vat_rates_v3()

        self.assertTrue(
            SmartBillRateGate.objects.filter(
                token_fingerprint=SmartBillRateGate.fingerprint(CREDS.v3_token)
            ).exists()
        )


class FailureHandlingTests(TransactionTestCase):
    def setUp(self) -> None:
        SmartBillRateGate.objects.all().delete()

    def _client(self) -> SmartBillClient:
        return SmartBillClient(CREDS)

    def test_a_transport_exception_becomes_ambiguous_not_rejected(self) -> None:
        """A lost reply must never invite an automatic retry."""
        with patch(
            "apps.billing.issuers.smartbill.client.safe_request",
            side_effect=OSError("connection reset"),
        ):
            result = self._client().create_invoice({"companyVatCode": "RO1"})

        self.assertIs(result.verdict, Verdict.AMBIGUOUS)

    def test_http_200_with_error_text_is_not_a_success(self) -> None:
        body = json.dumps({"errorText": "Seria nu a fost gasita!"})
        with patch("apps.billing.issuers.smartbill.client.safe_request", return_value=_response(200, body)):
            result = self._client().create_invoice({"companyVatCode": "RO1"})

        self.assertIs(result.verdict, Verdict.REJECTED)
        self.assertFalse(result.is_success)

    def test_an_html_body_does_not_raise(self) -> None:
        """A misspelled field returns HTML; the parser must survive it."""
        with patch(
            "apps.billing.issuers.smartbill.client.safe_request",
            return_value=_response(500, "<html>Internal Server Error</html>"),
        ):
            result = self._client().create_invoice({"nume": "wrong field name"})

        self.assertIs(result.verdict, Verdict.AMBIGUOUS)

    def test_retry_after_is_carried_through_on_429(self) -> None:
        with patch(
            "apps.billing.issuers.smartbill.client.safe_request",
            return_value=_response(429, json.dumps({"errors": [{"code": "rate_limit_exceeded"}]}), {"Retry-After": "300"}),
        ):
            result = self._client().create_invoice({"companyVatCode": "RO1"})

        self.assertEqual(result.retry_after_seconds, 300)
