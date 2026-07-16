"""Tests for domain registrar gateway layer (issue #93).

Tests the ABC, factory, circuit breaker, idempotency, error mapping,
and the Gandi/ROTLD concrete gateways with mocked HTTP responses.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock, patch

import requests
from django.test import TestCase, override_settings

from apps.common.types import Err, Ok
from apps.domains.gateways import (
    RegistrarGatewayFactory,
)
from apps.domains.gateways.base import (
    _IDEMPOTENCY_IN_PROGRESS,
    CIRCUIT_BREAKER_THRESHOLD,
    MAX_RESPONSE_SIZE_BYTES,
    DomainAvailabilityResult,
    DomainRegistrationResult,
)
from apps.domains.gateways.errors import (
    RegistrarAPIError,
    RegistrarAuthError,
    RegistrarConflictError,
    RegistrarErrorCode,
    RegistrarNotFoundError,
    RegistrarRateLimitError,
    RegistrarTransientError,
)
from apps.domains.gateways.gandi import GandiGateway
from apps.domains.gateways.rotld import ROTLDGateway
from apps.domains.models import Registrar


def _make_registrar(name: str = "gandi", **kwargs: Any) -> Registrar:
    """Create a Registrar instance for testing (not saved to DB)."""
    defaults = {
        "display_name": name.upper(),
        "website_url": f"https://{name}.net",
        "api_endpoint": f"https://api.{name}.net/v5",
        "api_username": "",
        "api_key": "test-api-key-encrypted",
        "api_secret": "",
        "webhook_secret": "",
        "status": "active",
    }
    defaults.update(kwargs)
    return Registrar(name=name, **defaults)


def _mock_response(status_code: int, json_data: dict | None = None, text: str = "") -> MagicMock:
    """Create a mock requests.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text or json.dumps(json_data or {})
    resp.headers = {}
    if json_data is not None:
        resp.json.return_value = json_data
    else:
        resp.json.side_effect = ValueError("No JSON")
    return resp


# ===============================================================================
# ERROR TYPES
# ===============================================================================


class RegistrarErrorTests(TestCase):
    """Error hierarchy carries correct codes and messages."""

    def test_auth_error_has_code(self) -> None:
        err = RegistrarAuthError("gandi")
        self.assertEqual(err.code, RegistrarErrorCode.AUTH_FAILED)
        self.assertEqual(err.registrar_name, "gandi")

    def test_conflict_error_has_domain(self) -> None:
        err = RegistrarConflictError("example.com", "gandi")
        self.assertEqual(err.code, RegistrarErrorCode.DOMAIN_ALREADY_REGISTERED)
        self.assertIn("example.com", str(err))

    def test_not_found_error(self) -> None:
        err = RegistrarNotFoundError("example.com", "rotld")
        self.assertEqual(err.code, RegistrarErrorCode.DOMAIN_NOT_FOUND)

    def test_rate_limit_error_with_retry_after(self) -> None:
        err = RegistrarRateLimitError("gandi", retry_after=60)
        self.assertEqual(err.retry_after, 60)
        self.assertEqual(err.code, RegistrarErrorCode.RATE_LIMITED)

    def test_transient_error_is_retryable(self) -> None:
        err = RegistrarTransientError("gandi", "timeout")
        self.assertEqual(err.code, RegistrarErrorCode.NETWORK_ERROR)


# ===============================================================================
# FACTORY
# ===============================================================================


class RegistrarGatewayFactoryTests(TestCase):
    """Factory creates correct gateway instances."""

    def test_creates_gandi_gateway(self) -> None:
        registrar = _make_registrar("gandi")
        gateway = RegistrarGatewayFactory.create_gateway(registrar)
        self.assertIsInstance(gateway, GandiGateway)

    def test_creates_rotld_gateway(self) -> None:
        registrar = _make_registrar("rotld", api_endpoint="https://rest2.rotld.ro")
        gateway = RegistrarGatewayFactory.create_gateway(registrar)
        self.assertIsInstance(gateway, ROTLDGateway)

    def test_unknown_registrar_raises(self) -> None:
        registrar = _make_registrar("unknown_registrar")
        with self.assertRaises(ValueError, msg="No gateway registered"):
            RegistrarGatewayFactory.create_gateway(registrar)

    def test_list_available_gateways(self) -> None:
        gateways = RegistrarGatewayFactory.list_available_gateways()
        self.assertIn("gandi", gateways)
        self.assertIn("rotld", gateways)


# ===============================================================================
# GANDI GATEWAY
# ===============================================================================


@override_settings(REGISTRAR_ADAPTERS_VERIFIED=True)
class GandiGatewayRegisterTests(TestCase):
    """Gandi domain registration."""

    def setUp(self) -> None:
        self.registrar = _make_registrar("gandi")
        self.gateway = GandiGateway(self.registrar)
        self.registrant = {
            "first_name": "Ion",
            "last_name": "Popescu",
            "email": "ion@example.com",
            "phone": "+40721000000",
            "address": "Str. Exemplu 1",
            "city": "Bucuresti",
            "postal_code": "010101",
            "country_code": "RO",
        }

    @patch("apps.domains.gateways.gandi.GandiGateway._api_request")
    @patch("apps.domains.gateways.base.cache")
    def test_successful_registration(self, mock_cache: MagicMock, mock_request: MagicMock) -> None:
        # First get: circuit breaker (returns 0 = OK), second get: idempotency (None = cache miss)
        mock_cache.get.side_effect = [0, None]
        mock_request.return_value = _mock_response(
            202,
            {
                "id": "gandi-dom-123",
                "expires_at": "2027-04-06T00:00:00Z",
                "auth_info": "EPP-SECRET",
            },
        )

        result = self.gateway.register_domain("example.com", 1, self.registrant)

        self.assertTrue(result.is_ok())
        reg = result.unwrap()
        self.assertEqual(reg.registrar_domain_id, "gandi-dom-123")
        self.assertEqual(reg.epp_code, "EPP-SECRET")

    @patch("apps.domains.gateways.gandi.GandiGateway._api_request")
    @patch("apps.domains.gateways.base.cache")
    def test_auth_failure_returns_err(self, mock_cache: MagicMock, mock_request: MagicMock) -> None:
        mock_cache.get.side_effect = [0, None]
        mock_request.return_value = _mock_response(401, {"message": "Invalid token"})

        result = self.gateway.register_domain("example.com", 1, self.registrant)

        self.assertTrue(result.is_err())
        self.assertIsInstance(result.unwrap_err(), RegistrarAuthError)

    @patch("apps.domains.gateways.gandi.GandiGateway._api_request")
    @patch("apps.domains.gateways.base.cache")
    def test_conflict_returns_err(self, mock_cache: MagicMock, mock_request: MagicMock) -> None:
        mock_cache.get.side_effect = [0, None]
        mock_request.return_value = _mock_response(409, {"message": "Domain already registered"})

        result = self.gateway.register_domain("example.com", 1, self.registrant)

        self.assertTrue(result.is_err())
        self.assertIsInstance(result.unwrap_err(), RegistrarConflictError)

    @patch("apps.domains.gateways.gandi.GandiGateway._api_request")
    @patch("apps.domains.gateways.base.cache")
    def test_conflict_error_message_uses_bare_domain_not_operation_label(
        self, mock_cache: MagicMock, mock_request: MagicMock
    ) -> None:
        """M3: typed not-found/conflict errors must carry the domain, not 'register <domain>'."""
        mock_cache.get.side_effect = [0, None]
        mock_request.return_value = _mock_response(409, {"message": "Domain already registered"})

        result = self.gateway.register_domain("example.com", 1, self.registrant)

        message = str(result.unwrap_err())
        self.assertIn("Domain 'example.com'", message)
        self.assertNotIn("register example.com", message)

    @patch("apps.domains.gateways.gandi.GandiGateway._api_request")
    @patch("apps.domains.gateways.base.cache")
    def test_rate_limit_returns_retriable_err(self, mock_cache: MagicMock, mock_request: MagicMock) -> None:
        mock_cache.get.side_effect = [0, None]
        resp = _mock_response(429, {"message": "Too many requests"})
        resp.headers = {"Retry-After": "30"}
        mock_request.return_value = resp

        result = self.gateway.register_domain("example.com", 1, self.registrant)

        self.assertTrue(result.is_err())
        self.assertIsInstance(result.unwrap_err(), RegistrarRateLimitError)


class GandiGatewayAvailabilityTests(TestCase):
    """Gandi domain availability check."""

    def setUp(self) -> None:
        self.registrar = _make_registrar("gandi")
        self.gateway = GandiGateway(self.registrar)

    @patch("apps.domains.gateways.gandi.GandiGateway._api_request")
    @patch("apps.domains.gateways.base.cache")
    def test_available_domain(self, mock_cache: MagicMock, mock_request: MagicMock) -> None:
        mock_cache.get.return_value = 0  # circuit breaker OK
        mock_request.return_value = _mock_response(
            200,
            {
                "products": [
                    {
                        "status": "available",
                        "premium": False,
                        "prices": [{"price_after_taxes": 12.50}],
                    }
                ],
            },
        )

        result = self.gateway.check_availability("example.com")

        self.assertTrue(result.is_ok())
        avail = result.unwrap()
        self.assertTrue(avail.available)
        self.assertFalse(avail.premium)
        self.assertEqual(avail.price_cents, 1250)

    @patch("apps.domains.gateways.gandi.GandiGateway._api_request")
    @patch("apps.domains.gateways.base.cache")
    def test_unavailable_domain(self, mock_cache: MagicMock, mock_request: MagicMock) -> None:
        mock_cache.get.return_value = 0
        mock_request.return_value = _mock_response(
            200,
            {
                "products": [{"status": "unavailable", "premium": False, "prices": []}],
            },
        )

        result = self.gateway.check_availability("taken.com")

        self.assertTrue(result.is_ok())
        self.assertFalse(result.unwrap().available)


# ===============================================================================
# ROTLD GATEWAY
# ===============================================================================


@override_settings(REGISTRAR_ADAPTERS_VERIFIED=True)
class ROTLDGatewayRegisterTests(TestCase):
    """ROTLD domain registration."""

    def setUp(self) -> None:
        self.registrar = _make_registrar("rotld", api_endpoint="https://rest2.rotld.ro")
        self.gateway = ROTLDGateway(self.registrar)
        self.registrant = {
            "first_name": "Ion",
            "last_name": "Popescu",
            "email": "ion@example.com",
            "phone": "+40721000000",
            "address": "Str. Exemplu 1",
            "city": "Bucuresti",
            "postal_code": "010101",
            "country_code": "RO",
            "entity_type": "company",
            "company_name": "SC Exemplu SRL",
            "cui": "RO12345678",
        }

    @patch("apps.domains.gateways.rotld.ROTLDGateway._api_request")
    @patch("apps.domains.gateways.base.cache")
    def test_successful_registration(self, mock_cache: MagicMock, mock_request: MagicMock) -> None:
        mock_cache.get.side_effect = [0, None]
        mock_request.return_value = _mock_response(
            201,
            {
                "domain": {
                    "id": "rotld-12345",
                    "expire_at": "2027-04-06T00:00:00Z",
                    "authcode": "RO-EPP-SECRET",
                },
            },
        )

        result = self.gateway.register_domain("exemplu.ro", 1, self.registrant)

        self.assertTrue(result.is_ok())
        reg = result.unwrap()
        self.assertEqual(reg.registrar_domain_id, "rotld-12345")
        self.assertEqual(reg.epp_code, "RO-EPP-SECRET")

    @patch("apps.domains.gateways.rotld.ROTLDGateway._api_request")
    @patch("apps.domains.gateways.base.cache")
    def test_server_error_returns_transient(self, mock_cache: MagicMock, mock_request: MagicMock) -> None:
        mock_cache.get.side_effect = [0, None]
        mock_request.return_value = _mock_response(503, {"error": "Service unavailable"})

        result = self.gateway.register_domain("exemplu.ro", 1, self.registrant)

        self.assertTrue(result.is_err())
        self.assertIsInstance(result.unwrap_err(), RegistrarTransientError)


class ROTLDGatewayRegistrantMappingTests(TestCase):
    """ROTLD registrant data mapping includes Romanian-specific fields."""

    def setUp(self) -> None:
        self.registrar = _make_registrar("rotld", api_endpoint="https://rest2.rotld.ro")
        self.gateway = ROTLDGateway(self.registrar)

    def test_company_registrant_includes_cui(self) -> None:
        data = {
            "first_name": "Ion",
            "last_name": "Popescu",
            "entity_type": "company",
            "company_name": "SC Exemplu SRL",
            "cui": "RO12345678",
            "email": "ion@example.com",
        }
        mapped = self.gateway._map_registrant_to_rotld(data)

        self.assertEqual(mapped["org"], "SC Exemplu SRL")
        self.assertEqual(mapped["fiscal_code"], "RO12345678")
        self.assertNotIn("cnp", mapped)

    def test_individual_registrant_includes_cnp(self) -> None:
        data = {
            "first_name": "Ion",
            "last_name": "Popescu",
            "entity_type": "individual",
            "cnp": "1234567890123",
            "email": "ion@example.com",
        }
        mapped = self.gateway._map_registrant_to_rotld(data)

        self.assertEqual(mapped["cnp"], "1234567890123")
        self.assertNotIn("org", mapped)
        self.assertNotIn("fiscal_code", mapped)


# ===============================================================================
# CIRCUIT BREAKER
# ===============================================================================


class CircuitBreakerTests(TestCase):
    """Circuit breaker prevents calls to failing registrars."""

    def setUp(self) -> None:
        self.registrar = _make_registrar("gandi")
        self.gateway = GandiGateway(self.registrar)

    @patch("apps.domains.gateways.base.cache")
    def test_open_circuit_blocks_calls(self, mock_cache: MagicMock) -> None:
        mock_cache.get.return_value = CIRCUIT_BREAKER_THRESHOLD

        result = self.gateway.check_availability("example.com")

        self.assertTrue(result.is_err())
        err = result.unwrap_err()
        self.assertIsInstance(err, RegistrarTransientError)
        self.assertIn("Circuit breaker", str(err))

    @patch("apps.domains.gateways.base.cache")
    def test_below_threshold_allows_calls(self, mock_cache: MagicMock) -> None:
        mock_cache.get.return_value = CIRCUIT_BREAKER_THRESHOLD - 1
        with patch.object(self.gateway, "_do_check_availability") as mock_do:
            mock_do.return_value = Ok(DomainAvailabilityResult("example.com", True))
            result = self.gateway.check_availability("example.com")

        self.assertTrue(result.is_ok())


# ===============================================================================
# IDEMPOTENCY
# ===============================================================================


@override_settings(REGISTRAR_ADAPTERS_VERIFIED=True)
class IdempotencyTests(TestCase):
    """Idempotency cache prevents duplicate registrations."""

    def setUp(self) -> None:
        self.registrar = _make_registrar("gandi")
        self.gateway = GandiGateway(self.registrar)

    @patch("apps.domains.gateways.base.cache")
    def test_cached_registration_returned_immediately(self, mock_cache: MagicMock) -> None:
        cached_result = DomainRegistrationResult(
            registrar_domain_id="cached-123",
            expires_at=datetime(2027, 1, 1, tzinfo=UTC),
            nameservers=["ns1.example.com"],
            epp_code="CACHED-EPP",
        )
        # First call returns None (circuit breaker), second returns cached result
        mock_cache.get.side_effect = [0, cached_result]

        result = self.gateway.register_domain("example.com", 1, {})

        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap().registrar_domain_id, "cached-123")

    @patch("apps.domains.gateways.base.cache")
    def test_concurrent_in_flight_registration_rejected(self, mock_cache: MagicMock) -> None:
        """A second concurrent register for the same domain is refused, not duplicated.

        The first request claims the idempotency key with _IDEMPOTENCY_IN_PROGRESS
        via cache.add(); the second loses that atomic claim (add() returns False) and,
        finding only the in-progress sentinel (no real result yet), must return a
        RegistrarConflictError rather than issuing a second chargeable registration.
        """
        # get(): circuit-breaker check -> 0 (OK); idempotency read -> the in-progress
        # sentinel (so the "cached real result" fast-path is skipped); after the lost
        # add() race, the re-read -> sentinel again (no real result landed yet).
        mock_cache.get.side_effect = [0, _IDEMPOTENCY_IN_PROGRESS, _IDEMPOTENCY_IN_PROGRESS]
        mock_cache.add.return_value = False  # slot already claimed by the in-flight request

        result = self.gateway.register_domain("example.com", 1, {})

        self.assertTrue(result.is_err())
        self.assertIsInstance(result.unwrap_err(), RegistrarConflictError)


# ===============================================================================
# BACKWARD-COMPATIBLE FACADE (services.py DomainRegistrarGateway)
# ===============================================================================


@override_settings(REGISTRAR_ADAPTERS_VERIFIED=True)
class DomainRegistrarGatewayFacadeTests(TestCase):
    """The facade in services.py delegates to the gateway layer."""

    def test_register_delegates_to_factory(self) -> None:
        from apps.domains.services import DomainRegistrarGateway  # noqa: PLC0415

        registrar = _make_registrar("gandi")

        with patch("apps.domains.gateways.RegistrarGatewayFactory.create_gateway") as mock_factory:
            mock_gw = MagicMock()
            mock_gw.register_domain.return_value = Ok(
                DomainRegistrationResult(
                    registrar_domain_id="test-123",
                    expires_at=datetime(2027, 1, 1, tzinfo=UTC),
                    nameservers=["ns1.gandi.net"],
                    epp_code="EPP123",
                )
            )
            mock_factory.return_value = mock_gw

            success, data = DomainRegistrarGateway.register_domain(registrar, "test.com", 1, {})

        self.assertTrue(success)
        self.assertEqual(data["registrar_domain_id"], "test-123")

    def test_unknown_registrar_returns_failure(self) -> None:
        from apps.domains.services import DomainRegistrarGateway  # noqa: PLC0415

        registrar = _make_registrar("nonexistent")

        success, data = DomainRegistrarGateway.register_domain(registrar, "test.com", 1, {})

        self.assertFalse(success)
        self.assertIn("error", data)

    def test_verify_webhook_delegates(self) -> None:
        from apps.domains.services import DomainRegistrarGateway  # noqa: PLC0415

        registrar = _make_registrar("gandi")

        with patch("apps.domains.gateways.RegistrarGatewayFactory.create_gateway") as mock_factory:
            mock_gw = MagicMock()
            mock_gw.verify_webhook_signature.return_value = True
            mock_factory.return_value = mock_gw

            result = DomainRegistrarGateway.verify_webhook_signature(registrar, "payload", "sig")

        self.assertTrue(result)


# ===============================================================================
# IDEMPOTENCY CLAIM + CIRCUIT-BREAKER RECOVERY (PR #169 review H1/H2)
# ===============================================================================


@override_settings(REGISTRAR_ADAPTERS_VERIFIED=True)
class IdempotencyClaimTests(TestCase):
    """The idempotency key is claimed atomically before the call (H1)."""

    def setUp(self) -> None:
        self.registrar = _make_registrar("gandi")
        self.gateway = GandiGateway(self.registrar)
        self.registrant = {"first_name": "Ion", "last_name": "Popescu", "email": "ion@example.com"}

    @patch("apps.domains.gateways.base.cache")
    def test_concurrent_in_progress_call_is_rejected(self, mock_cache: MagicMock) -> None:
        # breaker OK, idempotency miss, then add() loses the race, then re-read shows in-progress.
        mock_cache.get.side_effect = [0, None, _IDEMPOTENCY_IN_PROGRESS]
        mock_cache.add.return_value = False

        with patch.object(self.gateway, "_do_register") as mock_do:
            result = self.gateway.register_domain("example.com", 1, self.registrant)

        self.assertTrue(result.is_err())
        self.assertIsInstance(result.unwrap_err(), RegistrarConflictError)
        # Crucially, the registrar was never called for the duplicate request.
        mock_do.assert_not_called()

    @patch("apps.domains.gateways.base.cache")
    def test_claim_is_released_on_failure(self, mock_cache: MagicMock) -> None:
        mock_cache.get.side_effect = [0, None]
        mock_cache.add.return_value = True

        with patch.object(self.gateway, "_do_register") as mock_do:
            mock_do.return_value = Err(RegistrarTransientError("gandi", "boom"))
            result = self.gateway.register_domain("example.com", 1, self.registrant)

        self.assertTrue(result.is_err())
        # The in-progress claim must be deleted so a legitimate retry can proceed.
        mock_cache.delete.assert_any_call("domain_reg:gandi:example.com")


class CircuitBreakerRecoveryTests(TestCase):
    """_record_failure keeps a fixed TTL window so the breaker auto-recovers (H2)."""

    def setUp(self) -> None:
        self.registrar = _make_registrar("gandi")
        self.gateway = GandiGateway(self.registrar)

    @patch("apps.domains.gateways.base.cache")
    def test_subsequent_failure_does_not_reset_ttl(self, mock_cache: MagicMock) -> None:
        # Counter already exists → add() fails, incr() bumps it; the sliding-window
        # touch() must be gone and set() must not reseed the TTL.
        mock_cache.add.return_value = False
        mock_cache.incr.return_value = 2
        self.gateway._record_failure(RegistrarTransientError("gandi", "boom"))
        mock_cache.touch.assert_not_called()
        mock_cache.set.assert_not_called()

    @patch("apps.domains.gateways.base.cache")
    def test_first_failure_seeds_fixed_ttl_atomically(self, mock_cache: MagicMock) -> None:
        from apps.domains.gateways.base import CIRCUIT_BREAKER_RESET_SECONDS  # noqa: PLC0415

        # add() atomically seeds the counter + TTL on the first failure (no incr/set race).
        mock_cache.add.return_value = True
        self.gateway._record_failure(RegistrarTransientError("gandi", "boom"))
        mock_cache.add.assert_called_once_with("cb:gandi:failures", 1, CIRCUIT_BREAKER_RESET_SECONDS)
        mock_cache.incr.assert_not_called()


# ===============================================================================
# INVALID-RESPONSE + ROBUSTNESS (PR #169 review M2/M4)
# ===============================================================================


@override_settings(REGISTRAR_ADAPTERS_VERIFIED=True)
class GandiInvalidResponseTests(TestCase):
    """Missing/invalid expiry and malformed price are handled gracefully."""

    def setUp(self) -> None:
        self.registrar = _make_registrar("gandi")
        self.gateway = GandiGateway(self.registrar)

    @patch("apps.domains.gateways.gandi.GandiGateway._api_request")
    @patch("apps.domains.gateways.base.cache")
    def test_registration_missing_expires_at_is_invalid_response(
        self, mock_cache: MagicMock, mock_request: MagicMock
    ) -> None:
        mock_cache.get.side_effect = [0, None]
        # 202 success but NO expires_at → must not fabricate a date.
        mock_request.return_value = _mock_response(202, {"id": "g-1", "auth_info": "EPP"})

        result = self.gateway.register_domain("example.com", 1, {})

        self.assertTrue(result.is_err())
        self.assertEqual(result.unwrap_err().code, RegistrarErrorCode.INVALID_RESPONSE)

    @patch("apps.domains.gateways.gandi.GandiGateway._api_request")
    @patch("apps.domains.gateways.base.cache")
    def test_malformed_price_does_not_break_availability(
        self, mock_cache: MagicMock, mock_request: MagicMock
    ) -> None:
        mock_cache.get.return_value = 0  # circuit breaker OK
        mock_request.return_value = _mock_response(
            200,
            {"products": [{"status": "available", "prices": [{"price_after_taxes": "not-a-number"}]}]},
        )

        result = self.gateway.check_availability("example.com")

        self.assertTrue(result.is_ok())
        self.assertTrue(result.unwrap().available)
        self.assertIsNone(result.unwrap().price_cents)


class SafeJsonResponseSizeTests(TestCase):
    """M5: _safe_json rejects oversized bodies before deserializing."""

    def setUp(self) -> None:
        self.gateway = GandiGateway(_make_registrar("gandi"))

    def _resp(self, *, content_length: str | None, content: bytes, json_data: dict | None = None) -> MagicMock:
        resp = MagicMock()
        resp.headers = {"content-length": content_length} if content_length is not None else {}
        resp.content = content
        resp.json.return_value = json_data or {}
        return resp

    def test_rejects_oversized_via_content_length_header(self) -> None:
        resp = self._resp(content_length=str(MAX_RESPONSE_SIZE_BYTES + 1), content=b"{}")
        with self.assertRaises(RegistrarAPIError) as ctx:
            self.gateway._safe_json(resp)
        self.assertEqual(ctx.exception.code, RegistrarErrorCode.INVALID_RESPONSE)
        resp.json.assert_not_called()

    def test_rejects_oversized_body_when_header_absent_or_lying(self) -> None:
        # No content-length header, but the actual body exceeds the cap.
        resp = self._resp(content_length=None, content=b"x" * (MAX_RESPONSE_SIZE_BYTES + 1))
        with self.assertRaises(RegistrarAPIError) as ctx:
            self.gateway._safe_json(resp)
        self.assertEqual(ctx.exception.code, RegistrarErrorCode.INVALID_RESPONSE)

    def test_parses_normal_response(self) -> None:
        resp = self._resp(content_length="12", content=b'{"ok": true}', json_data={"ok": True})
        self.assertEqual(self.gateway._safe_json(resp), {"ok": True})


@override_settings(REGISTRAR_ADAPTERS_VERIFIED=True)
class RetryHonorsRetriabilityTests(TestCase):
    """_retry must key off the Err's Retriability tag, not the error class.

    A registration/renewal POST network error is tagged UNKNOWN (the POST may
    have reached the registrar), so it must NOT be auto-replayed — replay could
    double-register/double-charge. An availability GET is a safe read, so its
    network error IS retried.
    """

    def setUp(self) -> None:
        self.registrar = _make_registrar("gandi")
        self.gateway = GandiGateway(self.registrar)
        self.registrant = {
            "first_name": "Ion", "last_name": "Pop", "email": "ion@example.ro",
            "phone": "+40712345678", "address": "Str. Test 1", "city": "Bucuresti",
            "postal_code": "010101", "country_code": "RO", "entity_type": "individual",
        }

    @patch("apps.domains.gateways.gandi.GandiGateway._api_request")
    @patch("apps.domains.gateways.base.cache")
    def test_registration_network_error_is_not_retried(self, mock_cache: MagicMock, mock_request: MagicMock) -> None:
        mock_cache.get.side_effect = [0, None]
        mock_cache.add.return_value = True
        mock_request.side_effect = requests.RequestException("connection reset")

        result = self.gateway.register_domain("example.com", 1, self.registrant)

        self.assertTrue(result.is_err())
        # UNKNOWN outcome — the POST may have landed, so exactly one attempt, no replay.
        self.assertEqual(mock_request.call_count, 1)

    @patch("apps.domains.gateways.gandi.GandiGateway._api_request")
    @patch("apps.domains.gateways.base.cache")
    def test_availability_network_error_is_retried(self, mock_cache: MagicMock, mock_request: MagicMock) -> None:
        mock_cache.get.return_value = 0  # circuit breaker OK
        mock_request.side_effect = requests.RequestException("connection reset")

        result = self.gateway.check_availability("example.com")

        self.assertTrue(result.is_err())
        # Idempotent read — retried up to MAX_RETRIES.
        self.assertEqual(mock_request.call_count, 3)


@override_settings(REGISTRAR_ADAPTERS_VERIFIED=True)
class IdempotencyCacheSecretRedactionTests(TestCase):
    """The idempotency cache must never persist the EPP/auth transfer credential.

    DatabaseCache/Redis serialize the cached value in plaintext; the EPP code is a
    transfer secret (encrypted at rest in the Domain row), so it must be stripped
    from the cached DomainRegistrationResult while the immediate caller still gets
    the full result to persist.
    """

    def setUp(self) -> None:
        self.registrar = _make_registrar("gandi")
        self.gateway = GandiGateway(self.registrar)
        self.registrant = {
            "first_name": "Ion", "last_name": "Pop", "email": "ion@example.ro",
            "phone": "+40712345678", "address": "Str. Test 1", "city": "Bucuresti",
            "postal_code": "010101", "country_code": "RO", "entity_type": "individual",
        }

    @patch("apps.domains.gateways.gandi.GandiGateway._do_register")
    @patch("apps.domains.gateways.base.cache")
    def test_epp_code_is_not_written_to_cache(self, mock_cache: MagicMock, mock_do_register: MagicMock) -> None:
        mock_cache.get.side_effect = [0, None]  # breaker OK, idempotency miss
        mock_cache.add.return_value = True
        mock_do_register.return_value = Ok(
            DomainRegistrationResult(
                registrar_domain_id="REG-1",
                expires_at=datetime(2027, 1, 1, tzinfo=UTC),
                nameservers=[],
                epp_code="TOP-SECRET-EPP",
            )
        )

        result = self.gateway.register_domain("example.com", 1, self.registrant)

        # Immediate caller still receives the real EPP to persist encrypted.
        self.assertEqual(result.unwrap().epp_code, "TOP-SECRET-EPP")
        # But nothing containing the secret was ever written to the cache.
        for call in mock_cache.set.call_args_list:
            self.assertNotIn("TOP-SECRET-EPP", repr(call))


@override_settings(REGISTRAR_ADAPTERS_VERIFIED=False)
class UnverifiedAdapterGuardTests(TestCase):
    """Until an adapter is validated against the real registrar sandbox, chargeable
    register/renew calls are refused; read-only availability is still allowed."""

    def setUp(self) -> None:
        self.registrar = _make_registrar("gandi")
        self.gateway = GandiGateway(self.registrar)
        self.registrant = {
            "first_name": "Ion", "last_name": "Pop", "email": "ion@example.ro",
            "phone": "+40712345678", "address": "Str. Test 1", "city": "Bucuresti",
            "postal_code": "010101", "country_code": "RO", "entity_type": "individual",
        }

    @patch("apps.domains.gateways.gandi.GandiGateway._api_request")
    def test_register_refused_when_unverified(self, mock_request: MagicMock) -> None:
        result = self.gateway.register_domain("example.com", 1, self.registrant)
        self.assertTrue(result.is_err())
        self.assertEqual(result.unwrap_err().code, RegistrarErrorCode.NOT_CONFIGURED)
        # No outbound call was attempted.
        mock_request.assert_not_called()

    @patch("apps.domains.gateways.gandi.GandiGateway._api_request")
    def test_renew_refused_when_unverified(self, mock_request: MagicMock) -> None:
        result = self.gateway.renew_domain("REG-1", "example.com", 1)
        self.assertTrue(result.is_err())
        self.assertEqual(result.unwrap_err().code, RegistrarErrorCode.NOT_CONFIGURED)
        mock_request.assert_not_called()

    @patch("apps.domains.gateways.base.cache")
    @patch("apps.domains.gateways.gandi.GandiGateway._api_request")
    def test_availability_allowed_when_unverified(self, mock_request: MagicMock, mock_cache: MagicMock) -> None:
        mock_cache.get.return_value = 0
        mock_request.return_value = _mock_response(200, {"products": [{"status": "available", "prices": [{}]}]})
        result = self.gateway.check_availability("example.com")
        self.assertTrue(result.is_ok(), result)


@override_settings(REGISTRAR_ADAPTERS_VERIFIED=True)
class GatewayHardeningTests(TestCase):
    """W2/W3/W4: exception-safe idempotency claim, breaker counts only systemic
    failures, and audit never records raw registrar PII."""

    def setUp(self) -> None:
        self.registrar = _make_registrar("gandi")
        self.gateway = GandiGateway(self.registrar)
        self.registrant = {
            "first_name": "Ion", "last_name": "Pop", "email": "ion@example.ro",
            "phone": "+40712345678", "address": "Str. Test 1", "city": "Bucuresti",
            "postal_code": "010101", "country_code": "RO", "entity_type": "individual",
        }

    @patch("apps.domains.gateways.gandi.GandiGateway._do_register")
    @patch("apps.domains.gateways.base.cache")
    def test_idempotency_claim_released_when_operation_raises(self, mock_cache: MagicMock, mock_do: MagicMock) -> None:
        """An unexpected exception (e.g. oversized-response RegistrarAPIError) must still
        release the in-progress claim so a later retry isn't permanently blocked."""
        mock_cache.get.side_effect = [0, None]
        mock_cache.add.return_value = True
        mock_do.side_effect = RegistrarAPIError("boom", code=RegistrarErrorCode.INVALID_RESPONSE)

        result = self.gateway.register_domain("example.com", 1, self.registrant)

        self.assertTrue(result.is_err())
        mock_cache.delete.assert_called_once()  # claim released

    @patch("apps.domains.gateways.base.cache")
    def test_breaker_ignores_non_systemic_errors(self, mock_cache: MagicMock) -> None:
        """A domain conflict / auth error is not a registrar-wide outage — it must
        not count toward tripping the circuit breaker; a transient one does."""
        self.gateway._record_failure(RegistrarConflictError("example.com", self.registrar.name))
        mock_cache.add.assert_not_called()
        mock_cache.incr.assert_not_called()

        mock_cache.add.return_value = True
        self.gateway._record_failure(RegistrarTransientError(self.registrar.name, "5xx"))
        mock_cache.add.assert_called_once()

    @patch("apps.domains.gateways.gandi.GandiGateway._do_register")
    @patch("apps.domains.gateways.base.cache")
    def test_audit_records_error_code_not_raw_registrar_body(self, mock_cache: MagicMock, mock_do: MagicMock) -> None:
        """A registrar error echoing registrant PII must not reach the audit trail."""
        mock_cache.get.side_effect = [0, None]
        mock_cache.add.return_value = True
        mock_do.return_value = Err(
            RegistrarAPIError(
                "invalid registrant: CNP 1900101123456 rejected",
                code=RegistrarErrorCode.INVALID_REGISTRANT_DATA,
            )
        )
        with patch("apps.audit.services.AuditService.log_simple_event") as mock_audit:
            self.gateway.register_domain("example.com", 1, self.registrant)

        self.assertTrue(mock_audit.called)
        recorded = repr(mock_audit.call_args)
        self.assertNotIn("1900101123456", recorded)
        self.assertIn("invalid_registrant_data", recorded)
