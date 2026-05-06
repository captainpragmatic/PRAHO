"""Tests for domain registrar gateway layer (issue #93).

Tests the ABC, factory, circuit breaker, idempotency, error mapping,
and the Gandi/ROTLD concrete gateways with mocked HTTP responses.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock, patch

from django.test import TestCase

from apps.common.types import Ok
from apps.domains.gateways import (
    RegistrarGatewayFactory,
)
from apps.domains.gateways.base import (
    CIRCUIT_BREAKER_THRESHOLD,
    DomainAvailabilityResult,
    DomainRegistrationResult,
)
from apps.domains.gateways.errors import (
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


# ===============================================================================
# BACKWARD-COMPATIBLE FACADE (services.py DomainRegistrarGateway)
# ===============================================================================


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
