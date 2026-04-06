"""Tests for Phase 2 domain registrar gateway features.

Covers: DomainOperation model, transfer/nameserver/lock/info gateway methods,
DomainLifecycleService Phase 2 operations, bulk availability.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock, patch

from django.test import TestCase

from apps.common.types import Err, Ok
from apps.domains.gateways.base import (
    DomainAvailabilityResult,
    DomainInfoResult,
)
from apps.domains.gateways.errors import RegistrarTransientError
from apps.domains.gateways.gandi import GandiGateway
from apps.domains.gateways.rotld import ROTLDGateway
from apps.domains.models import DomainOperation, Registrar


def _make_registrar(name: str = "gandi", **kwargs: Any) -> Registrar:
    defaults = {
        "display_name": name.upper(),
        "website_url": f"https://{name}.net",
        "api_endpoint": f"https://api.{name}.net/v5",
        "api_username": "",
        "api_key": "test-key",
        "api_secret": "",
        "webhook_secret": "",
        "status": "active",
    }
    defaults.update(kwargs)
    return Registrar(name=name, **defaults)


def _mock_response(status_code: int, json_data: dict | None = None, text: str = "") -> MagicMock:
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
# DOMAIN OPERATION MODEL
# ===============================================================================


class DomainOperationModelTests(TestCase):
    """DomainOperation model basic behavior."""

    def test_can_retry_when_failed_under_max(self) -> None:
        op = DomainOperation(state="failed", retry_count=1, max_retries=3)
        self.assertTrue(op.can_retry)

    def test_cannot_retry_when_at_max(self) -> None:
        op = DomainOperation(state="failed", retry_count=3, max_retries=3)
        self.assertFalse(op.can_retry)

    def test_cannot_retry_when_completed(self) -> None:
        op = DomainOperation(state="completed", retry_count=0, max_retries=3)
        self.assertFalse(op.can_retry)

    def test_duration_seconds(self) -> None:
        op = DomainOperation(
            submitted_at=datetime(2027, 1, 1, 0, 0, 0, tzinfo=UTC),
            completed_at=datetime(2027, 1, 1, 0, 0, 5, tzinfo=UTC),
        )
        self.assertEqual(op.duration_seconds, 5)

    def test_duration_zero_when_not_completed(self) -> None:
        op = DomainOperation(submitted_at=datetime(2027, 1, 1, tzinfo=UTC))
        self.assertEqual(op.duration_seconds, 0)


# ===============================================================================
# GANDI PHASE 2 GATEWAY
# ===============================================================================


class GandiTransferTests(TestCase):
    """Gandi domain transfer operations."""

    def setUp(self) -> None:
        self.registrar = _make_registrar("gandi")
        self.gateway = GandiGateway(self.registrar)

    @patch("apps.domains.gateways.gandi.GandiGateway._api_request")
    @patch("apps.domains.gateways.base.cache")
    def test_successful_transfer(self, mock_cache: MagicMock, mock_request: MagicMock) -> None:
        mock_cache.get.side_effect = [0, None]
        mock_request.return_value = _mock_response(
            202,
            {
                "id": "transfer-123",
                "status": "pending",
            },
        )

        result = self.gateway.initiate_transfer("example.com", "EPP-CODE")

        self.assertTrue(result.is_ok())
        transfer = result.unwrap()
        self.assertEqual(transfer.transfer_id, "transfer-123")
        self.assertEqual(transfer.status, "pending")

    @patch("apps.domains.gateways.gandi.GandiGateway._api_request")
    @patch("apps.domains.gateways.base.cache")
    def test_transfer_auth_failure(self, mock_cache: MagicMock, mock_request: MagicMock) -> None:
        mock_cache.get.side_effect = [0, None]
        mock_request.return_value = _mock_response(401, {"message": "Bad auth"})

        result = self.gateway.initiate_transfer("example.com", "BAD-EPP")

        self.assertTrue(result.is_err())


class GandiDomainInfoTests(TestCase):
    """Gandi domain info retrieval."""

    def setUp(self) -> None:
        self.registrar = _make_registrar("gandi")
        self.gateway = GandiGateway(self.registrar)

    @patch("apps.domains.gateways.gandi.GandiGateway._api_request")
    @patch("apps.domains.gateways.base.cache")
    def test_successful_info(self, mock_cache: MagicMock, mock_request: MagicMock) -> None:
        mock_cache.get.return_value = 0
        mock_request.return_value = _mock_response(
            200,
            {
                "id": "gandi-123",
                "fqdn": "example.com",
                "status": "active",
                "dates": {"registry_ends_at": "2028-01-01T00:00:00Z"},
                "nameservers": ["ns1.gandi.net", "ns2.gandi.net"],
                "whois_privacy": True,
                "auth_info": "EPP-CODE",
            },
        )

        result = self.gateway.get_domain_info("example.com")

        self.assertTrue(result.is_ok())
        info = result.unwrap()
        self.assertEqual(info.registrar_domain_id, "gandi-123")
        self.assertEqual(info.nameservers, ["ns1.gandi.net", "ns2.gandi.net"])
        self.assertTrue(info.whois_privacy)


class GandiNameserverTests(TestCase):
    """Gandi nameserver update operations."""

    def setUp(self) -> None:
        self.registrar = _make_registrar("gandi")
        self.gateway = GandiGateway(self.registrar)

    @patch("apps.domains.gateways.gandi.GandiGateway._api_request")
    @patch("apps.domains.gateways.base.cache")
    def test_successful_ns_update(self, mock_cache: MagicMock, mock_request: MagicMock) -> None:
        mock_cache.get.return_value = 0
        mock_request.return_value = _mock_response(200, {})

        result = self.gateway.update_nameservers("example.com", ["ns1.new.com", "ns2.new.com"])

        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap().nameservers, ["ns1.new.com", "ns2.new.com"])


class GandiLockTests(TestCase):
    """Gandi domain lock operations."""

    def setUp(self) -> None:
        self.registrar = _make_registrar("gandi")
        self.gateway = GandiGateway(self.registrar)

    @patch("apps.domains.gateways.gandi.GandiGateway._api_request")
    @patch("apps.domains.gateways.base.cache")
    def test_lock_domain(self, mock_cache: MagicMock, mock_request: MagicMock) -> None:
        mock_cache.get.return_value = 0
        mock_request.return_value = _mock_response(200, {})

        result = self.gateway.set_lock("example.com", locked=True)

        self.assertTrue(result.is_ok())
        self.assertTrue(result.unwrap().locked)


# ===============================================================================
# ROTLD PHASE 2 GATEWAY
# ===============================================================================


class ROTLDTransferTests(TestCase):
    """ROTLD domain transfer operations."""

    def setUp(self) -> None:
        self.registrar = _make_registrar("rotld", api_endpoint="https://rest2.rotld.ro")
        self.gateway = ROTLDGateway(self.registrar)

    @patch("apps.domains.gateways.rotld.ROTLDGateway._api_request")
    @patch("apps.domains.gateways.base.cache")
    def test_successful_transfer(self, mock_cache: MagicMock, mock_request: MagicMock) -> None:
        mock_cache.get.side_effect = [0, None]
        mock_request.return_value = _mock_response(
            201,
            {
                "id": "rotld-tx-456",
                "status": "pending",
            },
        )

        result = self.gateway.initiate_transfer("exemplu.ro", "EPP-CODE")

        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap().transfer_id, "rotld-tx-456")


class ROTLDDomainInfoTests(TestCase):
    """ROTLD domain info retrieval."""

    def setUp(self) -> None:
        self.registrar = _make_registrar("rotld", api_endpoint="https://rest2.rotld.ro")
        self.gateway = ROTLDGateway(self.registrar)

    @patch("apps.domains.gateways.rotld.ROTLDGateway._api_request")
    @patch("apps.domains.gateways.base.cache")
    def test_successful_info(self, mock_cache: MagicMock, mock_request: MagicMock) -> None:
        mock_cache.get.return_value = 0
        mock_request.return_value = _mock_response(
            200,
            {
                "domain": {
                    "id": "rotld-123",
                    "status": "active",
                    "expire_at": "2028-01-01T00:00:00Z",
                    "nameservers": [{"hostname": "ns1.rotld.ro"}, {"hostname": "ns2.rotld.ro"}],
                    "locked": True,
                },
            },
        )

        result = self.gateway.get_domain_info("exemplu.ro")

        self.assertTrue(result.is_ok())
        info = result.unwrap()
        self.assertTrue(info.locked)
        self.assertEqual(info.nameservers, ["ns1.rotld.ro", "ns2.rotld.ro"])
        self.assertFalse(info.whois_privacy)  # ROTLD doesn't support WHOIS privacy


# ===============================================================================
# BULK AVAILABILITY
# ===============================================================================


class BulkAvailabilityTests(TestCase):
    """Bulk availability check with sequential fallback."""

    def setUp(self) -> None:
        self.registrar = _make_registrar("gandi")
        self.gateway = GandiGateway(self.registrar)

    @patch("apps.domains.gateways.base.cache")
    def test_bulk_check_uses_sequential_fallback(self, mock_cache: MagicMock) -> None:
        mock_cache.get.return_value = 0

        with patch.object(self.gateway, "_do_check_availability") as mock_check:
            mock_check.side_effect = [
                Ok(DomainAvailabilityResult("a.com", True)),
                Ok(DomainAvailabilityResult("b.com", False)),
            ]

            result = self.gateway.check_availability_bulk(["a.com", "b.com"])

        self.assertTrue(result.is_ok())
        results = result.unwrap()
        self.assertEqual(len(results), 2)
        self.assertTrue(results[0].available)
        self.assertFalse(results[1].available)

    @patch("apps.domains.gateways.base.cache")
    def test_bulk_check_handles_failures_gracefully(self, mock_cache: MagicMock) -> None:
        mock_cache.get.return_value = 0

        with patch.object(self.gateway, "_do_check_availability") as mock_check:
            mock_check.side_effect = [
                Ok(DomainAvailabilityResult("a.com", True)),
                Err(RegistrarTransientError("gandi", "timeout")),
            ]

            result = self.gateway.check_availability_bulk(["a.com", "fail.com"])

        self.assertTrue(result.is_ok())
        results = result.unwrap()
        self.assertEqual(len(results), 2)
        self.assertTrue(results[0].available)
        self.assertFalse(results[1].available)  # failed check defaults to unavailable


# ===============================================================================
# LIFECYCLE SERVICE PHASE 2 (with mocked gateway)
# ===============================================================================


class LifecycleServicePhase2Tests(TestCase):
    """DomainLifecycleService Phase 2 operations with mocked gateways."""

    def test_sync_domain_info_updates_local_record(self) -> None:
        from apps.domains.services import DomainLifecycleService  # noqa: PLC0415

        # Create test data
        registrar = Registrar.objects.create(
            name="gandi",
            display_name="Gandi",
            website_url="https://gandi.net",
            api_endpoint="https://api.gandi.net/v5",
            status="active",
        )
        from apps.customers.models import Customer  # noqa: PLC0415
        from apps.domains.models import TLD  # noqa: PLC0415

        tld = TLD.objects.create(
            extension="com",
            description="Commercial",
            registration_price_cents=1200,
            renewal_price_cents=1200,
            transfer_price_cents=1200,
        )
        customer = Customer.objects.create(
            name="Test Customer",
            primary_email="test@example.com",
            company_name="Test Co",
            customer_type="individual",
        )
        from apps.domains.models import Domain  # noqa: PLC0415

        domain = Domain.objects.create(
            name="example.com",
            tld=tld,
            registrar=registrar,
            customer=customer,
            status="active",
            nameservers=["old-ns1.com", "old-ns2.com"],
            locked=False,
        )

        mock_info = DomainInfoResult(
            registrar_domain_id="gandi-999",
            domain_name="example.com",
            status="active",
            expires_at=datetime(2028, 6, 1, tzinfo=UTC),
            nameservers=["ns1.gandi.net", "ns2.gandi.net"],
            locked=True,
            whois_privacy=True,
        )

        with patch("apps.domains.gateways.RegistrarGatewayFactory.create_gateway") as mock_factory:
            mock_gw = MagicMock()
            mock_gw.get_domain_info.return_value = Ok(mock_info)
            mock_factory.return_value = mock_gw

            result = DomainLifecycleService.sync_domain_info(domain)

        self.assertTrue(result.is_ok())
        op = result.unwrap()
        self.assertEqual(op.state, "completed")

        domain.refresh_from_db()
        self.assertEqual(domain.nameservers, ["ns1.gandi.net", "ns2.gandi.net"])
        self.assertTrue(domain.locked)
        self.assertTrue(domain.whois_privacy)
        self.assertEqual(domain.registrar_domain_id, "gandi-999")
