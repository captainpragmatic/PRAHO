"""Tests for Phase 2 domain registrar gateway features.

Covers: DomainOperation model, transfer/nameserver/lock/info gateway methods,
DomainLifecycleService Phase 2 operations, bulk availability.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock, patch

from django.test import TestCase, override_settings
from django_fsm import TransitionNotAllowed

from apps.common.types import Err, Ok, Retriability
from apps.customers.models import Customer
from apps.domains.gateways.base import (
    _IDEMPOTENCY_IN_PROGRESS,
    DomainAvailabilityResult,
    DomainInfoResult,
    DomainTransferResult,
)
from apps.domains.gateways.errors import RegistrarAPIError, RegistrarErrorCode, RegistrarTransientError
from apps.domains.gateways.gandi import GandiGateway
from apps.domains.gateways.rotld import ROTLDGateway
from apps.domains.models import TLD, Domain, DomainOperation, Registrar
from apps.domains.services import DomainLifecycleService


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

    # --- FSM guardrails (ADR-0034) -------------------------------------------

    def test_state_is_protected_against_direct_assignment(self) -> None:
        """state is a protected FSMField: reassignment after construction raises.

        This is the guardrail that forces all state changes through the
        @transition-decorated mark_* methods. Without protected=True the FSM
        is decorative.
        """
        op = DomainOperation()  # defaults to "pending"
        with self.assertRaises(AttributeError):
            op.state = "completed"

    def test_mark_completed_allowed_directly_from_pending(self) -> None:
        """Synchronous ops (nameserver/lock/info-sync) complete straight from
        pending — the source list MUST include 'pending', not only 'submitted'."""
        op = DomainOperation()
        op.mark_completed(result_data={"drift_detected": False})
        self.assertEqual(op.state, "completed")
        self.assertIsNotNone(op.completed_at)

    def test_mark_failed_allowed_directly_from_pending(self) -> None:
        """A synchronous op that fails before any submit step goes pending→failed."""
        op = DomainOperation()
        op.mark_failed("registrar rejected")
        self.assertEqual(op.state, "failed")
        self.assertEqual(op.error_message, "registrar rejected")

    def test_completed_op_cannot_be_resubmitted(self) -> None:
        """A terminal 'completed' op has no path back to 'submitted' — the FSM
        rejects the transition rather than silently mutating state."""
        op = DomainOperation()
        op.mark_completed()
        with self.assertRaises(TransitionNotAllowed):
            op.mark_submitted()


# ===============================================================================
# GANDI PHASE 2 GATEWAY
# ===============================================================================


@override_settings(REGISTRAR_ADAPTERS_VERIFIED=True)
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


@override_settings(REGISTRAR_ADAPTERS_VERIFIED=True)
class TransferIdempotencyClaimTests(TestCase):
    """initiate_transfer must claim the idempotency slot atomically BEFORE posting,
    so two concurrent requests can't both submit a chargeable transfer (Codex P1)."""

    def setUp(self) -> None:
        self.registrar = _make_registrar("gandi")
        self.gateway = GandiGateway(self.registrar)

    @patch("apps.domains.gateways.gandi.GandiGateway._do_initiate_transfer")
    @patch("apps.domains.gateways.base.cache")
    def test_transfer_claims_slot_with_sentinel_before_posting(
        self, mock_cache: MagicMock, mock_do: MagicMock
    ) -> None:
        # circuit breaker closed (0), idempotency slot free (None), claim wins.
        mock_cache.get.side_effect = [0, None]
        mock_cache.add.return_value = True
        mock_do.return_value = Ok(DomainTransferResult(transfer_id="t-1", status="pending"))

        result = self.gateway.initiate_transfer("example.com", "EPP")

        self.assertTrue(result.is_ok(), result)
        # The atomic claim (cache.add of the in-progress sentinel) must have happened —
        # the naive get-then-set path never calls add().
        self.assertTrue(mock_cache.add.called)
        self.assertEqual(mock_cache.add.call_args.args[1], _IDEMPOTENCY_IN_PROGRESS)

    @patch("apps.domains.gateways.gandi.GandiGateway._do_initiate_transfer")
    @patch("apps.domains.gateways.base.cache")
    def test_concurrent_transfer_loses_claim_and_does_not_post(
        self, mock_cache: MagicMock, mock_do: MagicMock
    ) -> None:
        # slot free on first look, but the atomic add loses the race (another request
        # already claimed it) and the recheck finds no completed result yet.
        mock_cache.get.side_effect = [0, None, None]
        mock_cache.add.return_value = False  # claim lost

        result = self.gateway.initiate_transfer("example.com", "EPP")

        self.assertTrue(result.is_err(), result)
        # The chargeable registrar call must NOT be made when the claim is lost.
        mock_do.assert_not_called()


class BulkAvailabilityExceptionSafetyTests(TestCase):
    """check_availability_bulk must convert a raised registrar error into an Err,
    not let it propagate as a 500 (Copilot base.py finding)."""

    def setUp(self) -> None:
        self.registrar = _make_registrar("gandi")
        self.gateway = GandiGateway(self.registrar)

    @patch("apps.domains.gateways.gandi.GandiGateway._do_check_availability_bulk")
    @patch("apps.domains.gateways.base.cache")
    def test_raised_registrar_error_becomes_err(self, mock_cache: MagicMock, mock_bulk: MagicMock) -> None:
        mock_cache.get.return_value = 0  # circuit breaker closed
        mock_bulk.side_effect = RegistrarAPIError(
            "boom", code=RegistrarErrorCode.INTERNAL_ERROR, registrar_name="gandi"
        )

        result = self.gateway.check_availability_bulk(["a.com", "b.com"])

        self.assertTrue(result.is_err(), result)  # outage != unhandled 500


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


@override_settings(REGISTRAR_ADAPTERS_VERIFIED=True)
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


@override_settings(REGISTRAR_ADAPTERS_VERIFIED=True)
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


@override_settings(REGISTRAR_ADAPTERS_VERIFIED=True)
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
        # Create test data
        registrar = Registrar.objects.create(
            name="gandi",
            display_name="Gandi",
            website_url="https://gandi.net",
            api_endpoint="https://api.gandi.net/v5",
            status="active",
        )
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


class LifecycleServicePhase2FailureContractTests(TestCase):
    """Phase 2 service methods must return Err on registrar failure (not Ok), and
    initiate_transfer must not strand the unique Domain name on a definite rejection."""

    def setUp(self) -> None:
        self.registrar = Registrar.objects.create(
            name="gandi", display_name="Gandi", website_url="https://gandi.net",
            api_endpoint="https://api.gandi.net/v5", status="active",
        )
        self.tld = TLD.objects.create(
            extension="com", description="Commercial",
            registration_price_cents=1200, renewal_price_cents=1200, transfer_price_cents=1200,
        )
        self.customer = Customer.objects.create(
            name="Test Customer", primary_email="test@example.com",
            company_name="Test Co", customer_type="individual",
        )
        self.domain = Domain.objects.create(
            name="active.com", tld=self.tld, registrar=self.registrar, customer=self.customer,
            status="active", nameservers=["ns1.old.com"], locked=False,
        )
        self.Domain = Domain

    def _mock_gateway(self, **methods: Any):
        gw = MagicMock()
        for name, ret in methods.items():
            getattr(gw, name).return_value = ret
        return patch("apps.domains.gateways.RegistrarGatewayFactory.create_gateway", return_value=gw)

    @staticmethod
    def _err(code: RegistrarErrorCode, retriability: Retriability) -> Err:
        return Err(RegistrarAPIError("boom", code=code, registrar_name="gandi"), retriability=retriability)

    def test_transfer_definite_rejection_deletes_row(self) -> None:
        with self._mock_gateway(initiate_transfer=self._err(RegistrarErrorCode.INVALID_REGISTRANT_DATA, Retriability.NOT_RETRIABLE)):
            result = DomainLifecycleService.initiate_transfer("transfer.com", "BAD-EPP", self.customer, self.registrar)

        self.assertTrue(result.is_err(), result)
        # Row removed so the customer can retry with a corrected EPP (no #260 deadlock).
        self.assertFalse(self.Domain.objects.filter(name="transfer.com").exists())

    def test_transfer_retriable_breaker_open_deletes_row(self) -> None:
        """An open circuit breaker returns RETRIABLE — the row must still be deleted, else
        a manual retry hits the unique-name deadlock."""
        with self._mock_gateway(initiate_transfer=self._err(RegistrarErrorCode.INTERNAL_ERROR, Retriability.RETRIABLE)):
            result = DomainLifecycleService.initiate_transfer("transfer2.com", "EPP", self.customer, self.registrar)

        self.assertTrue(result.is_err(), result)
        self.assertFalse(self.Domain.objects.filter(name="transfer2.com").exists())

    def test_transfer_passes_lowercased_domain_to_gateway(self) -> None:
        """The DB row stores domain.name lowercased; the gateway call must use the SAME
        casing, or the gateway idempotency key (keyed on the passed name) won't match a
        retry and a duplicate chargeable transfer can slip through (Copilot finding)."""
        captured: dict[str, str] = {}

        def _capture(name: str, epp: str) -> Ok:
            captured["name"] = name
            return Ok(DomainTransferResult(transfer_id="t-1", status="pending"))

        gw = MagicMock()
        gw.initiate_transfer.side_effect = _capture
        with patch("apps.domains.gateways.RegistrarGatewayFactory.create_gateway", return_value=gw):
            result = DomainLifecycleService.initiate_transfer("Example.COM", "EPP", self.customer, self.registrar)

        self.assertTrue(result.is_ok(), result)
        self.assertEqual(captured["name"], "example.com")

    def test_transfer_unknown_keeps_pending_row(self) -> None:
        with self._mock_gateway(initiate_transfer=self._err(RegistrarErrorCode.NETWORK_ERROR, Retriability.UNKNOWN)):
            result = DomainLifecycleService.initiate_transfer("transfer3.com", "EPP", self.customer, self.registrar)

        self.assertTrue(result.is_err(), result)
        # UNKNOWN — the transfer may have started; keep the row for reconciliation.
        self.assertTrue(self.Domain.objects.filter(name="transfer3.com").exists())

    def test_update_nameservers_failure_returns_err(self) -> None:
        with self._mock_gateway(update_nameservers=self._err(RegistrarErrorCode.INTERNAL_ERROR, Retriability.UNKNOWN)):
            result = DomainLifecycleService.update_nameservers(self.domain, ["ns1.new.com"])

        self.assertTrue(result.is_err(), result)
        self.domain.refresh_from_db()
        self.assertEqual(self.domain.nameservers, ["ns1.old.com"])  # unchanged on failure

    def test_set_lock_failure_returns_err(self) -> None:
        with self._mock_gateway(set_lock=self._err(RegistrarErrorCode.INTERNAL_ERROR, Retriability.UNKNOWN)):
            result = DomainLifecycleService.set_domain_lock(self.domain, locked=True)

        self.assertTrue(result.is_err(), result)
        self.domain.refresh_from_db()
        self.assertFalse(self.domain.locked)

    def test_sync_failure_returns_err(self) -> None:
        with self._mock_gateway(get_domain_info=self._err(RegistrarErrorCode.NETWORK_ERROR, Retriability.RETRIABLE)):
            result = DomainLifecycleService.sync_domain_info(self.domain)

        self.assertTrue(result.is_err(), result)

    def test_sync_dry_run_does_not_persist_but_reports_drift(self) -> None:
        info = DomainInfoResult(
            registrar_domain_id="g-1", domain_name="active.com", status="active",
            expires_at=datetime(2028, 1, 1, tzinfo=UTC), nameservers=["ns1.new.com"], locked=True, whois_privacy=False,
        )
        with self._mock_gateway(get_domain_info=Ok(info)):
            result = DomainLifecycleService.sync_domain_info(self.domain, persist=False)

        self.assertTrue(result.is_ok(), result)
        op = result.unwrap()
        self.assertTrue(op.result["drift_detected"])
        self.assertIn("nameservers", op.result["changed_fields"])
        # Nothing persisted.
        self.assertEqual(DomainOperation.objects.count(), 0)
        self.domain.refresh_from_db()
        self.assertEqual(self.domain.nameservers, ["ns1.old.com"])
