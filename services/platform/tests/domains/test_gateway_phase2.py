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
from apps.customers.models import Customer, CustomerAddress, CustomerTaxProfile
from apps.domains.gateways.base import (
    _IDEMPOTENCY_IN_PROGRESS,
    DomainAvailabilityResult,
    DomainInfoResult,
    DomainLockResult,
    DomainTransferResult,
    NameserverUpdateResult,
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


def _cache_get_stub(key: str, default: object = None) -> object:
    """cache.get() stub keyed by NAME, not call order.

    The circuit breaker expects an int (`cb:...:failures`); everything else here is an
    idempotency claim that must read as absent. A positional side_effect list couples the
    test to the exact number of cache.get calls inside the base gateway and raises
    StopIteration the moment one is added.
    """
    return 0 if str(key).startswith("cb:") else default

def _mock_response(
    status_code: int, json_data: dict | None = None, text: str = "", headers: dict | None = None
) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text or json.dumps(json_data or {})
    # Gandi's 202 bodies carry only {"message": ...}; the operation handle is in Location,
    # so a fixture that cannot set headers can never notice the header matters.
    resp.headers = headers or {}
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
        mock_cache.get.side_effect = _cache_get_stub
        operation_url = "https://api.gandi.net/v5/domain/transferin/example.com"
        mock_request.return_value = _mock_response(
            202,
            {"message": "Transfer accepted"},
            headers={"Location": operation_url},
        )

        result = self.gateway.initiate_transfer("example.com", "EPP-CODE")

        self.assertTrue(result.is_ok())
        transfer = result.unwrap()
        self.assertEqual(transfer.transfer_id, operation_url)
        self.assertEqual(transfer.status, "pending")

    @patch("apps.domains.gateways.gandi.GandiGateway._api_request")
    @patch("apps.domains.gateways.base.cache")
    def test_transfer_auth_failure(self, mock_cache: MagicMock, mock_request: MagicMock) -> None:
        mock_cache.get.side_effect = _cache_get_stub
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
        mock_cache.get.side_effect = _cache_get_stub
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

    @patch("apps.domains.gateways.gandi.GandiGateway._do_initiate_transfer")
    @patch("apps.domains.gateways.base.cache")
    def test_unknown_outcome_retains_claim_instead_of_releasing_it(
        self, mock_cache: MagicMock, mock_do: MagicMock
    ) -> None:
        """A registrar-outcome-UNKNOWN failure (e.g. a lost response) must NOT release the
        claim — the transfer may have already applied. Mirrors
        RenewalIdempotencyTokenTests.test_unknown_outcome_blocks_same_token_retry; this
        gateway inlines its own claim/release protocol instead of routing through
        _execute_idempotent_operation, so it needed the identical fix applied separately."""
        mock_cache.get.side_effect = _cache_get_stub
        mock_cache.add.return_value = True
        mock_do.return_value = Err(RegistrarAPIError("transfer response lost"))  # default UNKNOWN

        result = self.gateway.initiate_transfer("example.com", "EPP")

        self.assertTrue(result.is_err())
        mock_cache.delete.assert_not_called()  # claim retained — outcome is ambiguous

    @patch("apps.domains.gateways.gandi.GandiGateway._do_initiate_transfer")
    @patch("apps.domains.gateways.base.cache")
    def test_not_retriable_outcome_releases_claim(self, mock_cache: MagicMock, mock_do: MagicMock) -> None:
        """A definite (NOT_RETRIABLE) rejection still releases the claim immediately —
        the carve-out proving the UNKNOWN fix doesn't overcorrect into blocking every
        failure."""
        mock_cache.get.side_effect = _cache_get_stub
        mock_cache.add.return_value = True
        mock_do.return_value = Err(
            RegistrarAPIError("epp code rejected"), retriability=Retriability.NOT_RETRIABLE
        )

        result = self.gateway.initiate_transfer("example.com", "EPP")

        self.assertTrue(result.is_err())
        mock_cache.delete.assert_called_once()


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
                "authinfo": "EPP-CODE",  # Gandi's documented field name
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
        self.assertFalse(result.unwrap().pending)


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
        self.assertFalse(result.unwrap().pending)


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
        mock_cache.get.side_effect = _cache_get_stub
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
            name="Test Customer",
            primary_email="test@example.com",
            primary_phone="+40712345678",
            company_name="Test Co",
            customer_type="individual",
        )
        CustomerAddress.objects.create(
            customer=self.customer,
            address_line1="Str. Test 1",
            city="Bucuresti",
            county="Bucuresti",
            postal_code="010101",
            country="România",
            is_primary=True,
            is_current=True,
        )
        CustomerTaxProfile.objects.create(customer=self.customer, cnp="1900101123456")
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

    def test_transfer_passes_lowercased_domain_and_registrant_data_to_gateway(self) -> None:
        """The gateway receives the canonical domain and validated owner contact."""
        captured: dict[str, Any] = {}

        def _capture(
            name: str,
            epp: str,
            registrant_data: dict[str, Any] | None = None,
        ) -> Ok[DomainTransferResult]:
            captured["name"] = name
            captured["epp"] = epp
            captured["registrant_data"] = registrant_data
            return Ok(DomainTransferResult(transfer_id="t-1", status="pending"))

        gw = MagicMock()
        gw.initiate_transfer.side_effect = _capture
        with patch("apps.domains.gateways.RegistrarGatewayFactory.create_gateway", return_value=gw):
            result = DomainLifecycleService.initiate_transfer("Example.COM", "EPP", self.customer, self.registrar)

        self.assertTrue(result.is_ok(), result)
        self.assertEqual(captured["name"], "example.com")
        self.assertEqual(captured["epp"], "EPP")
        registrant_data = captured["registrant_data"]
        self.assertIsNotNone(registrant_data)
        self.assertEqual(registrant_data["email"], "test@example.com")
        self.assertEqual(registrant_data["cnp"], "1900101123456")

    def test_transfer_unknown_keeps_pending_row(self) -> None:
        with self._mock_gateway(initiate_transfer=self._err(RegistrarErrorCode.NETWORK_ERROR, Retriability.UNKNOWN)):
            result = DomainLifecycleService.initiate_transfer("transfer3.com", "EPP", self.customer, self.registrar)

        self.assertTrue(result.is_err(), result)
        # UNKNOWN — the transfer may have started; keep the row for reconciliation.
        self.assertTrue(self.Domain.objects.filter(name="transfer3.com").exists())

    def test_transfer_missing_registrant_data_fails_before_creating_domain(self) -> None:
        incomplete_customer = Customer.objects.create(
            name="Missing Contact",
            primary_email="missing@example.com",
            customer_type="individual",
        )
        gateway = MagicMock()

        with patch(
            "apps.domains.gateways.RegistrarGatewayFactory.create_gateway",
            return_value=gateway,
        ):
            result = DomainLifecycleService.initiate_transfer(
                "missing.com",
                "EPP",
                incomplete_customer,
                self.registrar,
            )

        self.assertTrue(result.is_err(), result)
        self.assertIn("missing required registrant data", str(result.unwrap_err()))
        self.assertFalse(Domain.objects.filter(name="missing.com").exists())
        gateway.initiate_transfer.assert_not_called()

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

    def test_pending_nameserver_update_submits_operation_without_local_change(self) -> None:
        operation_url = "https://api.gandi.net/v5/domain/domains/active.com/nameservers/operations/42"
        gateway_result = Ok(
            NameserverUpdateResult(
                nameservers=["ns1.new.com"],
                pending=True,
                operation_handle=operation_url,
            )
        )

        with self._mock_gateway(update_nameservers=gateway_result):
            result = DomainLifecycleService.update_nameservers(self.domain, ["ns1.new.com"])

        self.assertTrue(result.is_ok(), result)
        op = result.unwrap()
        op.refresh_from_db()
        self.assertEqual(op.state, "submitted")
        self.assertEqual(op.registrar_operation_id, operation_url)
        self.assertIsNone(op.completed_at)
        self.domain.refresh_from_db()
        self.assertEqual(self.domain.nameservers, ["ns1.old.com"])

    def test_pending_lock_update_submits_operation_without_local_change(self) -> None:
        operation_url = "https://api.gandi.net/v5/domain/domains/active.com/status/operations/42"
        gateway_result = Ok(
            DomainLockResult(
                locked=True,
                pending=True,
                operation_handle=operation_url,
            )
        )

        with self._mock_gateway(set_lock=gateway_result):
            result = DomainLifecycleService.set_domain_lock(self.domain, locked=True)

        self.assertTrue(result.is_ok(), result)
        op = result.unwrap()
        op.refresh_from_db()
        self.assertEqual(op.state, "submitted")
        self.assertEqual(op.registrar_operation_id, operation_url)
        self.assertIsNone(op.completed_at)
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


# ===============================================================================
# GANDI REQUEST PAYLOAD SHAPES (#265)
# ===============================================================================


@override_settings(REGISTRAR_ADAPTERS_VERIFIED=True)
class GandiPayloadShapeTests(TestCase):
    """Assert the exact request bodies sent to Gandi.

    The pre-existing Phase 2 tests assert only the parsed RESULT, and all three payloads
    below were wrong while those tests passed — a mocked 200 response says nothing about
    whether the request Gandi received was well-formed. These pin the wire format against
    https://api.gandi.net/docs/domains/ so a regression fails here rather than in
    production (or, today, silently against a sandbox nobody has run yet).
    """

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
            "entity_type": "individual",
        }

    @patch("apps.domains.gateways.gandi.GandiGateway._api_request")
    @patch("apps.domains.gateways.base.cache")
    def test_transfer_sends_authinfo_not_auth_info(self, mock_cache: MagicMock, mock_request: MagicMock) -> None:
        """#265(1): Gandi's field is `authinfo`; `auth_info` was rejected outright."""
        mock_cache.get.side_effect = _cache_get_stub
        # The DOCUMENTED 202: body is {"message": ...} only, handle in Location. The
        # previous fixture invented id/status, which is exactly how a response shape Gandi
        # never emits stays pinned in the suite.
        mock_request.return_value = _mock_response(
            202,
            {"message": "Your transfer request has been accepted"},
            headers={"Location": "https://api.gandi.net/v5/domain/transferin/example.com"},
        )

        result = self.gateway.initiate_transfer(
            "example.com",
            "EPP-CODE",
            registrant_data=self.registrant,
        )

        body = mock_request.call_args.kwargs["json"]
        self.assertEqual(body["authinfo"], "EPP-CODE")
        self.assertNotIn("auth_info", body)
        self.assertEqual(body["fqdn"], "example.com")
        self.assertEqual(
            body["owner"],
            {
                "given": "Ion",
                "family": "Popescu",
                "email": "ion@example.com",
                "phone": "+40721000000",
                "streetaddr": "Str. Exemplu 1",
                "city": "Bucuresti",
                "zip": "010101",
                "country": "RO",
                "type": "individual",
                "orgname": "",
            },
        )
        self.assertEqual(
            mock_request.call_args.args[1],
            "https://api.gandi.net/v5/domain/transferin",
        )
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(
            result.unwrap().transfer_id,
            "https://api.gandi.net/v5/domain/transferin/example.com",
        )

    @patch("apps.domains.gateways.gandi.GandiGateway._api_request")
    @patch("apps.domains.gateways.base.cache")
    def test_transfer_sends_sharing_id_in_the_query_string(
        self, mock_cache: MagicMock, mock_request: MagicMock
    ) -> None:
        """#265: sharing_id is a query param AND the reseller billing identifier.

        In the body it is ignored, so a reseller's chargeable transfer bills the PAT's
        default organization instead of the customer's sharing org. _do_register already
        got this right; transfer-in contradicted it.
        """
        mock_cache.get.side_effect = _cache_get_stub
        mock_request.return_value = _mock_response(202, {"message": "accepted"})
        self.gateway.registrar.api_username = "reseller-org-id"

        self.gateway.initiate_transfer("example.com", "EPP-CODE")

        self.assertEqual(mock_request.call_args.kwargs["params"], {"sharing_id": "reseller-org-id"})
        self.assertNotIn("sharing_id", mock_request.call_args.kwargs["json"])
        self.assertNotIn("owner", mock_request.call_args.kwargs["json"])

    @patch("apps.domains.gateways.gandi.GandiGateway._api_request")
    @patch("apps.domains.gateways.base.cache")
    def test_transfer_rejects_the_dry_run_validation_response(
        self, mock_cache: MagicMock, mock_request: MagicMock
    ) -> None:
        """A 200 on transferin is the Dry-Run validation response, not a started transfer.

        Its body can be {"status": "error", "errors": [...]}; accepting it reported a
        failed validation as a submitted transfer.
        """
        mock_cache.get.side_effect = _cache_get_stub
        mock_request.return_value = _mock_response(200, {"status": "error", "errors": ["bad authinfo"]})

        result = self.gateway.initiate_transfer("example.com", "EPP-CODE")

        self.assertTrue(result.is_err(), "a validation response must not read as success")

    @patch("apps.domains.gateways.gandi.GandiGateway._api_request")
    @patch("apps.domains.gateways.base.cache")
    def test_nameserver_update_wraps_the_list_in_an_object(
        self, mock_cache: MagicMock, mock_request: MagicMock
    ) -> None:
        """#265(2): the endpoint takes {"nameservers": [...]}, not a bare array."""
        mock_cache.get.return_value = 0
        operation_url = "https://api.gandi.net/v5/domain/domains/example.com/nameservers/operations/42"
        mock_request.return_value = _mock_response(
            202,
            {"message": "Nameserver update accepted"},
            headers={"Location": operation_url},
        )
        nameservers = ["ns1.new.com", "ns2.new.com"]

        result = self.gateway.update_nameservers("example.com", nameservers)

        body = mock_request.call_args.kwargs["json"]
        self.assertEqual(body, {"nameservers": nameservers})
        self.assertNotIsInstance(body, list)
        self.assertEqual(
            mock_request.call_args.args[1],
            "https://api.gandi.net/v5/domain/domains/example.com/nameservers",
        )
        self.assertTrue(result.is_ok(), result)
        update = result.unwrap()
        self.assertEqual(update.nameservers, nameservers)
        self.assertTrue(update.pending)
        self.assertEqual(update.operation_handle, operation_url)

    @patch("apps.domains.gateways.gandi.GandiGateway._api_request")
    @patch("apps.domains.gateways.base.cache")
    def test_lock_patches_the_status_subresource(self, mock_cache: MagicMock, mock_request: MagicMock) -> None:
        """#265(3): lock lives on /status, and must not touch autorenew."""
        mock_cache.get.return_value = 0
        operation_url = "https://api.gandi.net/v5/domain/domains/example.com/status/operations/42"
        mock_request.return_value = _mock_response(
            202,
            {"message": "Lock update accepted"},
            headers={"Location": operation_url},
        )

        result = self.gateway.set_lock("example.com", locked=True)

        args = mock_request.call_args.args
        body = mock_request.call_args.kwargs["json"]
        self.assertEqual(args[0], "PATCH")
        self.assertEqual(
            args[1],
            "https://api.gandi.net/v5/domain/domains/example.com/status",
        )
        self.assertEqual(body, {"clientTransferProhibited": True})
        self.assertTrue(result.is_ok(), result)
        lock_result = result.unwrap()
        self.assertTrue(lock_result.locked)
        self.assertTrue(lock_result.pending)
        self.assertEqual(lock_result.operation_handle, operation_url)

    @patch("apps.domains.gateways.gandi.GandiGateway._api_request")
    @patch("apps.domains.gateways.base.cache")
    def test_unlock_clears_the_flag_without_touching_autorenew(
        self, mock_cache: MagicMock, mock_request: MagicMock
    ) -> None:
        """The unlock path previously sent {"autorenew": None} — a different field entirely."""
        mock_cache.get.return_value = 0
        operation_url = "https://api.gandi.net/v5/domain/domains/example.com/status/operations/43"
        mock_request.return_value = _mock_response(
            202,
            {"message": "Unlock accepted"},
            headers={"Location": operation_url},
        )

        result = self.gateway.set_lock("example.com", locked=False)

        body = mock_request.call_args.kwargs["json"]
        self.assertEqual(body, {"clientTransferProhibited": False})
        self.assertNotIn("autorenew", body)
        self.assertNotIn("tags", body)
        self.assertEqual(
            mock_request.call_args.args[1],
            "https://api.gandi.net/v5/domain/domains/example.com/status",
        )
        self.assertTrue(result.is_ok(), result)
        lock_result = result.unwrap()
        self.assertFalse(lock_result.locked)
        self.assertTrue(lock_result.pending)
        self.assertEqual(lock_result.operation_handle, operation_url)
