"""Regression tests for the registrar-gateway wiring (PR #169 review C1/C2).

C1: the concrete gateways must be registered with the factory simply by importing
    the gateways package — otherwise the registry is empty at runtime and the whole
    gateway layer is dead code in production.
C2: create_domain_registration must actually call the registrar gateway and only
    activate the domain when the registrar confirms; a registrar failure must leave
    the domain pending (not falsely report it registered).
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

from django.test import TestCase

from apps.customers.models import Customer
from apps.domains.gateways import RegistrarGatewayFactory
from apps.domains.models import TLD, Registrar, TLDRegistrarAssignment
from apps.domains.services import DomainLifecycleService


class GatewayFactoryRegistrationTests(TestCase):
    """C1 — importing the package alone must populate the factory registry."""

    def test_importing_gateways_package_registers_concrete_gateways(self) -> None:
        # The module-level `from apps.domains.gateways import ...` (no direct
        # import of the concrete gandi/rotld modules) must be enough to register them.
        available = RegistrarGatewayFactory.list_available_gateways()
        self.assertIn("gandi", available)
        self.assertIn("rotld", available)


class DomainRegistrationGatewayWiringTests(TestCase):
    """C2 — the live registration path must invoke the gateway."""

    def setUp(self) -> None:
        self.tld = TLD.objects.create(
            extension="com",
            description=".com",
            registration_price_cents=1000,
            renewal_price_cents=1000,
            transfer_price_cents=1000,
            registrar_cost_cents=500,
            min_registration_period=1,
            max_registration_period=10,
        )
        self.registrar = Registrar.objects.create(
            name="test-registrar",
            display_name="Test Registrar",
            website_url="https://example.com",
            api_endpoint="https://api.example.com",
            status="active",
        )
        TLDRegistrarAssignment.objects.create(
            tld=self.tld,
            registrar=self.registrar,
            is_primary=True,
            is_active=True,
            priority=1,
        )

        self.customer = Customer.objects.create(
            name="John Doe",
            primary_email="cust@example.com",
            company_name="ACME",
            customer_type="individual",
        )

    def test_successful_registrar_call_activates_domain_and_persists_fields(self) -> None:
        expires = datetime(2027, 1, 1, tzinfo=UTC)
        gateway_payload = {
            "registrar_domain_id": "REG-12345",
            "expires_at": expires,
            "nameservers": ["ns1.example.com", "ns2.example.com"],
            "epp_code": "EPP-SECRET",
        }

        with patch(
            "apps.domains.services.DomainRegistrarGateway.register_domain",
            return_value=(True, gateway_payload),
        ) as mock_register:
            result = DomainLifecycleService.create_domain_registration(
                customer=self.customer,
                domain_name="example.com",
                years=2,
            )

        self.assertTrue(result.is_ok(), result)
        mock_register.assert_called_once()
        # Gateway was called with the resolved registrar, domain, and years.
        args = mock_register.call_args.args
        self.assertEqual(args[0], self.registrar)
        self.assertEqual(args[1], "example.com")
        self.assertEqual(args[2], 2)

        domain = result.unwrap()
        domain.refresh_from_db()
        self.assertEqual(domain.status, "active")
        self.assertEqual(domain.registrar_domain_id, "REG-12345")
        self.assertEqual(domain.expires_at, expires)
        self.assertEqual(domain.nameservers, ["ns1.example.com", "ns2.example.com"])
        self.assertIsNotNone(domain.registered_at)
        # epp_code is stored encrypted, not in plaintext.
        self.assertNotEqual(domain.epp_code, "EPP-SECRET")
        self.assertEqual(domain.get_decrypted_epp_code(), "EPP-SECRET")

    def test_registrar_failure_leaves_domain_pending(self) -> None:
        with patch(
            "apps.domains.services.DomainRegistrarGateway.register_domain",
            return_value=(False, {"error": "registrar down"}),
        ) as mock_register:
            result = DomainLifecycleService.create_domain_registration(
                customer=self.customer,
                domain_name="example.com",
                years=1,
            )

        self.assertTrue(result.is_ok(), result)
        mock_register.assert_called_once()

        domain = result.unwrap()
        domain.refresh_from_db()
        self.assertEqual(domain.status, "pending")
        self.assertEqual(domain.registrar_domain_id, "")
