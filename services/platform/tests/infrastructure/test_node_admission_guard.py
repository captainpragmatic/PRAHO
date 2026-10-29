"""Node teardown and account admission decide under the same VirtualminServer row lock.

Teardown's guard locks the server, refuses while any account still lives there, and closes admission
(status "disabled"). Account creation locks the same row and refuses a server that is not active or is
draining, so a guard that found the node empty can never be followed by a new account on it. These tests
run each ordering sequentially; the interleaved orderings run on PostgreSQL in
test_node_admission_race.
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase

from apps.billing.models import Currency
from apps.common.types import Ok, Result
from apps.customers.models import Customer
from apps.infrastructure.audit_service import InfrastructureAuditContext
from apps.infrastructure.deployment_service import NodeDeploymentService
from apps.infrastructure.models import NodeDeployment
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from apps.provisioning.virtualmin_service import VirtualminAccountCreationData, VirtualminProvisioningService
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment, _make_service


def make_service(domain: str) -> Service:
    customer = Customer.objects.create(
        name=f"{domain} SRL", customer_type="company", status="active", primary_email=f"owner@{domain}"
    )
    currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
    plan, _ = ServicePlan.objects.get_or_create(
        name="Admission Hosting", defaults={"plan_type": "shared_hosting", "price_monthly": Decimal("10")}
    )
    return Service.objects.create(
        customer=customer,
        service_plan=plan,
        currency=currency,
        service_name=domain,
        domain=domain,
        username=domain.partition(".")[0][:8],
        billing_cycle="monthly",
        price=Decimal("10.00"),
        status="active",
    )


def make_node(name: str) -> tuple[VirtualminServer, NodeDeployment]:
    server = VirtualminServer.objects.create(
        name=name, hostname=f"{name}.example.test", api_username="api", encrypted_api_password=b"", status="active"
    )
    deployment = _create_deployment("completed", external_node_id=f"{name}-vm")
    deployment.virtualmin_server = server
    deployment.save(update_fields=["virtualmin_server"])
    return server, deployment


def create_account(server: VirtualminServer, domain: str, service: Service | None = None) -> Result[VirtualminAccount, str]:
    data = VirtualminAccountCreationData(service=service or make_service(domain), domain=domain, server=server)
    with patch.object(VirtualminProvisioningService, "_execute_domain_creation", return_value=Ok(True)):
        return VirtualminProvisioningService().create_virtualmin_account(data)


class AdmissionRefusesAClosedNodeTests(TestCase):
    def test_a_disabled_node_admits_no_account(self) -> None:
        server, _deployment = make_node("closed")
        VirtualminServer.objects.filter(pk=server.pk).update(status="disabled")

        result = create_account(server, "late.example.com")

        self.assertTrue(result.is_err())
        self.assertFalse(VirtualminAccount.objects.filter(domain="late.example.com").exists())

    def test_a_draining_node_admits_no_account(self) -> None:
        server, _deployment = make_node("draining")
        VirtualminServer.objects.filter(pk=server.pk).update(is_draining=True)

        result = create_account(server, "drain.example.com")

        self.assertTrue(result.is_err())
        self.assertFalse(VirtualminAccount.objects.filter(domain="drain.example.com").exists())

    def test_an_open_node_still_admits(self) -> None:
        server, _deployment = make_node("open")

        result = create_account(server, "fine.example.com")

        self.assertTrue(result.is_ok(), result)


class TeardownGuardSeesEveryLiveAccountTests(TestCase):
    def _guard(self, deployment: NodeDeployment) -> Result[bool, str]:
        service: NodeDeploymentService = _make_service()
        return service._disable_linked_server_for_stop(deployment, InfrastructureAuditContext())

    def test_an_account_still_provisioning_blocks_the_guard(self) -> None:
        server, deployment = make_node("busy")
        VirtualminAccount.objects.create(
            domain="new.example.com",
            service=make_service("new.example.com"),
            server=server,
            virtualmin_username="newacct",
            status="provisioning",
        )

        result = self._guard(deployment)

        self.assertTrue(result.is_err())
        server.refresh_from_db()
        self.assertEqual(server.status, "active")

    def test_a_terminated_account_does_not_block_the_guard(self) -> None:
        server, deployment = make_node("emptied")
        VirtualminAccount.objects.create(
            domain="gone.example.com",
            service=make_service("gone.example.com"),
            server=server,
            virtualmin_username="goneacct",
            status="terminated",
        )

        result = self._guard(deployment)

        self.assertTrue(result.is_ok(), result)
        server.refresh_from_db()
        self.assertEqual(server.status, "disabled")
