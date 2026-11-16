"""An adopted, quota-managed hosting account with its usage state, for the database overage tests."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from apps.provisioning.virtualmin_usage_models import AccountUsageState


@dataclass
class OverageFixture:
    customer: Customer
    service: Service
    server: VirtualminServer
    account: VirtualminAccount
    usage: AccountUsageState
    installation: UUID


def make_overage_account(label: str = "overage") -> OverageFixture:
    customer = Customer.objects.create(
        name=f"{label} customer", customer_type="company", status="active", primary_email=f"{label}@example.test"
    )
    currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
    plan = ServicePlan.objects.create(
        name=f"{label} plan", plan_type="shared_hosting", price_monthly=10, disk_space_gb=1, bandwidth_gb=1
    )
    service = Service.objects.create(
        customer=customer,
        service_plan=plan,
        currency=currency,
        service_name=f"{label}.example.test",
        domain=f"{label}.example.test",
        username=f"{label}fixture",
        status="active",
        price=10,
    )
    server = VirtualminServer.objects.create(
        name=f"{label} node", hostname=f"{label}-node.example.test", api_username=f"praho-{label}", status="active"
    )
    account = VirtualminAccount.objects.create(
        service=service,
        server=server,
        domain=service.domain,
        virtualmin_username=f"{label}fixture",
        status="active",
        quota_managed=True,
        praho_customer_id=customer.pk,
        praho_service_id=service.pk,
    )
    installation = uuid4()
    usage = AccountUsageState.objects.create(
        account=account,
        service_id_snapshot=service.pk,
        customer_id_snapshot=customer.pk,
        server_id_snapshot=server.pk,
        domain_id="17001",
        installation=installation,
    )
    return OverageFixture(customer, service, server, account, usage, installation)
