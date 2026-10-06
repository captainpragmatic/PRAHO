"""Virtualmin account saves survive optional audit failures."""

from decimal import Decimal

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from tests.common._signal_isolation import SignalIsolationTestCase


class VirtualminSignalIsolationTests(SignalIsolationTestCase):
    def test_account_creation_survives_failed_audit_write(self) -> None:
        server = VirtualminServer.objects.create(
            name="Isolation", hostname="isolation.example.com", api_username="test", encrypted_api_password=b"test"
        )
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
        customer = Customer.objects.create(name="Isolation", primary_email="vm-customer@example.com")
        plan = ServicePlan.objects.create(name="Isolation", plan_type="shared_hosting", price_monthly=Decimal("10.00"))
        service = Service.objects.create(
            customer=customer,
            service_plan=plan,
            currency=currency,
            service_name="Isolation",
            username="isolation",
            price=Decimal("10.00"),
        )
        account = self.run_effect(
            "apps.provisioning.virtualmin_signals.AuditService.log_event",
            lambda: VirtualminAccount.objects.create(
                domain="isolation.example.com",
                server=server,
                service=service,
                virtualmin_username="isolation",
                encrypted_password=b"test",
            ),
        )
        self.assertTrue(VirtualminAccount.objects.filter(pk=account.pk).exists())
