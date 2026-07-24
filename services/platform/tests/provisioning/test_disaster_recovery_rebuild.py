"""#326 [CRITICAL]: rebuild_server_from_praho must actually rebuild surviving accounts.

The rebuild loop called create_virtualmin_account() for each surviving VirtualminAccount
row, but that method rejects any domain that already has a row ("already exists in PRAHO")
— the row being rebuilt is the collision — so 100% of accounts failed and disaster
recovery restored nothing. Rebuild now REUSES the existing rows via
reprovision_virtualmin_account().
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase

from apps.billing.models import Currency
from apps.common.types import Err, Ok
from apps.customers.models import Customer
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_disaster_recovery import VirtualminDisasterRecoveryService
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer


class RebuildServerFromPrahoTests(TestCase):
    """rebuild_server_from_praho reuses existing rows and can actually rebuild."""

    def setUp(self) -> None:
        self.customer = Customer.objects.create(
            name="DR Customer", primary_email="dr@example.com", customer_type="individual"
        )
        self.plan = ServicePlan.objects.create(
            name="DR Plan", plan_type="shared_hosting", price_monthly=Decimal("10.00"), setup_fee=Decimal("0.00")
        )
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )
        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name="DR Service",
            username="dr_user",
            price=Decimal("10.00"),
            status="active",
        )
        self.server = VirtualminServer.objects.create(
            name="dead-server",
            hostname="dead.example.com",
            api_username="api_user",
            max_domains=1000,
            current_domains=0,
        )
        self.server.set_api_password("pw")
        self.server.save()
        self.account = VirtualminAccount.objects.create(
            domain="survivor.ro",
            service=self.service,
            server=self.server,
            virtualmin_username="survivor",
            status="active",
            praho_customer_id=self.customer.id,
            praho_service_id=self.service.id,
        )

    def test_rebuild_reuses_existing_row_and_succeeds(self) -> None:
        """With the server-side create mocked to succeed, rebuild restores the account."""
        service = VirtualminDisasterRecoveryService()

        # Mock the actual server-side domain creation so no real gateway is hit; simulate
        # success and mark the row active the way _execute_domain_creation would.
        def fake_execute(account: VirtualminAccount, _job: object) -> object:
            account.status = "active"
            account.save(update_fields=["status"])
            return Ok({"created": True})

        with patch(
            "apps.provisioning.virtualmin_service.VirtualminProvisioningService._execute_domain_creation",
            side_effect=fake_execute,
        ):
            result = service.rebuild_server_from_praho(self.server, dry_run=False)

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        data = result.unwrap()
        self.assertEqual(data["successful_rebuilds"], 1)
        self.assertEqual(data["failed_rebuilds"], 0)
        # The original row is reused — no duplicate account was inserted.
        self.assertEqual(VirtualminAccount.objects.filter(domain="survivor.ro").count(), 1)

    def test_rebuild_does_not_call_create_virtualmin_account(self) -> None:
        """Rebuild must NOT go through create_virtualmin_account (which collides on the row)."""
        service = VirtualminDisasterRecoveryService()

        with (
            patch(
                "apps.provisioning.virtualmin_service.VirtualminProvisioningService.create_virtualmin_account",
                return_value=Err("Domain survivor.ro already exists in PRAHO"),
            ) as mock_create,
            patch(
                "apps.provisioning.virtualmin_service.VirtualminProvisioningService.reprovision_virtualmin_account",
                return_value=Ok(self.account),
            ) as mock_reprovision,
        ):
            result = service.rebuild_server_from_praho(self.server, dry_run=False)

        self.assertTrue(result.is_ok())
        mock_create.assert_not_called()
        mock_reprovision.assert_called_once()

    def test_server_domain_count_reconciled_from_db(self) -> None:
        """current_domains is recounted from active rows, not clobbered to a stale value."""
        service = VirtualminDisasterRecoveryService()

        with patch(
            "apps.provisioning.virtualmin_service.VirtualminProvisioningService.reprovision_virtualmin_account",
            return_value=Ok(self.account),
        ):
            service.rebuild_server_from_praho(self.server, dry_run=False)

        self.server.refresh_from_db()
        # One active account exists on this server after rebuild.
        self.assertEqual(self.server.current_domains, 1)
