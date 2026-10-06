"""A staff Activate and a customer suspension cannot interleave into hosting for a suspended customer.

Activate reads the customer's status and then resumes the Service. A customer suspension that
committed between that read and the resume would be missed twice:
- Activate decided on the old status;
- the customer's suspension cascade selects only active services, so it skipped this Service,
  which was still suspended when it ran.

Activate therefore locks the customer row before the Service, the same customer-first order
billing uses, and decides on the locked row. Row locks are real only on PostgreSQL, so this
runs there (CI's PostgreSQL step) and skips on SQLite.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal

from django.db import close_old_connections, connection, transaction
from django.test import TransactionTestCase

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.services import STAFF_ACCOUNT_SUSPENSION_REASON, HostingAccountStaffActions
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer

# Long enough for an unblocked Activate to finish, short enough to keep the test quick.
_HOLD_SECONDS = 2.0


class StaffActivateCustomerSuspensionRaceTests(TransactionTestCase):
    def setUp(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("row-lock guarantees require PostgreSQL")
        self.customer = Customer.objects.create(
            name="Race SRL", customer_type="company", status="active", primary_email="race@example.com"
        )
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        plan = ServicePlan.objects.create(name="Race Hosting", plan_type="shared_hosting", price_monthly=Decimal("10"))
        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=plan,
            currency=currency,
            service_name="race.example.com",
            domain="race.example.com",
            username="race",
            billing_cycle="monthly",
            price=Decimal("10.00"),
            status="active",
        )
        Service.objects.filter(pk=self.service.pk).update(
            status="suspended", suspension_reason=STAFF_ACCOUNT_SUSPENSION_REASON
        )
        server = VirtualminServer.objects.create(
            name="race-vm", hostname="race-vm.example.com", api_username="api", status="active"
        )
        self.account = VirtualminAccount.objects.create(
            domain="race.example.com", service=self.service, server=server, virtualmin_username="race", status="suspended"
        )

    def test_a_customer_suspension_in_flight_is_seen_by_activate(self) -> None:
        suspension_locked = threading.Event()
        activate_done = threading.Event()

        def suspend_customer_and_hold() -> None:
            close_old_connections()
            try:
                with transaction.atomic():
                    # The customer's suspension, uncommitted and holding the customer row.
                    Customer.objects.filter(pk=self.customer.pk).update(status="suspended")
                    suspension_locked.set()
                    # Unblocked, Activate finishes inside this window and reads the old status.
                    # Locking the customer first, it waits here until this commits.
                    activate_done.wait(timeout=_HOLD_SECONDS)
            finally:
                connection.close()

        def activate() -> bool:
            close_old_connections()
            try:
                suspension_locked.wait(timeout=10)
                return HostingAccountStaffActions.activate(VirtualminAccount.objects.get(pk=self.account.pk)).is_ok()
            finally:
                activate_done.set()
                connection.close()

        with ThreadPoolExecutor(max_workers=2) as executor:
            holder = executor.submit(suspend_customer_and_hold)
            resumed = executor.submit(activate)
            holder.result(timeout=30)
            activated = resumed.result(timeout=30)

        self.service.refresh_from_db()
        self.assertFalse(activated, "Activate resumed a service while its customer's suspension was committing")
        self.assertEqual(self.service.status, "suspended")
