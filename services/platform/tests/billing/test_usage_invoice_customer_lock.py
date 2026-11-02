"""A public billing edit must be observed before a waited usage invoice freezes its buyer."""

from threading import Event
from unittest import skipUnless

from django.core.cache import cache
from django.db import connection, transaction
from django.test import TransactionTestCase, override_settings

from apps.billing.models import Invoice
from apps.customers.models import Customer
from apps.users.models import CustomerMembership, User
from tests.billing import test_metering_services as usage_fixtures
from tests.common.postgres_locking import backend_pid, database_worker, wait_for_blocker
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin
from tests.helpers.portal_session import BoundSessionMixin
from tests.helpers.task_queue import quiet_task_queue


@skipUnless(connection.vendor == "postgresql", "Requires PostgreSQL customer lock waits")
@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
class UsageInvoiceCustomerLockTests(BoundSessionMixin, HMACTestMixin, TransactionTestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        quiet_task_queue(self)
        usage_fixtures.UsageInvoiceServiceTestCase.setUp(self)
        self.owner = User.objects.create_user(email="usage-owner@example.test")
        CustomerMembership.objects.create(customer=self.customer, user=self.owner, role="owner", is_primary=True)

    def test_waited_invoice_uses_identity_committed_by_public_billing_edit(self) -> None:
        start = Event()
        owner_pid = backend_pid()
        self.assertEqual(self.customer.company_name, "Test Company SRL")

        def invoice():
            assert start.wait(10)
            return self.service.generate_invoice_from_cycle(str(self.billing_cycle.pk))

        with database_worker(invoice) as (pid, pending):
            try:
                with transaction.atomic():
                    response = self.portal_post("/api/customers/billing-address/", {
                        "customer_id": self.customer.pk, "user_id": self.owner.pk,
                        "company_name": "Current Buyer SRL", "email": "current-buyer@example.test",
                    })
                    self.assertEqual(response.status_code, 200, response.content)
                    start.set()
                    wait_for_blocker(pid, owner_pid, pending, table=Customer._meta.db_table)
            finally:
                start.set()
            result = pending.result(timeout=30)
        self.assertTrue(result.is_ok(), result)
        issued = Invoice.objects.get(pk=result.unwrap()["invoice_id"])
        self.assertEqual((issued.bill_to_name, issued.bill_to_email), ("Current Buyer SRL", "current-buyer@example.test"))
        self.assertEqual((issued.subtotal_cents, issued.tax_cents, issued.total_cents), (2500, 525, 3025))
        self.assertEqual(issued.currency_id, self.billing_cycle.subscription.currency_id)
