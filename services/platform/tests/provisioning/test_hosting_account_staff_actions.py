"""The Virtualmin account page's Suspend and Activate act on the Service, not the panel (#566).

These buttons used to call Virtualmin directly and leave `Service.status` alone, so the
reconciler, which owns the enabled state (ADR-0051), turned a staff suspension back on
within one sweep. They now change the Service under a row lock, or queue a reconcile, and
never call the gateway themselves. Driven through the real views, so every test that
changes behaviour is red on master for that reason, not for a missing name.
"""

from __future__ import annotations

from unittest.mock import patch

from django.urls import reverse
from django.utils import timezone

from apps.billing.subscription_models import Subscription
from apps.customers.models import Customer
from apps.products.models import Product
from apps.provisioning.models import Service
from apps.provisioning.services import HostingAccountStaffActions
from apps.provisioning.virtualmin_models import VirtualminAccount
from apps.provisioning.virtualmin_tasks import reconcile_divergent_services_task, reconcile_virtualmin_service_state
from apps.users.models import User
from tests.helpers.fsm_helpers import force_status
from tests.mocks.virtualmin_mock import MockVirtualminGateway
from tests.provisioning.test_virtualmin_domain_veto import _DomainVetoBase

ENQUEUE = "apps.provisioning.virtualmin_tasks.reconcile_virtualmin_service_state_async"
GATEWAY = "apps.provisioning.virtualmin_service.VirtualminGateway"
STAFF_TOKEN = "staff_account_suspend"


class _StaffButtonBase(_DomainVetoBase):
    def setUp(self) -> None:
        super().setUp()
        staff = User.objects.create_user(email="panel-staff@example.com", password="Panel-staff-pass123!", staff_role="support")
        self.client.force_login(staff)

    def _press(self, button: str, *, account_enabled: bool) -> tuple[MockVirtualminGateway, list[str]]:
        """POST a button with the gateway and the reconcile queue both observed."""
        gateway = MockVirtualminGateway()
        gateway.seed_domain(self.account.domain, enabled=account_enabled)
        url = reverse(f"provisioning:virtualmin_account_{button}", args=[self.account.id])
        with (
            patch(GATEWAY, return_value=gateway),
            patch(ENQUEUE) as enqueue,
            self.captureOnCommitCallbacks(execute=True),
        ):
            self.client.post(url)
        return gateway, [call.args[0] for call in enqueue.call_args_list]

    def _set(self, *, service: str, account: str, reason: str = "") -> None:
        force_status(self.service, service)
        Service.objects.filter(pk=self.service.pk).update(suspension_reason=reason)
        self.account.status = account
        self.account.save(update_fields=["status"])

    def _assert_untouched(self, gateway: MockVirtualminGateway, service: str) -> None:
        self.assertEqual(gateway.get_calls(), [])
        self.service.refresh_from_db()
        self.assertEqual(self.service.status, service)


class StaffSuspendTests(_StaffButtonBase):
    def test_suspend_on_an_active_service_suspends_the_service_and_queues(self) -> None:
        """FAILS on master: the button disabled the panel and left the Service active."""
        self._set(service="active", account="active")

        gateway, queued = self._press("suspend", account_enabled=True)

        self.assertEqual(gateway.get_calls(), [])
        self.service.refresh_from_db()
        self.assertEqual((self.service.status, self.service.suspension_reason), ("suspended", STAFF_TOKEN))
        self.assertEqual(queued, [str(self.service.id)])

    def test_suspend_is_refused_for_a_service_the_provisioning_pipeline_owns(self) -> None:
        """FAILS on master: a failed service's account was disabled directly."""
        for status in ("pending", "provisioning", "failed"):
            with self.subTest(status=status):
                self._set(service=status, account="active")

                gateway, queued = self._press("suspend", account_enabled=True)

                self._assert_untouched(gateway, status)
                self.assertEqual(queued, [])

    def test_a_staff_suspension_survives_the_sweep_and_an_executed_reconcile(self) -> None:
        """FAILS on master: the sweep's reconcile turned the account back on.

        The sweep only queues work, so this executes the reconcile it would run.
        """
        self._set(service="active", account="active")
        self._press("suspend", account_enabled=True)
        self.service.refresh_from_db()
        self.assertEqual((self.service.status, self.service.suspension_reason), ("suspended", STAFF_TOKEN))

        with patch(ENQUEUE) as enqueue:
            reconcile_divergent_services_task()
        self.assertIn(str(self.service.id), {call.args[0] for call in enqueue.call_args_list})

        gateway = MockVirtualminGateway()
        gateway.seed_domain(self.account.domain, enabled=True)
        with patch(GATEWAY, return_value=gateway):
            reconcile_virtualmin_service_state(str(self.service.id))
            reconcile_virtualmin_service_state(str(self.service.id))

        self.account.refresh_from_db()
        self.assertEqual(self.account.status, "suspended")
        self.assertEqual(gateway.get_calls("enable-domain"), [])


class StaffActivateTests(_StaffButtonBase):
    def _delinquent_subscription(self) -> None:
        product = Product.objects.create(slug="panel-delinquent", name="Panel Delinquent", product_type="shared_hosting")
        now = timezone.now()
        subscription = Subscription.objects.create(
            customer=self.customer,
            product=product,
            currency=self.currency,
            service_id=self.service.id,
            unit_price_cents=5000,
            billing_cycle="monthly",
            current_period_start=now,
            current_period_end=now + timezone.timedelta(days=30),
            next_billing_date=now + timezone.timedelta(days=30),
        )
        force_status(subscription, "past_due")

    def test_activate_on_a_staff_suspension_resumes_the_service(self) -> None:
        """FAILS on master: the button enabled the panel and left the Service suspended."""
        self._set(service="suspended", account="suspended", reason=STAFF_TOKEN)

        gateway, queued = self._press("activate", account_enabled=False)

        self.assertEqual(gateway.get_calls(), [])
        self.service.refresh_from_db()
        self.assertEqual((self.service.status, self.service.suspension_reason), ("active", ""))
        self.assertEqual(queued, [str(self.service.id)])

    def test_activate_on_an_active_service_only_queues_a_reconcile(self) -> None:
        """FAILS on master: the button called enable-domain itself instead of the reconciler."""
        self._set(service="active", account="suspended")

        gateway, queued = self._press("activate", account_enabled=False)

        self.assertEqual(gateway.get_calls(), [])
        self.assertEqual(queued, [str(self.service.id)])

    def test_activate_on_an_active_service_still_checks_the_customer(self) -> None:
        """Activate on an active service queues a reconcile, but only for an eligible customer.

        If the customer was suspended and its cascade has not yet suspended this service, the
        staff button must not help turn hosting back on.
        """
        self._set(service="active", account="suspended")
        Customer.objects.filter(pk=self.customer.pk).update(status="suspended")

        gateway, queued = self._press("activate", account_enabled=False)

        self._assert_untouched(gateway, "active")
        self.assertEqual(queued, [])

    def test_activate_is_refused_for_a_soft_deleted_customer(self) -> None:
        """The default customer manager hides soft-deleted rows, so a deleted customer must
        not read as "no status" and pass as eligible."""
        self._set(service="suspended", account="suspended", reason=STAFF_TOKEN)
        Customer.all_objects.filter(pk=self.customer.pk).update(deleted_at=timezone.now())

        gateway, queued = self._press("activate", account_enabled=False)

        self._assert_untouched(gateway, "suspended")
        self.assertEqual(queued, [])

    def test_activate_is_refused_while_a_bound_domain_holds_hosting_off(self) -> None:
        """FAILS on master: the button enabled a domain-held account."""
        self._set(service="active", account="suspended")
        self._domain("expired", service=self.service)

        gateway, queued = self._press("activate", account_enabled=False)

        self._assert_untouched(gateway, "active")
        self.assertEqual(queued, [])

    def test_activate_is_refused_once_the_customer_has_been_suspended(self) -> None:
        """FAILS on master. The customer cascade skips a service that is already suspended,
        so nothing else stops a staff resume for a suspended customer."""
        self._set(service="suspended", account="suspended", reason=STAFF_TOKEN)
        Customer.objects.filter(pk=self.customer.pk).update(status="suspended")

        gateway, queued = self._press("activate", account_enabled=False)

        self._assert_untouched(gateway, "suspended")
        self.assertEqual(queued, [])

    def test_activate_is_refused_while_the_subscription_is_unpaid(self) -> None:
        """FAILS on master: an unpaid customer's hosting came back on."""
        self._set(service="suspended", account="suspended", reason=STAFF_TOKEN)
        self._delinquent_subscription()

        gateway, queued = self._press("activate", account_enabled=False)

        self._assert_untouched(gateway, "suspended")
        self.assertEqual(queued, [])

    def test_activate_does_not_lift_a_suspension_another_workflow_owns(self) -> None:
        """FAILS on master: billing's and the customer cascade's suspensions were lifted."""
        for reason in ("payment_overdue", "customer_suspended", "manual_stop"):
            with self.subTest(reason=reason):
                self._set(service="suspended", account="suspended", reason=reason)

                gateway, queued = self._press("activate", account_enabled=False)

                self._assert_untouched(gateway, "suspended")
                self.assertEqual(queued, [])

    def test_activate_is_refused_for_a_service_the_provisioning_pipeline_owns(self) -> None:
        """FAILS on master: this enabled hosting that the reconciler never reverts."""
        for status in ("pending", "provisioning", "failed"):
            with self.subTest(status=status):
                self._set(service=status, account="suspended")

                gateway, queued = self._press("activate", account_enabled=False)

                self._assert_untouched(gateway, status)
                self.assertEqual(queued, [])


class StaffActionsRereadUnderLockTests(_StaffButtonBase):
    def test_activate_decides_on_the_row_it_locks_not_on_a_stale_copy(self) -> None:
        """The guards and the transition are one locked step.

        The caller's account carries a cached Service that still says staff suspension, but
        billing has since taken it over. Deciding on the cached copy would resume an unpaid
        service; the helper must re-read the row under its lock and refuse.
        """
        self._set(service="suspended", account="suspended", reason=STAFF_TOKEN)
        account = VirtualminAccount.objects.select_related("service").get(pk=self.account.pk)
        self.assertEqual(account.service.suspension_reason, STAFF_TOKEN, "precondition: the cached copy")
        Service.objects.filter(pk=self.service.pk).update(suspension_reason="payment_overdue")

        with patch(ENQUEUE), self.captureOnCommitCallbacks(execute=True):
            result = HostingAccountStaffActions.activate(account)

        self.assertTrue(result.is_err())
        self.service.refresh_from_db()
        self.assertEqual((self.service.status, self.service.suspension_reason), ("suspended", "payment_overdue"))
