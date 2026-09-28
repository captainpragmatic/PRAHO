"""Regression coverage: suspending a customer must actually suspend their services.

The cascade called ``ServiceManagementService.suspend_service``, which has never
existed. The resulting ``AttributeError`` was swallowed by the receiver's broad
handler inside a ``transaction.on_commit`` callback, so setting a customer to
SUSPENDED wrote the status, logged the security event, sent the suspension email —
and left every service running, with no error surfaced anywhere.

These tests assert the observable end state, not that a mock was called, so they
stay honest if the call is rewired again.
"""

from __future__ import annotations

from decimal import Decimal

from django.test import TestCase

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.customers.signals import CUSTOMER_SUSPENSION_REASON
from apps.provisioning.models import Service, ServicePlan


class CustomerSuspensionCascadeTests(TestCase):
    def setUp(self) -> None:
        self.customer = Customer.objects.create(
            customer_type="company",
            company_name="Suspension Cascade SRL",
            primary_email="suspension-cascade@test.ro",
            status=Customer.CustomerStatus.ACTIVE,
        )
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2}
        )
        self.plan = ServicePlan.objects.create(
            name="Cascade Plan",
            plan_type="shared_hosting",
            price_monthly=Decimal("50.00"),
            setup_fee=Decimal("0.00"),
            is_active=True,
        )

    def _service(self, *, domain: str, status: str = "active") -> Service:
        return Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name=f"Service {domain}",
            domain=domain,
            username=domain.split(".", maxsplit=1)[0],
            billing_cycle="monthly",
            price=Decimal("50.00"),
            status=status,
        )

    def _suspend_customer(self) -> None:
        """Drive the real FSM transition and drain the post-commit callbacks.

        ``Customer.status`` is an FSMField, so it can only move through
        ``suspend()``; that is also the only path a real caller takes.
        """
        with self.captureOnCommitCallbacks(execute=True):
            self.customer.suspend()
            self.customer.save()

    def test_suspending_a_customer_suspends_their_active_service(self) -> None:
        service = self._service(domain="cascade-active.example.com")

        self._suspend_customer()

        service.refresh_from_db()
        self.assertEqual(service.status, "suspended")

    def test_suspension_records_the_reason(self) -> None:
        """The reason is the only operator-visible trace of WHY a service went down."""
        service = self._service(domain="cascade-reason.example.com")

        self._suspend_customer()

        service.refresh_from_db()
        self.assertEqual(service.suspension_reason, CUSTOMER_SUSPENSION_REASON)
        self.assertIsNotNone(service.suspended_at)

    def test_every_active_service_is_suspended_not_just_the_first(self) -> None:
        first = self._service(domain="cascade-one.example.com")
        second = self._service(domain="cascade-two.example.com")

        self._suspend_customer()

        first.refresh_from_db()
        second.refresh_from_db()
        self.assertEqual(first.status, "suspended")
        self.assertEqual(second.status, "suspended")

    def test_already_suspended_service_is_left_alone(self) -> None:
        """Service.suspend() only accepts source 'active'; a repeat must not explode."""
        untouched = self._service(domain="cascade-done.example.com", status="suspended")

        self._suspend_customer()

        untouched.refresh_from_db()
        self.assertEqual(untouched.status, "suspended")


class CustomerReactivationCascadeTests(CustomerSuspensionCascadeTests):
    """Suspending must not be a one-way door.

    Making the suspend half work turned a previously dead path live in one direction
    only. Activation looked exclusively at services in "pending", so every service the
    cascade suspended stayed down: the customer-level reactivation did not touch it,
    payment_convergence resumes only its own "payment_overdue" token, and the generic
    reactivate_services_for_customer helper has no production caller. Recovery was
    manual, one service at a time, while the provider had already converged to disabled.
    """

    def _reactivate_customer(self) -> None:
        """suspended -> active is unsuspend(); activate() only leaves prospect."""
        with self.captureOnCommitCallbacks(execute=True):
            self.customer.unsuspend()
            self.customer.save()

    def test_reactivating_the_customer_resumes_what_the_cascade_suspended(self) -> None:
        service = self._service(domain="cascade-roundtrip.example.com")

        self._suspend_customer()
        service.refresh_from_db()
        self.assertEqual(service.status, "suspended", "precondition: the cascade suspended it")

        self._reactivate_customer()

        service.refresh_from_db()
        self.assertEqual(service.status, "active", "the customer came back but the service stayed down")
        self.assertEqual(service.suspension_reason, "")

    def test_a_service_suspended_for_another_reason_is_not_resurrected(self) -> None:
        """The reason token is the whole point: reactivation must be narrow.

        A service down for non-payment, or suspended by hand for abuse, must survive a
        customer reactivation. Resuming on status alone would silently restore service
        to an account that has not paid.
        """
        unpaid = self._service(domain="cascade-unpaid.example.com")
        unpaid.suspend(reason="payment_overdue")
        unpaid.save(update_fields=["status", "suspended_at", "suspension_reason", "updated_at"])

        self._suspend_customer()
        self._reactivate_customer()

        unpaid.refresh_from_db()
        self.assertEqual(unpaid.status, "suspended")
        self.assertEqual(unpaid.suspension_reason, "payment_overdue")
