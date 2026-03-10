"""
Service Lifecycle Timestamp Tests

Verifies that service_activate and service_suspend views use the model's
lifecycle methods (activate(), suspend()) which set timestamps correctly.

Covers:
  - service_activate must set activated_at and clear suspended_at
  - service_suspend must set suspended_at and suspension_reason
"""

from decimal import Decimal

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from apps.billing.models import Currency
from apps.customers.models import Customer, CustomerAddress, CustomerBillingProfile, CustomerTaxProfile
from apps.provisioning.models import Service, ServicePlan
from apps.users.models import CustomerMembership

User = get_user_model()


def _setup_service_fixtures(test_case: TestCase) -> None:
    """Create shared fixtures for service lifecycle tests."""
    test_case.client = Client()
    test_case.admin = User.objects.create_user(
        email="lifecycle-admin@test.ro", password="testpass123", is_staff=True, staff_role="admin"
    )
    test_case.customer = Customer.objects.create(
        customer_type="company",
        company_name="Lifecycle Corp",
        primary_email="lifecycle@test.ro",
        primary_phone="+40700000001",
        data_processing_consent=True,
        created_by=test_case.admin,
    )
    CustomerTaxProfile.objects.create(
        customer=test_case.customer, cui="RO11111111", vat_number="RO11111111",
        registration_number="J40/999/2023", is_vat_payer=True, vat_rate=Decimal("19.00"),
    )
    CustomerBillingProfile.objects.create(
        customer=test_case.customer, payment_terms=30,
        credit_limit=Decimal("5000.00"), preferred_currency="RON",
    )
    CustomerAddress.objects.create(
        customer=test_case.customer, address_type="legal", address_line1="Str. Lifecycle 1",
        city="București", county="Sector 1", postal_code="010101", country="România", is_current=True,
    )
    CustomerMembership.objects.create(user=test_case.admin, customer=test_case.customer, role="admin")

    test_case.currency, _ = Currency.objects.get_or_create(
        code="RON", defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2}
    )
    test_case.plan = ServicePlan.objects.create(
        name="Lifecycle Plan", plan_type="shared_hosting", price_monthly=Decimal("50.00"),
        setup_fee=Decimal("0.00"), is_active=True, is_public=True, sort_order=1, auto_provision=True,
    )


class ServiceSuspendTimestampTest(TestCase):
    """H2: service_suspend view must call service.suspend() which sets suspended_at."""

    def setUp(self) -> None:
        _setup_service_fixtures(self)
        self.service = Service.objects.create(
            customer=self.customer, service_plan=self.plan, currency=self.currency,
            service_name="Timestamp Service", domain="timestamp.example.com",
            username="ts_user", billing_cycle="monthly", price=Decimal("50.00"), status="active",
        )

    def test_suspend_sets_suspended_at(self) -> None:
        """Suspending via view must populate suspended_at timestamp."""
        self.assertIsNone(self.service.suspended_at)

        self.client.force_login(self.admin)
        self.client.post(reverse("provisioning:service_suspend", args=[self.service.pk]))

        self.service.refresh_from_db()
        self.assertEqual(self.service.status, "suspended")
        self.assertIsNotNone(self.service.suspended_at)

    def test_suspend_sets_reason(self) -> None:
        """Suspending via view must populate suspension_reason."""
        self.client.force_login(self.admin)
        self.client.post(
            reverse("provisioning:service_suspend", args=[self.service.pk]),
            data={"reason": "Non-payment"},
        )

        self.service.refresh_from_db()
        self.assertEqual(self.service.suspension_reason, "Non-payment")


class ServiceActivateTimestampTest(TestCase):
    """H1: service_activate view must call service.activate() which sets activated_at."""

    def setUp(self) -> None:
        _setup_service_fixtures(self)
        self.service = Service.objects.create(
            customer=self.customer, service_plan=self.plan, currency=self.currency,
            service_name="Activate Service", domain="activate.example.com",
            username="act_user", billing_cycle="monthly", price=Decimal("50.00"), status="suspended",
        )

    def test_activate_sets_activated_at(self) -> None:
        """Activating via view must populate activated_at timestamp."""
        self.assertIsNone(self.service.activated_at)

        self.client.force_login(self.admin)
        self.client.post(reverse("provisioning:service_activate", args=[self.service.pk]))

        self.service.refresh_from_db()
        self.assertEqual(self.service.status, "active")
        self.assertIsNotNone(self.service.activated_at)

    def test_activate_clears_suspended_at(self) -> None:
        """Activating a suspended service must clear suspended_at and suspension_reason."""
        from django.utils import timezone  # noqa: PLC0415

        self.service.suspended_at = timezone.now()
        self.service.suspension_reason = "Test suspension"
        self.service.save(update_fields=["suspended_at", "suspension_reason"])

        self.client.force_login(self.admin)
        self.client.post(reverse("provisioning:service_activate", args=[self.service.pk]))

        self.service.refresh_from_db()
        self.assertEqual(self.service.status, "active")
        self.assertIsNone(self.service.suspended_at)
        self.assertEqual(self.service.suspension_reason, "")
