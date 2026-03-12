from __future__ import annotations

from decimal import Decimal

from django.test import TestCase

from apps.customers.models import Customer, CustomerBillingProfile, CustomerTaxProfile
from apps.users.models import CustomerMembership, User


class CustomerUserDomainIntegrationTests(TestCase):
    def setUp(self) -> None:
        self.admin = User.objects.create_user(
            email="domain-admin@example.ro",
            password="testpass123",
            is_staff=True,
            staff_role="admin",
        )
        self.user = User.objects.create_user(email="domain-user@example.ro", password="testpass123")

        self.customer = Customer.objects.create(
            name="Domain Customer SRL",
            company_name="Domain Customer SRL",
            customer_type="company",
            status="active",
            primary_email="domain-customer@example.ro",
            data_processing_consent=True,
            created_by=self.admin,
        )

    def test_soft_delete_hides_customer_and_preserves_audit_trail(self) -> None:
        customer_id = self.customer.id

        self.customer.soft_delete(user=self.admin)

        self.assertFalse(Customer.objects.filter(id=customer_id).exists())
        deleted = Customer.all_objects.get(id=customer_id)
        self.assertIsNotNone(deleted.deleted_at)
        self.assertEqual(deleted.deleted_by, self.admin)
        self.assertTrue(deleted.is_deleted)

    def test_restore_returns_customer_to_active_manager(self) -> None:
        self.customer.soft_delete(user=self.admin)

        self.customer.restore()

        self.assertTrue(Customer.objects.filter(id=self.customer.id).exists())
        restored = Customer.objects.get(id=self.customer.id)
        self.assertIsNone(restored.deleted_at)
        self.assertFalse(restored.is_deleted)

    def test_hard_delete_cascades_profiles_and_memberships(self) -> None:
        CustomerTaxProfile.objects.create(
            customer=self.customer,
            cui="RO12345678",
            vat_number="RO12345678",
            is_vat_payer=True,
        )
        CustomerBillingProfile.objects.create(
            customer=self.customer,
            payment_terms=30,
            credit_limit=Decimal("1000.00"),
            preferred_currency="RON",
        )
        CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role="owner",
            is_primary=True,
            is_active=True,
        )

        self.customer.delete()

        self.assertEqual(CustomerTaxProfile.objects.count(), 0)
        self.assertEqual(CustomerBillingProfile.objects.count(), 0)
        self.assertEqual(CustomerMembership.objects.count(), 0)

    def test_primary_customer_and_access_checks_follow_memberships(self) -> None:
        secondary = Customer.objects.create(
            name="Secondary Customer SRL",
            company_name="Secondary Customer SRL",
            customer_type="company",
            status="active",
            primary_email="secondary@example.ro",
            created_by=self.admin,
        )

        CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role="owner",
            is_primary=True,
            is_active=True,
        )
        CustomerMembership.objects.create(
            user=self.user,
            customer=secondary,
            role="viewer",
            is_primary=False,
            is_active=True,
        )

        self.assertEqual(self.user.primary_customer, self.customer)
        self.assertTrue(self.user.can_access_customer(self.customer))
        self.assertTrue(self.user.can_access_customer(secondary))
        self.assertEqual(self.user.get_role_for_customer(secondary), "viewer")
