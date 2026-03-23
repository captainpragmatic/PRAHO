"""
Tests for ContactService — IDOR prevention, atomicity, and address versioning.

Regression guard: these tests capture the chaos-monkey finding that
set_default_payment_method did NOT validate payment method ownership,
allowing cross-customer IDOR attacks.
"""

import contextlib
import time

from django.test import TestCase

from apps.customers.contact_service import AddressData, ContactService
from apps.customers.customer_service import CustomerService
from tests.factories.core_factories import CustomerCreationRequest, create_admin_user, create_full_customer


def _create_customer(name: str = "Test Customer SRL") -> object:
    unique_email = f"contact_{int(time.time() * 1000)}@testcustomer.ro"
    req = CustomerCreationRequest(
        name=name,
        company_name=name,
        primary_email=unique_email,
        with_tax_profile=False,
        with_billing_profile=False,
        with_address=False,
    )
    return create_full_customer(req)


def _create_user() -> object:
    return create_admin_user(username=f"admin_{int(time.time() * 1000)}")


class TestContactServiceIDOR(TestCase):
    """Payment method operations must prevent cross-customer IDOR attacks."""

    def setUp(self) -> None:
        self.user = _create_user()
        self.customer1 = _create_customer("Customer One SRL")
        self.customer2 = _create_customer("Customer Two SRL")

        # Create one payment method per customer (stripe_card is a valid method_type choice)
        self.pm1 = ContactService.create_payment_method(
            self.customer1, self.user, "stripe_card", "Visa *1234"
        )
        self.pm2 = ContactService.create_payment_method(
            self.customer2, self.user, "stripe_card", "Visa *5678"
        )

    def test_set_default_accepts_own_payment_method(self) -> None:
        """Setting default with the customer's own payment method must succeed."""
        result = ContactService.set_default_payment_method(self.customer1, self.pm1, self.user)
        self.assertTrue(result.is_default)

    def test_set_default_rejects_other_customers_payment_method(self) -> None:
        """Setting default with another customer's payment method must raise ValueError.

        Regression: before the fix, this would silently set pm2 as the default
        for customer1, exposing customer2's payment information.
        """
        with self.assertRaises(ValueError) as ctx:
            ContactService.set_default_payment_method(self.customer1, self.pm2, self.user)
        self.assertIn("does not belong", str(ctx.exception))

    def test_set_default_error_message_is_informative(self) -> None:
        """ValueError message must explicitly state the ownership mismatch."""
        with self.assertRaises(ValueError) as ctx:
            ContactService.set_default_payment_method(self.customer2, self.pm1, self.user)
        self.assertIn("does not belong", str(ctx.exception))

    def test_set_default_does_not_mutate_on_idor_attempt(self) -> None:
        """After an IDOR attempt, pm2 must remain unchanged (not set as default)."""
        pm2_default_before = self.pm2.is_default
        with contextlib.suppress(ValueError):
            ContactService.set_default_payment_method(self.customer1, self.pm2, self.user)
        self.pm2.refresh_from_db()
        self.assertEqual(self.pm2.is_default, pm2_default_before)


class TestContactServiceSetDefault(TestCase):
    """ContactService.set_default_payment_method() — atomicity and idempotency."""

    def setUp(self) -> None:
        self.user = _create_user()
        self.customer = _create_customer()

        self.pm_a = ContactService.create_payment_method(
            self.customer, self.user, "stripe_card", "Visa *0001"
        )
        self.pm_b = ContactService.create_payment_method(
            self.customer, self.user, "stripe_card", "Visa *0002"
        )

    def test_only_one_default_after_set(self) -> None:
        """After setting pm_b as default, pm_a must no longer be default."""
        # First make pm_a the default
        ContactService.set_default_payment_method(self.customer, self.pm_a, self.user)
        # Now switch to pm_b
        ContactService.set_default_payment_method(self.customer, self.pm_b, self.user)

        self.pm_a.refresh_from_db()
        self.pm_b.refresh_from_db()

        self.assertFalse(self.pm_a.is_default)
        self.assertTrue(self.pm_b.is_default)

    def test_set_default_returns_payment_method(self) -> None:
        result = ContactService.set_default_payment_method(self.customer, self.pm_a, self.user)
        self.assertEqual(result.pk, self.pm_a.pk)


class TestContactServiceCreatePaymentMethod(TestCase):
    """ContactService.create_payment_method() — creation and retrieval."""

    def setUp(self) -> None:
        self.user = _create_user()
        self.customer = _create_customer()

    def test_create_payment_method_persisted(self) -> None:
        pm = ContactService.create_payment_method(
            self.customer, self.user, "bank_transfer", "Banca Transilvania"
        )
        self.assertIsNotNone(pm.pk)

    def test_create_payment_method_linked_to_customer(self) -> None:
        pm = ContactService.create_payment_method(
            self.customer, self.user, "bank_transfer", "Banca Transilvania"
        )
        self.assertEqual(pm.customer_id, self.customer.id)

    def test_get_active_payment_methods_returns_created(self) -> None:
        ContactService.create_payment_method(
            self.customer, self.user, "stripe_card", "Visa *9999"
        )
        active = ContactService.get_active_payment_methods(self.customer)
        self.assertGreater(active.count(), 0)


class TestContactServiceCreateAddress(TestCase):
    """ContactService.create_address() — versioning and current-flag management."""

    def setUp(self) -> None:
        self.user = _create_user()
        self.customer = _create_customer()

    def test_create_address_persisted(self) -> None:
        addr_data = AddressData(
            is_primary=True,
            address_line1="Str. Test Nr. 1",
            city="București",
            county="Sector 1",
            postal_code="010101",
        )
        addr = ContactService.create_address(self.customer, self.user, addr_data)
        self.assertIsNotNone(addr.pk)

    def test_create_address_is_current_by_default(self) -> None:
        addr_data = AddressData(
            is_primary=True,
            address_line1="Str. Test Nr. 1",
            city="București",
            county="Sector 1",
            postal_code="010101",
        )
        addr = ContactService.create_address(self.customer, self.user, addr_data)
        self.assertTrue(addr.is_current)

    def test_new_current_address_supersedes_old(self) -> None:
        """Creating a second current address supersedes the first (signal sets is_current=False)."""
        addr_data_v1 = AddressData(
            is_billing=True,
            address_line1="Str. Veche Nr. 10",
            city="Cluj-Napoca",
            county="Cluj",
            postal_code="400001",
        )
        addr_v1 = ContactService.create_address(self.customer, self.user, addr_data_v1)

        addr_data_v2 = AddressData(
            is_billing=True,
            address_line1="Str. Noua Nr. 20",
            city="Cluj-Napoca",
            county="Cluj",
            postal_code="400002",
        )
        ContactService.create_address(self.customer, self.user, addr_data_v2)

        addr_v1.refresh_from_db()
        self.assertFalse(addr_v1.is_current)


class TestCustomerServiceSearch(TestCase):
    """CustomerService.search_customers() — canonical search including CUI."""

    def setUp(self) -> None:
        self.user = _create_user()

        # Customer with a tax profile containing a known CUI
        self.customer_with_cui = create_full_customer(
            CustomerCreationRequest(
                name="Alpha Tech SRL",
                company_name="Alpha Tech SRL",
                primary_email=f"alpha_{int(time.time() * 1000)}@example.ro",
                with_tax_profile=True,
                with_billing_profile=False,
                with_address=False,
                cui="RO98765432",
            )
        )

        # Customer without a tax profile — should not appear in CUI searches
        self.customer_no_cui = create_full_customer(
            CustomerCreationRequest(
                name="Beta Services SRL",
                company_name="Beta Services SRL",
                primary_email=f"beta_{int(time.time() * 1000)}@example.ro",
                with_tax_profile=False,
                with_billing_profile=False,
                with_address=False,
            )
        )

    def test_search_by_full_cui_finds_customer(self) -> None:
        """Full CUI match must return the customer with that tax profile."""
        results = CustomerService.search_customers("RO98765432", self.user)
        pks = list(results.values_list("pk", flat=True))
        self.assertIn(self.customer_with_cui.pk, pks)

    def test_search_by_partial_cui_finds_customer(self) -> None:
        """Partial CUI prefix must still find the customer (icontains)."""
        results = CustomerService.search_customers("RO9876", self.user)
        pks = list(results.values_list("pk", flat=True))
        self.assertIn(self.customer_with_cui.pk, pks)

    def test_search_by_cui_excludes_unrelated_customers(self) -> None:
        """A CUI search must not return customers whose CUI does not match."""
        results = CustomerService.search_customers("RO98765432", self.user)
        pks = list(results.values_list("pk", flat=True))
        self.assertNotIn(self.customer_no_cui.pk, pks)

    def test_search_no_duplicates_when_cui_matches(self) -> None:
        """A customer matched via tax_profile__cui must appear exactly once (distinct)."""
        results = CustomerService.search_customers("RO98765432", self.user)
        pks = list(results.values_list("pk", flat=True))
        self.assertEqual(pks.count(self.customer_with_cui.pk), 1)

    def test_search_by_name_still_works(self) -> None:
        """Name search must continue to work after adding CUI lookup."""
        results = CustomerService.search_customers("Alpha Tech", self.user)
        pks = list(results.values_list("pk", flat=True))
        self.assertIn(self.customer_with_cui.pk, pks)

    def test_empty_query_returns_all_accessible(self) -> None:
        """Empty / whitespace-only query must return the full accessible queryset."""
        results = CustomerService.search_customers("", self.user)
        pks = list(results.values_list("pk", flat=True))
        self.assertIn(self.customer_with_cui.pk, pks)
        self.assertIn(self.customer_no_cui.pk, pks)
