"""
Tests for Customer.is_business.

Covers #295: `customer.is_business` was read at integrations/services.py:104 behind a
`# type: ignore[attr-defined]`, but the attribute did not exist — every customer sync raised
AttributeError, and the surrounding `except` only catches Customer.DoesNotExist.
"""

from __future__ import annotations

from django.test import TestCase

from apps.customers.models import Customer


class CustomerIsBusinessTestCase(TestCase):
    """#295: is_business must match the definition the VAT path applies to real invoices.

    `_build_customer_vat_info` (billing/services.py) derives is_business from company_name, so
    company/pfa/ngo — all of which require a company name — are businesses, and individuals are
    not. Keying off the same field keeps the accounting-sync decision consistent with VAT.
    """

    def test_individual_is_not_a_business(self):
        customer = Customer(customer_type="individual", name="Ion Popescu", company_name="")

        self.assertFalse(customer.is_business)

    def test_company_is_a_business(self):
        customer = Customer(customer_type="company", name="Internal", company_name="Test SRL")

        self.assertTrue(customer.is_business)

    def test_pfa_is_a_business(self):
        customer = Customer(customer_type="pfa", name="Popescu Ion PFA", company_name="Popescu Ion PFA")

        self.assertTrue(customer.is_business)

    def test_ngo_is_a_business(self):
        """An NGO has a company name and is treated as a business by the VAT path, so it syncs
        to accounting like any other non-consumer."""
        customer = Customer(customer_type="ngo", name="Asociatia Test", company_name="Asociatia Test")

        self.assertTrue(customer.is_business)


class ExternalSyncCustomerTestCase(TestCase):
    """#295: the sync path read customer.is_business and raised AttributeError uncaught."""

    def test_sync_routes_a_business_customer_to_accounting(self):
        """The whole point of the missing attribute: business customers sync to accounting."""
        from apps.integrations.services import ExternalSyncService  # noqa: PLC0415

        customer = Customer.objects.create(
            name="Test SRL",
            customer_type="company",
            company_name="Test SRL",
            primary_email="billing@test.ro",
            status="active",
        )

        result = ExternalSyncService._sync_customer(str(customer.id))

        self.assertIn({"target": "accounting", "status": "synced"}, result["sync_targets"])
        self.assertEqual(result["customer_name"], "Test SRL")

    def test_sync_does_not_route_an_individual_to_accounting(self):
        from apps.integrations.services import ExternalSyncService  # noqa: PLC0415

        customer = Customer.objects.create(
            name="Ion Popescu",
            customer_type="individual",
            company_name="",
            primary_email="ion@example.ro",
            status="active",
        )

        result = ExternalSyncService._sync_customer(str(customer.id))

        self.assertEqual(result["sync_targets"], [])

    def test_individual_with_registered_company_name_is_business(self):
        """Field-based, not type-based: an individual who registered a company name is
        classified as a business — exactly as the VAT path treats them on real invoices."""
        customer = Customer.objects.create(
            name='Maria Ionescu',
            customer_type='individual',
            company_name='Side Business SRL',
            primary_email='maria-side@example.ro',
            status='active',
        )

        self.assertTrue(customer.is_business)

    def test_company_with_empty_company_name_is_not_business(self):
        """The complementary edge: a company record missing its company name falls out of
        the business classification, matching the VAT path's field-based rule."""
        customer = Customer.objects.create(
            name='Shellco',
            customer_type='company',
            company_name='',
            primary_email='shellco@example.ro',
            status='active',
        )

        self.assertFalse(customer.is_business)
