"""Regression coverage for configured TLD resolution and registration periods."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

from django.test import TestCase

from apps.billing.models import Currency
from apps.customers.models import Customer, CustomerAddress, CustomerTaxProfile
from apps.domains.models import TLD, Domain, DomainOrderItem, Registrar, TLDRegistrarAssignment
from apps.domains.services import DomainLifecycleService, DomainOrderService, DomainValidationService
from apps.orders.models import Order


class DomainServiceLogicTests(TestCase):
    def setUp(self) -> None:
        self.ro = TLD.objects.create(
            extension="ro",
            description=".ro",
            registration_price_cents=1000,
            renewal_price_cents=900,
            transfer_price_cents=800,
        )
        self.com_ro = TLD.objects.create(
            extension="com.ro",
            description=".com.ro",
            registration_price_cents=2500,
            renewal_price_cents=2300,
            transfer_price_cents=2100,
            min_registration_period=2,
            max_registration_period=3,
        )
        self.ro_registrar = Registrar.objects.create(
            name="ro-registrar",
            display_name="RO Registrar",
            website_url="https://ro.example.test",
            api_endpoint="https://api.ro.example.test",
        )
        self.com_ro_registrar = Registrar.objects.create(
            name="com-ro-registrar",
            display_name="COM.RO Registrar",
            website_url="https://com-ro.example.test",
            api_endpoint="https://api.com-ro.example.test",
        )
        TLDRegistrarAssignment.objects.create(
            tld=self.ro,
            registrar=self.ro_registrar,
            is_primary=True,
            is_active=True,
        )
        TLDRegistrarAssignment.objects.create(
            tld=self.com_ro,
            registrar=self.com_ro_registrar,
            is_primary=True,
            is_active=True,
        )
        self.customer = Customer.objects.create(
            name="Domain Owner",
            company_name="Domain Owner SRL",
            customer_type="company",
            primary_email="domains@example.test",
            primary_phone="+40712345678",
        )
        CustomerAddress.objects.create(
            customer=self.customer,
            address_line1="Str. Test 1",
            city="Bucuresti",
            county="Bucuresti",
            postal_code="010101",
            country="RO",
            is_primary=True,
            is_current=True,
        )
        CustomerTaxProfile.objects.create(customer=self.customer, cui="RO12345678")
        currency, _ = Currency.objects.get_or_create(
            code="RON",
            defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2},
        )
        self.order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-DOMAIN-LOGIC-1",
            currency=currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
        )

    def test_longest_configured_tld_suffix_wins(self) -> None:
        self.assertEqual(DomainValidationService.extract_tld_from_domain("Shop.Example.COM.RO"), "com.ro")
        self.assertEqual(DomainValidationService.extract_tld_from_domain("example.ro"), "ro")

    def test_domain_model_clean_uses_longest_configured_tld_suffix(self) -> None:
        domain = Domain(
            name="shop.example.com.ro",
            registrar=self.com_ro_registrar,
            customer=self.customer,
        )

        domain.clean()

        self.assertEqual(domain.tld, self.com_ro)

    def test_inactive_specific_tld_does_not_fall_back_to_active_parent(self) -> None:
        self.com_ro.is_active = False
        self.com_ro.save(update_fields=["is_active", "updated_at"])

        self.assertEqual(DomainValidationService.extract_tld_from_domain("example.com.ro"), "com.ro")
        result = DomainLifecycleService._get_registration_components("example.com.ro")
        self.assertTrue(result.is_err(), result)
        self.assertIn("TLD '.com.ro' is not supported", str(result.unwrap_err()))

    @patch("apps.domains.services.DomainRegistrarGateway.register_domain")
    def test_registration_uses_multi_label_tld_and_its_registrar(self, mock_register) -> None:
        mock_register.return_value = (
            True,
            {
                "registrar_domain_id": "COMRO-1",
                "expires_at": datetime(2028, 1, 1, tzinfo=UTC),
                "nameservers": [],
                "epp_code": "",
            },
        )

        result = DomainLifecycleService.create_domain_registration(
            customer=self.customer,
            domain_name="shop.example.com.ro",
            years=2,
        )

        self.assertTrue(result.is_ok(), result)
        domain = result.unwrap()
        self.assertEqual(domain.tld, self.com_ro)
        self.assertEqual(domain.registrar, self.com_ro_registrar)
        self.assertEqual(mock_register.call_args.args[:3], (self.com_ro_registrar, "shop.example.com.ro", 2))

    @patch("apps.domains.services.DomainRegistrarGateway.register_domain")
    def test_registration_rejects_years_outside_resolved_tld_bounds(self, mock_register) -> None:
        mock_register.return_value = (
            False,
            {"error": "unexpected registrar call", "retriability": "not_retriable"},
        )
        for years in (1, 4):
            with self.subTest(years=years):
                result = DomainLifecycleService.create_domain_registration(
                    customer=self.customer,
                    domain_name=f"invalid-{years}.com.ro",
                    years=years,
                )
                self.assertTrue(result.is_err(), result)
                self.assertIn("between 2 and 3 years", str(result.unwrap_err()))

        mock_register.assert_not_called()
        self.assertFalse(Domain.objects.filter(name__startswith="invalid-").exists())

    def test_registration_order_items_enforce_tld_bounds_and_preserve_pricing(self) -> None:
        for years in (1, 4):
            with self.subTest(years=years):
                success, error = DomainOrderService.create_domain_order_item(
                    order=self.order,
                    domain_name=f"invalid-{years}.com.ro",
                    action="register",
                    years=years,
                )
                self.assertFalse(success)
                self.assertIn("between 2 and 3 years", str(error))

        for years in (2, 3):
            with self.subTest(years=years):
                success, item_or_error = DomainOrderService.create_domain_order_item(
                    order=self.order,
                    domain_name=f"valid-{years}.com.ro",
                    action="register",
                    years=years,
                )
                self.assertTrue(success, item_or_error)
                item = DomainOrderItem.objects.get(domain_name=f"valid-{years}.com.ro")
                self.assertEqual(item.tld, self.com_ro)
                self.assertEqual(item.unit_price_cents, 2500)
                self.assertEqual(item.total_price_cents, 2500 * years)

        self.assertEqual(DomainOrderItem.objects.count(), 2)

    def test_renewal_order_items_enforce_tld_bounds_and_preserve_pricing(self) -> None:
        for years in (1, 4):
            with self.subTest(years=years):
                success, error = DomainOrderService.create_domain_order_item(
                    order=self.order,
                    domain_name=f"renew-invalid-{years}.com.ro",
                    action="renew",
                    years=years,
                )
                self.assertFalse(success)
                self.assertIn("between 2 and 3 years", str(error))

        for years in (2, 3):
            with self.subTest(years=years):
                success, item_or_error = DomainOrderService.create_domain_order_item(
                    order=self.order,
                    domain_name=f"renew-valid-{years}.com.ro",
                    action="renew",
                    years=years,
                )
                self.assertTrue(success, item_or_error)
                item = DomainOrderItem.objects.get(domain_name=f"renew-valid-{years}.com.ro")
                self.assertEqual(item.tld, self.com_ro)
                self.assertEqual(item.unit_price_cents, 2300)
                self.assertEqual(item.total_price_cents, 2300 * years)

        self.assertEqual(DomainOrderItem.objects.count(), 2)
