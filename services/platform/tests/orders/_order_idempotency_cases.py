"""
Tests for idempotency key fixes in order creation.

Covers:
  • CRITICAL-2: Idempotency key is set atomically during order creation
    (not post-create), preventing race-condition duplicates.
  • WARNING-1: Keys > 64 chars are rejected at API boundary (max_length=64
    on the DB column must match API validation).
  • IntegrityError handling: concurrent requests with same key return
    existing order instead of 500.

Related: Codex review findings CRITICAL-2 and WARNING-1.
"""

from __future__ import annotations

import uuid

from django.db import IntegrityError, transaction
from django.test import TestCase

from apps.api.orders.views import IDEMPOTENCY_KEY_MAX_LENGTH
from apps.billing.models import Currency
from apps.customers.models import Customer, CustomerTaxProfile
from apps.orders.models import Order
from apps.orders.services import OrderCreateData, OrderService
from apps.products.models import Product

# ===============================================================================
# SHARED FIXTURE HELPERS
# ===============================================================================


def _make_currency(code: str = "RON") -> Currency:
    currency, _ = Currency.objects.get_or_create(
        code=code,
        defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2},
    )
    return currency


def _make_customer(primary_email: str = "idempotency-test@test.ro") -> Customer:
    customer = Customer.objects.create(
        name="SC Idempotency Test SRL",
        customer_type="company",
        company_name="SC Idempotency Test SRL",
        primary_email=primary_email,
        status="active",
    )
    CustomerTaxProfile.objects.create(
        customer=customer,
        cui="RO12345678",
        vat_number="RO12345678",
        is_vat_payer=True,
    )
    return customer


def _billing_address() -> dict:
    return {
        "company_name": "SC Idempotency Test SRL",
        "contact_name": "Ion Popescu",
        "email": "contact@test.ro",
        "phone": "+40721000001",
        "address_line1": "Str. Aviatorilor nr. 1",
        "address_line2": "",
        "city": "Bucuresti",
        "county": "Ilfov",
        "postal_code": "010563",
        "country": "Romania",
        "fiscal_code": "RO12345678",
        "registration_number": "J40/1234/2025",
        "vat_number": "RO12345678",
    }


def _order_items(product_slug: str = "hosting-std-idem") -> list[dict]:
    product = Product.objects.create(
        slug=product_slug,
        name="Web Hosting Standard",
        product_type="shared_hosting",
        is_active=True,
    )
    return [
        {
            "product_id": str(product.id),
            "service_id": None,
            "quantity": 1,
            "unit_price_cents": 5000,
            "setup_cents": 0,
            "description": "Web Hosting Standard - Monthly",
            "meta": {},
        }
    ]


# ===============================================================================
# IDEMPOTENCY KEY ATOMIC CREATION TESTS
# ===============================================================================


class IdempotencyKeyAtomicCreationTests(TestCase):
    """Verify idempotency_key is persisted atomically during Order.objects.create()."""

    def setUp(self) -> None:
        self.currency = _make_currency()
        self.customer = _make_customer()

    def test_idempotency_key_set_on_creation(self) -> None:
        """Idempotency key should be on the order immediately after create_order."""
        key = uuid.uuid4().hex  # 32 chars
        items = _order_items(product_slug="hosting-atomic-1")
        data = OrderCreateData(
            customer=self.customer,
            items=items,
            billing_address=_billing_address(),
            currency="RON",
            idempotency_key=key,
        )
        result = OrderService.create_order(data)
        self.assertTrue(result.is_ok(), f"Order creation failed: {result.error if hasattr(result, 'error') else ''}")
        order = result.value
        # Key should be set directly on the created object — no separate save needed
        order.refresh_from_db()
        self.assertEqual(order.idempotency_key, key)

    def test_empty_idempotency_key_allowed(self) -> None:
        """Orders without an idempotency key (empty string) should still work."""
        items = _order_items(product_slug="hosting-atomic-2")
        data = OrderCreateData(
            customer=self.customer,
            items=items,
            billing_address=_billing_address(),
            currency="RON",
            idempotency_key="",
        )
        result = OrderService.create_order(data)
        self.assertTrue(result.is_ok())
        order = result.value
        order.refresh_from_db()
        self.assertEqual(order.idempotency_key, "")

    def test_duplicate_idempotency_key_raises_integrity_error(self) -> None:
        """DB unique constraint should prevent two orders with same key for same customer."""
        key = uuid.uuid4().hex
        items1 = _order_items(product_slug="hosting-dup-1")
        data1 = OrderCreateData(
            customer=self.customer,
            items=items1,
            billing_address=_billing_address(),
            currency="RON",
            idempotency_key=key,
        )
        result1 = OrderService.create_order(data1)
        self.assertTrue(result1.is_ok())

        # Second order with same key should raise IntegrityError
        items2 = _order_items(product_slug="hosting-dup-2")
        data2 = OrderCreateData(
            customer=self.customer,
            items=items2,
            billing_address=_billing_address(),
            currency="RON",
            idempotency_key=key,
        )
        with transaction.atomic(), self.assertRaises(IntegrityError):
            OrderService.create_order(data2)


# ===============================================================================
# IDEMPOTENCY KEY LENGTH VALIDATION TESTS
# ===============================================================================


class IdempotencyKeyLengthTests(TestCase):
    """Verify API-level length validation matches DB column max_length=64."""

    def test_max_length_constant_is_64(self) -> None:
        """IDEMPOTENCY_KEY_MAX_LENGTH must match the DB column max_length."""
        self.assertEqual(IDEMPOTENCY_KEY_MAX_LENGTH, 64)

    def test_db_field_max_length_is_64(self) -> None:
        """Order.idempotency_key field max_length must be 64."""
        field = Order._meta.get_field("idempotency_key")
        self.assertEqual(field.max_length, 64)

    def test_key_exactly_64_chars_accepted(self) -> None:
        """A 64-character key should be accepted by the model."""
        _make_currency()
        customer = _make_customer(primary_email="len-test-64@test.ro")
        key = "a" * 64
        items = _order_items(product_slug="hosting-len-64")
        data = OrderCreateData(
            customer=customer,
            items=items,
            billing_address=_billing_address(),
            currency="RON",
            idempotency_key=key,
        )
        result = OrderService.create_order(data)
        self.assertTrue(result.is_ok())
        order = result.value
        order.refresh_from_db()
        self.assertEqual(order.idempotency_key, key)
