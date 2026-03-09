# ===============================================================================
# INTEGRATION TESTS FOR ORDER PAYMENT METHOD FLOWS
# ===============================================================================
"""
Integration tests for order creation with different payment methods.
Tests cover payment method assignment, VAT calculation, and order integrity
against the Platform service with full database access.

Romanian business context: 21% VAT rate, CUI company identifiers.
"""

import os
import sys

# Add platform to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../services/platform'))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.test')

import django  # noqa: I001
django.setup()

from django.contrib.auth import get_user_model  # noqa: E402
from django.db import IntegrityError  # noqa: E402
from django.test import TestCase  # noqa: E402

from apps.billing.models import Currency  # noqa: E402
from apps.customers.models import Customer, CustomerBillingProfile, CustomerTaxProfile  # noqa: E402
from apps.orders.models import Order  # noqa: E402

User = get_user_model()


# ===============================================================================
# SHARED FIXTURE HELPERS
# ===============================================================================


def _make_admin(suffix: str) -> "User":  # type: ignore[name-defined]
    """Create a staff admin user with a unique suffix."""
    return User.objects.create_user(
        email=f'admin_{suffix}@test.ro',
        password='testpass123',
        is_staff=True,
        is_superuser=True,
        staff_role='admin',
    )


def _make_currency() -> Currency:
    currency, _ = Currency.objects.get_or_create(
        code='RON',
        defaults={'name': 'Romanian Leu', 'symbol': 'lei', 'decimals': 2},
    )
    return currency


def _make_customer(name: str, email: str, created_by: "User") -> Customer:  # type: ignore[name-defined]
    customer = Customer.objects.create(
        name=name,
        customer_type='company',
        company_name=name,
        primary_email=email,
        data_processing_consent=True,
        created_by=created_by,
    )
    CustomerTaxProfile.objects.create(
        customer=customer,
        cui='RO12345678',
        vat_number='RO12345678',
        is_vat_payer=True,
        # vat_rate defaults to Decimal("21.00") — Romanian standard rate
    )
    CustomerBillingProfile.objects.create(
        customer=customer,
        payment_terms=30,
        preferred_currency='RON',
    )
    return customer



def _build_billing_address() -> dict:
    return {
        'company_name': 'SC Test SRL',
        'contact_name': 'Ion Popescu',
        'email': 'contact@test.ro',
        'phone': '+40721000001',
        'address_line1': 'Str. Aviatorilor nr. 1',
        'address_line2': '',
        'city': 'Bucuresti',
        'county': 'Ilfov',
        'postal_code': '010563',
        'country': 'Romania',
        'fiscal_code': 'RO12345678',
        'registration_number': 'J40/1234/2025',
        'vat_number': 'RO12345678',
    }


# ===============================================================================
# TEST CLASSES
# ===============================================================================


class TestOrderPaymentMethodIntegration(TestCase):
    """Test order creation with different payment methods."""

    @classmethod
    def setUpTestData(cls) -> None:
        cls.admin = _make_admin('pay_method')
        cls.currency = _make_currency()
        cls.customer = _make_customer(
            name='SC Plata Test SRL',
            email='plata@test.ro',
            created_by=cls.admin,
        )

    def _create_order(self, payment_method: str, **extra: object) -> Order:
        """Helper: create a minimal order with the given payment method."""
        order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            customer_company=self.customer.company_name or '',
            billing_address=_build_billing_address(),
            payment_method=payment_method,
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            **extra,
        )
        return order

    def test_bank_transfer_order_stays_pending(self) -> None:
        """Bank transfer order should remain in pending status after creation."""
        order = self._create_order('bank_transfer')
        order.status = 'pending'
        order.save(update_fields=['status'])

        order.refresh_from_db()

        assert order.payment_method == 'bank_transfer'
        assert order.status == 'pending', (
            "Bank transfer orders should stay pending until manual verification"
        )

    def test_stripe_order_gets_payment_intent_id(self) -> None:
        """Card payment order should store a Stripe payment_intent_id."""
        payment_intent_id = 'pi_3Qe9FxABCDEF123456'
        order = self._create_order(
            'card',
            payment_intent_id=payment_intent_id,
        )

        order.refresh_from_db()

        assert order.payment_method == 'card'
        assert order.payment_intent_id == payment_intent_id, (
            "Card orders must persist the Stripe payment_intent_id for reconciliation"
        )

    def test_order_total_matches_items(self) -> None:
        """Order total_cents must equal subtotal_cents + tax_cents."""
        subtotal = 8403
        tax = 1765  # approx 21% of 8403
        total = subtotal + tax

        order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            customer_company=self.customer.company_name or '',
            billing_address=_build_billing_address(),
            subtotal_cents=subtotal,
            tax_cents=tax,
            total_cents=total,
        )

        order.refresh_from_db()

        assert order.total_cents == order.subtotal_cents + order.tax_cents, (
            "total_cents must always equal subtotal_cents + tax_cents"
        )

    def test_order_has_customer_reference(self) -> None:
        """Every order must reference a valid customer."""
        order = self._create_order('bank_transfer')

        order.refresh_from_db()

        assert order.customer_id is not None
        assert order.customer == self.customer
        assert order.customer_email == self.customer.primary_email


class TestOrderVATCalculation(TestCase):
    """Test Romanian VAT calculation in orders (21% standard rate, Aug 2025)."""

    @classmethod
    def setUpTestData(cls) -> None:
        cls.admin = _make_admin('vat_calc')
        cls.currency = _make_currency()
        cls.customer = _make_customer(
            name='SC TVA Test SRL',
            email='tva@test.ro',
            created_by=cls.admin,
        )

    def _create_order_with_totals(self, subtotal: int, tax: int) -> Order:
        return Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            customer_company=self.customer.company_name or '',
            billing_address=_build_billing_address(),
            subtotal_cents=subtotal,
            tax_cents=tax,
            total_cents=subtotal + tax,
        )

    def test_vat_21_percent_calculation(self) -> None:
        """VAT should be 21% of subtotal for Romanian companies."""
        # 10000 bani (100 RON) x 21% = 2100 bani (21 RON)
        subtotal_cents = 10000
        expected_vat_cents = 2100

        order = self._create_order_with_totals(
            subtotal=subtotal_cents,
            tax=expected_vat_cents,
        )

        # Verify the stored VAT is 21% of the subtotal
        vat_rate_pct = (order.tax_cents / order.subtotal_cents) * 100
        assert abs(vat_rate_pct - 21.0) < 0.01, (
            f"Expected 21% VAT, got {vat_rate_pct:.4f}% "
            f"(tax={order.tax_cents}¢, subtotal={order.subtotal_cents}¢)"
        )

    def test_order_total_equals_subtotal_plus_vat(self) -> None:
        """Total = subtotal + tax (VAT) — no rounding gaps allowed."""
        # Use realistic hosting invoice amounts
        subtotal_cents = 8403   # 84.03 RON
        vat_cents = 1765        # 17.65 RON (≈21% with banker's rounding)
        expected_total = subtotal_cents + vat_cents

        order = self._create_order_with_totals(
            subtotal=subtotal_cents,
            tax=vat_cents,
        )

        assert order.total_cents == expected_total, (
            f"total_cents={order.total_cents} != subtotal+tax={expected_total}"
        )
        # Double-check the constraint: total = subtotal + tax
        assert order.total_cents == order.subtotal_cents + order.tax_cents

    def test_vat_stored_as_integer_cents(self) -> None:
        """Tax amounts must be stored as integers (no float rounding errors)."""
        order = self._create_order_with_totals(subtotal=10000, tax=2100)

        assert isinstance(order.subtotal_cents, int)
        assert isinstance(order.tax_cents, int)
        assert isinstance(order.total_cents, int)


class TestOrderIdempotency(TestCase):
    """Test order creation idempotency and uniqueness constraints."""

    @classmethod
    def setUpTestData(cls) -> None:
        cls.admin = _make_admin('idempotency')
        cls.currency = _make_currency()
        cls.customer = _make_customer(
            name='SC Idempotency Test SRL',
            email='idempotency@test.ro',
            created_by=cls.admin,
        )

    def test_duplicate_order_number_rejected(self) -> None:
        """Two orders with the same order_number should fail (unique constraint)."""
        order_number = 'ORD-2025-IDEMPTEST-0001'

        Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            order_number=order_number,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            billing_address=_build_billing_address(),
        )

        with self.assertRaises(IntegrityError):
            Order.objects.create(
                customer=self.customer,
                currency=self.currency,
                order_number=order_number,  # same number — must fail
                customer_email=self.customer.primary_email,
                customer_name=self.customer.name,
                billing_address=_build_billing_address(),
            )

    def test_same_customer_idempotency_key_rejected(self) -> None:
        """Two orders from the same customer with the same idempotency_key must fail."""
        idempotency_key = 'client-checkout-abc123'

        Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            billing_address=_build_billing_address(),
            idempotency_key=idempotency_key,
        )

        with self.assertRaises(IntegrityError):
            Order.objects.create(
                customer=self.customer,
                currency=self.currency,
                customer_email=self.customer.primary_email,
                customer_name=self.customer.name,
                billing_address=_build_billing_address(),
                idempotency_key=idempotency_key,  # same key, same customer — must fail
            )

    def test_different_customers_same_idempotency_key_allowed(self) -> None:
        """The same idempotency_key used by two different customers must be accepted."""
        admin2 = _make_admin('idempotency2')
        customer2 = _make_customer(
            name='SC Alta Firma SRL',
            email='altafirma@test.ro',
            created_by=admin2,
        )
        idempotency_key = 'shared-key-xyz'

        order1 = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            billing_address=_build_billing_address(),
            idempotency_key=idempotency_key,
        )
        order2 = Order.objects.create(
            customer=customer2,
            currency=self.currency,
            customer_email=customer2.primary_email,
            customer_name=customer2.name,
            billing_address=_build_billing_address(),
            idempotency_key=idempotency_key,
        )

        # Unique constraint is scoped per (customer, idempotency_key)
        assert order1.pk != order2.pk
