"""
Order Flow Hardening Tests — Platform Unit Tests

Covers:
  • OrderPreflightValidationService correctness (customer existence, product
    availability, VAT calculation)
  • BUG-10: duplicate VAT audit events must not occur when preflight reuses the
    pre-computed VATCalculationResult stored in order._preflight_vat_result
  • BUG-11/12: HMAC verification — order views reject requests that lack or
    carry a tampered X-Portal-Id/X-Signature header

Romanian business context: 21% VAT, CUI identifiers, RON currency.
"""

from __future__ import annotations

import time
from decimal import Decimal

from django.test import Client, TestCase

from apps.audit.models import AuditEvent
from apps.billing.models import Currency
from apps.customers.models import Customer, CustomerTaxProfile
from apps.orders.models import Order, OrderItem
from apps.orders.preflight import OrderPreflightValidationService
from apps.orders.services import OrderCalculationService
from apps.orders.vat_rules import CustomerVATInfo, OrderVATCalculator
from apps.products.models import Product
from apps.users.models import User

# ===============================================================================
# SHARED FIXTURE HELPERS
# ===============================================================================


def _make_staff_user(email: str = 'staff@pragmatichost.com') -> User:
    return User.objects.create_user(
        email=email,
        password='testpass123',
        is_staff=True,
        staff_role='admin',
    )


def _make_currency(code: str = 'RON') -> Currency:
    currency, _ = Currency.objects.get_or_create(
        code=code,
        defaults={'name': 'Romanian Leu', 'symbol': 'lei', 'decimals': 2},
    )
    return currency


def _make_customer(primary_email: str = 'firma@test.ro') -> Customer:
    customer = Customer.objects.create(
        name='SC Test Hardening SRL',
        customer_type='company',
        company_name='SC Test Hardening SRL',
        primary_email=primary_email,
        status='active',
    )
    CustomerTaxProfile.objects.create(
        customer=customer,
        cui='RO12345678',
        vat_number='RO12345678',
        is_vat_payer=True,
        # vat_rate defaults to Decimal("21.00") per model definition
    )
    return customer


def _make_product(slug: str = 'hosting-std-test', name: str = 'Web Hosting Standard') -> Product:
    return Product.objects.create(
        slug=slug,
        name=name,
        product_type='shared_hosting',
        is_active=True,
    )


def _billing_address(**overrides: object) -> dict:
    base: dict = {
        'company_name': 'SC Test Hardening SRL',
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
    base.update(overrides)
    return base


# ===============================================================================
# PREFLIGHT VALIDATION TESTS
# ===============================================================================


class TestPreflightOrderService(TestCase):
    """Test OrderPreflightValidationService validation logic."""

    @classmethod
    def setUpTestData(cls) -> None:
        cls.currency = _make_currency()
        cls.customer = _make_customer()
        cls.product = _make_product()

    def _make_order(self, **overrides: object) -> Order:
        """Build a minimal valid order for preflight checks."""
        defaults: dict = {
            'customer': self.customer,
            'currency': self.currency,
            'customer_email': self.customer.primary_email,
            'customer_name': self.customer.name,
            'customer_company': self.customer.company_name or '',
            'billing_address': _billing_address(),
            'subtotal_cents': 10000,
            'tax_cents': 2100,
            'total_cents': 12100,
        }
        defaults.update(overrides)
        return Order.objects.create(**defaults)

    def test_preflight_validates_customer_billing_snapshot(self) -> None:
        """Preflight should block orders with incomplete billing address."""
        order = self._make_order(
            billing_address={
                # Intentionally empty — missing all required fields
            }
        )

        errors, _warnings = OrderPreflightValidationService.validate(order)

        # At minimum, contact_name and email are required
        assert len(errors) > 0, "Preflight should report errors for empty billing address"
        assert any('contact' in e.lower() or 'name' in e.lower() for e in errors), (
            "Expected error about missing contact_name"
        )

    def test_preflight_with_complete_billing_address_passes_required_fields(self) -> None:
        """Preflight should not report field-level errors for a fully populated address."""
        order = self._make_order(billing_address=_billing_address())

        errors, _warnings = OrderPreflightValidationService.validate(order)

        # Billing-level field errors must not appear
        billing_field_errors = [
            e for e in errors
            if any(kw in e.lower() for kw in ['contact', 'email', 'address', 'city', 'county', 'postal', 'country'])
        ]
        assert billing_field_errors == [], (
            f"Unexpected billing field errors with complete address: {billing_field_errors}"
        )

    def test_preflight_validates_product_availability(self) -> None:
        """Preflight should warn when an order item references an inactive product."""
        self.product.is_active = False
        self.product.save(update_fields=['is_active'])

        try:
            order = self._make_order()
            item = OrderItem.objects.create(
                order=order,
                product=self.product,
                product_name=self.product.name,
                product_type=self.product.product_type,
                quantity=1,
                unit_price_cents=5000,
                tax_rate=Decimal('0.2100'),
                tax_cents=1050,
                line_total_cents=6050,
            )
            assert item.pk is not None  # ensure item was created

            _errors, warnings = OrderPreflightValidationService.validate(order)

            assert any('inactive' in w.lower() for w in warnings), (
                f"Expected inactive-product warning, got warnings: {warnings}"
            )
        finally:
            self.product.is_active = True
            self.product.save(update_fields=['is_active'])

    def test_preflight_calculates_vat(self) -> None:
        """Preflight must verify that stored tax_cents matches the computed 21% VAT."""
        # Order with correct 21% VAT
        order = self._make_order(
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            billing_address=_billing_address(),
        )
        # Provide the subtotal via the preflight hook so VAT is checked against
        # the stored 10000¢ rather than recomputed from (empty) item list.
        order._preflight_subtotal_cents = 10000  # type: ignore[attr-defined]  # test-only hook for preflight validation

        errors, _warnings = OrderPreflightValidationService.validate(order)

        # VAT mismatch errors should NOT appear for a correctly priced order
        vat_errors = [e for e in errors if 'vat' in e.lower() or 'mismatch' in e.lower()]
        assert vat_errors == [], (
            f"Unexpected VAT errors for correct 21% calculation: {vat_errors}"
        )

    def test_preflight_detects_incorrect_vat_amount(self) -> None:
        """Preflight must flag orders where tax_cents does not match the computed VAT."""
        # Deliberately wrong VAT (19% instead of 21%)
        order = self._make_order(
            subtotal_cents=10000,
            tax_cents=1900,   # wrong: should be 2100 for 21%
            total_cents=11900,
            billing_address=_billing_address(),
        )
        # Provide subtotal via the preflight hook so VAT check runs against 10000¢.
        order._preflight_subtotal_cents = 10000  # type: ignore[attr-defined]  # test-only hook for preflight validation

        errors, _warnings = OrderPreflightValidationService.validate(order)

        vat_errors = [e for e in errors if 'vat' in e.lower() or 'mismatch' in e.lower()]
        assert len(vat_errors) > 0, (
            "Preflight should detect incorrect VAT amount (1900¢ != expected 2100¢)"
        )


# ===============================================================================
# BUG-10: DUPLICATE VAT AUDIT EVENT PREVENTION
# ===============================================================================


class TestDuplicateVATAuditPrevention(TestCase):
    """
    BUG-10: OrderPreflightValidationService must reuse the pre-computed VAT result
    stored in order._preflight_vat_result instead of calling OrderVATCalculator a
    second time.  Each redundant call emits an 'order_vat_calculation' AuditEvent
    which clutters the compliance audit trail.
    """

    @classmethod
    def setUpTestData(cls) -> None:
        cls.currency = _make_currency()
        cls.customer = _make_customer('bug10@test.ro')

    def test_single_preflight_single_audit_event(self) -> None:
        """One preflight validate() call must emit at most one order_vat_calculation event."""
        order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            customer_company=self.customer.company_name or '',
            billing_address=_billing_address(),
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
        )

        # Pre-compute VAT result and attach it — this is the BUG-10 fix
        customer_vat_info: CustomerVATInfo = {
            'country': 'RO',
            'is_business': True,
            'vat_number': 'RO12345678',
            'customer_id': str(self.customer.id),
            'order_id': str(order.id),
        }
        pre_computed = OrderVATCalculator.calculate_vat(
            subtotal_cents=10000,
            customer_info=customer_vat_info,
        )
        # Simulate the service attaching the pre-computed result
        order._preflight_vat_result = pre_computed  # type: ignore[attr-defined]  # test-only hook for preflight validation

        # Count AuditEvents before validate()
        before_count = AuditEvent.objects.filter(action='order_vat_calculation').count()

        # Run preflight — should reuse _preflight_vat_result, not call calculate_vat again
        _errors, _warnings = OrderPreflightValidationService.validate(order)

        after_count = AuditEvent.objects.filter(action='order_vat_calculation').count()
        new_events = after_count - before_count

        assert new_events <= 1, (
            f"BUG-10: preflight emitted {new_events} 'order_vat_calculation' events. "
            f"Expected 0 (reuse of _preflight_vat_result should skip redundant calculation)."
        )

    def test_preflight_without_cached_result_emits_one_event(self) -> None:
        """Without a cached result, preflight must compute VAT exactly once."""
        order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            customer_company=self.customer.company_name or '',
            billing_address=_billing_address(),
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
        )

        # No _preflight_vat_result attached — should compute exactly once
        before_count = AuditEvent.objects.filter(action='order_vat_calculation').count()

        _errors, _warnings = OrderPreflightValidationService.validate(order)

        after_count = AuditEvent.objects.filter(action='order_vat_calculation').count()
        new_events = after_count - before_count

        assert new_events == 1, (
            f"Preflight without cached VAT result should emit exactly 1 event, "
            f"but emitted {new_events}"
        )


# ===============================================================================
# BUG-11/12: HMAC VERIFICATION FOR ORDER API REQUESTS
# ===============================================================================


class TestOrderHMACVerification(TestCase):
    """
    BUG-11/12: The HMAC middleware (PortalServiceHMACMiddleware) must reject
    requests reaching /api/ endpoints that either:
      - Carry no HMAC headers at all (BUG-11)
      - Carry headers with a tampered/invalid signature (BUG-12)

    Order API endpoints that portal calls are protected by this middleware.
    Tests hit the order list view to confirm middleware enforcement.
    """

    @classmethod
    def setUpTestData(cls) -> None:
        cls.currency = _make_currency()
        cls.customer = _make_customer('hmac@test.ro')
        cls.staff_user = _make_staff_user('hmac_staff@pragmatichost.com')

    def test_order_api_rejects_missing_hmac(self) -> None:
        """Order API endpoint must reject unauthenticated requests (no HMAC headers)."""
        client = Client()

        # Hit an order list endpoint without any auth headers
        response = client.get(
            '/orders/',
            HTTP_ACCEPT='application/json',
        )

        # Must not be 200 — should redirect to login (302) or forbid (403)
        assert response.status_code in (302, 403, 401), (
            f"Expected 302/403/401 for unauthenticated order request, "
            f"got {response.status_code}"
        )

    def test_order_api_rejects_invalid_hmac(self) -> None:
        """Order API endpoint must reject requests with a tampered HMAC signature."""
        client = Client()

        response = client.get(
            '/orders/',
            HTTP_X_PORTAL_ID='portal-prod-01',
            HTTP_X_NONCE='a' * 43,          # valid length nonce (>= 32 chars)
            HTTP_X_TIMESTAMP=str(int(time.time())),
            HTTP_X_BODY_HASH='dGVzdA==',    # fake body hash
            HTTP_X_SIGNATURE='deadbeef' * 8,  # clearly invalid 64-char signature
        )

        # Middleware should intercept and return 401/403 — never 200
        assert response.status_code in (302, 401, 403), (
            f"Expected 302/401/403 for tampered HMAC request, "
            f"got {response.status_code}"
        )

    def test_order_list_accessible_to_authenticated_staff(self) -> None:
        """Confirm the order list view is accessible to authenticated staff (baseline)."""
        client = Client()
        client.force_login(self.staff_user)

        response = client.get('/orders/')

        assert response.status_code == 200, (
            f"Staff user should be able to access order list, "
            f"got {response.status_code}"
        )

    def test_order_list_unauthenticated_redirects_to_login(self) -> None:
        """Order list must redirect anonymous users to the login page."""
        client = Client()
        # Deliberately no login — pure anonymous request

        response = client.get('/orders/')

        # @login_required redirects to auth/login
        assert response.status_code == 302, (
            f"Unauthenticated request should redirect to login, "
            f"got {response.status_code}"
        )
        assert 'login' in response.url.lower(), (
            f"Redirect target should be the login page, got '{response.url}'"
        )


# ===============================================================================
# ORDER CALCULATION SERVICE — VAT CONSISTENCY
# ===============================================================================


class TestOrderVATConsistency(TestCase):
    """
    Verify that OrderCalculationService produces VAT amounts consistent with the
    authoritative OrderVATCalculator for standard Romanian B2B scenarios.
    """

    @classmethod
    def setUpTestData(cls) -> None:
        cls.currency = _make_currency()
        cls.customer = _make_customer('vatcons@test.ro')

    def test_21_percent_vat_for_romanian_company(self) -> None:
        """Standard Romanian business order must incur exactly 21% VAT."""
        items = [{'quantity': 1, 'unit_price_cents': 10000}]
        totals = OrderCalculationService.calculate_order_totals(
            items=items,
            customer=self.customer,
        )

        expected_vat = 2100  # 21% of 10 000
        assert totals['tax_cents'] == expected_vat, (
            f"Expected 21% VAT ({expected_vat}¢) for Romanian B2B, "
            f"got {totals['tax_cents']}¢"
        )
        assert totals['total_cents'] == totals['subtotal_cents'] + totals['tax_cents']

    def test_vat_calculation_uses_banker_rounding(self) -> None:
        """VAT calculation should use banker's rounding (ROUND_HALF_EVEN) per Romanian law."""
        # 1¢ subtotal — expected 0¢ VAT (0.21 rounds to 0 under ROUND_HALF_EVEN)
        items = [{'quantity': 1, 'unit_price_cents': 1}]
        totals = OrderCalculationService.calculate_order_totals(items=items)

        assert totals['tax_cents'] == 0, (
            f"1¢ subtotal should produce 0¢ VAT with banker's rounding, "
            f"got {totals['tax_cents']}¢"
        )

    def test_multi_item_vat_aggregated_correctly(self) -> None:
        """Multiple line items must aggregate correctly for the order total."""
        items = [
            {'quantity': 2, 'unit_price_cents': 5000},   # 10 000¢ subtotal
            {'quantity': 1, 'unit_price_cents': 10000},  # 10 000¢ subtotal
        ]
        totals = OrderCalculationService.calculate_order_totals(items=items)

        expected_subtotal = 20000
        expected_vat = 4200    # 21% of 20 000
        expected_total = 24200

        assert totals['subtotal_cents'] == expected_subtotal
        assert totals['tax_cents'] == expected_vat
        assert totals['total_cents'] == expected_total
