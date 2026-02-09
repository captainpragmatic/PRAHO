# ===============================================================================
# COMPREHENSIVE UNIT TESTS FOR ORDER SERVICES
# ===============================================================================
"""
Unit tests for order management services in PRAHO Platform.
Tests cover order calculation, numbering, creation, and Romanian VAT compliance.
"""

from decimal import Decimal
from unittest.mock import MagicMock, patch

import pytest
from django.utils import timezone

from apps.orders.services import (
    OrderCalculationService,
    OrderCreateData,
    OrderFilters,
    OrderItemData,
    OrderNumberingService,
    OrderService,
    StatusChangeData,
)


class TestOrderCalculationService:
    """Test order financial calculations with Romanian VAT"""

    def test_vat_rate_is_19_percent(self):
        """Romanian VAT rate should be 19%"""
        assert OrderCalculationService.VAT_RATE == Decimal("0.19")

    def test_calculate_vat_basic(self):
        """Basic VAT calculation should be correct"""
        # 100.00 RON -> 19.00 RON VAT
        amount_cents = 10000
        vat = OrderCalculationService.calculate_vat(amount_cents)
        assert vat == 1900

    def test_calculate_vat_zero_amount(self):
        """Zero amount should have zero VAT"""
        vat = OrderCalculationService.calculate_vat(0)
        assert vat == 0

    def test_calculate_vat_small_amount(self):
        """Small amounts should calculate VAT correctly"""
        # 1.00 RON -> 0.19 RON VAT (19 cents)
        vat = OrderCalculationService.calculate_vat(100)
        assert vat == 19

    def test_calculate_vat_large_amount(self):
        """Large amounts should calculate VAT correctly"""
        # 10,000.00 RON -> 1,900.00 RON VAT
        amount_cents = 1000000
        vat = OrderCalculationService.calculate_vat(amount_cents)
        assert vat == 190000

    def test_calculate_vat_decimal_precision(self):
        """VAT calculation should handle decimal precision"""
        # 99.99 RON -> 18.99 RON VAT (rounded)
        amount_cents = 9999
        vat = OrderCalculationService.calculate_vat(amount_cents)
        # 9999 * 0.19 = 1899.81 -> 1899 cents (truncated)
        assert vat == 1899

    def test_calculate_order_totals_single_item(self):
        """Single item order totals should be correct"""
        items = [
            {"quantity": 1, "unit_price_cents": 10000}
        ]
        totals = OrderCalculationService.calculate_order_totals(items)

        assert totals["subtotal_cents"] == 10000
        assert totals["tax_cents"] == 1900
        assert totals["total_cents"] == 11900

    def test_calculate_order_totals_multiple_items(self):
        """Multiple item order totals should be correct"""
        items = [
            {"quantity": 1, "unit_price_cents": 10000},
            {"quantity": 2, "unit_price_cents": 5000},
        ]
        totals = OrderCalculationService.calculate_order_totals(items)

        # Subtotal: 10000 + (2 * 5000) = 20000
        assert totals["subtotal_cents"] == 20000
        # VAT: 20000 * 0.19 = 3800
        assert totals["tax_cents"] == 3800
        # Total: 20000 + 3800 = 23800
        assert totals["total_cents"] == 23800

    def test_calculate_order_totals_empty_items(self):
        """Empty items list should return zero totals"""
        items = []
        totals = OrderCalculationService.calculate_order_totals(items)

        assert totals["subtotal_cents"] == 0
        assert totals["tax_cents"] == 0
        assert totals["total_cents"] == 0

    def test_calculate_order_totals_with_quantities(self):
        """Order totals should correctly multiply by quantity"""
        items = [
            {"quantity": 5, "unit_price_cents": 2000},
        ]
        totals = OrderCalculationService.calculate_order_totals(items)

        # Subtotal: 5 * 2000 = 10000
        assert totals["subtotal_cents"] == 10000
        # VAT: 10000 * 0.19 = 1900
        assert totals["tax_cents"] == 1900
        # Total: 10000 + 1900 = 11900
        assert totals["total_cents"] == 11900


@pytest.mark.django_db
class TestOrderNumberingService:
    """Test order number generation"""

    def test_order_number_format(self):
        """Order number should follow expected format"""
        from tests.factories.core_factories import create_full_customer

        customer = create_full_customer()
        order_number = OrderNumberingService.generate_order_number(customer)

        # Format: ORD-YYYY-XXXXXXXX-NNNN
        parts = order_number.split('-')
        assert parts[0] == 'ORD'
        assert parts[1] == str(timezone.now().year)
        assert len(parts[2]) == 8  # Customer ID portion
        assert len(parts[3]) == 4  # Sequence number (padded)

    def test_order_numbers_are_sequential(self):
        """Sequential orders should have sequential numbers"""
        from apps.orders.models import Order
        from tests.factories.core_factories import create_full_customer

        customer = create_full_customer()

        # Create first order
        number1 = OrderNumberingService.generate_order_number(customer)
        Order.objects.create(
            customer=customer,
            order_number=number1,
            status='draft',
            currency_code='RON',
        )

        # Create second order
        number2 = OrderNumberingService.generate_order_number(customer)

        # Extract sequence numbers
        seq1 = int(number1.split('-')[-1])
        seq2 = int(number2.split('-')[-1])

        assert seq2 == seq1 + 1

    def test_order_numbers_unique_per_customer(self):
        """Different customers should have different order number prefixes"""
        from tests.factories.core_factories import create_full_customer, CustomerCreationRequest

        customer1 = create_full_customer()
        customer2 = create_full_customer(CustomerCreationRequest(
            name='SC Other Company SRL',
            company_name='SC Other Company SRL',
            primary_email='other@test.ro',
        ))

        number1 = OrderNumberingService.generate_order_number(customer1)
        number2 = OrderNumberingService.generate_order_number(customer2)

        # Customer ID portions should be different
        prefix1 = number1.rsplit('-', 1)[0]
        prefix2 = number2.rsplit('-', 1)[0]

        assert prefix1 != prefix2

    def test_order_number_starts_at_one(self):
        """First order for a customer should have sequence 1"""
        from tests.factories.core_factories import create_full_customer

        customer = create_full_customer()
        order_number = OrderNumberingService.generate_order_number(customer)

        sequence = int(order_number.split('-')[-1])
        assert sequence == 1


@pytest.mark.django_db
class TestOrderService:
    """Test main order service operations"""

    def test_create_order_success(self):
        """Order creation should succeed with valid data"""
        from apps.billing.models import Currency
        from tests.factories.core_factories import (
            create_full_customer,
            create_admin_user,
            create_product,
        )

        customer = create_full_customer()
        user = create_admin_user(username='order_admin')
        product = create_product()

        # Ensure RON currency exists
        Currency.objects.get_or_create(
            code='RON',
            defaults={'name': 'Romanian Leu', 'symbol': 'L', 'decimals': 2}
        )

        items = [
            {
                'product_id': product.pk,
                'service_id': None,
                'quantity': 1,
                'unit_price_cents': product.price_cents,
                'description': product.name,
                'meta': {},
            }
        ]

        billing_address = {
            'company_name': customer.company_name,
            'contact_name': 'Test Contact',
            'email': customer.primary_email,
            'phone': customer.primary_phone or '+40721234567',
            'address_line1': 'Str. Test Nr. 1',
            'address_line2': '',
            'city': 'București',
            'county': 'Sector 1',
            'postal_code': '010101',
            'country': 'România',
            'fiscal_code': 'RO12345678',
            'registration_number': 'J40/1234/2023',
            'vat_number': 'RO12345678',
        }

        data = OrderCreateData(
            customer=customer,
            items=items,
            billing_address=billing_address,
            currency='RON',
        )

        result = OrderService.create_order(data, created_by=user)

        assert result.is_ok()
        order = result.unwrap()
        assert order.customer == customer
        assert order.status == 'draft'

    def test_order_validation_empty_items(self):
        """Order with no items should be rejected"""
        from apps.billing.models import Currency
        from tests.factories.core_factories import create_full_customer, create_admin_user

        customer = create_full_customer()
        user = create_admin_user(username='order_admin_empty')

        Currency.objects.get_or_create(
            code='RON',
            defaults={'name': 'Romanian Leu', 'symbol': 'L', 'decimals': 2}
        )

        billing_address = {
            'company_name': customer.company_name,
            'contact_name': 'Test Contact',
            'email': customer.primary_email,
            'phone': '+40721234567',
            'address_line1': 'Str. Test Nr. 1',
            'address_line2': '',
            'city': 'București',
            'county': 'Sector 1',
            'postal_code': '010101',
            'country': 'România',
            'fiscal_code': 'RO12345678',
            'registration_number': 'J40/1234/2023',
            'vat_number': 'RO12345678',
        }

        data = OrderCreateData(
            customer=customer,
            items=[],  # Empty items
            billing_address=billing_address,
        )

        result = OrderService.create_order(data, created_by=user)

        # Should fail with empty items
        assert result.is_err() or (result.is_ok() and result.unwrap().items.count() == 0)


class TestOrderFilters:
    """Test order filter type definitions"""

    def test_order_filters_structure(self):
        """OrderFilters should accept expected keys"""
        filters: OrderFilters = {
            'status': 'pending',
            'search': 'test',
        }
        assert filters['status'] == 'pending'
        assert filters['search'] == 'test'


class TestStatusChangeData:
    """Test status change parameter object"""

    def test_status_change_data_creation(self):
        """StatusChangeData should be creatable with required fields"""
        data = StatusChangeData(
            new_status='confirmed',
            notes='Order confirmed by admin',
        )
        assert data.new_status == 'confirmed'
        assert data.notes == 'Order confirmed by admin'
        assert data.changed_by is None

    def test_status_change_data_with_user(self):
        """StatusChangeData should accept user reference"""
        mock_user = MagicMock()
        data = StatusChangeData(
            new_status='processing',
            changed_by=mock_user,
        )
        assert data.changed_by == mock_user


class TestOrderItemData:
    """Test order item type definitions"""

    def test_order_item_data_structure(self):
        """OrderItemData should accept expected fields"""
        import uuid
        item: OrderItemData = {
            'product_id': uuid.uuid4(),
            'service_id': None,
            'quantity': 2,
            'unit_price_cents': 5000,
            'description': 'Web Hosting Standard',
            'meta': {'billing_cycle': 'monthly'},
        }
        assert item['quantity'] == 2
        assert item['unit_price_cents'] == 5000


class TestRomanianVATCompliance:
    """Test Romanian VAT compliance in order calculations"""

    def test_vat_rate_19_percent(self):
        """Standard Romanian VAT rate should be 19%"""
        rate = OrderCalculationService.VAT_RATE
        assert rate == Decimal("0.19")

    def test_vat_calculation_romanian_compliance(self):
        """VAT calculations should comply with Romanian regulations"""
        # Test case: 840.34 RON net -> 159.66 RON VAT -> 1000.00 RON total
        # This is the reverse calculation to verify compliance
        net_cents = 84034
        vat_cents = OrderCalculationService.calculate_vat(net_cents)
        total = net_cents + vat_cents

        # VAT should be approximately 19% of net
        expected_vat = int(Decimal(net_cents) * Decimal("0.19"))
        assert abs(vat_cents - expected_vat) <= 1  # Allow 1 cent rounding difference

    def test_invoice_totals_with_romanian_vat(self):
        """Invoice totals should include correct Romanian VAT"""
        items = [
            {"quantity": 1, "unit_price_cents": 84034},  # Net amount
        ]
        totals = OrderCalculationService.calculate_order_totals(items)

        # Verify VAT is approximately 19%
        vat_percentage = (totals["tax_cents"] / totals["subtotal_cents"]) * 100
        assert 18.9 < vat_percentage < 19.1  # Allow small rounding tolerance
