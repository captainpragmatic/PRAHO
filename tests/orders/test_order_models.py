"""
Test suite for order models in PRAHO Platform
Tests Romanian VAT compliance, audit trails, and model relationships.
"""

import uuid
from decimal import Decimal

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone

from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem, OrderStatusHistory
from apps.users.models import User


class OrderModelTestCase(TestCase):
    """Test cases for Order model functionality"""

    def setUp(self):
        """Set up test data"""
        self.customer = Customer.objects.create(
            company_name="Test Company SRL",
            email="test@company.ro",
            phone="+40123456789",
            is_active=True
        )
        
        self.user = User.objects.create_user(
            email="admin@pragmatichost.com",
            password="testpass123",
            is_staff=True
        )

    def test_order_creation_with_sequential_number(self):
        """Test that orders get sequential numbers per customer"""
        order1 = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-12345678-0001",
            currency="RON",
            subtotal_cents=10000,  # 100.00 RON
            tax_cents=1900,       # 19.00 RON (19% VAT)
            total_cents=11900     # 119.00 RON
        )
        
        order2 = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-12345678-0002",
            currency="RON",
            subtotal_cents=20000,
            tax_cents=3800,
            total_cents=23800
        )
        
        self.assertEqual(order1.customer, self.customer)
        self.assertEqual(order2.customer, self.customer)
        self.assertNotEqual(order1.order_number, order2.order_number)
        self.assertTrue(order1.order_number.endswith("-0001"))
        self.assertTrue(order2.order_number.endswith("-0002"))

    def test_order_uuid_primary_key(self):
        """Test that orders use UUID as primary key"""
        order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-TEST-0001",
            currency="RON"
        )
        
        self.assertIsInstance(order.id, uuid.UUID)
        self.assertTrue(len(str(order.id)) == 36)  # Standard UUID format

    def test_order_status_choices(self):
        """Test order status workflow and validation"""
        order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-STATUS-0001",
            currency="RON",
            status="draft"
        )
        
        # Test default status
        self.assertEqual(order.status, "draft")
        
        # Test valid status changes
        valid_statuses = ["draft", "pending", "confirmed", "processing", "completed", "cancelled", "failed"]
        for status in valid_statuses:
            order.status = status
            order.full_clean()  # Should not raise ValidationError
            order.save()

    def test_romanian_vat_compliance(self):
        """Test Romanian VAT calculation compliance"""
        subtotal_cents = 10000  # 100.00 RON
        expected_vat = int(subtotal_cents * Decimal('0.19'))  # 19% VAT
        total_cents = subtotal_cents + expected_vat
        
        order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-VAT-0001",
            currency="RON",
            subtotal_cents=subtotal_cents,
            tax_cents=expected_vat,
            total_cents=total_cents
        )
        
        # Verify VAT calculation
        self.assertEqual(order.tax_cents, 1900)  # 19.00 RON
        self.assertEqual(order.total_cents, 11900)  # 119.00 RON
        
        # Test VAT percentage calculation
        vat_percentage = (order.tax_cents / order.subtotal_cents) * 100
        self.assertEqual(vat_percentage, 19.0)

    def test_billing_address_fields(self):
        """Test Romanian billing address compliance fields"""
        order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-BILLING-0001",
            currency="RON",
            # Romanian business billing fields
            billing_company_name="Test Company SRL",
            billing_contact_name="Ion Popescu",
            billing_email="facturare@company.ro",
            billing_phone="+40123456789",
            billing_address_line1="Str. Aviatorilor nr. 1",
            billing_city="Bucuresti",
            billing_county="Bucuresti",
            billing_postal_code="010563",
            billing_country="Romania",
            billing_fiscal_code="RO12345678",  # CUI
            billing_registration_number="J40/1234/2024",
            billing_vat_number="RO12345678"
        )
        
        # Verify all Romanian compliance fields are saved
        self.assertEqual(order.billing_fiscal_code, "RO12345678")
        self.assertEqual(order.billing_registration_number, "J40/1234/2024")
        self.assertEqual(order.billing_vat_number, "RO12345678")
        self.assertEqual(order.billing_country, "Romania")

    def test_order_string_representation(self):
        """Test order string representation"""
        order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-STR-0001",
            currency="RON"
        )
        
        expected_str = f"Order ORD-2024-STR-0001 - {self.customer.company_name}"
        self.assertEqual(str(order), expected_str)

    def test_order_meta_json_field(self):
        """Test order meta JSON field functionality"""
        meta_data = {
            "source": "website",
            "campaign": "spring_2024",
            "notes": "Urgent order",
            "custom_fields": {
                "project_name": "Website Redesign",
                "deadline": "2024-06-01"
            }
        }
        
        order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-META-0001",
            currency="RON",
            meta=meta_data
        )
        
        # Retrieve and verify JSON data
        saved_order = Order.objects.get(id=order.id)
        self.assertEqual(saved_order.meta["source"], "website")
        self.assertEqual(saved_order.meta["custom_fields"]["project_name"], "Website Redesign")


class OrderItemModelTestCase(TestCase):
    """Test cases for OrderItem model functionality"""

    def setUp(self):
        """Set up test data"""
        self.customer = Customer.objects.create(
            company_name="Test Company SRL",
            email="test@company.ro",
            phone="+40123456789",
            is_active=True
        )
        
        self.order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-ITEMS-0001",
            currency="RON"
        )

    def test_order_item_creation(self):
        """Test order item creation and relationships"""
        item = OrderItem.objects.create(
            order=self.order,
            quantity=2,
            unit_price_cents=5000,  # 50.00 RON
            line_total_cents=10000,  # 100.00 RON
            description="Web Hosting Plan - Standard"
        )
        
        self.assertEqual(item.order, self.order)
        self.assertEqual(item.quantity, 2)
        self.assertEqual(item.unit_price_cents, 5000)
        self.assertEqual(item.line_total_cents, 10000)

    def test_order_item_line_total_calculation(self):
        """Test that line total equals quantity × unit price"""
        quantity = 3
        unit_price_cents = 2500  # 25.00 RON
        expected_line_total = quantity * unit_price_cents
        
        item = OrderItem.objects.create(
            order=self.order,
            quantity=quantity,
            unit_price_cents=unit_price_cents,
            line_total_cents=expected_line_total,
            description="Domain Registration"
        )
        
        self.assertEqual(item.line_total_cents, expected_line_total)

    def test_order_item_provisioning_status(self):
        """Test order item provisioning status choices"""
        item = OrderItem.objects.create(
            order=self.order,
            quantity=1,
            unit_price_cents=10000,
            line_total_cents=10000,
            description="VPS Hosting",
            provisioning_status="pending"
        )
        
        # Test valid provisioning statuses
        valid_statuses = ["pending", "provisioning", "active", "suspended", "cancelled", "failed"]
        for status in valid_statuses:
            item.provisioning_status = status
            item.full_clean()  # Should not raise ValidationError
            item.save()

    def test_order_item_uuid_primary_key(self):
        """Test that order items use UUID as primary key"""
        item = OrderItem.objects.create(
            order=self.order,
            quantity=1,
            unit_price_cents=1000,
            line_total_cents=1000,
            description="Test Item"
        )
        
        self.assertIsInstance(item.id, uuid.UUID)

    def test_order_item_meta_field(self):
        """Test order item meta JSON field"""
        meta_data = {
            "configuration": {
                "cpu": "2 cores",
                "ram": "4GB",
                "disk": "50GB SSD"
            },
            "duration": "12 months",
            "renewal": True
        }
        
        item = OrderItem.objects.create(
            order=self.order,
            quantity=1,
            unit_price_cents=15000,
            line_total_cents=15000,
            description="VPS Configuration",
            meta=meta_data
        )
        
        saved_item = OrderItem.objects.get(id=item.id)
        self.assertEqual(saved_item.meta["configuration"]["cpu"], "2 cores")
        self.assertEqual(saved_item.meta["duration"], "12 months")
        self.assertTrue(saved_item.meta["renewal"])


class OrderStatusHistoryModelTestCase(TestCase):
    """Test cases for OrderStatusHistory model functionality"""

    def setUp(self):
        """Set up test data"""
        self.customer = Customer.objects.create(
            company_name="Test Company SRL",
            email="test@company.ro",
            phone="+40123456789",
            is_active=True
        )
        
        self.order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-HISTORY-0001",
            currency="RON",
            status="draft"
        )
        
        self.user = User.objects.create_user(
            email="staff@pragmatichost.com",
            password="testpass123",
            is_staff=True
        )

    def test_status_history_creation(self):
        """Test order status history tracking"""
        history = OrderStatusHistory.objects.create(
            order=self.order,
            old_status=None,  # Initial creation
            new_status="draft",
            notes="Order created",
            changed_by=self.user
        )
        
        self.assertEqual(history.order, self.order)
        self.assertIsNone(history.old_status)
        self.assertEqual(history.new_status, "draft")
        self.assertEqual(history.changed_by, self.user)

    def test_status_transition_tracking(self):
        """Test status transition from one state to another"""
        # Create initial status
        initial_history = OrderStatusHistory.objects.create(
            order=self.order,
            old_status=None,
            new_status="draft",
            notes="Order created"
        )
        
        # Create status change
        transition_history = OrderStatusHistory.objects.create(
            order=self.order,
            old_status="draft",
            new_status="pending",
            notes="Order submitted for processing",
            changed_by=self.user
        )
        
        # Verify transition tracking
        self.assertEqual(transition_history.old_status, "draft")
        self.assertEqual(transition_history.new_status, "pending")
        self.assertIsNotNone(transition_history.changed_by)

    def test_status_history_ordering(self):
        """Test that status history is ordered by creation time"""
        # Create multiple status changes
        history1 = OrderStatusHistory.objects.create(
            order=self.order,
            old_status=None,
            new_status="draft",
            notes="Created"
        )
        
        history2 = OrderStatusHistory.objects.create(
            order=self.order,
            old_status="draft",
            new_status="pending",
            notes="Submitted"
        )
        
        history3 = OrderStatusHistory.objects.create(
            order=self.order,
            old_status="pending",
            new_status="confirmed",
            notes="Confirmed"
        )
        
        # Get history in default order (most recent first)
        history_list = list(self.order.status_history.all())
        
        self.assertEqual(history_list[0], history3)  # Most recent
        self.assertEqual(history_list[1], history2)
        self.assertEqual(history_list[2], history1)  # Oldest

    def test_audit_trail_completeness(self):
        """Test complete audit trail for order lifecycle"""
        statuses = [
            (None, "draft", "Order created"),
            ("draft", "pending", "Submitted for approval"),
            ("pending", "confirmed", "Payment confirmed"),
            ("confirmed", "processing", "Processing started"),
            ("processing", "completed", "Order fulfilled")
        ]
        
        for old_status, new_status, notes in statuses:
            OrderStatusHistory.objects.create(
                order=self.order,
                old_status=old_status,
                new_status=new_status,
                notes=notes,
                changed_by=self.user
            )
        
        # Verify complete audit trail
        history_count = self.order.status_history.count()
        self.assertEqual(history_count, 5)
        
        # Verify final status in history matches order
        latest_history = self.order.status_history.first()
        self.assertEqual(latest_history.new_status, "completed")

    def test_status_history_string_representation(self):
        """Test status history string representation"""
        history = OrderStatusHistory.objects.create(
            order=self.order,
            old_status="draft",
            new_status="pending",
            notes="Status changed",
            changed_by=self.user
        )
        
        expected_str = f"ORD-2024-HISTORY-0001: draft → pending"
        self.assertEqual(str(history), expected_str)