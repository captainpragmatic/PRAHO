"""
Tests for Order Item Expandable Rows Functionality
=================================================
Tests the new expandable row pattern for order item management
"""

from django.test import TestCase
from django.urls import reverse
from django.contrib.auth import get_user_model
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product, ProductPrice
from apps.billing.models import Currency
from decimal import Decimal

User = get_user_model()


class ExpandableRowTestCase(TestCase):
    """Test expandable row functionality for order items"""

    def setUp(self):
        """Set up test data"""
        # Create test user with staff permissions
        self.staff_user = User.objects.create_user(
            email='staff@test.com',
            password='test123',
            is_staff=True
        )
        
        # Create test customer
        self.customer = Customer.objects.create(
            company_name="Test Customer Ltd",
            primary_email="customer@test.com",
            status="active"
        )
        
        # Create currency
        self.currency = Currency.objects.create(
            code='RON',
            symbol='RON'
        )
        
        # Create test product
        self.product = Product.objects.create(
            name="Test Product",
            description="Test product description",
            product_type="hosting",
            is_active=True
        )
        
        # Create product price
        self.price = ProductPrice.objects.create(
            product=self.product,
            currency=self.currency,
            amount_cents=1999,  # 19.99 RON
            setup_cents=500,    # 5.00 RON setup
            billing_period='monthly'
        )
        
        # Create test order
        self.order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            order_number="TEST-001",
            status="draft",
            subtotal_cents=0,
            tax_cents=0,
            total_cents=0
        )

    def test_order_edit_page_shows_expandable_controls(self):
        """Test that the order edit page shows expandable row controls"""
        self.client.force_login(self.staff_user)
        
        # Create an order item
        order_item = OrderItem.objects.create(
            order=self.order,
            product=self.product,
            quantity=1,
            unit_price_cents=1999,
            setup_cents=500,
            billing_period='monthly'
        )
        
        # Get the order edit page
        url = reverse('orders:order_edit', kwargs={'pk': self.order.id})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, 200)
        
        # Check that expandable edit controls are present
        content = response.content.decode()
        
        # Should contain the expandable edit buttons
        self.assertIn('toggleExpandableEdit', content)
        self.assertIn('edit-btn-', content)
        
        # Should contain expandable row structure
        self.assertIn('edit-row-', content)
        self.assertIn('inline-edit-form-', content)

    def test_order_detail_page_readonly_mode(self):
        """Test that the order detail page is read-only without edit controls"""
        self.client.force_login(self.staff_user)
        
        # Create an order item
        order_item = OrderItem.objects.create(
            order=self.order,
            product=self.product,
            quantity=1,
            unit_price_cents=1999,
            setup_cents=500,
            billing_period='monthly'
        )
        
        # Get the order detail page (read-only)
        url = reverse('orders:order_detail', kwargs={'pk': self.order.id})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, 200)
        
        content = response.content.decode()
        
        # Should NOT contain expandable edit controls in read-only view
        self.assertNotIn('toggleExpandableEdit', content)
        
        # Should show "Edit Order" link instead
        self.assertIn('Edit Order', content)

    def test_add_item_expandable_form_in_edit_mode(self):
        """Test that add item form is expandable in edit mode"""
        self.client.force_login(self.staff_user)
        
        # Get the order edit page
        url = reverse('orders:order_edit', kwargs={'pk': self.order.id})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, 200)
        
        content = response.content.decode()
        
        # Should contain add item expandable controls
        self.assertIn('toggleAddItemForm', content)
        self.assertIn('add-item-form-section', content)

    def test_order_item_edit_returns_inline_form_for_htmx(self):
        """Test that HTMX requests to edit order item return inline form"""
        self.client.force_login(self.staff_user)
        
        # Create an order item
        order_item = OrderItem.objects.create(
            order=self.order,
            product=self.product,
            quantity=1,
            unit_price_cents=1999,
            setup_cents=500,
            billing_period='monthly'
        )
        
        # Make HTMX request to edit the item
        url = reverse('orders:order_item_edit', kwargs={
            'pk': self.order.id,
            'item_pk': order_item.id
        })
        
        response = self.client.get(url, headers={
            'HX-Request': 'true',
            'X-Requested-With': 'XMLHttpRequest'
        })
        
        self.assertEqual(response.status_code, 200)
        
        content = response.content.decode()
        
        # Should return the inline form template
        self.assertIn('id_product_inline', content)
        self.assertIn('id_quantity_inline', content)
        self.assertIn('Price Preview', content)

    def test_order_item_create_returns_inline_form_for_htmx(self):
        """Test that HTMX requests to create order item return inline form"""
        self.client.force_login(self.staff_user)
        
        # Make HTMX request to create new item
        url = reverse('orders:order_item_create', kwargs={
            'pk': self.order.id
        })
        
        response = self.client.get(url, headers={
            'HX-Request': 'true',
            'X-Requested-With': 'XMLHttpRequest'
        })
        
        self.assertEqual(response.status_code, 200)
        
        content = response.content.decode()
        
        # Should return the inline form template
        self.assertIn('id_product_inline', content)
        self.assertIn('id_quantity_inline', content)
        self.assertIn('Price Preview', content)

    def test_no_add_item_in_readonly_view(self):
        """Test that read-only view doesn't show Add Item controls"""
        self.client.force_login(self.staff_user)
        
        # Get the order detail page (read-only)
        url = reverse('orders:order_detail', kwargs={'pk': self.order.id})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, 200)
        
        content = response.content.decode()
        
        # Should NOT contain Add Item buttons in read-only view
        self.assertNotIn('Add Item', content)
        self.assertNotIn('Add First Item', content)

    def test_expandable_row_accessibility_features(self):
        """Test that expandable rows include accessibility features"""
        self.client.force_login(self.staff_user)
        
        # Create an order item
        order_item = OrderItem.objects.create(
            order=self.order,
            product=self.product,
            quantity=1,
            unit_price_cents=1999,
            setup_cents=500,
            billing_period='monthly'
        )
        
        # Get the order edit page
        url = reverse('orders:order_edit', kwargs={'pk': self.order.id})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, 200)
        
        content = response.content.decode()
        
        # Check for proper ARIA labels and titles
        self.assertIn('title=', content)  # Button titles for screen readers
        self.assertIn('Edit item inline', content)  # Descriptive text
        self.assertIn('Delete item', content)  # Descriptive text

    def test_javascript_functionality_included(self):
        """Test that required JavaScript functions are included"""
        self.client.force_login(self.staff_user)
        
        # Get the order edit page
        url = reverse('orders:order_edit', kwargs={'pk': self.order.id})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, 200)
        
        content = response.content.decode()
        
        # Check for required JavaScript functions
        self.assertIn('toggleExpandableEdit', content)
        self.assertIn('cancelExpandableEdit', content)
        self.assertIn('toggleAddItemForm', content)
        self.assertIn('cancelAddItemForm', content)
        self.assertIn('deleteOrderItem', content)
        self.assertIn('refreshOrderItemsSection', content)
        
        # Check for keyboard shortcut support
        self.assertIn('keydown', content)
        self.assertIn('Escape', content)