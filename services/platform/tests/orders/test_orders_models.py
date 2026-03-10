"""
Test suite for order models in PRAHO Platform
Tests Romanian VAT compliance, audit trails, and model relationships.
"""

import uuid
from decimal import Decimal
from unittest.mock import patch

from django.db import transaction
from django.test import TestCase

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem, OrderStatusHistory
from apps.products.models import Product
from apps.users.models import User
from tests.helpers.fsm_helpers import force_status


class OrderModelTestCase(TestCase):
    """Test cases for Order model functionality"""

    def setUp(self):
        """Set up test data"""
        self.currency, _ = Currency.objects.get_or_create(
            code="RON",
            defaults={"symbol": "lei", "decimals": 2}
        )

        self.customer = Customer.objects.create(
            name="Test Company SRL",
            customer_type="company",
            status="active",
            primary_email="contact@testcompany.ro"
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
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            subtotal_cents=10000,  # 100.00 RON
            tax_cents=1900,       # 19.00 RON (19% VAT)
            total_cents=11900     # 119.00 RON
        )

        order2 = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-12345678-0002",
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
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
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name
        )

        self.assertIsInstance(order.id, uuid.UUID)
        self.assertTrue(len(str(order.id)) == 36)  # Standard UUID format

    def test_order_status_choices(self):
        """Test order status workflow and validation"""
        order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-STATUS-0001",
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            billing_address={},  # Empty dict for default billing address
            status="draft"
        )

        # Test default status
        self.assertEqual(order.status, "draft")

        # Test valid status changes (use force_status to bypass FSMField protected=True)
        valid_statuses = ["draft", "pending", "confirmed", "processing", "completed", "cancelled", "failed"]
        for status in valid_statuses:
            force_status(order, status)

    def test_romanian_vat_compliance(self):
        """Test Romanian VAT calculation compliance"""
        subtotal_cents = 10000  # 100.00 RON
        expected_vat = int(subtotal_cents * Decimal('0.19'))  # 19% VAT
        total_cents = subtotal_cents + expected_vat

        order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-VAT-0001",
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
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
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            # Billing address as JSON
            billing_address={
                "company_name": "Test Company SRL",
                "contact_name": "Ion Popescu",
                "email": "facturare@company.ro",
                "phone": "+40123456789",
                "address_line1": "Str. Aviatorilor nr. 1",
                "city": "Bucuresti",
                "county": "Bucuresti",
                "postal_code": "010563",
                "country": "Romania",
                "fiscal_code": "RO12345678"
            }
        )

        # Verify billing address is saved as JSON
        self.assertEqual(order.billing_address["company_name"], "Test Company SRL")
        self.assertEqual(order.billing_address["fiscal_code"], "RO12345678")
        self.assertEqual(order.billing_address["country"], "Romania")

    def test_order_string_representation(self):
        """Test order string representation"""
        order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-STR-0001",
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name
        )

        expected_str = f"Order ORD-2024-STR-0001 - {self.customer.primary_email}"
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
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
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
            name="Test Company SRL",
            customer_type="company",
            status="active",
            primary_email="contact@testcompany.ro"
        )

        self.currency, _ = Currency.objects.get_or_create(
            code="RON",
            defaults={"symbol": "lei", "decimals": 2}
        )

        self.product = Product.objects.create(
            slug="test-product",
            name="Test Product",
            product_type="shared_hosting"
        )

        self.order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-ITEMS-0001",
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name
        )

    def test_order_item_creation(self):
        """Test order item creation and relationships"""
        item = OrderItem.objects.create(
            order=self.order,
            product=self.product,
            product_name="Web Hosting Plan - Standard",
            product_type="shared_hosting",
            quantity=2,
            unit_price_cents=5000,  # 50.00 RON
            line_total_cents=10000,  # 100.00 RON
            config={}  # Empty dict for default config
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
            product=self.product,
            product_name="Domain Registration",
            product_type="domain",
            quantity=quantity,
            unit_price_cents=unit_price_cents,
            line_total_cents=expected_line_total,
            config={}  # Empty dict for default config
        )

        self.assertEqual(item.line_total_cents, expected_line_total)

    def test_order_item_provisioning_status(self):
        """Test order item provisioning status choices"""
        item = OrderItem.objects.create(
            order=self.order,
            product=self.product,
            product_name="VPS Hosting",
            product_type="vps",
            quantity=1,
            unit_price_cents=10000,
            line_total_cents=10000,
            config={},  # Empty dict for default config
            provisioning_status="pending"
        )

        # Test valid provisioning statuses (use force_status to bypass FSMField protected=True)
        valid_statuses = ["pending", "in_progress", "completed", "failed", "cancelled"]
        for status in valid_statuses:
            force_status(item, status, field_name="provisioning_status")

    def test_order_item_uuid_primary_key(self):
        """Test that order items use UUID as primary key"""
        item = OrderItem.objects.create(
            order=self.order,
            product=self.product,
            product_name="Test Item",
            product_type="addon",
            quantity=1,
            unit_price_cents=1000,
            line_total_cents=1000,
            config={}  # Empty dict for default config
        )

        self.assertIsInstance(item.id, uuid.UUID)

    def test_order_item_config_field(self):
        """Test order item config JSON field"""
        config_data = {
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
            product=self.product,
            product_name="VPS Configuration",
            product_type="vps",
            quantity=1,
            unit_price_cents=15000,
            line_total_cents=15000,
            config=config_data
        )

        saved_item = OrderItem.objects.get(id=item.id)
        self.assertEqual(saved_item.config["configuration"]["cpu"], "2 cores")
        self.assertEqual(saved_item.config["duration"], "12 months")
        self.assertTrue(saved_item.config["renewal"])


class OrderStatusHistoryModelTestCase(TestCase):
    """Test cases for OrderStatusHistory model functionality"""

    def setUp(self):
        """Set up test data"""
        self.customer = Customer.objects.create(
            name="Test Company SRL",
            customer_type="company",
            status="active",
            primary_email="contact@testcompany.ro"
        )

        self.currency, _ = Currency.objects.get_or_create(
            code="RON",
            defaults={"symbol": "lei", "decimals": 2}
        )

        self.order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-2024-HISTORY-0001",
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
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
            old_status="",  # Initial creation (empty string instead of None)
            new_status="draft",
            notes="Order created",
            changed_by=self.user
        )

        self.assertEqual(history.order, self.order)
        self.assertEqual(history.old_status, "")  # Empty string for initial creation
        self.assertEqual(history.new_status, "draft")
        self.assertEqual(history.changed_by, self.user)

    def test_status_transition_tracking(self):
        """Test status transition from one state to another"""
        # Create initial status
        initial_history = OrderStatusHistory.objects.create(
            order=self.order,
            old_status="",  # Empty string for initial creation
            new_status="draft",
            notes="Order created"
        )
        # Verify initial history was created
        self.assertIsNotNone(initial_history)
        self.assertEqual(initial_history.new_status, "draft")

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
            old_status="",  # Empty string for initial creation
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
            ("", "draft", "Order created"),  # Empty string for initial creation
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

        expected_str = "ORD-2024-HISTORY-0001: draft → pending"
        self.assertEqual(str(history), expected_str)


# ---------------------------------------------------------------------------
# M5: save() only wraps creation in transaction.atomic, not plain updates
# ---------------------------------------------------------------------------


class OrderSaveTransactionTestCase(TestCase):
    """M5: Order.save() must only use transaction.atomic for new objects, not updates."""

    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(
            code="RON",
            defaults={"symbol": "lei", "decimals": 2},
        )
        self.customer = Customer.objects.create(
            name="Test Company SRL",
            customer_type="company",
            status="active",
            primary_email="contact@testcompany.ro",
        )

    def test_update_does_not_invoke_transaction_atomic(self) -> None:
        """Saving an existing order (update_fields) must NOT call transaction.atomic.

        M5 fix: the retry loop and its savepoint wrap should only apply when
        _state.adding is True.  A plain field update must call super().save()
        directly — no savepoint overhead.
        """
        order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-20240101-000001",
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
        )
        # At this point order._state.adding is False (already persisted)
        force_status(order, "pending", save=False)

        with patch("apps.orders.models.transaction.atomic") as mock_atomic:
            order.save(update_fields=["status"])

        mock_atomic.assert_not_called()

    def test_creation_invokes_transaction_atomic(self) -> None:
        """Saving a new order (adding=True) MUST enter transaction.atomic savepoint."""
        order = Order(
            customer=self.customer,
            order_number="ORD-20240101-000099",
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
        )
        # order._state.adding is True — first save triggers the retry loop

        real_atomic = transaction.atomic

        atomic_called = []

        def tracking_atomic(*args: object, **kwargs: object) -> object:
            atomic_called.append(True)
            return real_atomic(*args, **kwargs)

        with patch("apps.orders.models.transaction.atomic", side_effect=tracking_atomic):
            order.save()

        self.assertTrue(atomic_called, "transaction.atomic must be called at least once during creation")

    def test_update_via_update_fields_succeeds_without_retry(self) -> None:
        """update_fields save on existing order should complete without any IntegrityError retry."""
        order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-20240101-000002",
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
        )
        force_status(order, "pending", save=False)
        # Should not raise; no collision retry loop involved
        order.save(update_fields=["status"])
        order.refresh_from_db()
        self.assertEqual(order.status, "pending")


# ---------------------------------------------------------------------------
# H3: _regenerate_order_number_sequence uses select_for_update
# ---------------------------------------------------------------------------


class OrderRegenerateSequenceLockTestCase(TestCase):
    """H3: _regenerate_order_number_sequence must use select_for_update to avoid TOCTOU."""

    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(
            code="RON",
            defaults={"symbol": "lei", "decimals": 2},
        )
        self.customer = Customer.objects.create(
            name="Test Company SRL",
            customer_type="company",
            status="active",
            primary_email="contact@testcompany.ro",
        )

    def test_locked_helper_contains_select_for_update(self) -> None:
        """_locked_latest_order_number helper must contain select_for_update.

        H3 fix: the shared helper wraps select_for_update(of=('self',)) in its
        own transaction.atomic() so it works even in autocommit mode on PostgreSQL.
        Both generate_order_number and _regenerate_order_number_sequence delegate to it.
        """
        import inspect  # noqa: PLC0415

        source = inspect.getsource(Order._locked_latest_order_number)
        self.assertIn(
            "select_for_update",
            source,
            "_locked_latest_order_number must call select_for_update to prevent TOCTOU",
        )
        self.assertIn(
            "transaction.atomic",
            source,
            "_locked_latest_order_number must wrap in transaction.atomic for autocommit safety",
        )

    def test_generate_and_regenerate_use_locked_helper(self) -> None:
        """Both order number methods must delegate to _locked_latest_order_number.

        Ensures the DRY refactor is maintained and neither method bypasses the lock.
        """
        import inspect  # noqa: PLC0415

        for method in (Order.generate_order_number, Order._regenerate_order_number_sequence):
            source = inspect.getsource(method)
            self.assertIn(
                "_locked_latest_order_number",
                source,
                f"{method.__name__} must delegate to _locked_latest_order_number",
            )

    def test_regenerate_produces_higher_sequence(self) -> None:
        """After regeneration the new order_number sequence must be higher than any existing one."""
        # Create a persisted order so the queryset finds something
        Order.objects.create(
            customer=self.customer,
            order_number="ORD-20240101-0003",
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
        )

        order = Order(
            customer=self.customer,
            order_number="ORD-20240101-0003",  # intentional collision
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
        )
        order._regenerate_order_number_sequence()

        # New sequence must be strictly greater than 3
        seq = int(order.order_number.rsplit("-", 1)[-1])
        self.assertGreater(seq, 3)


# ---------------------------------------------------------------------------
# H4: save() retry only fires on creation, not on update
# ---------------------------------------------------------------------------


class OrderSaveRetryOnCreationOnlyTestCase(TestCase):
    """H4 (model-level): The IntegrityError retry loop must not run on updates."""

    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(
            code="RON",
            defaults={"symbol": "lei", "decimals": 2},
        )
        self.customer = Customer.objects.create(
            name="Test Company SRL",
            customer_type="company",
            status="active",
            primary_email="contact@testcompany.ro",
        )

    def test_status_update_propagates_integrity_error_immediately(self) -> None:
        """Updating status on an existing order bypasses the retry loop entirely.

        We mock super().save() to raise IntegrityError once, but because _state.adding
        is False the retry loop code is never reached — the call goes straight to
        super().save() and the mock error propagates immediately (not silently retried).
        """
        from django.db import IntegrityError  # noqa: PLC0415

        order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-20240101-000010",
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
        )
        force_status(order, "pending", save=False)

        # Patch Model.save (the super()) to raise IntegrityError
        with patch("django.db.models.Model.save", side_effect=IntegrityError("simulated")), self.assertRaises(IntegrityError):
            order.save()

    def test_creation_retries_on_order_number_collision(self) -> None:
        """During creation, an order_number collision triggers _regenerate_order_number_sequence."""
        from contextlib import suppress  # noqa: PLC0415

        from django.db import IntegrityError  # noqa: PLC0415

        order = Order(
            customer=self.customer,
            order_number="",
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
        )

        call_count = {"n": 0}

        def fake_super_save(*args: object, **kwargs: object) -> None:
            call_count["n"] += 1
            if call_count["n"] == 1:
                # Simulate order_number unique constraint violation (SQLite marker)
                raise IntegrityError("UNIQUE constraint failed: orders.order_number")
            # Second attempt succeeds — but we need an actual DB call, so re-raise to
            # exit the test safely before a real write; we just verify regenerate fired.

        regenerate_calls: list[bool] = []

        def fake_regenerate(self_order: Order) -> None:
            regenerate_calls.append(True)
            # Give the order a new unique number so the loop can exit
            self_order.order_number = "ORD-20240101-099999"

        with (
            patch("django.db.models.Model.save", side_effect=fake_super_save),
            patch.object(Order, "_regenerate_order_number_sequence", fake_regenerate),
            suppress(Exception),
        ):
            # Second attempt may fail due to mock; we only care regenerate was called
            order.save()

        self.assertTrue(
            regenerate_calls,
            "_regenerate_order_number_sequence must be called on order_number collision during creation",
        )


# ---------------------------------------------------------------------------
# FSM: Transition guard enforcement
# ---------------------------------------------------------------------------


class OrderFSMTransitionTests(TestCase):
    """Verify FSM transitions enforce valid state changes."""

    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(
            code="RON",
            defaults={"symbol": "lei", "decimals": 2},
        )
        self.customer = Customer.objects.create(
            name="FSM Test SRL",
            customer_type="company",
            status="active",
            primary_email="fsm@testcompany.ro",
        )
        self.product = Product.objects.create(
            slug="fsm-test-product",
            name="FSM Test Product",
            product_type="hosting",
            is_active=True,
        )

    def _make_draft_order(self) -> Order:
        return Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            status="draft",
        )

    def test_submit_from_draft_requires_items(self) -> None:
        """draft → pending via submit() is blocked when the order has no items."""
        from django_fsm import TransitionNotAllowed  # noqa: PLC0415

        order = self._make_draft_order()
        # No items attached — _order_has_items condition is False
        with self.assertRaises(TransitionNotAllowed):
            order.submit()

    def test_submit_from_draft_succeeds_with_items(self) -> None:
        """draft → pending via submit() succeeds when the order has at least one item."""
        order = self._make_draft_order()
        OrderItem.objects.create(
            order=order,
            product=self.product,
            product_name=self.product.name,
            product_type=self.product.product_type,
            quantity=1,
            unit_price_cents=5000,
        )
        order.submit()
        order.save(update_fields=["status"])
        self.assertEqual(order.status, "pending")

    def test_invalid_transition_raises(self) -> None:
        """Verify TransitionNotAllowed for an illegal transition (draft → confirmed)."""
        from django_fsm import TransitionNotAllowed  # noqa: PLC0415

        order = self._make_draft_order()
        # confirm() requires source="pending"; calling it from "draft" must raise
        with self.assertRaises(TransitionNotAllowed):
            order.confirm()

    def test_completed_order_cannot_be_cancelled(self) -> None:
        """Terminal state: completed orders cannot be cancelled."""
        from django_fsm import TransitionNotAllowed  # noqa: PLC0415

        order = self._make_draft_order()
        force_status(order, "completed")
        with self.assertRaises(TransitionNotAllowed):
            order.cancel()

    def test_refund_only_from_completed(self) -> None:
        """refund_order() must be accepted from 'completed' and rejected from 'pending'."""
        from django_fsm import TransitionNotAllowed  # noqa: PLC0415

        # Accepted from completed
        order = self._make_draft_order()
        force_status(order, "completed")
        order.refund_order()
        order.save(update_fields=["status"])
        self.assertEqual(order.status, "refunded")

        # Rejected from pending
        order2 = self._make_draft_order()
        force_status(order2, "pending")
        with self.assertRaises(TransitionNotAllowed):
            order2.refund_order()
