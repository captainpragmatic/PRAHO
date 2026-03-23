"""
Tests for Order FSM state rename (Phase A of Order-Proforma-Invoice lifecycle).

Validates:
- New state names (awaiting_payment, paid, in_review, provisioning)
- New transitions (mark_paid, flag_for_review, approve_review, reject_review)
- Removed transitions (refund_order, partial_refund, complete_refund)
- Updated properties (is_paid, can_be_cancelled)
- EDITABLE_FIELDS_BY_STATUS includes new states
"""

from django.test import TestCase
from django_fsm import TransitionNotAllowed

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from tests.helpers.fsm_helpers import force_status


class OrderStateRenameTestCase(TestCase):
    """Base test case with common order setup."""

    def setUp(self):
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="Test Company SRL",
            customer_type="company",
            status="active",
            primary_email="test@example.ro",
        )
        self.product = Product.objects.create(
            name="Shared Hosting",
            slug="shared-hosting",
            product_type="shared_hosting",
            is_active=True,
        )

    def _create_order(self, **kwargs):
        defaults = {
            "customer": self.customer,
            "currency": self.currency,
            "customer_email": self.customer.primary_email,
            "customer_name": self.customer.name,
            "subtotal_cents": 10000,
            "tax_cents": 2100,
            "total_cents": 12100,
            "billing_address": {},
        }
        defaults.update(kwargs)
        return Order.objects.create(**defaults)

    def _create_order_with_item(self, **kwargs):
        order = self._create_order(**kwargs)
        OrderItem.objects.create(
            order=order,
            product=self.product,
            product_name=self.product.name,
            product_type=self.product.product_type,
            quantity=1,
            unit_price_cents=10000,
            tax_rate="0.2100",
            tax_cents=2100,
            line_total_cents=12100,
        )
        return order


class TestNewStatusChoices(OrderStateRenameTestCase):
    """Verify new STATUS_CHOICES values exist and old ones are gone."""

    def test_awaiting_payment_is_valid_status(self):
        """awaiting_payment replaces old 'pending' status."""
        valid_statuses = [choice[0] for choice in Order.STATUS_CHOICES]
        self.assertIn("awaiting_payment", valid_statuses)

    def test_paid_is_valid_status(self):
        """paid replaces old 'confirmed' status."""
        valid_statuses = [choice[0] for choice in Order.STATUS_CHOICES]
        self.assertIn("paid", valid_statuses)

    def test_in_review_is_valid_status(self):
        """in_review is a new state for high-value order review gate."""
        valid_statuses = [choice[0] for choice in Order.STATUS_CHOICES]
        self.assertIn("in_review", valid_statuses)

    def test_provisioning_is_valid_status(self):
        """provisioning replaces old 'processing' status."""
        valid_statuses = [choice[0] for choice in Order.STATUS_CHOICES]
        self.assertIn("provisioning", valid_statuses)

    def test_pending_removed_from_choices(self):
        """Old 'pending' status should not exist in choices."""
        valid_statuses = [choice[0] for choice in Order.STATUS_CHOICES]
        self.assertNotIn("pending", valid_statuses)

    def test_confirmed_removed_from_choices(self):
        """Old 'confirmed' status should not exist in choices."""
        valid_statuses = [choice[0] for choice in Order.STATUS_CHOICES]
        self.assertNotIn("confirmed", valid_statuses)

    def test_processing_removed_from_choices(self):
        """Old 'processing' status should not exist in choices."""
        valid_statuses = [choice[0] for choice in Order.STATUS_CHOICES]
        self.assertNotIn("processing", valid_statuses)

    def test_refunded_removed_from_choices(self):
        """Refunds handled at Invoice/Payment level, not Order."""
        valid_statuses = [choice[0] for choice in Order.STATUS_CHOICES]
        self.assertNotIn("refunded", valid_statuses)

    def test_partially_refunded_removed_from_choices(self):
        """Partial refunds handled at Invoice/Payment level, not Order."""
        valid_statuses = [choice[0] for choice in Order.STATUS_CHOICES]
        self.assertNotIn("partially_refunded", valid_statuses)


class TestNewFSMTransitions(OrderStateRenameTestCase):
    """Verify new FSM transition methods exist and work correctly."""

    def test_submit_draft_to_awaiting_payment(self):
        """submit() transitions draft → awaiting_payment (was draft → pending)."""
        order = self._create_order_with_item()
        self.assertEqual(order.status, "draft")
        order.submit()
        order.save()
        self.assertEqual(order.status, "awaiting_payment")

    def test_mark_paid_awaiting_payment_to_paid(self):
        """mark_paid() transitions awaiting_payment → paid (new transition)."""
        order = self._create_order_with_item()
        force_status(order, "awaiting_payment")
        order.mark_paid()
        order.save()
        self.assertEqual(order.status, "paid")

    def test_start_provisioning_paid_to_provisioning(self):
        """start_provisioning() transitions paid → provisioning."""
        order = self._create_order_with_item()
        force_status(order, "paid")
        order.start_provisioning()
        order.save()
        self.assertEqual(order.status, "provisioning")

    def test_flag_for_review_paid_to_in_review(self):
        """flag_for_review() transitions paid → in_review (new transition for review gate)."""
        order = self._create_order_with_item()
        force_status(order, "paid")
        order.flag_for_review()
        order.save()
        self.assertEqual(order.status, "in_review")

    def test_approve_review_in_review_to_provisioning(self):
        """approve_review() transitions in_review → provisioning (admin approves)."""
        order = self._create_order_with_item()
        force_status(order, "in_review")
        order.approve_review()
        order.save()
        self.assertEqual(order.status, "provisioning")

    def test_reject_review_in_review_to_cancelled(self):
        """reject_review() transitions in_review → cancelled (admin rejects)."""
        order = self._create_order_with_item()
        force_status(order, "in_review")
        order.reject_review()
        order.save()
        self.assertEqual(order.status, "cancelled")

    def test_complete_provisioning_to_completed(self):
        """complete() transitions provisioning → completed."""
        order = self._create_order_with_item()
        force_status(order, "provisioning")
        order.complete()
        order.save()
        self.assertEqual(order.status, "completed")

    def test_cancel_from_awaiting_payment(self):
        """cancel() works from awaiting_payment."""
        order = self._create_order_with_item()
        force_status(order, "awaiting_payment")
        order.cancel()
        order.save()
        self.assertEqual(order.status, "cancelled")

    def test_cancel_from_paid(self):
        """cancel() works from paid (pre-delivery cancel)."""
        order = self._create_order_with_item()
        force_status(order, "paid")
        order.cancel()
        order.save()
        self.assertEqual(order.status, "cancelled")

    def test_cancel_from_in_review(self):
        """cancel() works from in_review."""
        order = self._create_order_with_item()
        force_status(order, "in_review")
        order.cancel()
        order.save()
        self.assertEqual(order.status, "cancelled")

    def test_cancel_from_provisioning(self):
        """cancel() works from provisioning."""
        order = self._create_order_with_item()
        force_status(order, "provisioning")
        order.cancel()
        order.save()
        self.assertEqual(order.status, "cancelled")

    def test_fail_from_awaiting_payment(self):
        """fail() works from awaiting_payment."""
        order = self._create_order_with_item()
        force_status(order, "awaiting_payment")
        order.fail()
        order.save()
        self.assertEqual(order.status, "failed")

    def test_fail_from_provisioning(self):
        """fail() works from provisioning."""
        order = self._create_order_with_item()
        force_status(order, "provisioning")
        order.fail()
        order.save()
        self.assertEqual(order.status, "failed")

    def test_retry_failed_to_awaiting_payment(self):
        """retry() transitions failed → awaiting_payment (was failed → pending)."""
        order = self._create_order_with_item()
        force_status(order, "failed")
        order.retry()
        order.save()
        self.assertEqual(order.status, "awaiting_payment")


class TestRemovedTransitions(OrderStateRenameTestCase):
    """Verify removed FSM transitions no longer exist."""

    def test_refund_order_removed(self):
        """refund_order() should not exist — refunds are Invoice/Payment concern."""
        order = self._create_order()
        self.assertFalse(hasattr(order, "refund_order"))

    def test_partial_refund_removed(self):
        """partial_refund() should not exist — refunds are Invoice/Payment concern."""
        order = self._create_order()
        self.assertFalse(hasattr(order, "partial_refund"))

    def test_complete_refund_removed(self):
        """complete_refund() should not exist — refunds are Invoice/Payment concern."""
        order = self._create_order()
        self.assertFalse(hasattr(order, "complete_refund"))

    def test_confirm_removed(self):
        """confirm() replaced by mark_paid() — different semantics."""
        order = self._create_order()
        self.assertFalse(hasattr(order, "confirm"))

    def test_start_processing_removed(self):
        """start_processing() replaced by start_provisioning() from paid state."""
        order = self._create_order()
        self.assertFalse(hasattr(order, "start_processing"))


class TestInvalidTransitions(OrderStateRenameTestCase):
    """Verify invalid FSM transitions are blocked."""

    def test_cannot_mark_paid_from_draft(self):
        """mark_paid() only from awaiting_payment, not draft."""
        order = self._create_order()
        with self.assertRaises(TransitionNotAllowed):
            order.mark_paid()

    def test_cannot_flag_for_review_from_awaiting_payment(self):
        """flag_for_review() only from paid, not awaiting_payment."""
        order = self._create_order_with_item()
        force_status(order, "awaiting_payment")
        with self.assertRaises(TransitionNotAllowed):
            order.flag_for_review()

    def test_cannot_approve_review_from_paid(self):
        """approve_review() only from in_review, not paid."""
        order = self._create_order_with_item()
        force_status(order, "paid")
        with self.assertRaises(TransitionNotAllowed):
            order.approve_review()

    def test_cannot_complete_from_paid(self):
        """complete() only from provisioning, not paid."""
        order = self._create_order_with_item()
        force_status(order, "paid")
        with self.assertRaises(TransitionNotAllowed):
            order.complete()


class TestUpdatedProperties(OrderStateRenameTestCase):
    """Verify updated model properties use new state names."""

    def test_is_paid_includes_paid_state(self):
        """is_paid returns True for paid status."""
        order = self._create_order()
        force_status(order, "paid")
        self.assertTrue(order.is_paid)

    def test_is_paid_includes_provisioning_state(self):
        """is_paid returns True for provisioning status."""
        order = self._create_order()
        force_status(order, "provisioning")
        self.assertTrue(order.is_paid)

    def test_is_paid_includes_completed_state(self):
        """is_paid returns True for completed status."""
        order = self._create_order()
        force_status(order, "completed")
        self.assertTrue(order.is_paid)

    def test_is_paid_false_for_awaiting_payment(self):
        """is_paid returns False for awaiting_payment (not yet paid)."""
        order = self._create_order()
        force_status(order, "awaiting_payment")
        self.assertFalse(order.is_paid)

    def test_can_be_cancelled_includes_awaiting_payment(self):
        """can_be_cancelled includes awaiting_payment."""
        order = self._create_order()
        force_status(order, "awaiting_payment")
        self.assertTrue(order.can_be_cancelled)

    def test_can_be_cancelled_includes_paid(self):
        """can_be_cancelled includes paid (pre-delivery cancel)."""
        order = self._create_order()
        force_status(order, "paid")
        self.assertTrue(order.can_be_cancelled)

    def test_can_be_cancelled_includes_in_review(self):
        """can_be_cancelled includes in_review."""
        order = self._create_order()
        force_status(order, "in_review")
        self.assertTrue(order.can_be_cancelled)

    def test_can_be_cancelled_false_for_completed(self):
        """can_be_cancelled returns False for completed orders."""
        order = self._create_order()
        force_status(order, "completed")
        self.assertFalse(order.can_be_cancelled)


class TestEditableFieldsByStatus(OrderStateRenameTestCase):
    """Verify EDITABLE_FIELDS_BY_STATUS includes all new states."""

    def test_awaiting_payment_editable_fields(self):
        """CODEX-6 fix: awaiting_payment allows contact/delivery edits, NOT financial fields."""
        fields = Order.EDITABLE_FIELDS_BY_STATUS["awaiting_payment"]
        self.assertIn("notes", fields)
        self.assertIn("billing_address", fields)
        self.assertIn("customer_email", fields)
        # Financial fields must NOT be editable post-submit
        self.assertNotIn("total_cents", fields)
        self.assertNotIn("subtotal_cents", fields)
        self.assertNotIn("payment_intent_id", fields)
        self.assertNotEqual(fields, ["*"])

    def test_paid_editable_fields(self):
        """paid allows limited editing (notes, delivery)."""
        self.assertIn("paid", Order.EDITABLE_FIELDS_BY_STATUS)
        self.assertIn("notes", Order.EDITABLE_FIELDS_BY_STATUS["paid"])

    def test_in_review_editable_fields(self):
        """in_review allows limited editing (notes only)."""
        self.assertIn("in_review", Order.EDITABLE_FIELDS_BY_STATUS)
        self.assertIn("notes", Order.EDITABLE_FIELDS_BY_STATUS["in_review"])

    def test_provisioning_editable_fields(self):
        """provisioning allows limited editing (notes, delivery)."""
        self.assertIn("provisioning", Order.EDITABLE_FIELDS_BY_STATUS)
        self.assertIn("notes", Order.EDITABLE_FIELDS_BY_STATUS["provisioning"])

    def test_old_pending_removed(self):
        """Old 'pending' key should not exist."""
        self.assertNotIn("pending", Order.EDITABLE_FIELDS_BY_STATUS)

    def test_old_confirmed_removed(self):
        """Old 'confirmed' key should not exist."""
        self.assertNotIn("confirmed", Order.EDITABLE_FIELDS_BY_STATUS)

    def test_old_processing_removed(self):
        """Old 'processing' key should not exist."""
        self.assertNotIn("processing", Order.EDITABLE_FIELDS_BY_STATUS)

    def test_old_refunded_removed(self):
        """Old 'refunded' key should not exist."""
        self.assertNotIn("refunded", Order.EDITABLE_FIELDS_BY_STATUS)

    def test_old_partially_refunded_removed(self):
        """Old 'partially_refunded' key should not exist."""
        self.assertNotIn("partially_refunded", Order.EDITABLE_FIELDS_BY_STATUS)
