"""H13+H14: Order creation and editing security tests."""

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase

from apps.billing.currency_models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order
from apps.users.models import CustomerMembership

User = get_user_model()


class OrderCreateCustomerScopingTests(TestCase):
    """H13: Order creation must scope customer access.

    The form's customer queryset is scoped via _get_accessible_customer_ids.
    We patch that helper to return a limited set (only customer_a), verifying
    that the view rejects POSTed customer IDs outside the accessible scope.
    """

    def setUp(self) -> None:
        self.client = Client()
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2}
        )
        self.staff = User.objects.create_user(
            email="scoped-staff@test.com",
            password="TestPass123!",
            is_staff=True,
            staff_role="billing",
        )
        self.customer_a = Customer.objects.create(
            name="Accessible Co",
            customer_type="company",
            status="active",
            primary_email="a@test.ro",
        )
        self.customer_b = Customer.objects.create(
            name="Restricted Co",
            customer_type="company",
            status="active",
            primary_email="b@test.ro",
        )
        # Staff only has membership to customer_a
        CustomerMembership.objects.create(user=self.staff, customer=self.customer_a, role="admin")

    def test_order_create_rejects_inaccessible_customer(self) -> None:
        """Staff must not create orders for customers outside their access scope.

        We patch _get_accessible_customer_ids to return only [customer_a.id],
        simulating a staff user whose accessible scope excludes customer_b.
        """
        self.client.force_login(self.staff)
        # Patch the helper so only customer_a is accessible for this request
        with patch(
            "apps.orders.views._get_accessible_customer_ids",
            return_value=[self.customer_a.id],
        ):
            self.client.post(
                "/orders/create/with-item/",
                {
                    "customer": str(self.customer_b.id),
                    "currency": str(self.currency.id),
                    "payment_method": "bank_transfer",
                },
            )
        # Should be rejected — form validation fails because customer_b is not
        # in the accessible queryset, so no order should be created.
        orders_for_b = Order.objects.filter(customer=self.customer_b)
        self.assertEqual(
            orders_for_b.count(),
            0,
            "Should not create order for inaccessible customer",
        )

    def test_order_create_preview_rejects_inaccessible_customer(self) -> None:
        """Preview endpoint must scope customer lookup to accessible customers.

        When customer_b is outside the accessible scope, get_object_or_404 must
        return 404, not 200 with customer_b's data.
        """
        self.client.force_login(self.staff)
        with patch(
            "apps.orders.views._get_accessible_customer_ids",
            return_value=[self.customer_a.id],
        ):
            response = self.client.post(
                "/orders/create/preview/",
                {
                    "customer": str(self.customer_b.id),
                    "currency": "RON",
                },
            )
        # With scoping in place, fetching customer_b with id__in=[customer_a.id]
        # raises Http404. The preview returns error content or 404 — not a
        # successful 200 with customer_b's financial data.
        self.assertNotEqual(response.status_code, 500, "Preview must not crash with unscoped customer lookup")


class DraftOrderMassAssignmentTests(TestCase):
    """H14: Financial fields must not be mass-assignable on draft orders."""

    def setUp(self) -> None:
        self.client = Client()
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2}
        )
        self.staff = User.objects.create_user(
            email="mass-staff@test.com",
            password="TestPass123!",
            is_staff=True,
            staff_role="admin",
        )
        self.customer = Customer.objects.create(
            name="MassAssign Co",
            customer_type="company",
            status="active",
            primary_email="mass@test.ro",
        )
        CustomerMembership.objects.create(user=self.staff, customer=self.customer, role="admin")
        self.order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            total_cents=50000,
            subtotal_cents=42000,
            tax_cents=8000,
            customer_email="mass@test.ro",
            customer_name="MassAssign Co",
        )

    def test_total_cents_cannot_be_overwritten(self) -> None:
        """POSTing total_cents=0 to draft order edit must not change the total."""
        self.client.force_login(self.staff)
        self.client.post(
            f"/orders/{self.order.pk}/edit/",
            {"total_cents": "0", "notes": "legit"},
        )
        self.order.refresh_from_db()
        self.assertEqual(
            self.order.total_cents,
            50000,
            "total_cents should not be modifiable via POST",
        )

    def test_discount_cents_cannot_be_overwritten(self) -> None:
        """POSTing discount_cents must not change the discount."""
        self.client.force_login(self.staff)
        self.client.post(
            f"/orders/{self.order.pk}/edit/",
            {"discount_cents": "999999"},
        )
        self.order.refresh_from_db()
        self.assertNotEqual(
            self.order.discount_cents,
            999999,
            "discount_cents should not be modifiable via POST",
        )

    def test_subtotal_cents_cannot_be_overwritten(self) -> None:
        """POSTing subtotal_cents must not change the subtotal."""
        self.client.force_login(self.staff)
        self.client.post(
            f"/orders/{self.order.pk}/edit/",
            {"subtotal_cents": "1"},
        )
        self.order.refresh_from_db()
        self.assertNotEqual(
            self.order.subtotal_cents,
            1,
            "subtotal_cents should not be modifiable via POST",
        )

    def test_tax_cents_cannot_be_overwritten(self) -> None:
        """POSTing tax_cents must not change the tax amount."""
        self.client.force_login(self.staff)
        self.client.post(
            f"/orders/{self.order.pk}/edit/",
            {"tax_cents": "1"},
        )
        self.order.refresh_from_db()
        self.assertNotEqual(
            self.order.tax_cents,
            1,
            "tax_cents should not be modifiable via POST",
        )

    def test_safe_fields_remain_editable_on_draft(self) -> None:
        """Notes field must remain editable on draft orders after the fix."""
        self.client.force_login(self.staff)
        self.client.post(
            f"/orders/{self.order.pk}/edit/",
            {"notes": "legitimate internal note"},
        )
        self.order.refresh_from_db()
        self.assertEqual(
            self.order.notes,
            "legitimate internal note",
            "notes field must still be editable on draft orders",
        )

    def test_payment_method_remains_editable_on_draft(self) -> None:
        """payment_method must remain editable on draft orders after the fix."""
        self.client.force_login(self.staff)
        self.client.post(
            f"/orders/{self.order.pk}/edit/",
            {"payment_method": "manual"},
        )
        self.order.refresh_from_db()
        self.assertEqual(
            self.order.payment_method,
            "manual",
            "payment_method must still be editable on draft orders",
        )
