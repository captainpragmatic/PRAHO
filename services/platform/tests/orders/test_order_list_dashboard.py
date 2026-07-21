"""
Tests for order list dashboard stats, billing address rendering, and status counts.
Covers PR #132 review findings.
"""
from unittest.mock import patch

from django.test import Client, TestCase
from django.urls import reverse

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order
from apps.users.models import CustomerMembership, User
from tests.helpers.fsm_helpers import force_status


class OrderListStatusCountsTestCase(TestCase):
    """Test status_counts context in order_list view."""

    def setUp(self) -> None:
        self.client = Client()
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="Stats Test SRL",
            customer_type="company",
            status="active",
            primary_email="stats@test.ro",
        )
        self.staff = User.objects.create_user(
            email="staff-stats@pragmatichost.com",
            password="testpass123",
            is_staff=True,
            staff_role="admin",
        )
        CustomerMembership.objects.create(
            user=self.staff, customer=self.customer, role="admin"
        )
        self.client.login(email="staff-stats@pragmatichost.com", password="testpass123")

    def _create_order(self, status: str, suffix: str) -> Order:
        order = Order.objects.create(
            customer=self.customer,
            order_number=f"ORD-STATS-{suffix}",
            currency=self.currency,
            status="draft",
        )
        if status != "draft":
            force_status(order, status)
        return order

    def test_status_counts_includes_all_valid_statuses(self) -> None:
        """status_counts must have keys for all Order statuses + total."""
        response = self.client.get(reverse("orders:order_list"))
        self.assertEqual(response.status_code, 200)
        status_counts = response.context["status_counts"]

        expected_keys = {status for status, _label in Order.STATUS_CHOICES} | {"total"}
        self.assertEqual(set(status_counts.keys()), expected_keys)

    def test_status_counts_correct_values(self) -> None:
        """Verify counts match actual orders per status."""
        self._create_order("draft", "D1")
        self._create_order("draft", "D2")
        self._create_order("completed", "C1")
        self._create_order("cancelled", "X1")
        self._create_order("failed", "F1")

        response = self.client.get(reverse("orders:order_list"))
        counts = response.context["status_counts"]

        self.assertEqual(counts["total"], 5)
        self.assertEqual(counts["draft"], 2)
        self.assertEqual(counts["completed"], 1)
        self.assertEqual(counts["cancelled"], 1)
        self.assertEqual(counts["failed"], 1)
        self.assertEqual(counts["awaiting_payment"], 0)

    def test_status_counts_zero_when_empty(self) -> None:
        """All counts should be 0 (or None from aggregate) when no orders exist."""
        response = self.client.get(reverse("orders:order_list"))
        counts = response.context["status_counts"]
        self.assertEqual(counts["total"], 0)
        self.assertEqual(counts["draft"], 0)
        self.assertEqual(response.context["other_status_summary"], {"total": 0, "breakdown": []})
        self.assertNotContains(response, 'data-testid="orders-other-status-count"')

    def test_status_summaries_follow_the_order_status_source_of_truth(self) -> None:
        """A new enum status cannot silently disappear from dashboard summaries.

        A quality_hold order cannot be created here — the order_status_valid_values
        DB constraint pins rows to the migrated enum — so the addition direction
        can only assert the zero-count key appears.
        """
        future_choices = (*Order.STATUS_CHOICES, ("quality_hold", "Quality Hold"))

        with patch.object(Order, "STATUS_CHOICES", future_choices):
            response = self.client.get(reverse("orders:order_list"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["status_counts"]["quality_hold"], 0)
        self.assertEqual(
            [item["label"] for item in response.context["other_status_summary"]["breakdown"]],
            [],
        )

    def test_other_summary_follows_enum_removal_not_a_hardcoded_list(self) -> None:
        """Removing a status from the enum removes it from the summaries.

        This mirrors the real refunded removal: with an in_review order in the
        DB but in_review dropped from STATUS_CHOICES, an enum-driven Other
        summary excludes it, while a hardcoded in_review/failed/cancelled list
        would still count the row.
        """
        self._create_order("in_review", "ENUM-RM")
        reduced_choices = tuple(
            (status, label) for status, label in Order.STATUS_CHOICES if status != "in_review"
        )

        with patch.object(Order, "STATUS_CHOICES", reduced_choices):
            response = self.client.get(reverse("orders:order_list"))

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("in_review", response.context["status_counts"])
        self.assertEqual(response.context["other_status_summary"], {"total": 0, "breakdown": []})

    def test_other_status_summary_covers_every_status_without_a_card(self) -> None:
        """The compact Other card must account for every omitted status."""
        for suffix, status in enumerate(("in_review", "failed", "cancelled"), start=1):
            self._create_order(status, f"OTHER-{suffix}")

        response = self.client.get(reverse("orders:order_list"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.context["other_status_summary"],
            {
                "total": 3,
                "breakdown": [
                    {"label": "In Review", "count": 1},
                    {"label": "Failed", "count": 1},
                    {"label": "Cancelled", "count": 1},
                ],
            },
        )
        self.assertContains(response, 'data-testid="orders-other-status-count">3</p>')


class OrderDetailBillingAddressTestCase(TestCase):
    """Test billing address rendering from JSONField in order detail."""

    def setUp(self) -> None:
        self.client = Client()
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="Address Test SRL",
            customer_type="company",
            status="active",
            primary_email="addr@test.ro",
        )
        self.staff = User.objects.create_user(
            email="staff-addr@pragmatichost.com",
            password="testpass123",
            is_staff=True,
            staff_role="admin",
        )
        CustomerMembership.objects.create(
            user=self.staff, customer=self.customer, role="admin"
        )
        self.client.login(email="staff-addr@pragmatichost.com", password="testpass123")

    def test_billing_address_renders_from_json_field(self) -> None:
        """Billing address from JSONField should render in the detail page."""
        order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-ADDR-001",
            currency=self.currency,
            status="draft",
            billing_address={
                "line1": "Str. Victoriei 10",
                "line2": "Et. 3, Ap. 12",
                "city": "Bucuresti",
                "county": "Bucuresti",
                "postal_code": "010001",
                "country": "Romania",
            },
        )
        response = self.client.get(reverse("orders:order_detail", args=[order.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Str. Victoriei 10")
        self.assertContains(response, "Bucuresti")
        self.assertContains(response, "Romania")

    def test_empty_billing_address_shows_not_provided(self) -> None:
        """Empty billing_address dict should show 'Not provided'."""
        order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-ADDR-002",
            currency=self.currency,
            status="draft",
            billing_address={},
        )
        response = self.client.get(reverse("orders:order_detail", args=[order.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Not provided")

    def test_partial_billing_address_no_crash(self) -> None:
        """Partial billing address should render without template errors."""
        order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-ADDR-003",
            currency=self.currency,
            status="draft",
            billing_address={"city": "Cluj-Napoca", "country": "Romania"},
        )
        response = self.client.get(reverse("orders:order_detail", args=[order.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Cluj-Napoca")
        self.assertNotContains(response, "Not provided")
