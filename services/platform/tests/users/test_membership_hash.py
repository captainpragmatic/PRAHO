"""Tests for membership_hash computation in validate_session_secure endpoint.

The membership_hash is a truncated SHA-256 of active memberships, used by Portal
to detect membership changes (role grant/revoke) without polling.

Computation (views.py lines 448-454):
    memberships = CustomerMembership.objects.filter(user=user, is_active=True)
        .order_by("customer_id").values_list("customer_id", "role")
    hash_input = ",".join(f"{cid}:{role}" for cid, role in memberships)
    membership_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:16]
"""

from __future__ import annotations

import hashlib

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.customers.customer_models import Customer
from apps.users.models import CustomerMembership
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin

User = get_user_model()


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
)
class MembershipHashValidationTest(HMACTestMixin, TestCase):
    """Test membership_hash computation in validate_session_secure endpoint."""

    def setUp(self) -> None:
        super().setUp()
        self.user = User.objects.create_user(email="test@example.com", password="testpass123")
        self.other_user = User.objects.create_user(email="other@example.com", password="testpass123")
        self.customer1 = Customer.objects.create(name="Customer 1")
        self.customer2 = Customer.objects.create(name="Customer 2")
        self.customer3 = Customer.objects.create(name="Customer 3")

    def _validate_session(self, user_id: int) -> dict:
        """Send HMAC-signed validate-session request and return response data."""
        response = self.portal_post(
            "/api/users/session/validate/",
            {
                "user_id": user_id,
                "jti": f"test-nonce-{timezone.now().timestamp()}",
            },
        )
        self.assertEqual(response.status_code, 200)
        return response.json()

    def _compute_expected_hash(self, memberships: list[tuple[int, str]]) -> str:
        """Manually compute expected membership hash."""
        sorted_memberships = sorted(memberships, key=lambda x: x[0])
        hash_input = ",".join(f"{cid}:{role}" for cid, role in sorted_memberships)
        return hashlib.sha256(hash_input.encode()).hexdigest()[:16]

    def test_membership_hash_in_response(self) -> None:
        """Response contains 'membership_hash' key with 16 hex characters."""
        CustomerMembership.objects.create(user=self.user, customer=self.customer1, role="owner")
        data = self._validate_session(self.user.id)
        self.assertIn("membership_hash", data)
        self.assertRegex(data["membership_hash"], r"^[0-9a-f]{16}$")

    def test_hash_matches_expected(self) -> None:
        """Hash matches manually computed expected value for known memberships."""
        CustomerMembership.objects.create(user=self.user, customer=self.customer1, role="owner")
        CustomerMembership.objects.create(user=self.user, customer=self.customer2, role="billing")
        expected = self._compute_expected_hash(
            [
                (self.customer1.id, "owner"),
                (self.customer2.id, "billing"),
            ]
        )
        data = self._validate_session(self.user.id)
        self.assertEqual(data["membership_hash"], expected)

    def test_hash_changes_on_membership_add(self) -> None:
        """Adding a CustomerMembership changes the membership_hash."""
        CustomerMembership.objects.create(user=self.user, customer=self.customer1, role="owner")
        hash1 = self._validate_session(self.user.id)["membership_hash"]

        CustomerMembership.objects.create(user=self.user, customer=self.customer2, role="billing")
        hash2 = self._validate_session(self.user.id)["membership_hash"]

        self.assertNotEqual(hash1, hash2)

    def test_hash_changes_on_role_change(self) -> None:
        """Changing a membership role changes the membership_hash."""
        membership = CustomerMembership.objects.create(user=self.user, customer=self.customer1, role="owner")
        hash1 = self._validate_session(self.user.id)["membership_hash"]

        membership.role = "viewer"
        membership.save(update_fields=["role"])
        hash2 = self._validate_session(self.user.id)["membership_hash"]

        self.assertNotEqual(hash1, hash2)

    def test_inactive_membership_excluded(self) -> None:
        """Inactive memberships (is_active=False) are excluded from hash."""
        CustomerMembership.objects.create(user=self.user, customer=self.customer1, role="owner", is_active=True)
        CustomerMembership.objects.create(user=self.user, customer=self.customer2, role="billing", is_active=False)
        expected = self._compute_expected_hash([(self.customer1.id, "owner")])
        data = self._validate_session(self.user.id)
        self.assertEqual(data["membership_hash"], expected)

    def test_empty_memberships_deterministic(self) -> None:
        """User with zero memberships gets sha256('').hexdigest()[:16]."""
        expected = hashlib.sha256(b"").hexdigest()[:16]
        data = self._validate_session(self.user.id)
        self.assertEqual(data["membership_hash"], expected)

    def test_ordering_by_customer_id(self) -> None:
        """Memberships are sorted by customer_id regardless of creation order."""
        # Create in reverse order (customer3 first, customer1 last)
        CustomerMembership.objects.create(user=self.user, customer=self.customer3, role="owner")
        CustomerMembership.objects.create(user=self.user, customer=self.customer1, role="billing")
        CustomerMembership.objects.create(user=self.user, customer=self.customer2, role="tech")
        expected = self._compute_expected_hash(
            [
                (self.customer1.id, "billing"),
                (self.customer2.id, "tech"),
                (self.customer3.id, "owner"),
            ]
        )
        data = self._validate_session(self.user.id)
        self.assertEqual(data["membership_hash"], expected)

    def test_cross_user_isolation(self) -> None:
        """Other user's memberships do not leak into this user's hash."""
        CustomerMembership.objects.create(user=self.user, customer=self.customer1, role="owner")
        CustomerMembership.objects.create(user=self.other_user, customer=self.customer2, role="billing")
        CustomerMembership.objects.create(user=self.other_user, customer=self.customer3, role="tech")

        user_expected = self._compute_expected_hash([(self.customer1.id, "owner")])
        other_expected = self._compute_expected_hash(
            [
                (self.customer2.id, "billing"),
                (self.customer3.id, "tech"),
            ]
        )

        user_data = self._validate_session(self.user.id)
        other_data = self._validate_session(self.other_user.id)

        self.assertEqual(user_data["membership_hash"], user_expected)
        self.assertEqual(other_data["membership_hash"], other_expected)
        self.assertNotEqual(user_data["membership_hash"], other_data["membership_hash"])
