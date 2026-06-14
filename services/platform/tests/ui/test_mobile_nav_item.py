"""Regression tests for the shared `components/mobile_nav_item.html` staff gating.

Guards the is_staff_user migration: staff-only mobile nav items must be visible to
staff_role users who do NOT carry the Django ``is_staff`` flag (e.g. support agents),
and must stay hidden from customers. Reverting the gate to bare ``user.is_staff`` would
re-lock support agents and fail ``test_support_role_without_django_staff_flag_*``.
"""

from django.contrib.auth import get_user_model
from django.template.loader import render_to_string
from django.test import TestCase

User = get_user_model()

# A staff-only item; "Customers" is the discriminating marker we assert on. No icon_name
# is supplied so the template renders the legacy (empty) icon slot, keeping the test
# independent of the icon registry.
STAFF_ONLY_CONTEXT = {
    "staff_only": True,
    "title": "Customers",
    "subtitle": "Manage customers",
    "url": "/app/customers/",
}


class MobileNavItemStaffGatingTest(TestCase):
    """components/mobile_nav_item.html must gate staff_only items on is_staff_user."""

    def _render_for(self, user):
        return render_to_string("components/mobile_nav_item.html", {**STAFF_ONLY_CONTEXT, "user": user})

    def test_support_role_without_django_staff_flag_sees_staff_only_item(self):
        support = User.objects.create_user(email="nav-support@test.ro", password="testpass")
        support.is_staff = False
        support.staff_role = "support"
        support.save()
        self.assertIn("Customers", self._render_for(support))

    def test_admin_staff_sees_staff_only_item(self):
        admin = User.objects.create_user(email="nav-admin@test.ro", password="testpass")
        admin.is_staff = True
        admin.staff_role = "admin"
        admin.save()
        self.assertIn("Customers", self._render_for(admin))

    def test_customer_does_not_see_staff_only_item(self):
        customer = User.objects.create_user(email="nav-customer@test.ro", password="testpass")
        self.assertNotIn("Customers", self._render_for(customer))
