"""The Invoices menu item shows as unavailable to staff the invoice list would refuse.

It was offered to every staff member, but billing:invoice_list is billing_staff_required (admin, billing, manager or
superuser), so support staff were sent back to the dashboard with "Access denied". The desktop and mobile menus now
use the view's rule, User.can_manage_financial_data, and show the item disabled with the reason.
"""

from __future__ import annotations

from django.test import TestCase
from django.urls import reverse

from apps.users.models import User
from tests.ui.node_harness import Markup

REASON = "Only billing staff can open invoices."


class InvoicesNavTests(TestCase):
    def page(self, role: str) -> str:
        user = User.objects.create_user(email=f"nav-{role}@example.test", is_staff=True, staff_role=role)
        self.client.force_login(user)
        return self.client.get(reverse("dashboard")).content.decode()

    def invoice_links(self, html: str) -> list[dict[str, str]]:
        return [a for t, a in Markup(html).elements if t == "a" and a.get("href", "").startswith("/billing/invoices/")]

    def test_support_sees_invoices_unavailable_in_both_menus(self) -> None:
        html = self.page("support")
        self.assertEqual(self.invoice_links(html), [])
        self.assertGreaterEqual(html.count(REASON), 2)  # desktop dropdown and mobile menu

    def test_billing_staff_get_the_links(self) -> None:
        html = self.page("billing")
        self.assertGreaterEqual(len(self.invoice_links(html)), 2)
        self.assertNotIn(REASON, html)
