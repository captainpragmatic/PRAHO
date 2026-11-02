"""Catalog changes are admin-only; other staff see those controls disabled, with the reason.

The product pages are open to every staff member, but creating, editing, toggling and pricing products are
`@admin_required`. Support or billing staff clicked them and got a 403 (a generic alert for the toggles, a bare 403
page for New Product). The pages use the views' own rule, `is_administrator`, and show the action disabled with why.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from apps.common.decorators import is_administrator
from apps.products.models import Product
from tests.ui.node_harness import Markup

REASON = "Only administrators can change the product catalog."
ADMIN_ONLY_URLS = ("toggle-active", "toggle-public", "toggle-featured", "/edit/", "/prices/create/", "/create/")


class CatalogAdminControlTests(TestCase):
    def setUp(self) -> None:
        user = get_user_model()
        self.admin = user.objects.create_user(
            email="catalog-admin@test.ro", password="pw", is_staff=True, staff_role="admin"
        )
        self.support = user.objects.create_user(
            email="catalog-support@test.ro", password="pw", is_staff=True, staff_role="support"
        )
        self.product = Product.objects.create(slug="catalog-gate", name="Catalog Gate", product_type="shared_hosting")

    def pages(self) -> list[str]:
        slug = {"slug": self.product.slug}
        return [
            reverse("products:product_list"),
            reverse("products:product_list_htmx"),
            reverse("products:product_detail", kwargs=slug),
            reverse("products:product_prices", kwargs=slug),
        ]

    def admin_only_controls(self, html: str) -> list[dict[str, str]]:
        controls = []
        for tag, attrs in Markup(html).elements:
            target = attrs.get("hx-post", "") or attrs.get("href", "")
            if tag in ("a", "button") and target.startswith("/products/") and any(p in target for p in ADMIN_ONLY_URLS):
                controls.append(attrs)
        return controls

    def test_the_rule_is_the_views_rule(self) -> None:
        self.assertTrue(is_administrator(self.admin))
        self.assertFalse(is_administrator(self.support))
        self.client.force_login(self.support)
        refused = self.client.post(reverse("products:product_toggle_active", kwargs={"slug": self.product.slug}))
        self.assertNotEqual(refused.status_code, 200)

    def test_other_staff_see_admin_controls_disabled_with_the_reason(self) -> None:
        self.client.force_login(self.support)
        for url in self.pages():
            with self.subTest(url=url):
                html = self.client.get(url).content.decode()
                self.assertEqual(self.admin_only_controls(html), [], "an admin-only action is still actionable")
                self.assertIn(REASON, html)

    def test_admins_get_working_controls(self) -> None:
        self.client.force_login(self.admin)
        found = 0
        for url in self.pages():
            with self.subTest(url=url):
                html = self.client.get(url).content.decode()
                found += len(self.admin_only_controls(html))
                self.assertNotIn(REASON, html)
        self.assertGreaterEqual(found, 8)  # create, toggles (list and detail), edit, price create
