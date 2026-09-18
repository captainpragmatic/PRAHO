"""HTMX product toggles must remain usable after each swap."""

from django.test import TestCase

from apps.products.models import Product
from apps.users.models import User


class ProductToggleHTMLContracts(TestCase):
    def test_each_toggle_returns_a_reusable_control_and_persists_both_states(self):
        admin = User.objects.create_user(
            email="toggle@example.com", password="Toggle-pass123!", is_staff=True, is_superuser=True
        )
        self.client.force_login(admin)
        product = Product.objects.create(name="Toggle product", slug="toggle", product_type="shared_hosting")
        for field in ("active", "public", "featured"):
            path = f"/products/{product.slug}/toggle-{field}/"
            before = getattr(product, "is_" + field)
            for expected in (not before, before):
                response = self.client.post(path, HTTP_HX_REQUEST="true")
                self.assertContains(response, f'hx-post="{path}"')
                self.assertContains(response, 'hx-swap="outerHTML"')
                self.assertContains(response, f'aria-pressed="{str(expected).lower()}"')
                product.refresh_from_db()
                self.assertEqual(getattr(product, "is_" + field), expected)
            response = self.client.post(path)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response["Content-Type"], "application/json")
