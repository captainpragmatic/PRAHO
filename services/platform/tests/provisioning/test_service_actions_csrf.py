"""The service page's Suspend and Activate buttons work under CSRF and show their result.

The buttons are `{% button hx_post %}` with no form around them. With CSRF enforced (staging, prod) they only work if
the page gives htmx the token, and once they work the page has to show the new status: the view answers htmx with
HX-Redirect to the detail page, because its redirect would otherwise be swapped into a hidden container.
"""

from __future__ import annotations

from decimal import Decimal

from django.test import Client, TestCase
from django.urls import reverse

from apps.billing.models import Currency
from apps.provisioning.models import Service
from apps.users.models import CustomerMembership
from tests.helpers.csrf import body_csrf_token
from tests.provisioning.test_provisioning_views import (
    create_test_customer,
    create_test_service_plan,
    create_test_user,
)


class ServiceActionCsrfTests(TestCase):
    def setUp(self) -> None:
        self.admin = create_test_user("csrf-admin@test.ro", staff_role="admin", is_staff=True)
        customer = create_test_customer("CSRF Customer", self.admin)
        CustomerMembership.objects.create(user=self.admin, customer=customer, role="admin")
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.service = Service.objects.create(
            customer=customer,
            service_plan=create_test_service_plan(),
            currency=currency,
            service_name="CSRF Service",
            domain="csrf.example.com",
            username="csrf_user",
            billing_cycle="monthly",
            price=Decimal("50.00"),
            status="active",
        )
        self.strict = Client(enforce_csrf_checks=True)
        self.strict.force_login(self.admin)
        self.detail = reverse("provisioning:service_detail", args=[self.service.pk])

    def _page_token(self) -> str:
        page = self.strict.get(self.detail)
        self.assertEqual(page.status_code, 200)
        return body_csrf_token(page.content.decode())

    def _htmx_post(self, name: str, token: str | None) -> object:
        headers = {"HTTP_HX_REQUEST": "true"}
        if token is not None:
            headers["HTTP_X_CSRFTOKEN"] = token
        return self.strict.post(reverse(f"provisioning:{name}", args=[self.service.pk]), **headers)

    def test_suspend_without_the_token_is_refused_and_changes_nothing(self) -> None:
        response = self._htmx_post("service_suspend", None)
        self.assertEqual(response.status_code, 403)
        self.service.refresh_from_db()
        self.assertEqual(self.service.status, "active")

    def test_suspend_then_activate_with_the_page_token_and_land_on_the_detail_page(self) -> None:
        response = self._htmx_post("service_suspend", self._page_token())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["HX-Redirect"], self.detail)
        self.service.refresh_from_db()
        self.assertEqual(self.service.status, "suspended")

        response = self._htmx_post("service_activate", self._page_token())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["HX-Redirect"], self.detail)
        self.service.refresh_from_db()
        self.assertEqual(self.service.status, "active")

    def test_a_refused_transition_also_returns_to_the_detail_page(self) -> None:
        """Activating an active service is refused; htmx still gets a page it can show, not a hidden swap."""
        response = self._htmx_post("service_activate", self._page_token())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["HX-Redirect"], self.detail)
        self.service.refresh_from_db()
        self.assertEqual(self.service.status, "active")
