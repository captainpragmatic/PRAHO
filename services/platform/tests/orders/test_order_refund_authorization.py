"""#104 [M11]: order refunds are a financial operation, not a general staff one.

``order_refund`` is the declared twin of ``billing.views.invoice_refund`` ("bidirectional
with invoice refunds"). It carried ``@staff_required_strict`` — a different decorator name
with the *same* effective predicate, ``is_staff_user`` — so fixing only the invoice door
would have left this one open. Its in-view ``can_access_customer`` check adds nothing for
staff: ``User.can_access_customer`` returns True unconditionally when ``is_staff_user``.

The denial must be JSON. ``order_refund`` returns ``JsonResponse`` and its client parses
the body unconditionally, so neither an HTML redirect nor a plain-text 403 is usable.
"""

from __future__ import annotations

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from apps.billing.currency_models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order

User = get_user_model()

REFUND_SERVICE = "apps.orders.views.RefundService.refund_order"


class OrderRefundAuthorizationTests(TestCase):
    """The role matrix for ``orders:order_refund``."""

    def setUp(self) -> None:
        self.client = Client()
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="Refund Matrix SRL",
            customer_type="company",
            status="active",
            primary_email="refund-matrix@test.ro",
        )
        self.admin_user = User.objects.create_user(
            email="rm-admin@test.ro", password="TestPass123!", is_staff=True, is_superuser=True, staff_role="admin"
        )
        self.billing_user = User.objects.create_user(
            email="rm-billing@test.ro", password="TestPass123!", is_staff=True, staff_role="billing"
        )
        self.manager_user = User.objects.create_user(
            email="rm-manager@test.ro", password="TestPass123!", is_staff=True, staff_role="manager"
        )
        self.support_user = User.objects.create_user(
            email="rm-support@test.ro", password="TestPass123!", is_staff=True, staff_role="support"
        )
        # Bare is_staff with no role also satisfied the old is_staff_user predicate.
        self.bare_staff_user = User.objects.create_user(
            email="rm-bare@test.ro", password="TestPass123!", is_staff=True
        )
        self.customer_user = User.objects.create_user(email="rm-customer@test.ro", password="TestPass123!")

        self.order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            status="completed",
            subtotal_cents=10000,
            tax_cents=1900,
            total_cents=11900,
        )
        self.url = reverse("orders:order_refund", kwargs={"pk": self.order.id})

    def _post_refund(self, user: object | None) -> object:
        """POST a *valid* payload so authorization, not validation, is what blocks."""
        if user is not None:
            self.client.force_login(user)
        else:
            self.client.logout()
        return self.client.post(self.url, {"refund_type": "full", "reason": "customer_request"})

    def test_financial_roles_may_reach_the_refund_service(self) -> None:
        for user in (self.admin_user, self.billing_user, self.manager_user):
            with self.subTest(role=user.staff_role), patch(REFUND_SERVICE) as refund:
                refund.return_value.is_ok.return_value = False
                refund.return_value.unwrap_err.return_value = "stub"
                response = self._post_refund(user)
                self.assertNotIn(response.status_code, (401, 403))
                refund.assert_called_once()

    def test_non_financial_staff_are_denied_and_never_reach_the_service(self) -> None:
        for user in (self.support_user, self.bare_staff_user):
            with self.subTest(role=user.staff_role or "<bare is_staff>"), patch(REFUND_SERVICE) as refund:
                response = self._post_refund(user)
                self.assertEqual(response.status_code, 403)
                self.assertEqual(response["Content-Type"], "application/json")
                self.assertFalse(response.json()["success"])
                refund.assert_not_called()

    def test_authenticated_customer_is_denied_in_json(self) -> None:
        with patch(REFUND_SERVICE) as refund:
            response = self._post_refund(self.customer_user)
            self.assertEqual(response.status_code, 403)
            self.assertEqual(response["Content-Type"], "application/json")
            refund.assert_not_called()

    def test_anonymous_is_denied_in_json_not_redirected_to_login(self) -> None:
        with patch(REFUND_SERVICE) as refund:
            response = self._post_refund(None)
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response["Content-Type"], "application/json")
            refund.assert_not_called()
