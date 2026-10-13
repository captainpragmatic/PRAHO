"""The draft order page has one preflight summary in its status dialog.

The preflight partial ends with an out-of-band update for the dialog's summary, which only the
validate endpoint's HTMX answer needs. Included in the page, it gave every draft order page a second
element with the dialog summary's id.
"""

from django.test import TestCase
from django.urls import reverse

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order
from apps.users.models import User

SUMMARY = 'id="modal-preflight"'


class OrderDetailPreflightTests(TestCase):
    def setUp(self) -> None:
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        customer = Customer.objects.create(name="Preflight", primary_email="preflight@example.test")
        self.order = Order.objects.create(customer=customer, currency=currency, order_number="PREFLIGHT-1")
        staff = User.objects.create_user(email="preflight-staff@example.test", is_staff=True, staff_role="admin")
        self.client.force_login(staff)

    def test_the_draft_order_page_has_one_dialog_summary(self) -> None:
        response = self.client.get(reverse("orders:order_detail", kwargs={"pk": self.order.pk}))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'id="preflight-container"')  # the preflight card is on the page
        self.assertEqual(response.content.decode().count(SUMMARY), 1)

    def test_validating_still_updates_the_dialog_summary(self) -> None:
        response = self.client.get(
            reverse("orders:order_validate", kwargs={"pk": self.order.pk}), HTTP_HX_REQUEST="true"
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, f'{SUMMARY} hx-swap-oob="true"', count=1)
