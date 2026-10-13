"""The proforma page's send button posts to the send route.

The script built /app/billing/proformas/<id>/send/, which no route serves, so sending a proforma
from its page answered 404 and the script reported a failure.
"""

from datetime import timedelta

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.billing.models import Currency, ProformaInvoice
from apps.customers.models import Customer
from apps.users.models import User


class ProformaSendUrlTests(TestCase):
    def test_the_send_button_posts_to_the_send_route(self) -> None:
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
        customer = Customer.objects.create(name="Send link", primary_email="send-link@example.test")
        proforma = ProformaInvoice.objects.create(
            customer=customer,
            currency=currency,
            number="SEND-LINK-1",
            valid_until=timezone.now() + timedelta(days=7),
        )
        staff = User.objects.create_user(email="send-link-staff@example.test", is_staff=True, staff_role="billing")
        self.client.force_login(staff)

        response = self.client.get(reverse("billing:proforma_detail", args=[proforma.pk]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, reverse("billing:proforma_send", args=[proforma.pk]))
        self.assertNotContains(response, "/app/")
