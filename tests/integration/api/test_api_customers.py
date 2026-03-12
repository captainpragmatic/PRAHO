from __future__ import annotations

import time

from django.test import TestCase
from rest_framework.test import APIRequestFactory

from apps.api.customers.views import customer_create_api, customer_register_api
from apps.customers.models import Customer
from apps.users.models import CustomerMembership, User


class CustomerAPIIntegrationTests(TestCase):
    def setUp(self) -> None:
        self.factory = APIRequestFactory()
        self.user = User.objects.create_user(email="customer-api-user@example.ro", password="testpass123")

    def test_customer_create_requires_portal_authentication(self) -> None:
        request = self.factory.post(
            "/api/customers/create/",
            data={"user_id": self.user.id, "action": "create_company", "company_data": {}},
            format="json",
        )

        response = customer_create_api(request)

        self.assertEqual(response.status_code, 403)

    def test_customer_create_creates_company_and_owner_membership(self) -> None:
        request = self.factory.post(
            "/api/customers/create/",
            data={
                "user_id": self.user.id,
                "action": "create_company",
                "timestamp": int(time.time()),
                "company_data": {
                    "name": "New Integration Company SRL",
                    "company_name": "New Integration Company SRL",
                    "vat_number": "RO12345678",
                    "trade_registry_number": "J40/1234/2026",
                    "billing_address": {
                        "street_address": "Str. Integrarii 1",
                        "city": "Bucuresti",
                    },
                    "contact": {
                        "primary_email": "office@integration.ro",
                        "primary_phone": "+40721234567",
                        "website": "https://integration.ro",
                    },
                },
            },
            format="json",
        )
        request._portal_authenticated = True

        response = customer_create_api(request)

        self.assertEqual(response.status_code, 201)
        self.assertTrue(response.data["success"])

        customer = Customer.objects.get(id=response.data["customer_id"])
        self.assertEqual(customer.company_name, "New Integration Company SRL")
        self.assertEqual(customer.status, "active")

        self.assertTrue(
            CustomerMembership.objects.filter(user=self.user, customer=customer, role="owner", is_active=True).exists()
        )

    def test_customer_create_rejects_invalid_action_payload(self) -> None:
        request = self.factory.post(
            "/api/customers/create/",
            data={"user_id": self.user.id, "action": "wrong_action", "company_data": {}},
            format="json",
        )
        request._portal_authenticated = True

        response = customer_create_api(request)

        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.data["success"])

    def test_customer_register_endpoint_is_public_but_validates_payload(self) -> None:
        request = self.factory.post(
            "/api/customers/register/",
            data={"user_data": {"email": "bad@example.ro"}},
            format="json",
        )

        response = customer_register_api(request)

        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.data["success"])
