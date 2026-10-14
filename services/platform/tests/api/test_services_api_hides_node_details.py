"""The customer services API never exposes which node hosts a service (ADR-0061 P0.9).

The IP and hostname came from a placeholder server picked at order time, so they were wrong from
day one, and a real one would be stale after the first move. Neither belongs in a customer payload.
"""

from __future__ import annotations

import json
from decimal import Decimal
from typing import Any
from unittest.mock import patch

from django.test import TestCase
from rest_framework.test import APIRequestFactory

from apps.api.services.views import (
    customer_service_detail_api,
    customer_services_api,
    customer_services_summary_api,
    update_service_auto_renew_api,
)
from apps.billing.currency_models import Currency
from apps.customers.models import Customer
from apps.provisioning.models import Server
from apps.provisioning.service_models import Service, ServicePlan

NODE_IP = "203.0.113.77"
NODE_HOSTNAME = "node-secret-7.hosting.example.net"
NODE_NAME = "node-secret-7"
AUTH = "apps.api.secure_auth.get_authenticated_customer"


class NodeDetailsHiddenTests(TestCase):
    def setUp(self) -> None:
        self.customer = Customer.objects.create(name="Node customer", primary_email="n@example.com")
        self.plan = ServicePlan.objects.create(name="Plan", price_monthly=Decimal("10.00"))
        Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.server = Server.objects.create(
            name=NODE_NAME,
            hostname=NODE_HOSTNAME,
            server_type="shared",
            primary_ip=NODE_IP,
            cpu_cores=4,
            ram_gb=8,
            disk_capacity_gb=100,
        )
        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency_id="RON",
            service_name="Hosting",
            username="nodeuser",
            domain="site.example.com",
            price=Decimal("10.00"),
            status="active",
            server=self.server,
        )
        self.factory = APIRequestFactory()

    def post(
        self, view: Any, path: str, body: dict[str, Any] | None = None, view_kwargs: dict[str, int] | None = None
    ) -> Any:
        request = self.factory.post(path, body or {}, format="json")
        with patch(AUTH, return_value=(self.customer, None)):
            return view(request, **(view_kwargs or {}))

    def assert_no_node_details(self, payload: Any) -> None:
        text = json.dumps(payload, default=str)
        for secret in (NODE_IP, NODE_HOSTNAME, NODE_NAME):
            self.assertNotIn(secret, text)
        self.assertNotIn("server_ip", text)
        self.assertNotIn("primary_ip", text)

    def test_detail_payload_has_no_node_details(self) -> None:
        response = self.post(customer_service_detail_api, "/api/services/1/", view_kwargs={"service_id": self.service.id})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["data"]["service"]["domain"], "site.example.com")
        self.assert_no_node_details(response.data)
        self.assertNotIn("server", response.data["data"]["service"])

    def test_list_payload_has_no_node_details(self) -> None:
        response = self.post(customer_services_api, "/api/services/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data["data"]["services"]), 1)
        self.assert_no_node_details(response.data)

    def test_summary_payload_has_no_node_details(self) -> None:
        response = self.post(customer_services_summary_api, "/api/services/summary/")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["data"]["summary"]["recent_services"])
        self.assert_no_node_details(response.data)

    def test_auto_renew_payload_has_no_node_details(self) -> None:
        response = self.post(
            update_service_auto_renew_api,
            "/api/services/1/auto-renew/",
            {"auto_renew": False},
            view_kwargs={"service_id": self.service.id},
        )

        self.assertEqual(response.status_code, 200)
        self.assert_no_node_details(response.data)

    def test_search_cannot_probe_the_node_behind_a_service(self) -> None:
        for term in (NODE_IP, NODE_HOSTNAME, NODE_NAME):
            with self.subTest(term=term):
                response = self.post(customer_services_api, "/api/services/", {"search": term})
                self.assertEqual(response.data["data"]["services"], [])

    def test_a_service_without_a_node_or_a_hosting_account_answers_normally(self) -> None:
        self.service.server = None
        self.service.save(update_fields=["server", "updated_at"])

        for view, path, kwargs in (
            (customer_service_detail_api, "/api/services/1/", {"service_id": self.service.id}),
            (customer_services_api, "/api/services/", {}),
            (customer_services_summary_api, "/api/services/summary/", {}),
        ):
            with self.subTest(view=view.__name__):
                response = self.post(view, path, view_kwargs=kwargs)
                self.assertEqual(response.status_code, 200)
                self.assertTrue(response.data["success"])
