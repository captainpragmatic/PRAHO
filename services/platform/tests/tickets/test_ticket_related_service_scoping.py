"""Customer ticket service links must stay within the authenticated customer."""

from importlib import import_module

from django.apps import apps
from django.db import connection
from django.test import TestCase, override_settings

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.provisioning.service_models import Server, Service, ServicePlan
from apps.tickets.models import Ticket
from apps.users.models import CustomerMembership, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE, LANGUAGE_CODE="en")
class TicketRelatedServiceScopingTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2}
        )
        plan = ServicePlan.objects.create(name="Basic Hosting", plan_type="shared_hosting", price_monthly="29.99")
        server = Server.objects.create(
            name="Test Server", hostname="tickets.test.ro", primary_ip="10.0.0.1",
            server_type="shared", status="active", location="Bucharest", datacenter="M247",
            cpu_model="Xeon E5", cpu_cores=8, ram_gb=32, disk_type="ssd", disk_capacity_gb=500, os_type="linux",
        )
        self.owner = User.objects.create_user(email="ticket-owner@example.com")
        other_owner = User.objects.create_user(email="other-ticket-owner@example.com")
        self.customer = Customer.objects.create(
            name="Acme", customer_type="company", status="active", primary_email=self.owner.email
        )
        other_customer = Customer.objects.create(
            name="Other", customer_type="company", status="active", primary_email=other_owner.email
        )
        CustomerMembership.objects.create(user=self.owner, customer=self.customer, role="owner", is_active=True)
        CustomerMembership.objects.create(user=other_owner, customer=other_customer, role="owner", is_active=True)
        self.service = Service.objects.create(
            customer=self.customer, service_plan=plan, server=server, currency=currency,
            service_name="web.example.com", username="ticket-own", price="29.99", status="active",
        )
        self.other_service = Service.objects.create(
            customer=other_customer, service_plan=plan, server=server, currency=currency,
            service_name="other.example.com", username="ticket-other", price="29.99", status="active",
        )

    def _body(self) -> dict[str, object]:
        return {
            "customer_id": self.customer.pk,
            "user_id": self.owner.pk,
            "action": "create_ticket",
            "title": "Hosting question",
            "description": "Please check my hosting service.",
        }

    def test_own_service_is_accepted_and_echoed(self) -> None:
        response = self.portal_post("/api/tickets/create/", {**self._body(), "related_service": self.service.pk})
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(response.json()["data"]["ticket"]["related_service"], self.service.pk)
        self.assertEqual(Ticket.objects.get().related_service_id, self.service.pk)

    def test_foreign_service_is_rejected_like_a_nonexistent_one(self) -> None:
        for service_id in (self.other_service.pk, 999999):
            with self.subTest(service_id=service_id):
                response = self.portal_post("/api/tickets/create/", {**self._body(), "related_service": service_id})
                self.assertEqual(response.status_code, 400, response.content)
                self.assertEqual(
                    response.json()["errors"]["related_service"],
                    [f'Invalid pk "{service_id}" - object does not exist.'],
                )
                self.assertFalse(Ticket.objects.exists())

    def test_absent_service_is_allowed(self) -> None:
        response = self.portal_post("/api/tickets/create/", self._body())
        self.assertEqual(response.status_code, 201, response.content)
        self.assertIsNone(response.json()["data"]["ticket"]["related_service"])
        self.assertIsNone(Ticket.objects.get().related_service_id)

    def test_legacy_foreign_link_is_hidden_on_read(self) -> None:
        ticket = Ticket.objects.create(
            customer=self.customer, related_service=self.other_service,
            title="Legacy link", description="Legacy customer mismatch",
        )
        response = self.portal_post(
            f"/api/tickets/{ticket.pk}/",
            {"customer_id": self.customer.pk, "user_id": self.owner.pk, "action": "get_ticket_detail"},
        )
        self.assertEqual(response.status_code, 200, response.content)
        data = response.json()["data"]["ticket"]
        self.assertIsNone(data["related_service"])
        self.assertEqual(data["related_service_name"], "")

    def test_migration_unlinks_foreign_services(self) -> None:
        foreign_ticket = Ticket.objects.create(
            customer=self.customer, related_service=self.other_service, title="Foreign", description="Legacy"
        )
        own_ticket = Ticket.objects.create(
            customer=self.customer, related_service=self.service, title="Own", description="Valid"
        )
        migration = import_module("apps.tickets.migrations.0005_unlink_foreign_services")
        migration.unlink_foreign_services(apps, connection.schema_editor())
        self.assertIsNone(Ticket.objects.get(pk=foreign_ticket.pk).related_service_id)
        self.assertEqual(Ticket.objects.get(pk=own_ticket.pk).related_service_id, self.service.pk)
