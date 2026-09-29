"""Service action requests create attributed support tickets."""

from uuid import uuid4

from django.contrib.contenttypes.models import ContentType
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.billing.models import Currency, Invoice
from apps.customers.models import Customer
from apps.orders.models import Order
from apps.provisioning.service_models import Server, Service, ServicePlan
from apps.provisioning.service_request_models import ServiceRequest
from apps.tickets.models import SupportCategory, Ticket
from apps.users.models import CustomerMembership, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE, LANGUAGE_CODE="en")
class ServiceActionRequestTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="Acme", customer_type="company", status="active", primary_email="acme@example.com"
        )
        other_customer = Customer.objects.create(
            name="Other", customer_type="company", status="active", primary_email="other@example.com"
        )
        self.users: dict[str, User] = {}
        for role in ("owner", "billing", "tech", "viewer"):
            user = User.objects.create_user(email=f"service-{role}@example.com")
            CustomerMembership.objects.create(user=user, customer=self.customer, role=role, is_active=True)
            self.users[role] = user
        other_owner = User.objects.create_user(email="other-service-owner@example.com")
        CustomerMembership.objects.create(user=other_owner, customer=other_customer, role="owner", is_active=True)
        plan = ServicePlan.objects.create(name="Basic Hosting", plan_type="shared_hosting", price_monthly="29.99")
        server = Server.objects.create(
            name="Test Server", hostname="actions.test.ro", primary_ip="10.0.0.1",
            server_type="shared", status="active", location="Bucharest", datacenter="M247",
            cpu_model="Xeon E5", cpu_cores=8, ram_gb=32, disk_type="ssd", disk_capacity_gb=500, os_type="linux",
        )
        self.service = Service.objects.create(
            customer=self.customer, service_plan=plan, server=server, currency=self.currency,
            service_name="web.example.com", username="action-own", price="29.99", status="active",
        )
        self.other_service = Service.objects.create(
            customer=other_customer, service_plan=plan, server=server, currency=self.currency,
            service_name="other.example.com", username="action-other", price="29.99", status="active",
        )
        self.path = f"/api/services/{self.service.pk}/actions/"

    def _body(self, action: str, *, role: str = "owner", reason: object = "moving") -> dict[str, object]:
        return {
            "customer_id": self.customer.pk, "user_id": self.users[role].pk, "action": action, "reason": reason,
            "submission_id": str(uuid4()),
        }

    def test_owner_cancel_request_creates_a_ticket_with_actor_and_audit(self) -> None:
        response = self.portal_post(self.path, self._body("cancel_request"))
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(Ticket.objects.filter(related_service=self.service).count(), 1)
        ticket = Ticket.objects.get(related_service=self.service)
        self.assertEqual(response.json(), {
            "success": True,
            "data": {"request_id": str(ServiceRequest.objects.get(ticket=ticket).pk), "ticket_id": ticket.pk,
                     "ticket_number": ticket.ticket_number},
        })
        self.assertEqual(ticket.customer, self.customer)
        self.assertEqual(ticket.category_id, SupportCategory.objects.get(name="Service Requests").pk)
        self.assertEqual(ticket.created_by, self.users["owner"])
        self.assertEqual(ticket.priority, "high")
        self.assertEqual(ticket.source, "api")
        self.assertEqual(ticket.title, "Cancellation request: web.example.com")
        self.assertEqual(ticket.description, "moving")
        self.assertEqual(ticket.contact_email, self.customer.primary_email)
        self.assertEqual(ticket.contact_person, self.customer.name)
        events = AuditEvent.objects.filter(
            action="support_ticket_created", content_type=ContentType.objects.get_for_model(Ticket),
            object_id=str(ticket.pk),
        )
        self.assertEqual(events.count(), 1)
        self.assertEqual(events.get().user_id, self.users["owner"].pk)
        self.assertEqual(Service.objects.get(pk=self.service.pk).status, "active")

    def test_tech_can_request_upgrade_but_not_cancel(self) -> None:
        upgrade = self.portal_post(self.path, self._body("upgrade_request", role="tech", reason=""))
        self.assertEqual(upgrade.status_code, 201, upgrade.content)
        ticket = Ticket.objects.get()
        self.assertEqual(ticket.created_by, self.users["tech"])
        self.assertEqual(ticket.priority, "normal")
        self.assertEqual(ticket.description, "Upgrade request")
        cancel = self.portal_post(self.path, self._body("cancel_request", role="tech"))
        self.assertEqual(cancel.status_code, 403, cancel.content)
        self.assertEqual(cancel.json(), {"success": False, "error": "Access denied."})
        self.assertEqual(list(Ticket.objects.values_list("pk", flat=True)), [ticket.pk])

    def test_viewer_is_denied(self) -> None:
        response = self.portal_post(self.path, self._body("upgrade_request", role="viewer"))
        self.assertEqual(response.status_code, 403, response.content)
        self.assertEqual(response.json(), {"success": False, "error": "Access denied"})
        self.assertFalse(Ticket.objects.exists())

    def test_foreign_service_is_404(self) -> None:
        response = self.portal_post(
            f"/api/services/{self.other_service.pk}/actions/", self._body("upgrade_request")
        )
        self.assertEqual(response.status_code, 404, response.content)
        self.assertEqual(response.json(), {"success": False, "error": "Service not found or access denied."})
        self.assertFalse(Ticket.objects.exists())

    def test_cancel_without_reason_is_400(self) -> None:
        for reason in ("", "   ", None, 123, "x" * 4001):
            with self.subTest(reason=reason):
                response = self.portal_post(self.path, self._body("cancel_request", reason=reason))
                self.assertEqual(response.status_code, 400, response.content)
                self.assertFalse(Ticket.objects.exists())

    def test_invalid_action_is_400(self) -> None:
        response = self.portal_post(self.path, self._body("terminate"))
        self.assertEqual(response.status_code, 400, response.content)
        self.assertIs(response.json()["success"], False)
        self.assertIn("action", response.json()["errors"])
        self.assertFalse(Ticket.objects.exists())

    def test_billing_can_request_suspension(self) -> None:
        response = self.portal_post(self.path, self._body("suspend_request", role="billing"))
        self.assertEqual(response.status_code, 201, response.content)
        ticket = Ticket.objects.get()
        self.assertEqual(ticket.created_by, self.users["billing"])
        self.assertEqual(ticket.priority, "normal")
        self.assertEqual(ticket.title, "Suspension request: web.example.com")

    def test_refund_ticket_category_is_created_without_sla_fields(self) -> None:
        self.client.force_login(self.users["owner"])
        order = Order.objects.create(
            customer=self.customer, currency=self.currency, order_number="ORD-REFUND-TEST",
            status="completed", customer_email=self.customer.primary_email, customer_name=self.customer.name,
        )
        invoice = Invoice.objects.create(
            customer=self.customer, currency=self.currency, number="INV-REFUND-TEST",
            status="paid", due_at=timezone.now(),
        )
        paths = (
            reverse("orders:order_refund_request", kwargs={"pk": order.pk}),
            reverse("billing:invoice_refund_request", kwargs={"pk": invoice.pk}),
        )
        for path in paths:
            with self.subTest(path=path):
                SupportCategory.objects.filter(name="Billing").delete()
                response = self.client.post(path, {
                    "refund_reason": "customer_request", "refund_notes": "Please refund this purchase.",
                })
                self.assertEqual(response.status_code, 200, response.content)
                self.assertTrue(response.json()["success"], response.content)
                category = SupportCategory.objects.get(name="Billing")
                self.assertEqual(category.name_en, "Billing")
                self.assertEqual(category.description, "Billing and refund related issues")
                self.assertEqual(category.icon, "credit-card")
                self.assertEqual(category.color, "#10B981")
                self.assertTrue(Ticket.objects.filter(customer=self.customer, category=category).exists())
