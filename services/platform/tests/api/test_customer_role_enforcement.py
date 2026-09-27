"""Role enforcement through signed customer API requests."""

import inspect
import time
from decimal import Decimal

from django.core.cache import cache
from django.test import RequestFactory, TestCase, override_settings

from apps.api.billing import views as billing_views
from apps.api.customers import views as customer_views
from apps.api.orders import views as order_views
from apps.api.secure_auth import BILLING_ROLES, get_authenticated_customer
from apps.api.services import views as service_views
from apps.api.tickets import views as ticket_views
from apps.billing.models import Currency, Invoice
from apps.customers.contact_models import CustomerAddress
from apps.customers.models import Customer
from apps.provisioning.service_models import Server, Service, ServicePlan
from apps.tickets.models import Ticket
from apps.users.models import CustomerMembership, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
class CustomerRoleEnforcementTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.customer = Customer.objects.create(
            name="Role Customer SRL",
            company_name="Role Customer SRL",
            customer_type="company",
            primary_email="roles@example.test",
            status="active",
        )
        self.users: dict[str, User] = {}
        for role in ("owner", "billing", "tech", "viewer"):
            user = User.objects.create_user(email=f"role-{role}@example.test")
            self.users[role] = user
            CustomerMembership.objects.create(
                customer=self.customer, user=user, role=role, is_active=True, is_primary=role == "owner"
            )
        self.outsider = User.objects.create_user(email="role-outsider@example.test")
        self.currency, _created = Currency.objects.get_or_create(
            code="RON", defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2}
        )
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="INV-ROLE-001",
            status="issued",
            subtotal_cents=1000,
            total_cents=1000,
        )

    def _payload(self, role: str, **extra: object) -> dict[str, object]:
        return {"customer_id": self.customer.pk, "user_id": self.users[role].pk, **extra}

    def test_viewer_is_denied_on_every_billing_read(self) -> None:
        for path in (
            "/api/billing/documents/",
            "/api/billing/invoices/",
            "/api/billing/summary/",
            "/api/billing/proformas/",
        ):
            with self.subTest(path=path, role="viewer"):
                response = self.portal_post(path, self._payload("viewer"))
                self.assertEqual(response.status_code, 403)
                self.assertEqual(response.json(), {"success": False, "error": "Access denied"})
            for role in ("owner", "billing"):
                with self.subTest(path=path, role=role):
                    response = self.portal_post(path, self._payload(role))
                    self.assertEqual(response.status_code, 200, response.content)
                    self.assertTrue(response.json()["success"])

    def test_tech_cannot_create_or_read_orders_but_can_open_tickets(self) -> None:
        for path in ("/api/orders/", "/api/orders/create/"):
            with self.subTest(path=path):
                response = self.portal_post(path, self._payload("tech"))
                self.assertEqual(response.status_code, 403)
                self.assertEqual(response.json(), {"success": False, "error": "Access denied"})
        response = self.portal_post(
            "/api/tickets/create/",
            self._payload("tech", title="Technical support", description="Please investigate the service."),
        )
        self.assertEqual(response.status_code, 201, response.content)
        self.assertTrue(Ticket.objects.filter(customer=self.customer, title="Technical support").exists())
        response = self.portal_post(
            "/api/tickets/create/",
            self._payload("viewer", title="Viewer ticket", description="This must not create a ticket."),
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Ticket.objects.filter(customer=self.customer, title="Viewer ticket").exists())

    def test_wrong_role_and_no_membership_produce_identical_denials(self) -> None:
        viewer = self.portal_post("/api/billing/documents/", self._payload("viewer"))
        outsider = self.portal_post(
            "/api/billing/documents/", {"customer_id": self.customer.pk, "user_id": self.outsider.pk}
        )
        self.assertEqual(viewer.status_code, 403)
        self.assertEqual(outsider.status_code, 403)
        self.assertEqual(viewer.json(), outsider.json())
        self.assertEqual(viewer.json(), {"success": False, "error": "Access denied"})

    def test_denied_billing_address_update_changes_nothing(self) -> None:
        CustomerAddress.objects.create(
            customer=self.customer,
            is_primary=True,
            is_billing=True,
            address_line1="Strada Test 1",
            city="Bucharest",
            county="Bucharest",
            postal_code="010000",
            country="RO",
        )
        before = list(CustomerAddress.objects.filter(customer=self.customer).order_by("pk").values())
        response = self.portal_post(
            "/api/customers/billing-address/",
            self._payload("viewer", city="Cluj-Napoca"),
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(list(CustomerAddress.objects.filter(customer=self.customer).order_by("pk").values()), before)

    def test_auto_renew_toggle_requires_billing_role(self) -> None:
        plan = ServicePlan.objects.create(
            name="Role Hosting",
            plan_type="shared_hosting",
            price_monthly=Decimal("29.99"),
            price_quarterly=Decimal("79.99"),
            price_annual=Decimal("299.99"),
        )
        server = Server.objects.create(
            name="Role Server",
            hostname="role-server.example.test",
            primary_ip="10.0.0.1",
            server_type="shared",
            status="active",
            location="Bucharest",
            datacenter="Test",
            cpu_model="Xeon",
            cpu_cores=8,
            ram_gb=32,
            disk_type="ssd",
            disk_capacity_gb=500,
            os_type="linux",
        )
        service = Service.objects.create(
            customer=self.customer,
            service_plan=plan,
            server=server,
            currency=self.currency,
            service_name="role.example.test",
            username="roleuser",
            status="active",
            domain="role.example.test",
            price=Decimal("29.99"),
            auto_renew=True,
        )
        path = f"/api/services/{service.pk}/auto-renew/"
        response = self.portal_post(path, self._payload("tech", auto_renew=False))
        self.assertEqual(response.status_code, 403)
        service.refresh_from_db()
        self.assertTrue(service.auto_renew)
        response = self.portal_post(path, self._payload("billing", auto_renew=False))
        self.assertEqual(response.status_code, 200, response.content)
        service.refresh_from_db()
        self.assertFalse(service.auto_renew)

    def test_decorated_views_keep_customer_as_second_positional_parameter(self) -> None:
        views = (
            billing_views.customer_invoices_api,
            billing_views.customer_billing_documents_api,
            billing_views.customer_invoice_detail_api,
            billing_views.customer_invoice_summary_api,
            billing_views.customer_proformas_api,
            billing_views.customer_proforma_detail_api,
            billing_views.invoice_pdf_export,
            billing_views.proforma_pdf_export,
            order_views.create_order,
            order_views.confirm_order,
            order_views.order_list,
            order_views.order_detail,
            customer_views.update_customer_billing_address,
            service_views.update_service_auto_renew_api,
            ticket_views.customer_ticket_create_api,
            ticket_views.customer_ticket_reply_api,
        )
        for view in views:
            with self.subTest(view=view):
                handler = view.cls.post
                originals = [
                    original
                    for cell in handler.__closure__ or ()
                    if (original := getattr(cell.cell_contents, "_praho_view", None)) is not None
                ]
                self.assertEqual(len(originals), 1)
                parameters = list(inspect.signature(originals[0]).parameters.values())
                self.assertGreaterEqual(len(parameters), 2)
                self.assertEqual(parameters[1].name, "customer")
                self.assertEqual(parameters[1].kind, inspect.Parameter.POSITIONAL_OR_KEYWORD)

    def test_roles_never_skip_membership_on_session_validate_path(self) -> None:
        request = RequestFactory().post(
            "/api/users/session/validate/",
            {"customer_id": self.customer.pk, "user_id": self.outsider.pk, "timestamp": time.time()},
            content_type="application/json",
        )
        request._portal_authenticated = True  # type: ignore[attr-defined]  # middleware contract
        customer, error = get_authenticated_customer(request, roles=BILLING_ROLES)
        self.assertIsNone(customer)
        self.assertIsNotNone(error)
        assert error is not None
        self.assertEqual(error.status_code, 403)
        self.assertEqual(error.data, {"success": False, "error": "Access denied"})

    def test_ticket_created_by_is_the_signed_user(self) -> None:
        response = self.portal_post(
            "/api/tickets/create/",
            self._payload("owner", title="Owner ticket", description="Please investigate this issue."),
        )
        self.assertEqual(response.status_code, 201, response.content)
        ticket = Ticket.objects.get(customer=self.customer, title="Owner ticket")
        self.assertEqual(ticket.created_by, self.users["owner"])

    def test_payment_endpoints_reject_tech_before_payload_validation(self) -> None:
        for path in ("/billing/create-payment-intent/", "/billing/confirm-payment/"):
            with self.subTest(path=path):
                response = self.portal_post(path, self._payload("tech"))
                self.assertEqual(response.status_code, 403, response.content[:400])
                self.assertEqual(response["Content-Type"], "application/json", response.content[:600])
                self.assertEqual(response.json(), {"success": False, "error": "Access denied"})
