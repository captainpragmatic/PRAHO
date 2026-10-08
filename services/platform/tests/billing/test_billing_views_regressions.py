# ===============================================================================
# COMPREHENSIVE BILLING VIEWS TESTS - Coverage maximization
# ===============================================================================
"""
Tests for apps/billing/views.py targeting all view functions, error paths,
edge cases, and API endpoints.
"""

from __future__ import annotations

import uuid
from datetime import date, timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.contrib.messages.middleware import MessageMiddleware
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import HttpResponse
from django.test import Client, RequestFactory, TestCase, override_settings
from django.utils import timezone

from apps.billing.currency_policy import get_selling_currency_policy
from apps.billing.models import (
    Currency,
    EFacturaDocument,
    Invoice,
    InvoiceSequence,
    Payment,
    ProformaInvoice,
    ProformaLine,
    ProformaSequence,
    Refund,
)
from apps.common.types import Ok
from apps.customers.models import Customer
from apps.users.models import CustomerMembership
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin, hmac_headers

User = get_user_model()


def _add_middleware(request):
    """Add session and message middleware to a RequestFactory request."""
    middleware = SessionMiddleware(lambda req: HttpResponse())
    middleware.process_request(request)
    request.session.save()
    middleware = MessageMiddleware(lambda req: HttpResponse())
    middleware.process_request(request)
    return request


class BillingViewsTestBase(TestCase):
    """Base class with common setup for billing views tests."""

    def setUp(self):
        self.factory = RequestFactory()
        self.client = Client()
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})

        # Staff user with billing role
        self.staff_user = User.objects.create_user(
            email="billing@test.ro",
            password="testpass123",
            is_staff=True,
            staff_role="billing",
        )

        # Admin user
        self.admin_user = User.objects.create_user(
            email="admin@test.ro",
            password="testpass123",
            is_staff=True,
            is_superuser=True,
            staff_role="admin",
        )

        # Regular user (non-staff)
        self.regular_user = User.objects.create_user(
            email="regular@test.ro",
            password="testpass123",
        )

        # Customer
        self.customer = Customer.objects.create(
            name="Test Company SRL",
            customer_type="company",
            company_name="Test Company SRL",
            primary_email="company@test.ro",
            status="active",
        )

        # Give regular user access to customer
        CustomerMembership.objects.create(
            user=self.regular_user,
            customer=self.customer,
            role="admin",
        )

        # Create sequences
        ProformaSequence.objects.get_or_create(scope="default")
        InvoiceSequence.objects.get_or_create(scope="default")

    def _create_invoice(self, **kwargs):
        defaults = {
            "customer": self.customer,
            "currency": self.currency,
            "number": f"INV-{Invoice.objects.count() + 1:05d}",
            "status": "issued",
            "total_cents": 10000,
            "subtotal_cents": 8403,
            "tax_cents": 1597,
            "due_at": timezone.now() + timedelta(days=14),
        }
        defaults.update(kwargs)
        return Invoice.objects.create(**defaults)

    def _create_proforma(self, **kwargs):
        defaults = {
            "customer": self.customer,
            "currency": self.currency,
            "number": f"PRO-{ProformaInvoice.objects.count() + 1:05d}",
            "status": "draft",
            "total_cents": 10000,
            "subtotal_cents": 8403,
            "tax_cents": 1597,
            "valid_until": timezone.now() + timedelta(days=30),
            "bill_to_name": "Test Company SRL",
            "bill_to_email": "company@test.ro",
        }
        defaults.update(kwargs)
        return ProformaInvoice.objects.create(**defaults)

    def _create_payment(self, invoice: Invoice, *, status: str = "pending", amount_cents: int = 1000) -> Payment:
        return Payment.objects.create(
            customer=invoice.customer,
            invoice=invoice,
            currency=invoice.currency,
            amount_cents=amount_cents,
            payment_method="bank",
            status=status,
        )

    def _create_efactura_document(
        self,
        *,
        number: str,
        status: str = "draft",
        upload_index: str = "",
    ) -> EFacturaDocument:
        return EFacturaDocument.objects.create(
            invoice=self._create_invoice(number=number),
            status=status,
            anaf_upload_index=upload_index,
        )


# ===============================================================================
# BILLING LIST VIEWS
# ===============================================================================


class BillingListViewTest(BillingViewsTestBase):
    """Tests for billing_list view."""

    def test_billing_list_staff_access(self):
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/invoices/")
        self.assertEqual(response.status_code, 200)

    def test_billing_list_anonymous_redirect(self):
        response = self.client.get("/billing/invoices/")
        self.assertEqual(response.status_code, 302)

    def test_billing_list_non_staff_redirect(self):
        self.client.force_login(self.regular_user)
        response = self.client.get("/billing/invoices/")
        self.assertEqual(response.status_code, 302)

    def test_billing_list_filter_by_type_proforma(self) -> None:
        proforma = self._create_proforma()
        invoice = self._create_invoice()
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/invoices/?type=proforma")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [(document["type"], document["id"]) for document in response.context["documents"]],
            [("proforma", proforma.pk)],
        )
        rows = self.client.get("/billing/invoices/list/?type=proforma")
        self.assertEqual(rows.status_code, 200)
        self.assertEqual(
            [(document["type"], document["id"]) for document in rows.context["documents"]],
            [("proforma", proforma.pk)],
        )
        self.assertContains(rows, proforma.number)
        self.assertNotContains(rows, invoice.display_number)

    def test_billing_list_filter_by_type_invoice(self) -> None:
        invoice = self._create_invoice()
        proforma = self._create_proforma()
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/invoices/?type=invoice")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [(document["type"], document["id"]) for document in response.context["documents"]],
            [("invoice", invoice.pk)],
        )
        rows = self.client.get("/billing/invoices/list/?type=invoice")
        self.assertEqual(rows.status_code, 200)
        self.assertEqual(
            [(document["type"], document["id"]) for document in rows.context["documents"]],
            [("invoice", invoice.pk)],
        )
        self.assertContains(rows, invoice.display_number)
        self.assertNotContains(rows, proforma.number)

    def test_billing_list_with_search(self) -> None:
        invoice = self._create_invoice(number="INV-SEARCH-001")
        excluded = self._create_invoice(number="INV-UNRELATED-001")
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/invoices/?search=SEARCH")
        self.assertEqual(response.status_code, 200)
        self.assertEqual([document["id"] for document in response.context["documents"]], [invoice.pk])
        rows = self.client.get("/billing/invoices/list/?search=SEARCH")
        self.assertEqual(rows.status_code, 200)
        self.assertEqual([document["id"] for document in rows.context["documents"]], [invoice.pk])
        self.assertContains(rows, invoice.display_number)
        self.assertNotContains(rows, excluded.display_number)

    def test_billing_list_pagination(self) -> None:
        invoices = [self._create_invoice(number=f"INV-PAGE-{index:03d}") for index in range(21)]
        expected_ids = [invoice.pk for invoice in reversed(invoices)]
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/invoices/?page=1")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["documents"].paginator.count, 21)
        self.assertEqual([document["id"] for document in response.context["documents"]], expected_ids[:20])

        second = self.client.get("/billing/invoices/?page=2")
        self.assertEqual(second.status_code, 200)
        self.assertEqual(second.context["documents"].number, 2)
        self.assertEqual([document["id"] for document in second.context["documents"]], expected_ids[20:])
        first_rows = self.client.get("/billing/invoices/list/?page=1")
        self.assertEqual(first_rows.status_code, 200)
        self.assertEqual([document["id"] for document in first_rows.context["documents"]], expected_ids[:20])
        self.assertContains(first_rows, invoices[-1].display_number)
        self.assertNotContains(first_rows, invoices[0].display_number)

        second_rows = self.client.get("/billing/invoices/list/?page=2")
        self.assertEqual(second_rows.status_code, 200)
        self.assertEqual([document["id"] for document in second_rows.context["documents"]], expected_ids[20:])
        self.assertContains(second_rows, invoices[0].display_number)
        self.assertNotContains(second_rows, invoices[-1].display_number)

    def test_billing_list_with_documents(self):
        self._create_invoice()
        self._create_proforma()
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/invoices/")
        self.assertEqual(response.status_code, 200)

    def test_billing_list_database_error(self):
        """Test that database errors are handled gracefully."""
        self.client.force_login(self.staff_user)
        with patch("apps.billing.views.Customer.objects") as mock_qs:
            mock_qs.values_list.side_effect = Exception("DB error")
            response = self.client.get("/billing/invoices/")
            self.assertEqual(response.status_code, 200)  # Renders error template


class ProformaListViewTest(BillingViewsTestBase):
    """Tests for proforma_list view."""

    def test_proforma_list_authenticated(self):
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/proformas/")
        self.assertEqual(response.status_code, 200)

    def test_proforma_list_with_search(self) -> None:
        proforma = self._create_proforma(number="PRO-SEARCH-001")
        excluded = self._create_proforma(number="PRO-UNRELATED-001")
        invoice = self._create_invoice(number="INV-SEARCH-001")
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/proformas/?search=SEARCH")
        self.assertEqual(response.status_code, 200)
        self.assertEqual([document["id"] for document in response.context["documents"]], [proforma.pk])
        self.assertEqual(response.context["doc_type"], "proforma")
        rows = self.client.get("/billing/invoices/list/", {"search": "SEARCH", "type": response.context["doc_type"]})
        self.assertEqual(rows.status_code, 200)
        self.assertEqual(
            [(document["type"], document["id"]) for document in rows.context["documents"]],
            [("proforma", proforma.pk)],
        )
        self.assertContains(rows, proforma.number)
        self.assertNotContains(rows, excluded.number)
        self.assertNotContains(rows, invoice.display_number)

    def test_proforma_list_anonymous_redirect(self):
        response = self.client.get("/billing/proformas/")
        self.assertEqual(response.status_code, 302)

    def test_proforma_list_database_error(self):
        self.client.force_login(self.staff_user)
        with patch("apps.billing.views.Customer.objects") as mock_qs:
            mock_qs.values_list.side_effect = Exception("DB error")
            response = self.client.get("/billing/proformas/")
            self.assertEqual(response.status_code, 200)


class BillingListHtmxViewTest(BillingViewsTestBase):
    """Tests for billing_list_htmx view."""

    def test_htmx_list_staff_access(self):
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/invoices/list/")
        self.assertEqual(response.status_code, 200)

    def test_htmx_list_filter_by_type(self) -> None:
        proforma = self._create_proforma()
        invoice = self._create_invoice()
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/invoices/list/?type=proforma")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [(document["type"], document["id"]) for document in response.context["documents"]],
            [("proforma", proforma.pk)],
        )
        self.assertContains(response, proforma.number)
        self.assertNotContains(response, invoice.display_number)

    def test_htmx_list_with_search(self) -> None:
        invoice = self._create_invoice(number="INV-SEARCH-001")
        excluded = self._create_invoice(number="INV-UNRELATED-001")
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/invoices/list/?search=SEARCH")
        self.assertEqual(response.status_code, 200)
        self.assertEqual([document["id"] for document in response.context["documents"]], [invoice.pk])
        self.assertContains(response, invoice.display_number)
        self.assertNotContains(response, excluded.display_number)

    def test_htmx_list_pagination(self) -> None:
        invoices = [self._create_invoice(number=f"INV-PAGE-{index:03d}") for index in range(21)]
        expected_ids = [invoice.pk for invoice in reversed(invoices)]
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/invoices/list/?page=1&type=all")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["documents"].paginator.count, 21)
        self.assertEqual([document["id"] for document in response.context["documents"]], expected_ids[:20])

        second = self.client.get("/billing/invoices/list/?page=2&type=all")
        self.assertEqual(second.status_code, 200)
        self.assertEqual(second.context["documents"].number, 2)
        self.assertEqual([document["id"] for document in second.context["documents"]], expected_ids[20:])
        self.assertContains(second, invoices[0].display_number)
        self.assertNotContains(second, invoices[-1].display_number)

    def test_htmx_list_database_error(self):
        self.client.force_login(self.staff_user)
        with patch("apps.billing.views.Customer.objects") as mock_qs:
            mock_qs.values_list.side_effect = Exception("DB error")
            response = self.client.get("/billing/invoices/list/")
            self.assertEqual(response.status_code, 200)

    def test_htmx_list_non_staff_redirect(self):
        self.client.force_login(self.regular_user)
        response = self.client.get("/billing/invoices/list/")
        self.assertEqual(response.status_code, 302)


# ===============================================================================
# INVOICE DETAIL / EDIT / PDF / SEND VIEWS
# ===============================================================================


class InvoiceDetailViewTest(BillingViewsTestBase):
    """Tests for invoice_detail view."""

    def test_invoice_detail_with_access(self):
        invoice = self._create_invoice()
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/invoices/{invoice.pk}/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["invoice"].pk, invoice.pk)
        self.assertContains(response, invoice.display_number)
        self.assertContains(response, self.customer.name)

    def test_invoice_detail_not_found(self):
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/invoices/99999/")
        self.assertEqual(response.status_code, 404)

    def test_invoice_detail_access_denied(self):
        """Regular user without membership should be redirected."""
        other_customer = Customer.objects.create(
            name="Other Co",
            customer_type="company",
            company_name="Other Co",
            status="active",
        )
        invoice = self._create_invoice(customer=other_customer)
        self.client.force_login(self.regular_user)
        response = self.client.get(f"/billing/invoices/{invoice.pk}/")
        self.assertEqual(response.status_code, 302)


class InvoiceEditViewTest(BillingViewsTestBase):
    """Tests for invoice_edit view."""

    def test_invoice_edit_get_draft(self) -> None:
        from apps.billing.invoice_models import InvoiceLine  # noqa: PLC0415

        invoice = self._create_invoice(status="draft")
        line = InvoiceLine.objects.create(
            invoice=invoice,
            kind="service",
            description="Existing WP14 hosting",
            quantity=Decimal("2.500"),
            unit_price_cents=125,
            tax_rate=Decimal("0.2100"),
        )
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/invoices/{invoice.pk}/edit/")
        self.assertContains(response, "Existing WP14 hosting")
        self.assertContains(response, f'name="line_0_id" value="{line.pk}"')
        self.assertContains(response, 'value="2.500"')
        self.assertContains(response, 'value="1.25"')
        self.assertIn(self.customer, response.context["customers"])
        for field in ("issued_at", "number", "status", "line_0_vat_rate"):
            self.assertNotContains(response, f'name="{field}"')
        self.assertContains(
            self.client.get(f"/billing/invoices/{invoice.pk}/"), f"/billing/invoices/{invoice.pk}/edit/"
        )

    def test_invoice_edit_non_draft_redirect(self):
        invoice = self._create_invoice(status="issued")
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/invoices/{invoice.pk}/edit/")
        self.assertEqual(response.status_code, 302)

    def test_invoice_edit_post_draft(self) -> None:
        from django.contrib.messages import get_messages  # noqa: PLC0415

        from apps.billing.invoice_models import InvoiceLine  # noqa: PLC0415
        from apps.provisioning.models import Service, ServicePlan  # noqa: PLC0415

        invoice = self._create_invoice(status="draft", number=None, meta={"keep": "untouched"})
        plan = ServicePlan.objects.create(name="WP14 plan", plan_type="shared_hosting", price_monthly=Decimal("10"))
        service = Service.objects.create(
            customer=self.customer,
            service_plan=plan,
            currency=self.currency,
            service_name="WP14 hosting",
            username="wp14",
            price=Decimal("10"),
            billing_cycle="monthly",
        )
        line = InvoiceLine.objects.create(
            invoice=invoice,
            service=service,
            kind="service",
            description="Original hosting",
            quantity=Decimal("1"),
            unit_price_cents=1000,
            tax_rate=Decimal("0.2100"),
            tax_category_code="S",
        )
        removed = InvoiceLine.objects.create(
            invoice=invoice,
            kind="misc",
            description="Remove this line",
            unit_price_cents=500,
        )
        self.client.force_login(self.staff_user)
        response = self.client.post(
            f"/billing/invoices/{invoice.pk}/edit/",
            {
                "customer": str(invoice.customer_id),
                "currency": invoice.currency_id,
                "due_at": "2026-11-01",
                "public_notes": "Updated draft",
                "line_0_id": str(line.pk),
                "line_0_description": "Updated hosting",
                "line_0_quantity": "2.3456",
                "line_0_unit_price": "10.005",
            },
        )
        line.refresh_from_db()
        self.assertEqual(line.description, "Updated hosting")
        self.assertEqual((line.quantity, line.unit_price_cents), (Decimal("2.346"), 1001))
        self.assertEqual(line.service_id, service.pk)
        self.assertEqual((line.tax_rate, line.tax_category_code), (Decimal("0.2100"), "S"))
        self.assertFalse(InvoiceLine.objects.filter(pk=removed.pk).exists())
        self.assertEqual(list(invoice.lines.values_list("pk", flat=True)), [line.pk])
        invoice.refresh_from_db()
        self.assertEqual((invoice.subtotal_cents, invoice.tax_cents, invoice.total_cents), (2348, 493, 2841))
        self.assertEqual(timezone.localdate(invoice.due_at).isoformat(), "2026-11-01")
        self.assertEqual(invoice.meta, {"keep": "untouched", "public_notes": "Updated draft"})
        self.assertEqual((invoice.status, invoice.number, invoice.issued_at), ("draft", None, None))
        self.assertRedirects(response, f"/billing/invoices/{invoice.pk}/", fetch_redirect_response=False)
        self.assertIn(invoice.display_number, " ".join(str(message) for message in get_messages(response.wsgi_request)))

    def test_invoice_edit_no_access(self):
        other_customer = Customer.objects.create(
            name="Noaccess Co", customer_type="company", company_name="Noaccess Co", status="active"
        )
        invoice = self._create_invoice(customer=other_customer, status="draft")
        # Use a regular user who doesn't have access but has billing role
        _no_access_user = User.objects.create_user(
            email="noaccess@test.ro", password="testpass123", is_staff=True, staff_role="billing"
        )
        # staff can_access_customer returns True for staff users, so test with non-staff
        self.client.force_login(self.regular_user)
        response = self.client.get(f"/billing/invoices/{invoice.pk}/edit/")
        # regular_user doesn't have billing_staff_required
        self.assertEqual(response.status_code, 302)


class InvoicePdfViewTest(BillingViewsTestBase):
    """Tests for invoice_pdf view."""

    @patch("apps.billing.issuers.documents.get_invoice_pdf_bytes")
    def test_invoice_pdf_success(self, mock_get_bytes):
        """Staff download goes through the issuer chokepoint, not the renderer.

        Rendering here directly would hand staff a second, unofficial copy of a
        provider-issued legal document - one that differs from what the customer
        received and what ANAF holds.
        """
        mock_get_bytes.return_value = Ok(b"%PDF")
        invoice = self._create_invoice()
        self.client.force_login(self.staff_user)

        response = self.client.get(f"/billing/invoices/{invoice.pk}/pdf/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pdf")
        mock_get_bytes.assert_called_once()
        self.assertEqual(mock_get_bytes.call_args.args[0].pk, invoice.pk)

    def test_invoice_pdf_not_found(self):
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/invoices/99999/pdf/")
        self.assertEqual(response.status_code, 404)

    def test_invoice_pdf_access_denied(self):
        other_customer = Customer.objects.create(
            name="PdfDeny Co", customer_type="company", company_name="PdfDeny Co", status="active"
        )
        invoice = self._create_invoice(customer=other_customer)
        self.client.force_login(self.regular_user)
        response = self.client.get(f"/billing/invoices/{invoice.pk}/pdf/")
        self.assertEqual(response.status_code, 302)


class InvoiceSendViewTest(BillingViewsTestBase):
    """Tests for invoice_send view."""

    def test_invoice_send_post(self):
        invoice = self._create_invoice()
        self.client.force_login(self.staff_user)
        response = self.client.post(f"/billing/invoices/{invoice.pk}/send/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])

    def test_invoice_send_get_method_not_allowed(self):
        invoice = self._create_invoice()
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/invoices/{invoice.pk}/send/")
        self.assertEqual(response.status_code, 405)

    def test_invoice_send_no_access(self):
        other_customer = Customer.objects.create(
            name="SendDeny Co", customer_type="company", company_name="SendDeny Co", status="active"
        )
        invoice = self._create_invoice(customer=other_customer)
        # Non-staff user can't pass billing_staff_required
        self.client.force_login(self.regular_user)
        response = self.client.post(f"/billing/invoices/{invoice.pk}/send/")
        self.assertEqual(response.status_code, 302)


# ===============================================================================
# PROFORMA VIEWS
# ===============================================================================


class ProformaCreateViewTest(BillingViewsTestBase):
    """Tests for proforma_create view."""

    def policy_fields(self):
        policy = get_selling_currency_policy()
        return {"currency": policy.currency_code, "currency_revision": policy.revision}

    def test_proforma_create_get(self):
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/proformas/create/")
        self.assertEqual(response.status_code, 200)

    def test_proforma_create_post_success(self):
        self.client.force_login(self.admin_user)
        response = self.client.post(
            "/billing/proformas/create/",
            {
                **self.policy_fields(),
                "customer": str(self.customer.pk),
                "valid_until": (timezone.now() + timedelta(days=30)).strftime("%Y-%m-%d"),
                "bill_to_name": "Test Company SRL",
                "bill_to_email": "company@test.ro",
                "line_0_description": "Hosting",
                "line_0_quantity": "1",
                "line_0_unit_price": "100.00",
                "line_0_vat_rate": "21",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(ProformaInvoice.objects.filter(customer=self.customer).exists())

    def test_proforma_create_post_no_customer(self):
        self.client.force_login(self.admin_user)
        response = self.client.post("/billing/proformas/create/", {})
        self.assertEqual(response.status_code, 302)

    def test_proforma_create_post_invalid_customer(self):
        self.client.force_login(self.admin_user)
        response = self.client.post("/billing/proformas/create/", {"customer": "99999"})
        self.assertEqual(response.status_code, 302)

    def test_proforma_create_post_invalid_date(self):
        self.client.force_login(self.admin_user)
        response = self.client.post(
            "/billing/proformas/create/",
            {
                **self.policy_fields(),
                "customer": str(self.customer.pk),
                "valid_until": "not-a-date",
            },
        )
        self.assertEqual(response.status_code, 302)

    def test_proforma_create_post_invalid_line_quantity(self):
        self.client.force_login(self.admin_user)
        response = self.client.post(
            "/billing/proformas/create/",
            {
                **self.policy_fields(),
                "customer": str(self.customer.pk),
                "line_0_description": "Bad line",
                "line_0_quantity": "abc",
                "line_0_unit_price": "100",
                "line_0_vat_rate": "21",
            },
        )
        self.assertEqual(response.status_code, 302)

    def test_proforma_create_post_invalid_unit_price(self):
        self.client.force_login(self.admin_user)
        response = self.client.post(
            "/billing/proformas/create/",
            {
                **self.policy_fields(),
                "customer": str(self.customer.pk),
                "line_0_description": "Bad line",
                "line_0_quantity": "1",
                "line_0_unit_price": "abc",
                "line_0_vat_rate": "21",
            },
        )
        self.assertEqual(response.status_code, 302)

    def test_proforma_create_post_invalid_vat_rate(self):
        self.client.force_login(self.admin_user)
        response = self.client.post(
            "/billing/proformas/create/",
            {
                **self.policy_fields(),
                "customer": str(self.customer.pk),
                "line_0_description": "Bad line",
                "line_0_quantity": "1",
                "line_0_unit_price": "100",
                "line_0_vat_rate": "abc",
            },
        )
        self.assertEqual(response.status_code, 302)


class ProformaDetailViewTest(BillingViewsTestBase):
    """Tests for proforma_detail view."""

    def test_proforma_detail_with_access(self):
        proforma = self._create_proforma()
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/proformas/{proforma.pk}/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["proforma"].pk, proforma.pk)
        self.assertContains(response, proforma.number)
        self.assertContains(response, proforma.bill_to_name)

    def test_proforma_detail_not_found(self):
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/proformas/99999/")
        self.assertEqual(response.status_code, 404)


class ProformaEditViewTest(BillingViewsTestBase):
    """Tests for proforma_edit view."""

    def test_proforma_edit_get(self) -> None:
        proforma = self._create_proforma()
        line = ProformaLine.objects.create(
            proforma=proforma,
            description="Existing proforma hosting",
            quantity=Decimal("2.500"),
            unit_price_cents=125,
            tax_rate=Decimal("0.2100"),
        )
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/proformas/{proforma.pk}/edit/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["proforma"].pk, proforma.pk)
        self.assertEqual([row.pk for row in response.context["lines"]], [line.pk])
        self.assertContains(response, "Existing proforma hosting")
        self.assertContains(response, proforma.bill_to_name)
        self.assertContains(response, proforma.bill_to_email)

    def test_proforma_line_edit_resets_document_discount(self):
        """#188: manually editing proforma lines sets explicit prices, so the stored
        document discount is reset to 0 — keeping subtotal = Σ(line gross) consistent."""
        from apps.billing.views import _process_proforma_line_items  # noqa: PLC0415

        proforma = self._create_proforma()
        proforma.discount_cents = 1000
        proforma.save(update_fields=["discount_cents"])

        errors = _process_proforma_line_items(
            proforma,
            {
                "line_0_description": "Hosting",
                "line_0_quantity": "1",
                "line_0_unit_price": "100.00",
                "line_0_vat_rate": "19",
            },
        )
        self.assertEqual(errors, [])
        self.assertEqual(proforma.discount_cents, 0)
        self.assertEqual(proforma.subtotal_cents, 10000)

    def test_proforma_edit_expired(self):
        proforma = self._create_proforma(valid_until=timezone.now() - timedelta(days=1))
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/proformas/{proforma.pk}/edit/")
        self.assertEqual(response.status_code, 302)

    def test_proforma_edit_post_success(self):
        proforma = self._create_proforma()
        self.client.force_login(self.admin_user)
        response = self.client.post(
            f"/billing/proformas/{proforma.pk}/edit/",
            {
                "customer": str(self.customer.pk),
                "valid_until": (timezone.now() + timedelta(days=30)).strftime("%Y-%m-%d"),
                "bill_to_name": "Updated Name",
                "bill_to_email": "updated@test.ro",
                "bill_to_tax_id": "RO12345",
                "line_0_description": "Updated service",
                "line_0_quantity": "2",
                "line_0_unit_price": "50.00",
                "line_0_vat_rate": "21",
            },
        )
        self.assertEqual(response.status_code, 302)

    def test_proforma_edit_post_no_customer(self):
        proforma = self._create_proforma()
        self.client.force_login(self.admin_user)
        response = self.client.post(f"/billing/proformas/{proforma.pk}/edit/", {})
        self.assertEqual(response.status_code, 302)


class ProformaPdfViewTest(BillingViewsTestBase):
    """Tests for proforma_pdf view."""

    @patch("apps.billing.views.RomanianProformaPDFGenerator")
    def test_proforma_pdf_success(self, mock_gen_cls: MagicMock) -> None:
        mock_gen = MagicMock()
        pdf_bytes = b"%PDF-1.4\nWP19 proforma document\n%%EOF"
        mock_gen.generate_response.return_value = HttpResponse(pdf_bytes, content_type="application/pdf")
        mock_gen_cls.return_value = mock_gen
        proforma = self._create_proforma()
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/proformas/{proforma.pk}/pdf/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pdf")
        self.assertEqual(response.content, pdf_bytes)
        mock_gen_cls.assert_called_once_with(proforma)
        mock_gen.generate_response.assert_called_once_with()


class ProformaSendViewTest(BillingViewsTestBase):
    """Tests for proforma_send view."""

    def test_proforma_send_post(self):
        proforma = self._create_proforma()
        self.client.force_login(self.staff_user)
        response = self.client.post(f"/billing/proformas/{proforma.pk}/send/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])

    def test_proforma_send_get(self):
        proforma = self._create_proforma()
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/proformas/{proforma.pk}/send/")
        self.assertEqual(response.status_code, 405)

    def test_proforma_send_no_access(self):
        other_customer = Customer.objects.create(
            name="NoSend Co", customer_type="company", company_name="NoSend Co", status="active"
        )
        proforma = self._create_proforma(customer=other_customer)
        # regular_user can't pass billing_staff_required
        self.client.force_login(self.regular_user)
        response = self.client.post(f"/billing/proformas/{proforma.pk}/send/")
        self.assertEqual(response.status_code, 302)


class ProformaToInvoiceViewTest(BillingViewsTestBase):
    """Tests for proforma_to_invoice view.

    Manual conversion was removed in Phase B. The view now always redirects to
    proforma_detail with an error message regardless of HTTP method.
    """

    def test_convert_get(self):
        # Manual conversion is removed — GET now redirects with error message
        proforma = self._create_proforma()
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/proformas/{proforma.pk}/convert/")
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, f"/billing/proformas/{proforma.pk}/", fetch_redirect_response=False)

    def test_convert_post_success(self):
        # Manual conversion is removed — POST also redirects with error message
        # No invoice is created; conversion only happens via ProformaPaymentService
        proforma = self._create_proforma()
        ProformaLine.objects.create(
            proforma=proforma,
            kind="service",
            description="Test Service",
            quantity=1,
            unit_price_cents=8403,
            tax_rate=Decimal("0.19"),
            line_total_cents=10000,
        )
        self.client.force_login(self.staff_user)
        response = self.client.post(f"/billing/proformas/{proforma.pk}/convert/")
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, f"/billing/proformas/{proforma.pk}/", fetch_redirect_response=False)
        # No invoice should be created — conversion is automatic, not manual
        self.assertFalse(Invoice.objects.filter(converted_from_proforma=proforma).exists())

    def test_convert_expired_proforma(self):
        proforma = self._create_proforma(valid_until=timezone.now() - timedelta(days=1))
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/proformas/{proforma.pk}/convert/")
        self.assertEqual(response.status_code, 302)

    def test_convert_already_converted(self):
        proforma = self._create_proforma()
        self._create_invoice(converted_from_proforma=proforma)
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/proformas/{proforma.pk}/convert/")
        self.assertEqual(response.status_code, 302)

    def test_convert_no_access(self):
        other_customer = Customer.objects.create(
            name="Convert Deny Co", customer_type="company", company_name="Convert Deny Co", status="active"
        )
        proforma = self._create_proforma(customer=other_customer)
        # Non-staff fails billing_staff_required
        self.client.force_login(self.regular_user)
        response = self.client.post(f"/billing/proformas/{proforma.pk}/convert/")
        self.assertEqual(response.status_code, 302)


# ===============================================================================
# PAYMENT VIEWS
# ===============================================================================


class PaymentListViewTest(BillingViewsTestBase):
    """Tests for payment_list view."""

    def test_payment_list_authenticated(self):
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/payments/")
        self.assertEqual(response.status_code, 200)

    def test_payment_list_with_status_filter(self) -> None:
        invoice = self._create_invoice()
        succeeded = self._create_payment(invoice, status="succeeded")
        self._create_payment(invoice, status="pending")
        self._create_payment(invoice, status="failed")
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/payments/?status=succeeded")
        self.assertEqual(response.status_code, 200)
        self.assertEqual([payment.pk for payment in response.context["payments"]], [succeeded.pk])

    def test_payment_list_with_invoice_filter(self) -> None:
        invoice = self._create_invoice()
        payment = self._create_payment(invoice)
        other_invoice = self._create_invoice()
        self._create_payment(other_invoice, amount_cents=2000)
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/payments/?invoice={invoice.pk}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual([row.pk for row in response.context["payments"]], [payment.pk])
        self.assertContains(response, "10,00 RON", count=2)
        self.assertNotContains(response, "20,00 RON")

    def test_payment_list_anonymous_redirect(self):
        response = self.client.get("/billing/payments/")
        self.assertEqual(response.status_code, 302)


class ProcessPaymentViewTest(BillingViewsTestBase):
    """Tests for process_payment view."""

    def test_process_payment_post_success(self):
        invoice = self._create_invoice()
        self.client.force_login(self.staff_user)
        response = self.client.post(
            f"/billing/invoices/{invoice.pk}/pay/",
            {"amount": "100.00", "payment_method": "bank"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])

    def test_process_payment_invalid_amount(self):
        invoice = self._create_invoice()
        self.client.force_login(self.staff_user)
        response = self.client.post(
            f"/billing/invoices/{invoice.pk}/pay/",
            {"amount": "not-a-number", "payment_method": "bank"},
        )
        self.assertEqual(response.status_code, 400)

    def test_process_payment_get_method(self):
        invoice = self._create_invoice()
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/invoices/{invoice.pk}/pay/")
        self.assertEqual(response.status_code, 405)

    def test_process_payment_marks_paid(self):
        invoice = self._create_invoice(total_cents=10000)
        self.client.force_login(self.staff_user)
        response = self.client.post(
            f"/billing/invoices/{invoice.pk}/pay/",
            {"amount": "100.00", "payment_method": "bank"},
        )
        self.assertEqual(response.status_code, 200)
        invoice.refresh_from_db()
        self.assertEqual(invoice.status, "paid")
        payment = invoice.payments.get()
        self.assertEqual(payment.status, "succeeded")
        self.assertEqual(payment.payment_method, "bank")

    def test_process_payment_rejects_unverified_gateway_method(self):
        invoice = self._create_invoice(total_cents=10000)
        self.client.force_login(self.staff_user)

        response = self.client.post(
            f"/billing/invoices/{invoice.pk}/pay/",
            {"amount": "100.00", "payment_method": "stripe"},
        )

        self.assertEqual(response.status_code, 400)
        self.assertFalse(invoice.payments.exists())

    def test_process_payment_rejects_unresolved_automatic_card_attempt(self):
        from apps.billing.payment_models import Payment  # noqa: PLC0415

        invoice = self._create_invoice(total_cents=10000)
        pending = Payment.objects.create(
            invoice=invoice,
            customer=self.customer,
            payment_method="stripe",
            amount_cents=invoice.total_cents,
            currency=self.currency,
            meta={"source": "recurring_billing"},
        )
        self.client.force_login(self.staff_user)

        response = self.client.post(
            f"/billing/invoices/{invoice.pk}/pay/",
            {"amount": "100.00", "payment_method": "bank"},
        )

        self.assertEqual(response.status_code, 409)
        self.assertIn("automatic card payment", response.json()["error"].lower())
        self.assertEqual(invoice.payments.count(), 1)
        pending.refresh_from_db()
        self.assertEqual(pending.status, "pending")

    def test_process_payment_routes_offline_success_through_local_convergence(self):
        invoice = self._create_invoice(total_cents=10000)
        convergence_result = MagicMock()
        convergence_result.is_err.return_value = False
        self.client.force_login(self.staff_user)

        with patch(
            "apps.billing.payment_convergence.PaymentSuccessService.converge_local_paid_document",
            return_value=convergence_result,
        ) as converge:
            response = self.client.post(
                f"/billing/invoices/{invoice.pk}/pay/",
                {"amount": "100.00", "payment_method": "bank"},
            )

        self.assertEqual(response.status_code, 200)
        converge.assert_called_once_with(invoice.payments.get().id)

    def test_process_payment_invalid_method_rejected(self):
        """Invalid payment methods are now rejected with 400 (strict allowlist)."""
        invoice = self._create_invoice()
        self.client.force_login(self.staff_user)
        response = self.client.post(
            f"/billing/invoices/{invoice.pk}/pay/",
            {"amount": "100.00", "payment_method": "bitcoin"},
        )
        self.assertEqual(response.status_code, 400)


class ProcessProformaPaymentViewTest(BillingViewsTestBase):
    """Tests for process_proforma_payment view.

    Phase B: The view now delegates to ProformaPaymentService.record_payment_and_convert()
    and returns redirects (not JSON) on both success and failure.
    """

    def test_proforma_payment_post_new_conversion(self):
        # View delegates to ProformaPaymentService; on success or error it redirects
        proforma = self._create_proforma()
        self.client.force_login(self.staff_user)
        response = self.client.post(
            f"/billing/proformas/{proforma.pk}/pay/",
            {"amount": "100.00", "payment_method": "bank"},
        )
        # Service is called and returns a redirect (302) regardless of outcome
        self.assertEqual(response.status_code, 302)

    def test_proforma_payment_already_converted(self):
        # Idempotent: already-converted proforma returns Ok(existing_invoice); view redirects
        proforma = self._create_proforma(status="converted")
        self._create_invoice(converted_from_proforma=proforma)
        self.client.force_login(self.staff_user)
        response = self.client.post(
            f"/billing/proformas/{proforma.pk}/pay/",
            {"amount": "100.00", "payment_method": "bank"},
        )
        self.assertEqual(response.status_code, 302)

    def test_proforma_payment_get_method(self):
        proforma = self._create_proforma()
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/proformas/{proforma.pk}/pay/")
        self.assertEqual(response.status_code, 405)

    def test_proforma_payment_no_access(self):
        other_customer = Customer.objects.create(
            name="PayDeny Co", customer_type="company", company_name="PayDeny Co", status="active"
        )
        proforma = self._create_proforma(customer=other_customer)
        self.client.force_login(self.regular_user)
        response = self.client.post(f"/billing/proformas/{proforma.pk}/pay/")
        self.assertEqual(response.status_code, 302)


# ===============================================================================
# E-FACTURA VIEWS
# ===============================================================================


class GenerateEFacturaViewTest(BillingViewsTestBase):
    """Tests for generate_e_factura view."""

    @override_settings(
        COMPANY_NAME="Test Company SRL",
        EFACTURA_COMPANY_CUI="12345678",
        COMPANY_STREET="Test Street 123",
        COMPANY_CITY="Bucharest",
        COMPANY_POSTAL_CODE="010101",
        COMPANY_COUNTRY_CODE="RO",
        COMPANY_BANK_ACCOUNT="RO49AAAA1B31007593840000",
        COMPANY_BANK_NAME="Test Bank",
    )
    def test_generate_efactura_success(self):
        # A complete, issued invoice generates the canonical CIUS-RO XML. The staff
        # download now routes through UBLInvoiceBuilder (#188), which requires real data.
        invoice = self._create_invoice(
            issued_at=timezone.now(),
            bill_to_name="Customer SRL",
            bill_to_country="RO",
            bill_to_tax_id="RO87654321",
        )
        from tests.factories import InvoiceLineFactory  # noqa: PLC0415

        InvoiceLineFactory(
            invoice=invoice,
            description="Service",
            unit_price_cents=8403,
            quantity=1,
            tax_rate=Decimal("0.19"),
        )
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/invoices/{invoice.pk}/e-factura/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/xml")

    def test_generate_efactura_no_access(self):
        other_customer = Customer.objects.create(
            name="EFDeny Co", customer_type="company", company_name="EFDeny Co", status="active"
        )
        invoice = self._create_invoice(customer=other_customer)
        self.client.force_login(self.regular_user)
        response = self.client.get(f"/billing/invoices/{invoice.pk}/e-factura/")
        self.assertEqual(response.status_code, 302)


class EFacturaDashboardViewTest(BillingViewsTestBase):
    """Tests for efactura_dashboard view."""

    def test_dashboard_staff_access(self):
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/e-factura/")
        self.assertEqual(response.status_code, 200)

    def test_dashboard_non_staff_redirect(self):
        self.client.force_login(self.regular_user)
        response = self.client.get("/billing/e-factura/")
        self.assertEqual(response.status_code, 302)

    def test_dashboard_with_status_filter(self) -> None:
        draft = self._create_efactura_document(number="INV-DRAFT")
        accepted = self._create_efactura_document(number="INV-ACCEPTED", status="accepted")
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/e-factura/?status=draft")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["status_filter"], "draft")
        self.assertEqual([document.pk for document in response.context["documents_page"]], [draft.pk])
        self.assertContains(response, draft.invoice.number)
        self.assertNotContains(response, accepted.invoice.number)


class EFacturaDocumentDetailViewTest(BillingViewsTestBase):
    """Tests for efactura_document_detail view."""

    def test_detail_not_found(self):
        self.client.force_login(self.staff_user)
        fake_uuid = str(uuid.uuid4())
        response = self.client.get(f"/billing/e-factura/{fake_uuid}/")
        self.assertEqual(response.status_code, 404)

    def test_detail_with_document(self):
        from apps.billing.efactura.models import EFacturaDocument  # noqa: PLC0415

        invoice = self._create_invoice()
        doc = EFacturaDocument.objects.create(
            invoice=invoice,
            status="draft",
            anaf_upload_index="",
        )
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/e-factura/{doc.pk}/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["document"].pk, doc.pk)
        self.assertEqual(response.context["invoice"].pk, invoice.pk)
        self.assertContains(response, invoice.number)


class EFacturaSubmitViewTest(BillingViewsTestBase):
    """Tests for efactura_submit view."""

    @patch("apps.billing.efactura.service.EFacturaService")
    def test_submit_success(self, mock_svc_cls):
        mock_svc = MagicMock()
        mock_result = MagicMock()
        mock_result.success = True
        mock_svc.submit_invoice.return_value = mock_result
        mock_svc_cls.return_value = mock_svc

        invoice = self._create_invoice()
        self.client.force_login(self.staff_user)
        response = self.client.post(f"/billing/e-factura/{invoice.pk}/submit/")
        self.assertEqual(response.status_code, 302)

    @patch("apps.billing.efactura.service.EFacturaService")
    def test_submit_failure(self, mock_svc_cls):
        mock_svc = MagicMock()
        mock_result = MagicMock()
        mock_result.success = False
        mock_result.message = "Validation failed"
        mock_svc.submit_invoice.return_value = mock_result
        mock_svc_cls.return_value = mock_svc

        invoice = self._create_invoice()
        self.client.force_login(self.staff_user)
        response = self.client.post(f"/billing/e-factura/{invoice.pk}/submit/")
        self.assertEqual(response.status_code, 302)

    def test_submit_get_not_allowed(self):
        invoice = self._create_invoice()
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/e-factura/{invoice.pk}/submit/")
        self.assertEqual(response.status_code, 405)


class EFacturaRetryViewTest(BillingViewsTestBase):
    """Tests for efactura_retry view."""

    def test_retry_not_found(self):
        self.client.force_login(self.staff_user)
        fake_uuid = str(uuid.uuid4())
        response = self.client.post(f"/billing/e-factura/{fake_uuid}/retry/")
        self.assertEqual(response.status_code, 404)

    def test_retry_cannot_retry(self):
        from apps.billing.efactura.models import EFacturaDocument  # noqa: PLC0415

        invoice = self._create_invoice()
        doc = EFacturaDocument.objects.create(
            invoice=invoice,
            status="accepted",  # Terminal state, can't retry
        )
        self.client.force_login(self.staff_user)
        response = self.client.post(f"/billing/e-factura/{doc.pk}/retry/")
        self.assertEqual(response.status_code, 302)

    @patch("apps.billing.efactura.service.EFacturaService")
    def test_retry_success(self, mock_svc_cls):
        from apps.billing.efactura.models import EFacturaDocument  # noqa: PLC0415

        mock_svc = MagicMock()
        mock_result = MagicMock()
        mock_result.success = True
        mock_svc.retry_failed_submission.return_value = mock_result
        mock_svc_cls.return_value = mock_svc

        invoice = self._create_invoice()
        doc = EFacturaDocument.objects.create(
            invoice=invoice,
            status="error",
            retry_count=0,
        )
        self.client.force_login(self.staff_user)
        response = self.client.post(f"/billing/e-factura/{doc.pk}/retry/")
        self.assertEqual(response.status_code, 302)

    @patch("apps.billing.efactura.service.EFacturaService")
    def test_retry_failure(self, mock_svc_cls):
        from apps.billing.efactura.models import EFacturaDocument  # noqa: PLC0415

        mock_svc = MagicMock()
        mock_result = MagicMock()
        mock_result.success = False
        mock_result.message = "Retry failed"
        mock_svc.retry_failed_submission.return_value = mock_result
        mock_svc_cls.return_value = mock_svc

        invoice = self._create_invoice()
        doc = EFacturaDocument.objects.create(
            invoice=invoice,
            status="error",
            retry_count=0,
        )
        self.client.force_login(self.staff_user)
        response = self.client.post(f"/billing/e-factura/{doc.pk}/retry/")
        self.assertEqual(response.status_code, 302)


class EFacturaDocumentsHtmxViewTest(BillingViewsTestBase):
    """Tests for efactura_documents_htmx view."""

    def test_htmx_documents_list(self):
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/e-factura/documents/")
        self.assertEqual(response.status_code, 200)

    def test_htmx_documents_with_status_filter(self) -> None:
        draft = self._create_efactura_document(number="INV-DRAFT")
        accepted = self._create_efactura_document(number="INV-ACCEPTED", status="accepted")
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/e-factura/documents/?status=draft")
        self.assertEqual(response.status_code, 200)
        self.assertEqual([document.pk for document in response.context["documents_page"]], [draft.pk])
        self.assertContains(response, draft.invoice.number)
        self.assertNotContains(response, accepted.invoice.number)

    def test_htmx_documents_with_search(self) -> None:
        invoice_match = self._create_efactura_document(number="INV-SEARCH-001")
        upload_match = self._create_efactura_document(number="OTHER-UPLOAD", upload_index="SEARCH-UPLOAD")
        excluded = self._create_efactura_document(number="OTHER-EXCLUDED", upload_index="UNRELATED")
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/e-factura/documents/?q=SEARCH")
        self.assertEqual(response.status_code, 200)
        self.assertCountEqual(
            [document.pk for document in response.context["documents_page"]],
            [invoice_match.pk, upload_match.pk],
        )
        self.assertContains(response, invoice_match.invoice.number)
        self.assertContains(response, upload_match.invoice.number)
        self.assertNotContains(response, excluded.invoice.number)


# ===============================================================================
# REPORTS VIEWS
# ===============================================================================


class BillingReportsViewTest(BillingViewsTestBase):
    """Tests for billing_reports view."""

    def test_reports_staff_access(self):
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/reports/")
        self.assertEqual(response.status_code, 200)

    def test_reports_non_staff_redirect(self):
        self.client.force_login(self.regular_user)
        response = self.client.get("/billing/reports/")
        self.assertEqual(response.status_code, 302)

    def test_reports_with_data(self):
        self._create_invoice(status="paid")
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/reports/")
        self.assertEqual(response.status_code, 200)


class VatReportViewTest(BillingViewsTestBase):
    """Tests for vat_report view."""

    def test_vat_report_staff_access(self):
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/reports/vat/")
        self.assertEqual(response.status_code, 200)

    def test_vat_report_with_dates(self) -> None:
        invoice = self._create_invoice(
            number="INV-VAT-INCLUDED",
            tax_point_date=date(2025, 6, 1),
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
        )
        self._create_invoice(
            number="INV-VAT-EXCLUDED",
            tax_point_date=date(2024, 12, 31),
            subtotal_cents=50000,
            tax_cents=10500,
            total_cents=60500,
        )
        self.client.force_login(self.staff_user)
        response = self.client.get("/billing/reports/vat/?start_date=2025-01-01&end_date=2025-12-31")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["start_date"], date(2025, 1, 1))
        self.assertEqual(response.context["end_date"], date(2025, 12, 31))
        self.assertEqual([document.pk for document in response.context["documents"]], [invoice.pk])
        self.assertEqual(response.context["total_net"], 10000)
        self.assertEqual(response.context["total_vat"], 2100)
        self.assertEqual(response.context["total_gross"], 12100)
        self.assertEqual(
            response.context["vat_summary_by_currency"],
            [{"currency": "RON", "net": 10000, "vat": 2100, "gross": 12100}],
        )
        self.assertContains(response, invoice.display_number)
        self.assertNotContains(response, "INV-VAT-EXCLUDED")

    def test_vat_report_non_staff_redirect(self):
        self.client.force_login(self.regular_user)
        response = self.client.get("/billing/reports/vat/")
        self.assertEqual(response.status_code, 302)


# ===============================================================================
# INVOICE REFUND VIEWS
# ===============================================================================


class InvoiceRefundViewTest(BillingViewsTestBase):
    """Tests for invoice_refund view."""

    def test_refund_missing_fields(self):
        invoice = self._create_invoice()
        self.client.force_login(self.admin_user)
        response = self.client.post(
            f"/billing/invoices/{invoice.id}/refund/",
            {"refund_type": "full"},
        )
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertFalse(data["success"])

    def _paid_card_invoice(self) -> tuple[Invoice, Payment]:
        invoice = self._create_invoice(status="paid", paid_at=timezone.now())
        payment = Payment.objects.create(
            customer=invoice.customer,
            invoice=invoice,
            currency=invoice.currency,
            amount_cents=invoice.total_cents,
            payment_method="stripe",
            gateway_txn_id="pi_staff_refund",
            status="succeeded",
        )
        return invoice, payment

    def _refund_through_the_view(self, invoice: Invoice, amount_cents: int, form: dict[str, str]):
        gateway = MagicMock()
        gateway.refund_payment.return_value = {
            "success": True,
            "refund_id": "re_staff",
            "status": "succeeded",
            "amount_refunded_cents": amount_cents,
        }
        self.client.force_login(self.admin_user)
        with patch("apps.billing.refund_service.PaymentGatewayFactory.create_gateway", return_value=gateway):
            response = self.client.post(f"/billing/invoices/{invoice.id}/refund/", form)
        return response, gateway

    def test_refund_full(self):
        """A staff full refund reaches the gateway and records the whole amount."""
        invoice, payment = self._paid_card_invoice()
        response, gateway = self._refund_through_the_view(
            invoice,
            invoice.total_cents,
            {"refund_type": "full", "refund_reason": "customer_request", "refund_notes": "Customer wants refund"},
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertTrue(response.json()["success"])
        gateway.refund_payment.assert_called_once()
        refund = Refund.objects.get(invoice=invoice)
        self.assertEqual(refund.amount_cents, invoice.total_cents)
        self.assertEqual(refund.payment, payment)

    def test_refund_partial_valid(self):
        """A staff partial refund moves exactly the typed amount, in cents."""
        invoice, _payment = self._paid_card_invoice()
        response, gateway = self._refund_through_the_view(
            invoice,
            5000,
            {
                "refund_type": "partial",
                "refund_reason": "service_failure",
                "refund_notes": "Partial refund",
                "refund_amount": "50.00",
                "idempotency_key": "staff-partial-1",
            },
        )
        self.assertEqual(response.status_code, 200, response.content)
        gateway.refund_payment.assert_called_once()
        self.assertEqual(Refund.objects.get(invoice=invoice).amount_cents, 5000)

    def test_the_refund_dialog_offers_no_gateway_opt_out(self):
        """No view reads `process_payment_refund`; a box promising a record-only refund would lie."""
        invoice, _payment = self._paid_card_invoice()
        self.client.force_login(self.admin_user)
        response = self.client.get(f"/billing/invoices/{invoice.id}/")
        self.assertContains(response, 'name="refund_notes"')  # the refund dialog rendered
        self.assertNotContains(response, "process_payment_refund")

    def test_refund_partial_zero_amount(self):
        invoice = self._create_invoice()
        self.client.force_login(self.admin_user)
        response = self.client.post(
            f"/billing/invoices/{invoice.id}/refund/",
            {
                "refund_type": "partial",
                "refund_reason": "quality_issue",
                "refund_notes": "Partial refund",
                "refund_amount": "0",
            },
        )
        data = response.json()
        self.assertFalse(data["success"])

    def test_refund_partial_invalid_amount(self):
        invoice = self._create_invoice()
        self.client.force_login(self.admin_user)
        response = self.client.post(
            f"/billing/invoices/{invoice.id}/refund/",
            {
                "refund_type": "partial",
                "refund_reason": "quality_issue",
                "refund_notes": "Partial refund",
                "refund_amount": "abc",
            },
        )
        data = response.json()
        self.assertFalse(data["success"])

    def test_refund_get_not_allowed(self):
        invoice = self._create_invoice()
        self.client.force_login(self.admin_user)
        response = self.client.get(f"/billing/invoices/{invoice.id}/refund/")
        self.assertEqual(response.status_code, 405)

    def test_refund_no_access(self):
        other_customer = Customer.objects.create(
            name="RefundDeny Co", customer_type="company", company_name="RefundDeny Co", status="active"
        )
        invoice = self._create_invoice(customer=other_customer)
        self.client.force_login(self.regular_user)
        response = self.client.post(f"/billing/invoices/{invoice.id}/refund/")
        # #104 [M11]: the denial is now a JSON 403, not a redirect. The client parses JSON
        # unconditionally, so a 302 to an HTML dashboard was never usable here.
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response["Content-Type"], "application/json")


class InvoiceRefundAuthorizationTests(BillingViewsTestBase):
    """#104 [M11] — refunds are a financial operation, not a general staff one.

    ``invoice_refund`` was the only view in ``apps/billing/views.py`` gated by
    ``@staff_required`` while its 19 siblings used ``@billing_staff_required``. Both of its
    gates reduced to ``is_staff_user`` — the in-view ``can_access_customer`` check returns
    True unconditionally for any staff user — so a support agent could issue a full refund
    on any invoice for any customer. ADR-0024 assigns financial operations to the billing
    role.

    The denial must be JSON: the client at ``templates/billing/invoice_detail.html``
    calls ``response.json()`` unconditionally, so an HTML redirect or a plain-text 403
    both break it silently.
    """

    REFUND_SERVICE = "apps.billing.refund_service.RefundService.refund_invoice"

    def setUp(self):
        super().setUp()
        self.manager_user = User.objects.create_user(
            email="manager@test.ro", password="testpass123", is_staff=True, staff_role="manager"
        )
        self.support_user = User.objects.create_user(
            email="support@test.ro", password="testpass123", is_staff=True, staff_role="support"
        )
        # Bare is_staff with no role: passes is_staff_user, so it passed the old gate too.
        self.bare_staff_user = User.objects.create_user(
            email="barestaff@test.ro", password="testpass123", is_staff=True
        )
        self.invoice = self._create_invoice()

    def _post_refund(self, user=None):
        """POST a *valid* payload so authorization, not form validation, is what blocks."""
        if user is not None:
            self.client.force_login(user)
        else:
            self.client.logout()
        return self.client.post(
            f"/billing/invoices/{self.invoice.id}/refund/",
            {
                "refund_type": "full",
                "refund_reason": "customer_request",
                "refund_notes": "Authorization matrix probe",
            },
        )

    def test_financial_roles_may_reach_the_refund_service(self):
        for user in (self.admin_user, self.staff_user, self.manager_user):
            with self.subTest(role=user.staff_role), patch(self.REFUND_SERVICE) as refund:
                refund.return_value = MagicMock(is_ok=lambda: False, unwrap_err=lambda: "stub")
                response = self._post_refund(user)
                self.assertNotIn(response.status_code, (401, 403))
                refund.assert_called_once()

    def test_non_financial_staff_are_denied_and_never_reach_the_service(self):
        for user in (self.support_user, self.bare_staff_user):
            with self.subTest(role=user.staff_role or "<bare is_staff>"), patch(self.REFUND_SERVICE) as refund:
                response = self._post_refund(user)
                self.assertEqual(response.status_code, 403)
                self.assertEqual(response["Content-Type"], "application/json")
                payload = response.json()
                self.assertFalse(payload["success"])
                # Both refund clients render `data.error` directly, so the denial reason must
                # live there as text. A boolean renders as the useless "Error: true".
                self.assertIsInstance(payload["error"], str)
                self.assertIn("privileges", payload["error"].lower())
                refund.assert_not_called()

    def test_authenticated_customer_is_denied_in_json(self):
        with patch(self.REFUND_SERVICE) as refund:
            response = self._post_refund(self.regular_user)
            self.assertEqual(response.status_code, 403)
            self.assertEqual(response["Content-Type"], "application/json")
            refund.assert_not_called()

    def test_anonymous_is_denied_in_json_not_redirected_to_login(self):
        with patch(self.REFUND_SERVICE) as refund:
            response = self._post_refund(None)
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response["Content-Type"], "application/json")
            refund.assert_not_called()


class InvoiceRefundRequestViewTest(BillingViewsTestBase):
    """Tests for invoice_refund_request view."""

    def test_refund_request_success(self):
        """Test refund request - creates a ticket (may fail if SupportCategory schema differs)."""
        from apps.tickets.models import SupportCategory  # noqa: PLC0415

        # Pre-create the category to avoid schema issues in get_or_create defaults
        SupportCategory.objects.get_or_create(name="Billing")

        invoice = self._create_invoice(status="paid")
        self.client.force_login(self.staff_user)
        response = self.client.post(
            f"/billing/invoices/{invoice.id}/refund-request/",
            {
                "refund_reason": "customer_request",
                "refund_notes": "I want a refund",
            },
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])

    def test_refund_request_not_paid(self):
        invoice = self._create_invoice(status="issued")
        self.client.force_login(self.staff_user)
        response = self.client.post(
            f"/billing/invoices/{invoice.id}/refund-request/",
            {
                "refund_reason": "customer_request",
                "refund_notes": "I want a refund",
            },
        )
        data = response.json()
        self.assertFalse(data["success"])

    def test_refund_request_missing_fields(self):
        invoice = self._create_invoice(status="paid")
        self.client.force_login(self.staff_user)
        response = self.client.post(
            f"/billing/invoices/{invoice.id}/refund-request/",
            {"refund_reason": "customer_request"},
        )
        data = response.json()
        self.assertFalse(data["success"])

    def test_refund_request_get_not_allowed(self):
        invoice = self._create_invoice()
        self.client.force_login(self.staff_user)
        response = self.client.get(f"/billing/invoices/{invoice.id}/refund-request/")
        self.assertEqual(response.status_code, 405)

    def test_refund_request_various_reasons(self) -> None:
        from apps.tickets.models import SupportCategory, Ticket  # noqa: PLC0415

        category, _ = SupportCategory.objects.get_or_create(name="Billing")
        invoice = self._create_invoice(status="paid")
        self.client.force_login(self.staff_user)
        reason_titles = {
            "service_failure": "Service Not Working",
            "quality_issue": "Quality Not As Expected",
            "duplicate_invoice": "Duplicate Invoice",
            "other": "Other Reason",
        }
        ticket_numbers: set[str] = set()
        for reason, title in reason_titles.items():
            with self.subTest(reason=reason):
                notes = f"Reason: {reason}"
                before = Ticket.objects.filter(customer=self.customer, object_id=str(invoice.pk)).count()
                response = self.client.post(
                    f"/billing/invoices/{invoice.id}/refund-request/",
                    {"refund_reason": reason, "refund_notes": notes},
                )
                self.assertEqual(response.status_code, 200)
                data = response.json()
                self.assertTrue(data["success"])
                self.assertEqual(data["data"]["invoice_number"], invoice.number)
                ticket = Ticket.objects.get(ticket_number=data["data"]["ticket_number"])
                self.assertEqual(ticket.customer_id, self.customer.pk)
                self.assertEqual(ticket.created_by_id, self.staff_user.pk)
                self.assertEqual(ticket.category_id, category.pk)
                self.assertEqual(str(ticket.object_id), str(invoice.pk))
                self.assertEqual(ticket.title, f"Refund Request for Invoice {invoice.number}")
                self.assertIn(f"Refund Reason: {title}", ticket.description)
                self.assertIn(notes, ticket.description)
                self.assertEqual(
                    Ticket.objects.filter(customer=self.customer, object_id=str(invoice.pk)).count(),
                    before + 1,
                )
                self.assertNotIn(ticket.ticket_number, ticket_numbers)
                ticket_numbers.add(ticket.ticket_number)
        self.assertEqual(len(ticket_numbers), 4)


# ===============================================================================
# API ENDPOINTS
# ===============================================================================


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
class SignedBillingViewsTestBase(HMACTestMixin, BillingViewsTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.api_actor = User.objects.create_user(email="apiactor@test.ro", password="testpass123")
        CustomerMembership.objects.create(user=self.api_actor, customer=self.customer, role="owner")

    def _post_json(self, url: str, data: dict[str, object]) -> HttpResponse:
        return self.portal_post(url, {"user_id": self.api_actor.pk, **data})

    def _post_invalid_json(self, url: str) -> HttpResponse:
        body = b"not json"
        return self.client.post(url, body, content_type="application/json", **hmac_headers("POST", url, body))


class ApiCreatePaymentIntentTest(SignedBillingViewsTestBase):
    """Tests for api_create_payment_intent."""

    @patch("apps.billing.views.PaymentService.create_payment_intent_direct")
    def test_create_intent_success(self, mock_create):
        mock_create.return_value = {
            "success": True,
            "payment_intent_id": "pi_test123",
            "client_secret": "cs_test123",
        }
        response = self._post_json(
            "/billing/create-payment-intent/",
            {
                "order_id": "order-123",
                "amount_cents": 5000,
                "currency": "RON",
                "customer_id": self.customer.pk,
                "order_number": "ORD-001",
                "gateway": "stripe",
            },
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])

    @patch("apps.billing.views.PaymentService.create_payment_intent_direct")
    def test_create_intent_service_failure(self, mock_create):
        mock_create.return_value = {"success": False, "error": "Stripe error"}
        response = self._post_json(
            "/billing/create-payment-intent/",
            {
                "order_id": "order-123",
                "amount_cents": 5000,
                "currency": "RON",
                "customer_id": self.customer.pk,
                "gateway": "stripe",
            },
        )
        self.assertEqual(response.status_code, 400)

    def test_create_intent_missing_order_id(self):
        response = self._post_json(
            "/billing/create-payment-intent/",
            {"amount_cents": 5000, "customer_id": self.customer.pk},
        )
        self.assertEqual(response.status_code, 400)

    def test_create_intent_missing_amount(self):
        response = self._post_json(
            "/billing/create-payment-intent/",
            {"order_id": "order-123", "customer_id": self.customer.pk},
        )
        self.assertEqual(response.status_code, 400)

    def test_create_intent_invalid_amount(self):
        response = self._post_json(
            "/billing/create-payment-intent/",
            {"order_id": "order-123", "amount_cents": -100, "customer_id": self.customer.pk},
        )
        self.assertEqual(response.status_code, 400)

    def test_create_intent_missing_customer(self):
        response = self._post_json(
            "/billing/create-payment-intent/",
            {"order_id": "order-123", "amount_cents": 5000},
        )
        self.assertEqual(response.status_code, 400)

    def test_create_intent_invalid_currency(self):
        response = self._post_json(
            "/billing/create-payment-intent/",
            {
                "order_id": "order-123",
                "amount_cents": 5000,
                "customer_id": self.customer.pk,
                "currency": "GBP",
            },
        )
        self.assertEqual(response.status_code, 400)

    def test_create_intent_invalid_gateway(self):
        response = self._post_json(
            "/billing/create-payment-intent/",
            {
                "order_id": "order-123",
                "amount_cents": 5000,
                "customer_id": self.customer.pk,
                "gateway": "paypal",
            },
        )
        self.assertEqual(response.status_code, 400)

    @patch("apps.billing.views.PaymentService.create_payment_intent_direct")
    def test_create_intent_rejects_bank_transfer_gateway(self, mock_create):
        response = self._post_json(
            "/billing/create-payment-intent/",
            {
                "order_id": "order-123",
                "amount_cents": 5000,
                "customer_id": self.customer.pk,
                "gateway": "bank",
            },
        )

        self.assertEqual(response.status_code, 400)
        mock_create.assert_not_called()

    def test_create_intent_invalid_json(self):
        response = self._post_invalid_json("/billing/create-payment-intent/")
        self.assertEqual(response.status_code, 400)

    def test_create_intent_get_not_allowed(self):
        path = "/billing/create-payment-intent/"
        body = b"{}"
        response = self.client.generic(
            "GET", path, body, content_type="application/json", **hmac_headers("GET", path, body)
        )
        self.assertEqual(response.status_code, 405)

    @patch("apps.billing.views.PaymentService.create_payment_intent_direct")
    def test_create_intent_exception(self, mock_create):
        mock_create.side_effect = Exception("Unexpected error")
        response = self._post_json(
            "/billing/create-payment-intent/",
            {
                "order_id": "order-123",
                "amount_cents": 5000,
                "currency": "RON",
                "customer_id": self.customer.pk,
                "gateway": "stripe",
            },
        )
        self.assertEqual(response.status_code, 500)

    def test_create_intent_order_id_not_string(self):
        response = self._post_json(
            "/billing/create-payment-intent/",
            {"order_id": 123, "amount_cents": 5000, "customer_id": self.customer.pk},
        )
        self.assertEqual(response.status_code, 400)

    def test_create_intent_amount_not_int(self):
        response = self._post_json(
            "/billing/create-payment-intent/",
            {"order_id": "order-123", "amount_cents": "5000", "customer_id": self.customer.pk},
        )
        self.assertEqual(response.status_code, 400)

    @patch("apps.billing.views.PaymentService.create_payment_intent_direct")
    def test_create_intent_rejects_non_object_metadata(self, mock_create):
        response = self._post_json(
            "/billing/create-payment-intent/",
            {
                "order_id": "order-123",
                "amount_cents": 5000,
                "customer_id": self.customer.pk,
                "metadata": "not-an-object",
            },
        )

        self.assertEqual(response.status_code, 400)
        mock_create.assert_not_called()


class ApiConfirmPaymentTest(SignedBillingViewsTestBase):
    """Tests for api_confirm_payment."""

    @patch("apps.billing.views.PaymentService.confirm_payment")
    def test_confirm_success(self, mock_confirm):
        mock_confirm.return_value = {"success": True, "status": "succeeded"}
        response = self._post_json(
            "/billing/confirm-payment/",
            {"payment_intent_id": "pi_test123", "gateway": "stripe", "customer_id": self.customer.pk},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])

    @patch("apps.billing.views.PaymentService.confirm_payment")
    def test_confirm_failure(self, mock_confirm):
        mock_confirm.return_value = {"success": False, "error": "Payment failed"}
        response = self._post_json(
            "/billing/confirm-payment/",
            {"payment_intent_id": "pi_test123", "gateway": "stripe", "customer_id": self.customer.pk},
        )
        self.assertEqual(response.status_code, 400)

    def test_confirm_missing_payment_id(self):
        response = self._post_json("/billing/confirm-payment/", {"gateway": "stripe", "customer_id": self.customer.pk})
        self.assertEqual(response.status_code, 400)

    def test_confirm_invalid_stripe_format(self):
        response = self._post_json(
            "/billing/confirm-payment/",
            {"payment_intent_id": "invalid_id", "gateway": "stripe", "customer_id": self.customer.pk},
        )
        self.assertEqual(response.status_code, 400)

    def test_confirm_invalid_gateway(self):
        response = self._post_json(
            "/billing/confirm-payment/",
            {"payment_intent_id": "pi_test123", "gateway": "paypal", "customer_id": self.customer.pk},
        )
        self.assertEqual(response.status_code, 400)

    def test_confirm_invalid_json(self):
        response = self._post_invalid_json("/billing/confirm-payment/")
        self.assertEqual(response.status_code, 400)

    @patch("apps.billing.views.PaymentService.confirm_payment")
    def test_confirm_exception(self, mock_confirm):
        mock_confirm.side_effect = Exception("Unexpected")
        response = self._post_json(
            "/billing/confirm-payment/",
            {"payment_intent_id": "pi_test123", "gateway": "stripe", "customer_id": self.customer.pk},
        )
        self.assertEqual(response.status_code, 500)

    def test_confirm_payment_id_not_string(self):
        response = self._post_json(
            "/billing/confirm-payment/",
            {"payment_intent_id": 123, "gateway": "stripe", "customer_id": self.customer.pk},
        )
        self.assertEqual(response.status_code, 400)


class ApiStripeConfigTest(BillingViewsTestBase):
    """Tests for api_stripe_config."""

    @patch("apps.settings.services.SettingsService")
    def test_stripe_config_enabled(self, mock_settings_cls):
        mock_settings_cls.get_setting.side_effect = lambda key, **kwargs: {
            "integrations.stripe_enabled": True,
            "integrations.stripe_publishable_key": "pk_test_123",
        }.get(key, kwargs.get("default"))
        response = self.client.get("/billing/stripe-config/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])

    @patch("apps.settings.services.SettingsService")
    def test_stripe_config_disabled(self, mock_settings_cls):
        mock_settings_cls.get_setting.side_effect = lambda key, **kwargs: {
            "integrations.stripe_enabled": False,
        }.get(key, kwargs.get("default", False))
        response = self.client.get("/billing/stripe-config/")
        self.assertEqual(response.status_code, 503)

    @patch("apps.settings.services.SettingsService")
    def test_stripe_config_no_key(self, mock_settings_cls):
        mock_settings_cls.get_setting.side_effect = lambda key, **kwargs: {
            "integrations.stripe_enabled": True,
            "integrations.stripe_publishable_key": None,
        }.get(key, kwargs.get("default"))
        response = self.client.get("/billing/stripe-config/")
        self.assertEqual(response.status_code, 500)

    @patch("apps.settings.services.SettingsService")
    def test_stripe_config_exception(self, mock_settings_cls):
        def setting_value(key, **kwargs):
            if key.startswith("integrations.stripe_"):
                raise Exception("Config error")
            return kwargs.get("default")

        mock_settings_cls.get_setting.side_effect = setting_value
        response = self.client.get("/billing/stripe-config/")
        self.assertEqual(response.status_code, 500)

    def test_stripe_config_post_not_allowed(self):
        response = self.client.post("/billing/stripe-config/")
        self.assertEqual(response.status_code, 405)


# ===============================================================================
# HELPER / INTERNAL FUNCTION TESTS
# ===============================================================================


class ValidateFinancialDocumentAccessTest(BillingViewsTestBase):
    """Tests for _validate_financial_document_access."""

    def test_none_request(self):
        from apps.billing.views import _validate_financial_document_access  # noqa: PLC0415

        invoice = self._create_invoice()
        result = _validate_financial_document_access(None, invoice)
        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 403)

    def test_none_document(self):
        from apps.billing.views import _validate_financial_document_access  # noqa: PLC0415

        request = self.factory.get("/")
        request.user = self.staff_user
        result = _validate_financial_document_access(request, None)
        self.assertIsNotNone(result)

    def test_unauthenticated_user(self):
        from django.contrib.auth.models import AnonymousUser  # noqa: PLC0415

        from apps.billing.views import _validate_financial_document_access  # noqa: PLC0415

        invoice = self._create_invoice()
        request = self.factory.get("/")
        request.user = AnonymousUser()
        result = _validate_financial_document_access(request, invoice)
        self.assertIsNotNone(result)

    def test_no_customer_access(self):
        from apps.billing.views import _validate_financial_document_access  # noqa: PLC0415

        other_customer = Customer.objects.create(
            name="NoAccess Co", customer_type="company", company_name="NoAccess Co", status="active"
        )
        invoice = self._create_invoice(customer=other_customer)
        request = self.factory.get("/")
        request.user = self.regular_user
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        result = _validate_financial_document_access(request, invoice)
        self.assertIsNotNone(result)

    def test_successful_access(self):
        from apps.billing.views import _validate_financial_document_access  # noqa: PLC0415

        invoice = self._create_invoice()
        request = self.factory.get("/")
        request.user = self.staff_user
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        result = _validate_financial_document_access(request, invoice)
        self.assertIsNone(result)


class ValidateFinancialDocumentAccessWithRedirectTest(BillingViewsTestBase):
    """Tests for _validate_financial_document_access_with_redirect."""

    def test_successful_access_returns_none(self):
        from apps.billing.views import _validate_financial_document_access_with_redirect  # noqa: PLC0415

        invoice = self._create_invoice()
        request = self.factory.get("/test/")
        request = _add_middleware(request)
        request.user = self.staff_user
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        result = _validate_financial_document_access_with_redirect(request, invoice)
        self.assertIsNone(result)

    def test_unauthenticated_redirects_to_login(self):
        from django.contrib.auth.models import AnonymousUser  # noqa: PLC0415

        from apps.billing.views import _validate_financial_document_access_with_redirect  # noqa: PLC0415

        invoice = self._create_invoice()
        request = self.factory.get("/test/")
        request = _add_middleware(request)
        request.user = AnonymousUser()
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        result = _validate_financial_document_access_with_redirect(request, invoice)
        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 302)

    def test_no_access_redirects_to_list(self):
        from apps.billing.views import _validate_financial_document_access_with_redirect  # noqa: PLC0415

        other_customer = Customer.objects.create(
            name="Redirect Co", customer_type="company", company_name="Redirect Co", status="active"
        )
        invoice = self._create_invoice(customer=other_customer)
        request = self.factory.get("/test/")
        request = _add_middleware(request)
        request.user = self.regular_user
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        result = _validate_financial_document_access_with_redirect(request, invoice)
        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 302)


class GetAccessibleCustomerIdsTest(BillingViewsTestBase):
    """Tests for _get_accessible_customer_ids."""

    def test_staff_user(self):
        from apps.billing.views import _get_accessible_customer_ids  # noqa: PLC0415

        ids = _get_accessible_customer_ids(self.staff_user)
        self.assertIsInstance(ids, list)

    def test_regular_user(self):
        from apps.billing.views import _get_accessible_customer_ids  # noqa: PLC0415

        ids = _get_accessible_customer_ids(self.regular_user)
        self.assertIsInstance(ids, list)


class ProcessValidUntilDateTest(BillingViewsTestBase):
    """Tests for _process_valid_until_date."""

    def test_none_data(self):
        from apps.billing.views import _process_valid_until_date  # noqa: PLC0415

        valid_until, errors = _process_valid_until_date(None)
        self.assertIsNotNone(valid_until)
        self.assertEqual(errors, [])

    def test_valid_date(self):
        from apps.billing.views import _process_valid_until_date  # noqa: PLC0415

        valid_until, errors = _process_valid_until_date({"valid_until": "2026-12-31"})
        self.assertIsNotNone(valid_until)
        self.assertEqual(errors, [])

    def test_invalid_date(self):
        from apps.billing.views import _process_valid_until_date  # noqa: PLC0415

        valid_until, errors = _process_valid_until_date({"valid_until": "not-a-date"})
        self.assertIsNotNone(valid_until)
        self.assertEqual(len(errors), 1)

    def test_empty_date(self):
        from apps.billing.views import _process_valid_until_date  # noqa: PLC0415

        valid_until, errors = _process_valid_until_date({"valid_until": ""})
        self.assertIsNotNone(valid_until)
        self.assertEqual(errors, [])


class ValidateCustomerAssignmentTest(BillingViewsTestBase):
    """Tests for _validate_customer_assignment."""

    def test_no_customer_id(self):
        from apps.billing.views import _validate_customer_assignment  # noqa: PLC0415

        customer, error = _validate_customer_assignment(self.staff_user, None, None)
        self.assertIsNone(customer)
        self.assertIsNotNone(error)

    def test_invalid_customer_id(self):
        from apps.billing.views import _validate_customer_assignment  # noqa: PLC0415

        customer, error = _validate_customer_assignment(self.staff_user, "99999", None)
        self.assertIsNone(customer)
        self.assertIsNotNone(error)

    def test_invalid_customer_id_with_proforma_pk(self):
        from apps.billing.views import _validate_customer_assignment  # noqa: PLC0415

        customer, error = _validate_customer_assignment(self.staff_user, "99999", 1)
        self.assertIsNone(customer)
        self.assertIsNotNone(error)

    def test_valid_customer_id(self):
        from apps.billing.views import _validate_customer_assignment  # noqa: PLC0415

        customer, error = _validate_customer_assignment(self.staff_user, str(self.customer.pk), None)
        self.assertEqual(customer, self.customer)
        self.assertIsNone(error)

    def test_customer_not_accessible(self):
        from apps.billing.views import _validate_customer_assignment  # noqa: PLC0415

        other_customer = Customer.objects.create(
            name="Inaccessible Co", customer_type="company", company_name="Inaccessible Co", status="active"
        )
        customer, error = _validate_customer_assignment(self.regular_user, str(other_customer.pk), None)
        self.assertIsNone(customer)
        self.assertIsNotNone(error)


class GetMaxPaymentAmountCentsTest(TestCase):
    """Tests for _get_max_payment_amount_cents."""

    @patch("apps.settings.services.SettingsService")
    def test_returns_setting_value(self, mock_settings_cls):
        from apps.billing.views import _get_max_payment_amount_cents  # noqa: PLC0415

        mock_settings_cls.get_integer_setting.return_value = 50_000_000
        result = _get_max_payment_amount_cents()
        self.assertEqual(result, 50_000_000)


# ===============================================================================
# S-1: payment_method allowlist on process_proforma_payment
# An arbitrary payment_method value must be rejected with HTTP 400 BEFORE
# calling the service, not silently normalised to "other" or forwarded as-is.
# ===============================================================================


class ProcessProformaPaymentAllowlistTest(BillingViewsTestBase):
    """S-1: process_proforma_payment must reject unknown payment_method values."""

    def test_unknown_payment_method_returns_400(self) -> None:
        """POST with payment_method='evil_method' must return 400, not call service."""
        proforma = self._create_proforma()
        self.client.force_login(self.staff_user)
        response = self.client.post(
            f"/billing/proformas/{proforma.pk}/pay/",
            {"payment_method": "evil_method"},
        )
        self.assertEqual(
            response.status_code,
            400,
            "Expected 400 for unknown payment_method, got "
            f"{response.status_code}. The view must validate payment_method "
            "against an allowlist before delegating to the service.",
        )

    def test_unknown_payment_method_does_not_call_service(self) -> None:
        """The service must NOT be called when payment_method is not allowed."""
        proforma = self._create_proforma()
        self.client.force_login(self.staff_user)
        with patch("apps.billing.proforma_service.ProformaPaymentService.record_payment_and_convert") as mock_service:
            response = self.client.post(
                f"/billing/proformas/{proforma.pk}/pay/",
                {"payment_method": "evil_method"},
            )
        self.assertEqual(response.status_code, 400)
        mock_service.assert_not_called()

    def test_known_payment_methods_are_accepted(self) -> None:
        """All allowed payment methods must not be rejected at the allowlist gate."""
        proforma = self._create_proforma()
        self.client.force_login(self.staff_user)
        allowed = ["bank_transfer", "bank", "cash", "other"]
        for method in allowed:
            with self.subTest(method=method):
                # View will call the service and redirect (302) — may succeed or fail
                # depending on proforma state, but it must NOT return 400 at the gate.
                response = self.client.post(
                    f"/billing/proformas/{proforma.pk}/pay/",
                    {"payment_method": method},
                )
                self.assertNotEqual(
                    response.status_code,
                    400,
                    f"Allowed method '{method}' was rejected by the allowlist gate.",
                )

    def test_gateway_methods_are_rejected_before_manual_conversion(self) -> None:
        proforma = self._create_proforma()
        self.client.force_login(self.staff_user)

        for method in ("card", "stripe"):
            with self.subTest(method=method):
                with patch(
                    "apps.billing.proforma_service.ProformaPaymentService.record_payment_and_convert"
                ) as mock_service:
                    response = self.client.post(
                        f"/billing/proformas/{proforma.pk}/pay/",
                        {"payment_method": method},
                    )
                self.assertEqual(response.status_code, 400)
                mock_service.assert_not_called()

    def test_case_insensitive_rejection(self) -> None:
        """Casing must not bypass the allowlist (e.g. 'Evil_Method' is still rejected)."""
        proforma = self._create_proforma()
        self.client.force_login(self.staff_user)
        response = self.client.post(
            f"/billing/proformas/{proforma.pk}/pay/",
            {"payment_method": "Evil_Method"},
        )
        self.assertEqual(response.status_code, 400)
