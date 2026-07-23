"""
Tests for e-Factura compliance dashboard views.
"""

from datetime import timedelta
from unittest.mock import Mock, patch
from uuid import uuid4

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from apps.billing.efactura.models import EFacturaDocument, EFacturaStatus
from apps.billing.models import Currency, Invoice
from apps.customers.models import Customer
from tests.helpers.fsm_helpers import force_status

User = get_user_model()


class EfacturaDashboardViewTestCase(TestCase):
    """Test the e-Factura dashboard view."""

    def setUp(self):
        self.user = User.objects.create_user(
            email="staff@example.com",
            password="testpass123",
            is_staff=True,
            staff_role="admin",
        )
        self.client = Client()
        self.client.force_login(self.user)

    def test_dashboard_requires_authentication(self):
        """Dashboard should require login."""
        anon_client = Client()
        response = anon_client.get(reverse("billing:efactura_dashboard"))
        self.assertEqual(response.status_code, 302)

    @patch("apps.billing.efactura.service.EFacturaService")
    def test_dashboard_renders_successfully(self, mock_service_class):
        """Dashboard should render with status 200."""
        mock_service = Mock()
        mock_service.check_approaching_deadlines.return_value = []
        mock_service_class.return_value = mock_service

        response = self.client.get(reverse("billing:efactura_dashboard"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "e-Factura")

    @patch("apps.billing.efactura.service.EFacturaService")
    def test_dashboard_has_status_cards(self, mock_service_class):
        """Dashboard context should contain status_cards."""
        mock_service = Mock()
        mock_service.check_approaching_deadlines.return_value = []
        mock_service_class.return_value = mock_service

        response = self.client.get(reverse("billing:efactura_dashboard"))
        self.assertIn("status_cards", response.context)
        self.assertEqual(len(response.context["status_cards"]), 9)
        card_keys = {card["key"] for card in response.context["status_cards"]}
        self.assertIn("uploading", card_keys)
        self.assertIn("outcome_unknown", card_keys)

    @patch("apps.billing.efactura.service.EFacturaService")
    def test_dashboard_status_filter(self, mock_service_class):
        """Dashboard should support status filtering via query param."""
        mock_service = Mock()
        mock_service.check_approaching_deadlines.return_value = []
        mock_service_class.return_value = mock_service

        response = self.client.get(
            reverse("billing:efactura_dashboard") + "?status=accepted"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["status_filter"], "accepted")


class EfacturaDocumentDetailViewTestCase(TestCase):
    """Test the e-Factura document detail view."""

    def setUp(self):
        self.user = User.objects.create_user(
            email="staff2@example.com",
            password="testpass123",
            is_staff=True,
            staff_role="admin",
        )
        self.client = Client()
        self.client.force_login(self.user)

    def test_detail_404_for_nonexistent_document(self):
        """Should return 404 for unknown document ID."""
        fake_uuid = str(uuid4())
        response = self.client.get(
            reverse("billing:efactura_document_detail", kwargs={"pk": fake_uuid})
        )
        self.assertEqual(response.status_code, 404)

    def test_unknown_outcome_requires_reconciliation_and_has_no_retry_action(self):
        from tests.factories import CurrencyFactory, CustomerFactory, InvoiceFactory  # noqa: PLC0415

        invoice = InvoiceFactory(
            customer=CustomerFactory(),
            currency=CurrencyFactory(code="RON"),
            number="INV-UNKNOWN-UI",
            bill_to_country="RO",
            status="issued",
        )
        claimed_at = timezone.now() - timedelta(minutes=11)
        document = EFacturaDocument.objects.create(
            invoice=invoice,
            status=EFacturaStatus.OUTCOME_UNKNOWN.value,
            submission_claimed_at=claimed_at,
            submission_claim_expires_at=claimed_at + timedelta(minutes=10),
            xml_content="<Invoice/>",
            last_error="ANAF upload response was lost",
        )

        response = self.client.get(reverse("billing:efactura_document_detail", kwargs={"pk": document.pk}))

        self.assertContains(response, "Reconciliation Required")
        self.assertContains(response, "Upload Claim Acquired")
        self.assertContains(response, "Claim Lease Expired")
        self.assertNotContains(response, "Retry Submission")

    def test_legacy_response_archive_is_visible_without_an_xml_hash(self):
        from tests.factories import CurrencyFactory, CustomerFactory, InvoiceFactory  # noqa: PLC0415

        invoice = InvoiceFactory(
            customer=CustomerFactory(),
            currency=CurrencyFactory(code="RON"),
            number="INV-LEGACY-ARCHIVE-UI",
            bill_to_country="RO",
            status="issued",
        )
        document = EFacturaDocument.objects.create(
            invoice=invoice,
            response_archive="efactura/pdf/2026/07/legacy-response.pdf",
        )

        response = self.client.get(reverse("billing:efactura_document_detail", kwargs={"pk": document.pk}))

        self.assertContains(response, "efactura/pdf/2026/07/legacy-response.pdf")
        self.assertContains(response, "Unverified legacy archive")


class EfacturaSubmitViewTestCase(TestCase):
    """Test the e-Factura submit view."""

    def setUp(self):
        self.user = User.objects.create_user(
            email="staff3@example.com",
            password="testpass123",
            is_staff=True,
            staff_role="admin",
        )
        self.client = Client()
        self.client.force_login(self.user)

    def test_submit_requires_post(self):
        """Submit should only accept POST requests."""
        response = self.client.get(
            reverse("billing:efactura_submit", kwargs={"pk": 999})
        )
        self.assertEqual(response.status_code, 405)


class EfacturaRetryViewTestCase(TestCase):
    """Test the e-Factura retry view."""

    def setUp(self):
        self.user = User.objects.create_user(
            email="staff4@example.com",
            password="testpass123",
            is_staff=True,
            staff_role="admin",
        )
        self.client = Client()
        self.client.force_login(self.user)

    def test_retry_requires_post(self):
        """Retry should only accept POST requests."""
        fake_uuid = str(uuid4())
        response = self.client.get(
            reverse("billing:efactura_retry", kwargs={"pk": fake_uuid})
        )
        self.assertEqual(response.status_code, 405)

    @patch("apps.billing.efactura.service.EFacturaService")
    def test_retry_allows_requeue_of_local_error_document(self, mock_service_class):
        """A local-error doc (never auto-retried) must accept operator requeue."""
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        customer = Customer.objects.create(name="Requeue SRL", customer_type="company", status="active")
        invoice = Invoice.objects.create(
            customer=customer,
            number="INV-REQUEUE-1",
            currency=currency,
            subtotal_cents=1000,
            tax_cents=210,
            total_cents=1210,
            issued_at=timezone.now(),
        )
        document = EFacturaDocument.objects.create(invoice=invoice)
        force_status(document, EFacturaStatus.QUEUED.value)
        document.mark_local_error("XML validation failed")
        document.save()

        mock_service = mock_service_class.return_value
        mock_service.retry_failed_submission.return_value = Mock(success=True)

        response = self.client.post(reverse("billing:efactura_retry", kwargs={"pk": str(document.pk)}))

        self.assertEqual(response.status_code, 302)
        mock_service.retry_failed_submission.assert_called_once()
