"""
Tests for e-Factura compliance dashboard views.
"""

from unittest.mock import Mock, patch
from uuid import uuid4

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

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
        self.assertEqual(len(response.context["status_cards"]), 7)

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
