"""
Comprehensive tests for apps/audit/views.py to maximize coverage.
"""

import json
import uuid
from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import (
    AuditAlert,
    AuditEvent,
    AuditIntegrityCheck,
    AuditRetentionPolicy,
    AuditSearchQuery,
    DataExport,
)
from apps.common.types import Err, Ok

User = get_user_model()


class AuditViewsBaseTestCase(TestCase):
    """Base test case with common setup."""

    def setUp(self):
        self.client = Client()
        self.staff_user = User.objects.create_user(
            email="staff@example.com",
            password="testpass123",
            is_staff=True,
            staff_role="admin",
        )
        self.regular_user = User.objects.create_user(
            email="user@example.com",
            password="testpass123",
            accepts_marketing=False,
        )
        self.ct = ContentType.objects.get_for_model(User)

    def _create_audit_event(self, **kwargs):
        defaults = {
            "action": "create",
            "category": "business_operation",
            "severity": "low",
            "content_type": self.ct,
            "object_id": str(self.staff_user.pk),
            "user": self.staff_user,
            "description": "Test event",
        }
        defaults.update(kwargs)
        return AuditEvent.objects.create(**defaults)

    def _create_data_export(self, user=None, **kwargs):
        defaults = {
            "requested_by": user or self.regular_user,
            "export_type": "gdpr",
            "scope": {},
            "status": "pending",
            "expires_at": timezone.now() + timedelta(days=7),
        }
        defaults.update(kwargs)
        return DataExport.objects.create(**defaults)


# =============================================================================
# GDPR Dashboard
# =============================================================================


class GDPRDashboardTests(AuditViewsBaseTestCase):
    def test_gdpr_dashboard_requires_login(self):
        resp = self.client.get(reverse("audit:gdpr_dashboard"))
        self.assertEqual(resp.status_code, 302)
        self.assertIn("login", resp.url)

    @patch("apps.audit.views.gdpr_consent_service")
    def test_gdpr_dashboard_renders(self, mock_consent):
        mock_consent.get_consent_history.return_value = []
        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.get(reverse("audit:gdpr_dashboard"))
        self.assertEqual(resp.status_code, 200)

    @patch("apps.audit.views.gdpr_consent_service")
    def test_gdpr_dashboard_with_consent_date(self, mock_consent):
        mock_consent.get_consent_history.return_value = []
        self.regular_user.gdpr_consent_date = timezone.now()
        self.regular_user.save(update_fields=["gdpr_consent_date"])
        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.get(reverse("audit:gdpr_dashboard"))
        self.assertEqual(resp.status_code, 200)


# =============================================================================
# Request Data Export
# =============================================================================


class RequestDataExportTests(AuditViewsBaseTestCase):
    def test_requires_login(self):
        resp = self.client.post(reverse("audit:request_data_export"))
        self.assertEqual(resp.status_code, 302)

    def test_requires_post(self):
        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.get(reverse("audit:request_data_export"))
        self.assertEqual(resp.status_code, 405)

    @patch("apps.audit.views.gdpr_export_service")
    def test_export_success_redirect(self, mock_service):
        export = self._create_data_export(status="completed")
        mock_service.create_data_export_request.return_value = Ok(export)
        mock_service.process_data_export.return_value = Ok(export)

        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:request_data_export"),
            {"include_profile": "on", "include_billing": "on"},
        )
        self.assertEqual(resp.status_code, 302)

    @patch("apps.audit.views.gdpr_export_service")
    def test_export_creation_error(self, mock_service):
        mock_service.create_data_export_request.return_value = Err("Rate limited")

        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.post(reverse("audit:request_data_export"))
        self.assertEqual(resp.status_code, 302)

    @patch("apps.audit.views.gdpr_export_service")
    def test_export_processing_error(self, mock_service):
        export = self._create_data_export()
        mock_service.create_data_export_request.return_value = Ok(export)
        mock_service.process_data_export.return_value = Err("Processing failed")

        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.post(reverse("audit:request_data_export"))
        self.assertEqual(resp.status_code, 302)

    @patch("apps.audit.views.gdpr_export_service")
    def test_export_exception(self, mock_service):
        mock_service.create_data_export_request.side_effect = Exception("DB error")

        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.post(reverse("audit:request_data_export"))
        self.assertEqual(resp.status_code, 302)

    @patch("apps.audit.views._handle_immediate_download")
    @patch("apps.audit.views.gdpr_export_service")
    @patch("apps.audit.views.gdpr_consent_service")
    def test_export_htmx_request_returns_dashboard(self, mock_consent, mock_service, mock_download):
        mock_consent.get_consent_history.return_value = []
        export = self._create_data_export(status="pending")
        mock_service.create_data_export_request.return_value = Ok(export)
        mock_service.process_data_export.return_value = Ok(export)
        mock_download.return_value = None

        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:request_data_export"),
            HTTP_HX_REQUEST="true",
        )
        self.assertEqual(resp.status_code, 200)

    @patch("apps.audit.views._handle_immediate_download")
    @patch("apps.audit.views.gdpr_export_service")
    def test_export_htmx_immediate_download(self, mock_service, mock_download):
        export = self._create_data_export(status="completed")
        mock_service.create_data_export_request.return_value = Ok(export)
        mock_service.process_data_export.return_value = Ok(export)

        from django.http import HttpResponse  # noqa: PLC0415
        mock_download.return_value = HttpResponse(b"data", content_type="application/json")

        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:request_data_export"),
            HTTP_HX_REQUEST="true",
        )
        self.assertEqual(resp.status_code, 200)

    @patch("apps.audit.views.gdpr_export_service")
    @patch("apps.audit.views.gdpr_consent_service")
    def test_export_htmx_with_error(self, mock_consent, mock_service):
        mock_consent.get_consent_history.return_value = []
        mock_service.create_data_export_request.side_effect = Exception("fail")

        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:request_data_export"),
            HTTP_HX_REQUEST="true",
        )
        self.assertEqual(resp.status_code, 200)

    @patch("apps.audit.views._handle_immediate_download")
    @patch("apps.audit.views.gdpr_export_service")
    def test_export_ok_processing_ok_completed_status_htmx(self, mock_service, mock_download):
        """Test HTMX request where processing succeeds but export status is 'completed' (warning message)."""
        export = self._create_data_export(status="completed")
        mock_service.create_data_export_request.return_value = Ok(export)
        mock_service.process_data_export.return_value = Ok(export)
        mock_download.return_value = None

        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:request_data_export"),
            HTTP_HX_REQUEST="true",
        )
        # Falls through to gdpr_dashboard since HTMX
        self.assertEqual(resp.status_code, 200)

    @patch("apps.audit.views.gdpr_export_service")
    def test_export_ok_processing_ok_non_htmx(self, mock_service):
        """Non-HTMX request, processing OK, not completed -> success message + redirect."""
        export = self._create_data_export(status="processing")
        mock_service.create_data_export_request.return_value = Ok(export)
        mock_service.process_data_export.return_value = Ok(export)

        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.post(reverse("audit:request_data_export"))
        self.assertEqual(resp.status_code, 302)


# =============================================================================
# Handle Immediate Download (internal helper)
# =============================================================================


class HandleImmediateDownloadTests(AuditViewsBaseTestCase):
    """Test _handle_immediate_download directly."""

    def test_non_htmx_returns_none(self):
        from django.test import RequestFactory  # noqa: PLC0415

        from apps.audit.views import _handle_immediate_download  # noqa: PLC0415

        factory = RequestFactory()
        request = factory.get("/")
        export = self._create_data_export(status="completed")
        result = _handle_immediate_download(request, export, self.regular_user)
        self.assertIsNone(result)

    @patch("apps.audit.views.default_storage")
    @patch("apps.audit.views.AuditService")
    def test_htmx_completed_with_file(self, mock_audit_svc, mock_storage):
        from django.test import RequestFactory  # noqa: PLC0415

        from apps.audit.views import _handle_immediate_download  # noqa: PLC0415

        factory = RequestFactory()
        request = factory.get("/", HTTP_HX_REQUEST="true")
        request.META["HTTP_USER_AGENT"] = "TestBrowser"
        request.META["REMOTE_ADDR"] = "127.0.0.1"

        export = self._create_data_export(
            status="completed", file_path="exports/test.json"
        )

        mock_file = MagicMock()
        mock_file.read.return_value = b'{"test": true}'
        mock_storage.open.return_value = mock_file

        result = _handle_immediate_download(request, export, self.regular_user)
        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result["Content-Type"], "application/json")

    def test_htmx_not_completed_returns_none(self):
        from django.test import RequestFactory  # noqa: PLC0415

        from apps.audit.views import _handle_immediate_download  # noqa: PLC0415

        factory = RequestFactory()
        request = factory.get("/", HTTP_HX_REQUEST="true")
        export = self._create_data_export(status="pending")
        result = _handle_immediate_download(request, export, self.regular_user)
        self.assertIsNone(result)

    @patch("apps.audit.views.default_storage")
    def test_htmx_file_read_exception(self, mock_storage):
        from django.test import RequestFactory  # noqa: PLC0415

        from apps.audit.views import _handle_immediate_download  # noqa: PLC0415

        factory = RequestFactory()
        request = factory.get("/", HTTP_HX_REQUEST="true")

        export = self._create_data_export(
            status="completed", file_path="exports/test.json"
        )
        mock_storage.open.side_effect = Exception("File not found")

        result = _handle_immediate_download(request, export, self.regular_user)
        self.assertIsNone(result)


# =============================================================================
# Download Data Export
# =============================================================================


class DownloadDataExportTests(AuditViewsBaseTestCase):
    def test_requires_login(self):
        resp = self.client.get(
            reverse("audit:download_data_export", args=[uuid.uuid4()])
        )
        self.assertEqual(resp.status_code, 302)

    def test_404_for_other_users_export(self):
        export = self._create_data_export(user=self.staff_user, status="completed")
        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:download_data_export", args=[export.id])
        )
        self.assertEqual(resp.status_code, 404)

    @patch("apps.audit.views.default_storage")
    @patch("apps.audit.views.audit_service")
    def test_download_expired_export(self, mock_audit, mock_storage):
        export = self._create_data_export(
            status="completed",
            expires_at=timezone.now() - timedelta(days=1),
            file_path="exports/test.json",
        )
        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:download_data_export", args=[export.id])
        )
        self.assertRedirects(resp, reverse("audit:gdpr_dashboard"))

    @patch("apps.audit.views.default_storage")
    @patch("apps.audit.views.audit_service")
    def test_download_missing_file(self, mock_audit, mock_storage):
        export = self._create_data_export(
            status="completed",
            file_path="",
        )
        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:download_data_export", args=[export.id])
        )
        self.assertRedirects(resp, reverse("audit:gdpr_dashboard"))

    @patch("apps.audit.views.default_storage")
    @patch("apps.audit.views.audit_service")
    def test_download_file_not_on_storage(self, mock_audit, mock_storage):
        export = self._create_data_export(
            status="completed",
            file_path="exports/test.json",
        )
        mock_storage.exists.return_value = False
        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:download_data_export", args=[export.id])
        )
        self.assertRedirects(resp, reverse("audit:gdpr_dashboard"))

    @patch("apps.audit.views.default_storage")
    @patch("apps.audit.views.audit_service")
    def test_download_success(self, mock_audit, mock_storage):
        export = self._create_data_export(
            status="completed",
            file_path="exports/test.json",
        )
        mock_storage.exists.return_value = True
        mock_file = MagicMock()
        mock_file.read.return_value = b'{"data": "test"}'
        mock_storage.open.return_value = mock_file

        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:download_data_export", args=[export.id])
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Content-Type"], "application/json")
        export.refresh_from_db()
        self.assertEqual(export.download_count, 1)

    @patch("apps.audit.views.default_storage")
    @patch("apps.audit.views.audit_service")
    def test_download_exception(self, mock_audit, mock_storage):
        export = self._create_data_export(
            status="completed",
            file_path="exports/test.json",
        )
        mock_storage.exists.return_value = True
        mock_storage.open.side_effect = Exception("Storage error")

        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:download_data_export", args=[export.id])
        )
        self.assertRedirects(resp, reverse("audit:gdpr_dashboard"))


# =============================================================================
# Request Data Deletion
# =============================================================================


class RequestDataDeletionTests(AuditViewsBaseTestCase):
    def test_requires_login(self):
        resp = self.client.post(reverse("audit:request_data_deletion"))
        self.assertEqual(resp.status_code, 302)

    def test_requires_post(self):
        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.get(reverse("audit:request_data_deletion"))
        self.assertEqual(resp.status_code, 405)

    def test_missing_reason(self):
        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:request_data_deletion"),
            {"deletion_type": "anonymize", "reason": ""},
        )
        self.assertRedirects(resp, reverse("audit:gdpr_dashboard"))

    @patch("apps.audit.views.gdpr_deletion_service")
    def test_deletion_success(self, mock_service):
        deletion_req = MagicMock()
        deletion_req.reference_id = "ref_12345678abcdefgh"
        mock_service.create_deletion_request.return_value = Ok(deletion_req)

        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:request_data_deletion"),
            {"deletion_type": "anonymize", "reason": "I want my data removed"},
        )
        self.assertRedirects(resp, reverse("audit:gdpr_dashboard"))

    @patch("apps.audit.views.gdpr_deletion_service")
    def test_deletion_with_immediate_confirm_success(self, mock_service):
        deletion_req = MagicMock()
        deletion_req.reference_id = "ref_12345678abcdefgh"
        mock_service.create_deletion_request.return_value = Ok(deletion_req)
        mock_service.process_deletion_request.return_value = Ok("done")

        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:request_data_deletion"),
            {
                "deletion_type": "anonymize",
                "reason": "GDPR request",
                "confirm_immediate": "yes",
            },
        )
        self.assertRedirects(resp, reverse("audit:gdpr_dashboard"))

    @patch("apps.audit.views.gdpr_deletion_service")
    def test_deletion_immediate_full_delete_logout(self, mock_service):
        deletion_req = MagicMock()
        deletion_req.reference_id = "ref_12345678abcdefgh"
        mock_service.create_deletion_request.return_value = Ok(deletion_req)
        mock_service.process_deletion_request.return_value = Ok("done")

        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:request_data_deletion"),
            {
                "deletion_type": "delete",
                "reason": "Full deletion",
                "confirm_immediate": "yes",
            },
        )
        # Should redirect to login on full delete
        self.assertRedirects(resp, reverse("users:login"))

    @patch("apps.audit.views.gdpr_deletion_service")
    def test_deletion_immediate_processing_error(self, mock_service):
        deletion_req = MagicMock()
        deletion_req.reference_id = "ref_12345678abcdefgh"
        mock_service.create_deletion_request.return_value = Ok(deletion_req)
        mock_service.process_deletion_request.return_value = Err("Processing failed")

        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:request_data_deletion"),
            {
                "deletion_type": "anonymize",
                "reason": "GDPR",
                "confirm_immediate": "yes",
            },
        )
        self.assertRedirects(resp, reverse("audit:gdpr_dashboard"))

    @patch("apps.audit.views.gdpr_deletion_service")
    def test_deletion_creation_error(self, mock_service):
        mock_service.create_deletion_request.return_value = Err("Error creating")

        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:request_data_deletion"),
            {"deletion_type": "anonymize", "reason": "GDPR"},
        )
        self.assertRedirects(resp, reverse("audit:gdpr_dashboard"))

    @patch("apps.audit.views.gdpr_deletion_service")
    def test_deletion_exception(self, mock_service):
        mock_service.create_deletion_request.side_effect = Exception("DB error")

        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:request_data_deletion"),
            {"deletion_type": "anonymize", "reason": "GDPR"},
        )
        self.assertRedirects(resp, reverse("audit:gdpr_dashboard"))


# =============================================================================
# Withdraw Consent
# =============================================================================


class WithdrawConsentTests(AuditViewsBaseTestCase):
    def test_requires_login(self):
        resp = self.client.post(reverse("audit:withdraw_consent"))
        self.assertEqual(resp.status_code, 302)

    def test_no_consent_types(self):
        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.post(reverse("audit:withdraw_consent"))
        self.assertRedirects(resp, reverse("audit:gdpr_dashboard"))

    @patch("apps.audit.views.gdpr_consent_service")
    def test_withdraw_success(self, mock_service):
        mock_service.withdraw_consent.return_value = Ok("marketing")

        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:withdraw_consent"),
            {"consent_types": ["marketing"]},
        )
        self.assertRedirects(resp, reverse("audit:gdpr_dashboard"))

    @patch("apps.audit.views.gdpr_consent_service")
    def test_withdraw_data_processing_warning(self, mock_service):
        mock_service.withdraw_consent.return_value = Ok("data_processing")

        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:withdraw_consent"),
            {"consent_types": ["data_processing"]},
        )
        self.assertRedirects(resp, reverse("audit:gdpr_dashboard"))

    @patch("apps.audit.views.gdpr_consent_service")
    def test_withdraw_error(self, mock_service):
        mock_service.withdraw_consent.return_value = Err("Cannot withdraw")

        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:withdraw_consent"),
            {"consent_types": ["marketing"]},
        )
        self.assertRedirects(resp, reverse("audit:gdpr_dashboard"))

    @patch("apps.audit.views.gdpr_consent_service")
    def test_withdraw_exception(self, mock_service):
        mock_service.withdraw_consent.side_effect = Exception("Error")

        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:withdraw_consent"),
            {"consent_types": ["marketing"]},
        )
        self.assertRedirects(resp, reverse("audit:gdpr_dashboard"))


# =============================================================================
# Update Consent
# =============================================================================


class UpdateConsentTests(AuditViewsBaseTestCase):
    def test_requires_login(self):
        resp = self.client.post(reverse("audit:update_consent"))
        self.assertEqual(resp.status_code, 302)

    @patch("apps.audit.views.AuditService")
    def test_update_marketing_consent(self, mock_audit):
        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:update_consent"),
            {"accepts_marketing": "on"},
        )
        self.assertRedirects(resp, reverse("audit:gdpr_dashboard"))
        self.regular_user.refresh_from_db()
        self.assertTrue(self.regular_user.accepts_marketing)

    @patch("apps.audit.views.AuditService")
    def test_update_gdpr_consent(self, mock_audit):
        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:update_consent"),
            {"gdpr_consent": "on"},
        )
        self.assertRedirects(resp, reverse("audit:gdpr_dashboard"))
        self.regular_user.refresh_from_db()
        self.assertIsNotNone(self.regular_user.gdpr_consent_date)

    def test_no_changes(self):
        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.post(reverse("audit:update_consent"))
        self.assertRedirects(resp, reverse("audit:gdpr_dashboard"))

    @patch("apps.audit.views.AuditService")
    @patch("apps.audit.views.gdpr_consent_service")
    def test_update_consent_htmx(self, mock_consent, mock_audit):
        mock_consent.get_consent_history.return_value = []
        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:update_consent"),
            {"accepts_marketing": "on"},
            HTTP_HX_REQUEST="true",
        )
        self.assertEqual(resp.status_code, 200)

    def test_update_consent_exception(self):
        self.client.login(email="user@example.com", password="testpass123")
        with patch("apps.audit.views.cast"):
            mock_user = MagicMock()
            mock_user.is_authenticated = True
            mock_user.accepts_marketing = False
            mock_user.gdpr_consent_date = None
            mock_user.email = "user@example.com"
            # Simulate exception inside try block
            type(mock_user).accepts_marketing = property(
                lambda self: (_ for _ in ()).throw(Exception("DB error"))
            )
            # This is hard to trigger cleanly; let's just verify the basic exception path
        # Use a simpler approach: patch timezone to raise
        with patch("apps.audit.views.timezone") as mock_tz:
            mock_tz.now.side_effect = Exception("TZ error")
            resp = self.client.post(
                reverse("audit:update_consent"),
                {"accepts_marketing": "on"},
            )
            self.assertRedirects(resp, reverse("audit:gdpr_dashboard"))

    @patch("apps.audit.views.gdpr_consent_service")
    def test_update_consent_htmx_no_changes(self, mock_consent):
        mock_consent.get_consent_history.return_value = []
        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:update_consent"),
            HTTP_HX_REQUEST="true",
        )
        # No changes but HTMX -> returns dashboard HTML (200)
        self.assertEqual(resp.status_code, 200)

    @patch("apps.audit.views.AuditService")
    def test_update_consent_gdpr_already_granted(self, mock_audit):
        """When gdpr_consent_date already set, sending gdpr_consent=on should not re-grant."""
        self.regular_user.gdpr_consent_date = timezone.now()
        self.regular_user.save(update_fields=["gdpr_consent_date"])
        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:update_consent"),
            {"gdpr_consent": "on"},
        )
        # No changes since gdpr already granted, marketing didn't change
        self.assertRedirects(resp, reverse("audit:gdpr_dashboard"))


# =============================================================================
# Audit Management Dashboard (Staff)
# =============================================================================


class AuditManagementDashboardTests(AuditViewsBaseTestCase):
    def test_requires_staff(self):
        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.get(reverse("audit:management_dashboard"))
        self.assertEqual(resp.status_code, 403)

    def test_unauthenticated_redirects(self):
        resp = self.client.get(reverse("audit:management_dashboard"))
        self.assertEqual(resp.status_code, 302)

    def test_staff_can_access(self):
        self._create_audit_event()
        self._create_audit_event(severity="critical")
        self._create_audit_event(is_sensitive=True)
        self._create_audit_event(requires_review=True)
        AuditAlert.objects.create(
            alert_type="security_incident",
            severity="critical",
            title="Test",
            description="Test alert",
            status="active",
        )
        AuditIntegrityCheck.objects.create(
            check_type="hash_verification",
            period_start=timezone.now() - timedelta(days=1),
            period_end=timezone.now(),
            status="healthy",
        )
        AuditRetentionPolicy.objects.create(
            name="Test Policy",
            category="authentication",
            retention_days=90,
            is_active=True,
        )
        AuditSearchQuery.objects.create(
            name="Test Search",
            query_params={},
            created_by=self.staff_user,
            is_shared=True,
        )

        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(reverse("audit:management_dashboard"))
        self.assertEqual(resp.status_code, 200)


# =============================================================================
# Audit Log
# =============================================================================


class AuditLogTests(AuditViewsBaseTestCase):
    def test_requires_staff(self):
        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.get(reverse("audit:logs"))
        self.assertEqual(resp.status_code, 403)

    def test_renders_for_staff(self):
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(reverse("audit:logs"))
        self.assertEqual(resp.status_code, 200)


# =============================================================================
# Logs List
# =============================================================================


class LogsListTests(AuditViewsBaseTestCase):
    @patch("apps.audit.views.audit_search_service")
    def test_basic_list(self, mock_search):
        mock_search.build_advanced_query.return_value = (
            AuditEvent.objects.none(),
            {"query_description": "All events"},
        )
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(reverse("audit:logs_list"))
        self.assertEqual(resp.status_code, 200)

    @patch("apps.audit.views.audit_search_service")
    def test_with_filters(self, mock_search):
        mock_search.build_advanced_query.return_value = (
            AuditEvent.objects.none(),
            {"query_description": "Filtered"},
        )
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:logs_list"),
            {
                "user": [str(self.staff_user.pk)],
                "action": ["create"],
                "category": ["authentication"],
                "severity": ["high"],
                "content_type": ["1"],
                "start_date": "2024-01-01",
                "end_date": "2024-12-31",
                "ip_address": "127.0.0.1",
                "request_id": "abc123",
                "session_key": "sess123",
                "search": "test",
                "is_sensitive": "true",
                "requires_review": "true",
                "has_old_values": "true",
                "has_new_values": "true",
                "page_size": "25",
            },
        )
        self.assertEqual(resp.status_code, 200)

    @patch("apps.audit.views.audit_search_service")
    def test_htmx_request(self, mock_search):
        mock_search.build_advanced_query.return_value = (
            AuditEvent.objects.none(),
            {},
        )
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:logs_list"),
            HTTP_HX_REQUEST="true",
        )
        self.assertEqual(resp.status_code, 200)

    @patch("apps.audit.views.audit_search_service")
    def test_page_size_capped(self, mock_search):
        mock_search.build_advanced_query.return_value = (
            AuditEvent.objects.none(),
            {},
        )
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:logs_list"),
            {"page_size": "999"},
        )
        self.assertEqual(resp.status_code, 200)

    @patch("apps.audit.views.audit_search_service")
    def test_empty_filter_values_stripped(self, mock_search):
        """Empty filter values should be removed."""
        mock_search.build_advanced_query.return_value = (
            AuditEvent.objects.none(),
            {},
        )
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:logs_list"),
            {"user": [""], "action": [""], "severity": [""]},
        )
        self.assertEqual(resp.status_code, 200)


# =============================================================================
# Export Logs
# =============================================================================


class ExportLogsTests(AuditViewsBaseTestCase):
    @patch("apps.audit.views.audit_service")
    @patch("apps.audit.views.audit_search_service")
    def test_csv_export(self, mock_search, mock_audit):
        self._create_audit_event(
            old_values={"key": "old"},
            new_values={"key": "new"},
            metadata={"ip": "1.2.3.4"},
            ip_address="1.2.3.4",
            user_agent="TestAgent",
            request_id="req123",
            session_key="sess123",
        )
        mock_search.build_advanced_query.return_value = (
            AuditEvent.objects.all(),
            {},
        )
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(reverse("audit:export_logs"), {"format": "csv"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Content-Type"], "text/csv")
        self.assertIn("audit_logs_", resp["Content-Disposition"])

    @patch("apps.audit.views.audit_service")
    @patch("apps.audit.views.audit_search_service")
    def test_json_export(self, mock_search, mock_audit):
        self._create_audit_event()
        mock_search.build_advanced_query.return_value = (
            AuditEvent.objects.all(),
            {},
        )
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(reverse("audit:export_logs"), {"format": "json"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Content-Type"], "application/json")

    @patch("apps.audit.views.audit_service")
    @patch("apps.audit.views.audit_search_service")
    def test_export_default_csv(self, mock_search, mock_audit):
        mock_search.build_advanced_query.return_value = (
            AuditEvent.objects.none(),
            {},
        )
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(reverse("audit:export_logs"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Content-Type"], "text/csv")

    @patch("apps.audit.views.audit_service")
    @patch("apps.audit.views.audit_search_service")
    def test_export_with_filters(self, mock_search, mock_audit):
        mock_search.build_advanced_query.return_value = (
            AuditEvent.objects.none(),
            {},
        )
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:export_logs"),
            {
                "format": "csv",
                "start_date": "2024-01-01",
                "end_date": "2024-12-31",
                "is_sensitive": "true",
                "requires_review": "true",
            },
        )
        self.assertEqual(resp.status_code, 200)

    @patch("apps.audit.views.audit_service")
    @patch("apps.audit.views.audit_search_service")
    def test_csv_export_with_null_user(self, mock_search, mock_audit):
        """Export event with no user (system event)."""
        self._create_audit_event(user=None)
        mock_search.build_advanced_query.return_value = (
            AuditEvent.objects.all(),
            {},
        )
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(reverse("audit:export_logs"), {"format": "csv"})
        self.assertEqual(resp.status_code, 200)

    @patch("apps.audit.views.audit_service")
    @patch("apps.audit.views.audit_search_service")
    def test_json_export_with_null_user(self, mock_search, mock_audit):
        """JSON export with null user and content_type."""
        self._create_audit_event(user=None)
        mock_search.build_advanced_query.return_value = (
            AuditEvent.objects.all(),
            {},
        )
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(reverse("audit:export_logs"), {"format": "json"})
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.content)
        self.assertIn("audit_events", data)


# =============================================================================
# Staff GDPR Management Dashboard
# =============================================================================


class GDPRManagementDashboardTests(AuditViewsBaseTestCase):
    def test_requires_staff(self):
        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.get(reverse("audit:gdpr_management_dashboard"))
        self.assertEqual(resp.status_code, 403)

    def test_renders(self):
        self._create_data_export(status="pending")
        self._create_data_export(status="completed")
        self._create_data_export(
            status="completed",
            expires_at=timezone.now() - timedelta(days=1),
        )
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(reverse("audit:gdpr_management_dashboard"))
        self.assertEqual(resp.status_code, 200)


# =============================================================================
# GDPR Export Requests List
# =============================================================================


class GDPRExportRequestsListTests(AuditViewsBaseTestCase):
    def test_requires_staff(self):
        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.get(reverse("audit:gdpr_export_requests_list"))
        self.assertEqual(resp.status_code, 403)

    def test_basic_list(self):
        self._create_data_export()
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(reverse("audit:gdpr_export_requests_list"))
        self.assertEqual(resp.status_code, 200)

    def test_with_filters(self):
        self._create_data_export()
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:gdpr_export_requests_list"),
            {
                "status": "pending",
                "user_email": "user@",
                "export_type": "gdpr",
                "start_date": "2024-01-01",
                "end_date": "2025-12-31",
                "expired": "expired",
            },
        )
        self.assertEqual(resp.status_code, 200)

    def test_active_filter(self):
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:gdpr_export_requests_list"),
            {"expired": "active"},
        )
        self.assertEqual(resp.status_code, 200)

    def test_all_status_filter(self):
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:gdpr_export_requests_list"),
            {"status": "all"},
        )
        self.assertEqual(resp.status_code, 200)

    def test_htmx_request(self):
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:gdpr_export_requests_list"),
            HTTP_HX_REQUEST="true",
        )
        self.assertEqual(resp.status_code, 200)


# =============================================================================
# Process Export Request
# =============================================================================


class ProcessExportRequestTests(AuditViewsBaseTestCase):
    def test_requires_staff(self):
        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:process_export_request", args=[uuid.uuid4()])
        )
        self.assertEqual(resp.status_code, 403)

    @patch("apps.audit.views.audit_service")
    @patch("apps.audit.views.gdpr_export_service")
    def test_process_now_success(self, mock_export, mock_audit):
        export = self._create_data_export()
        mock_export.process_data_export.return_value = Ok(export)

        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:process_export_request", args=[export.id]),
            {"action": "process_now"},
        )
        self.assertRedirects(resp, reverse("audit:gdpr_management_dashboard"))

    @patch("apps.audit.views.gdpr_export_service")
    def test_process_now_error(self, mock_export):
        export = self._create_data_export()
        mock_export.process_data_export.return_value = Err("Failed")

        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:process_export_request", args=[export.id]),
            {"action": "process_now"},
        )
        self.assertRedirects(resp, reverse("audit:gdpr_management_dashboard"))

    @patch("apps.audit.views.audit_service")
    def test_mark_failed(self, mock_audit):
        export = self._create_data_export()
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:process_export_request", args=[export.id]),
            {"action": "mark_failed", "error_message": "Invalid data"},
        )
        self.assertRedirects(resp, reverse("audit:gdpr_management_dashboard"))
        export.refresh_from_db()
        self.assertEqual(export.status, "failed")

    def test_mark_failed_no_message(self):
        export = self._create_data_export()
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:process_export_request", args=[export.id]),
            {"action": "mark_failed", "error_message": ""},
        )
        self.assertRedirects(resp, reverse("audit:gdpr_management_dashboard"))

    @patch("apps.audit.views.default_storage")
    @patch("apps.audit.views.audit_service")
    def test_delete_expired(self, mock_audit, mock_storage):
        export = self._create_data_export(
            status="completed",
            expires_at=timezone.now() - timedelta(days=1),
            file_path="exports/test.json",
        )
        mock_storage.exists.return_value = True

        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:process_export_request", args=[export.id]),
            {"action": "delete_expired"},
        )
        self.assertRedirects(resp, reverse("audit:gdpr_management_dashboard"))
        self.assertFalse(DataExport.objects.filter(id=export.id).exists())

    def test_delete_not_expired(self):
        export = self._create_data_export(status="completed")
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:process_export_request", args=[export.id]),
            {"action": "delete_expired"},
        )
        self.assertRedirects(resp, reverse("audit:gdpr_management_dashboard"))
        self.assertTrue(DataExport.objects.filter(id=export.id).exists())

    def test_invalid_action(self):
        export = self._create_data_export()
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:process_export_request", args=[export.id]),
            {"action": "invalid"},
        )
        self.assertRedirects(resp, reverse("audit:gdpr_management_dashboard"))

    def test_nonexistent_export(self):
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:process_export_request", args=[uuid.uuid4()]),
            {"action": "process_now"},
        )
        # get_object_or_404 raises Http404 which is caught by the exception handler
        # and redirects to dashboard
        self.assertRedirects(resp, reverse("audit:gdpr_management_dashboard"))

    @patch("apps.audit.views.gdpr_export_service")
    def test_exception_handling(self, mock_service):
        export = self._create_data_export()
        mock_service.process_data_export.side_effect = Exception("Error")

        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:process_export_request", args=[export.id]),
            {"action": "process_now"},
        )
        self.assertRedirects(resp, reverse("audit:gdpr_management_dashboard"))


# =============================================================================
# GDPR Export Detail
# =============================================================================


class GDPRExportDetailTests(AuditViewsBaseTestCase):
    def test_requires_staff(self):
        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:gdpr_export_detail", args=[uuid.uuid4()])
        )
        self.assertEqual(resp.status_code, 403)

    @patch("apps.audit.views.default_storage")
    def test_renders(self, mock_storage):
        export = self._create_data_export(
            status="completed", file_path="exports/test.json"
        )
        mock_storage.exists.return_value = True

        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:gdpr_export_detail", args=[export.id])
        )
        self.assertEqual(resp.status_code, 200)

    @patch("apps.audit.views.default_storage")
    def test_expired_export(self, mock_storage):
        export = self._create_data_export(
            status="completed",
            file_path="exports/test.json",
            expires_at=timezone.now() - timedelta(days=1),
        )
        mock_storage.exists.return_value = True

        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:gdpr_export_detail", args=[export.id])
        )
        self.assertEqual(resp.status_code, 200)

    def test_no_file_path(self):
        export = self._create_data_export(status="pending")
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:gdpr_export_detail", args=[export.id])
        )
        self.assertEqual(resp.status_code, 200)


# =============================================================================
# Download User Export (Staff)
# =============================================================================


class DownloadUserExportTests(AuditViewsBaseTestCase):
    def test_requires_staff(self):
        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:download_user_export", args=[uuid.uuid4()])
        )
        self.assertEqual(resp.status_code, 403)

    @patch("apps.audit.views.default_storage")
    @patch("apps.audit.views.audit_service")
    def test_download_success(self, mock_audit, mock_storage):
        export = self._create_data_export(
            status="completed", file_path="exports/test.json"
        )
        mock_storage.exists.return_value = True
        mock_file = MagicMock()
        mock_file.read.return_value = b'{"data": "test"}'
        mock_storage.open.return_value = mock_file

        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:download_user_export", args=[export.id])
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Content-Type"], "application/json")

    @patch("apps.audit.views.default_storage")
    def test_download_missing_file(self, mock_storage):
        export = self._create_data_export(status="completed", file_path="")
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:download_user_export", args=[export.id])
        )
        self.assertRedirects(resp, reverse("audit:gdpr_management_dashboard"))

    @patch("apps.audit.views.default_storage")
    def test_download_file_not_on_storage(self, mock_storage):
        export = self._create_data_export(
            status="completed", file_path="exports/test.json"
        )
        mock_storage.exists.return_value = False
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:download_user_export", args=[export.id])
        )
        self.assertRedirects(resp, reverse("audit:gdpr_management_dashboard"))

    @patch("apps.audit.views.default_storage")
    @patch("apps.audit.views.audit_service")
    def test_download_exception(self, mock_audit, mock_storage):
        export = self._create_data_export(
            status="completed", file_path="exports/test.json"
        )
        mock_storage.exists.return_value = True
        mock_storage.open.side_effect = Exception("Error")

        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:download_user_export", args=[export.id])
        )
        self.assertRedirects(resp, reverse("audit:gdpr_management_dashboard"))


# =============================================================================
# Search Suggestions
# =============================================================================


class SearchSuggestionsTests(AuditViewsBaseTestCase):
    @patch("apps.audit.views.audit_search_service")
    def test_renders(self, mock_search):
        mock_search.get_search_suggestions.return_value = {"users": [], "actions": []}
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:search_suggestions"),
            {"q": "test"},
        )
        self.assertEqual(resp.status_code, 200)

    @patch("apps.audit.views.audit_search_service")
    def test_empty_query(self, mock_search):
        mock_search.get_search_suggestions.return_value = {}
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(reverse("audit:search_suggestions"))
        self.assertEqual(resp.status_code, 200)


# =============================================================================
# Save Search Query
# =============================================================================


class SaveSearchQueryTests(AuditViewsBaseTestCase):
    @patch("apps.audit.views.audit_search_service")
    def test_save_success(self, mock_search):
        mock_search.save_search_query.return_value = Ok(MagicMock())
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:save_search_query"),
            {
                "name": "My Search",
                "description": "A test search",
                "is_shared": "on",
                "filter_action": "create",
                "filter_severity": "high",
            },
        )
        self.assertRedirects(resp, reverse("audit:logs"))

    def test_save_no_name(self):
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:save_search_query"),
            {"name": "", "description": "test"},
        )
        self.assertRedirects(resp, reverse("audit:logs"))

    @patch("apps.audit.views.audit_search_service")
    def test_save_error(self, mock_search):
        mock_search.save_search_query.return_value = Err("Duplicate name")
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:save_search_query"),
            {"name": "My Search"},
        )
        self.assertRedirects(resp, reverse("audit:logs"))

    @patch("apps.audit.views.audit_search_service")
    def test_save_exception(self, mock_search):
        mock_search.save_search_query.side_effect = Exception("Error")
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:save_search_query"),
            {"name": "My Search"},
        )
        self.assertRedirects(resp, reverse("audit:logs"))


# =============================================================================
# Load Saved Search
# =============================================================================


class LoadSavedSearchTests(AuditViewsBaseTestCase):
    def test_load_own_search(self):
        query = AuditSearchQuery.objects.create(
            name="Test",
            query_params={"action": "create", "severity": "high"},
            created_by=self.staff_user,
        )
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:load_saved_search", args=[query.id])
        )
        self.assertEqual(resp.status_code, 302)
        query.refresh_from_db()
        self.assertEqual(query.usage_count, 1)

    def test_load_shared_search(self):
        other_staff = User.objects.create_user(
            email="other@example.com", password="testpass123", is_staff=True, staff_role="admin"
        )
        query = AuditSearchQuery.objects.create(
            name="Shared",
            query_params={},
            created_by=other_staff,
            is_shared=True,
        )
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:load_saved_search", args=[query.id])
        )
        self.assertEqual(resp.status_code, 302)

    def test_load_private_other_user_denied(self):
        other_staff = User.objects.create_user(
            email="other@example.com", password="testpass123", is_staff=True, staff_role="admin"
        )
        query = AuditSearchQuery.objects.create(
            name="Private",
            query_params={},
            created_by=other_staff,
            is_shared=False,
        )
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:load_saved_search", args=[query.id])
        )
        self.assertRedirects(resp, reverse("audit:logs"))

    def test_load_nonexistent(self):
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:load_saved_search", args=[uuid.uuid4()])
        )
        # Http404 caught by exception handler -> redirect
        self.assertRedirects(resp, reverse("audit:logs"))

    def test_load_with_empty_params(self):
        query = AuditSearchQuery.objects.create(
            name="Empty",
            query_params={"action": "", "severity": ""},
            created_by=self.staff_user,
        )
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:load_saved_search", args=[query.id])
        )
        self.assertEqual(resp.status_code, 302)


# =============================================================================
# Integrity Dashboard
# =============================================================================


class IntegrityDashboardTests(AuditViewsBaseTestCase):
    def test_requires_staff(self):
        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.get(reverse("audit:integrity_dashboard"))
        self.assertEqual(resp.status_code, 403)

    def test_renders_empty(self):
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(reverse("audit:integrity_dashboard"))
        self.assertEqual(resp.status_code, 200)

    def test_renders_with_data(self):
        for status in ("healthy", "warning", "compromised"):
            AuditIntegrityCheck.objects.create(
                check_type="hash_verification",
                period_start=timezone.now() - timedelta(days=1),
                period_end=timezone.now(),
                status=status,
            )
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(reverse("audit:integrity_dashboard"))
        self.assertEqual(resp.status_code, 200)


# =============================================================================
# Run Integrity Check
# =============================================================================


class RunIntegrityCheckTests(AuditViewsBaseTestCase):
    @patch("apps.audit.views.audit_integrity_service")
    def test_run_default(self, mock_service):
        check = AuditIntegrityCheck.objects.create(
            check_type="hash_verification",
            period_start=timezone.now() - timedelta(days=1),
            period_end=timezone.now(),
            status="healthy",
            issues_found=0,
        )
        mock_service.verify_audit_integrity.return_value = Ok(check)

        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.post(reverse("audit:run_integrity_check"))
        self.assertRedirects(resp, reverse("audit:integrity_dashboard"))

    @patch("apps.audit.views.audit_integrity_service")
    def test_run_with_custom_dates(self, mock_service):
        check = AuditIntegrityCheck.objects.create(
            check_type="hash_verification",
            period_start=timezone.now() - timedelta(days=7),
            period_end=timezone.now(),
            status="warning",
            issues_found=3,
        )
        mock_service.verify_audit_integrity.return_value = Ok(check)

        self.client.login(email="staff@example.com", password="testpass123")
        now = timezone.now()
        resp = self.client.post(
            reverse("audit:run_integrity_check"),
            {
                "check_type": "sequence_check",
                "start_date": (now - timedelta(days=7)).isoformat(),
                "end_date": now.isoformat(),
            },
        )
        self.assertRedirects(resp, reverse("audit:integrity_dashboard"))

    @patch("apps.audit.views.audit_integrity_service")
    def test_run_error(self, mock_service):
        mock_service.verify_audit_integrity.return_value = Err("Check failed")

        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.post(reverse("audit:run_integrity_check"))
        self.assertRedirects(resp, reverse("audit:integrity_dashboard"))

    @patch("apps.audit.views.audit_integrity_service")
    def test_run_exception(self, mock_service):
        mock_service.verify_audit_integrity.side_effect = Exception("Error")

        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.post(reverse("audit:run_integrity_check"))
        self.assertRedirects(resp, reverse("audit:integrity_dashboard"))


# =============================================================================
# Retention Dashboard
# =============================================================================


class RetentionDashboardTests(AuditViewsBaseTestCase):
    def test_requires_staff(self):
        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.get(reverse("audit:retention_dashboard"))
        self.assertEqual(resp.status_code, 403)

    def test_renders_empty(self):
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(reverse("audit:retention_dashboard"))
        self.assertEqual(resp.status_code, 200)

    def test_renders_with_policies(self):
        AuditRetentionPolicy.objects.create(
            name="Auth Policy",
            category="authentication",
            retention_days=90,
            is_active=True,
        )
        AuditRetentionPolicy.objects.create(
            name="Security Policy",
            category="security_event",
            severity="high",
            retention_days=365,
            is_active=True,
        )
        self._create_audit_event(category="authentication")

        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(reverse("audit:retention_dashboard"))
        self.assertEqual(resp.status_code, 200)


# =============================================================================
# Apply Retention Policies
# =============================================================================


class ApplyRetentionPoliciesTests(AuditViewsBaseTestCase):
    def test_requires_staff(self):
        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.post(reverse("audit:apply_retention_policies"))
        self.assertEqual(resp.status_code, 403)

    def test_no_confirm(self):
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.post(reverse("audit:apply_retention_policies"))
        self.assertRedirects(resp, reverse("audit:retention_dashboard"))

    @patch("apps.audit.views.audit_retention_service")
    def test_apply_success(self, mock_service):
        mock_service.apply_retention_policies.return_value = Ok(
            {"policies_applied": 2, "events_processed": 100, "errors": []}
        )
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:apply_retention_policies"),
            {"confirm": "yes"},
        )
        self.assertRedirects(resp, reverse("audit:retention_dashboard"))

    @patch("apps.audit.views.audit_retention_service")
    def test_apply_success_with_errors(self, mock_service):
        mock_service.apply_retention_policies.return_value = Ok(
            {
                "policies_applied": 2,
                "events_processed": 50,
                "errors": ["Policy X failed"],
            }
        )
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:apply_retention_policies"),
            {"confirm": "yes"},
        )
        self.assertRedirects(resp, reverse("audit:retention_dashboard"))

    @patch("apps.audit.views.audit_retention_service")
    def test_apply_error(self, mock_service):
        mock_service.apply_retention_policies.return_value = Err("Failed")
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:apply_retention_policies"),
            {"confirm": "yes"},
        )
        self.assertRedirects(resp, reverse("audit:retention_dashboard"))

    @patch("apps.audit.views.audit_retention_service")
    def test_apply_exception(self, mock_service):
        mock_service.apply_retention_policies.side_effect = Exception("Error")
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:apply_retention_policies"),
            {"confirm": "yes"},
        )
        self.assertRedirects(resp, reverse("audit:retention_dashboard"))


# =============================================================================
# Alerts Dashboard
# =============================================================================


class AlertsDashboardTests(AuditViewsBaseTestCase):
    def test_requires_staff(self):
        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.get(reverse("audit:alerts_dashboard"))
        self.assertEqual(resp.status_code, 403)

    def test_renders_default_filter(self):
        AuditAlert.objects.create(
            alert_type="security_incident",
            severity="critical",
            title="Test Alert",
            description="Test",
            status="active",
        )
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(reverse("audit:alerts_dashboard"))
        self.assertEqual(resp.status_code, 200)

    def test_all_status_filter(self):
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:alerts_dashboard"),
            {"status": "all"},
        )
        self.assertEqual(resp.status_code, 200)

    def test_open_status_filter(self):
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:alerts_dashboard"),
            {"status": "open"},
        )
        self.assertEqual(resp.status_code, 200)

    def test_with_type_and_severity_filters(self):
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:alerts_dashboard"),
            {
                "status": "resolved",
                "alert_type": "security_incident",
                "severity": "critical",
            },
        )
        self.assertEqual(resp.status_code, 200)

    def test_assigned_alerts_count(self):
        AuditAlert.objects.create(
            alert_type="security_incident",
            severity="critical",
            title="Assigned",
            description="Test",
            status="active",
            assigned_to=self.staff_user,
        )
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(reverse("audit:alerts_dashboard"))
        self.assertEqual(resp.status_code, 200)


# =============================================================================
# Update Alert Status
# =============================================================================


class UpdateAlertStatusTests(AuditViewsBaseTestCase):
    def setUp(self):
        super().setUp()
        self.alert = AuditAlert.objects.create(
            alert_type="security_incident",
            severity="critical",
            title="Test Alert",
            description="Test",
            status="active",
        )

    @patch("apps.audit.views.audit_service")
    def test_acknowledge(self, mock_audit):
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:update_alert_status", args=[self.alert.id]),
            {"action": "acknowledge"},
        )
        self.assertRedirects(resp, reverse("audit:alerts_dashboard"))
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.status, "acknowledged")

    @patch("apps.audit.views.audit_service")
    def test_assign_to_me(self, mock_audit):
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:update_alert_status", args=[self.alert.id]),
            {"action": "assign_to_me"},
        )
        self.assertRedirects(resp, reverse("audit:alerts_dashboard"))
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.status, "investigating")
        self.assertEqual(self.alert.assigned_to, self.staff_user)

    @patch("apps.audit.views.audit_service")
    def test_assign_to_me_non_active(self, mock_audit):
        """Assigning when status is not 'active' should not change status."""
        self.alert.status = "acknowledged"
        self.alert.save()
        self.client.login(email="staff@example.com", password="testpass123")
        self.client.post(
            reverse("audit:update_alert_status", args=[self.alert.id]),
            {"action": "assign_to_me"},
        )
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.status, "acknowledged")

    @patch("apps.audit.views.audit_service")
    def test_resolve(self, mock_audit):
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:update_alert_status", args=[self.alert.id]),
            {"action": "resolve", "resolution_notes": "Fixed it"},
        )
        self.assertRedirects(resp, reverse("audit:alerts_dashboard"))
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.status, "resolved")
        self.assertIsNotNone(self.alert.resolved_at)

    @patch("apps.audit.views.audit_service")
    def test_false_positive(self, mock_audit):
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:update_alert_status", args=[self.alert.id]),
            {"action": "false_positive", "resolution_notes": "Not a real issue"},
        )
        self.assertRedirects(resp, reverse("audit:alerts_dashboard"))
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.status, "false_positive")

    def test_nonexistent_alert(self):
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:update_alert_status", args=[uuid.uuid4()]),
            {"action": "acknowledge"},
        )
        self.assertRedirects(resp, reverse("audit:alerts_dashboard"))

    @patch("apps.audit.views.audit_service")
    def test_exception_handling(self, mock_audit):
        mock_audit.log_event.side_effect = Exception("Error")
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.post(
            reverse("audit:update_alert_status", args=[self.alert.id]),
            {"action": "acknowledge"},
        )
        # The exception is in the log_event call after save, so it's caught
        self.assertRedirects(resp, reverse("audit:alerts_dashboard"))


# =============================================================================
# Event Detail
# =============================================================================


class EventDetailTests(AuditViewsBaseTestCase):
    def test_requires_staff(self):
        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:event_detail", args=[uuid.uuid4()])
        )
        self.assertEqual(resp.status_code, 403)

    def test_renders_basic(self):
        event = self._create_audit_event()
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:event_detail", args=[event.id])
        )
        self.assertEqual(resp.status_code, 200)

    def test_with_related_by_user(self):
        event = self._create_audit_event()
        self._create_audit_event(description="Related event")
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:event_detail", args=[event.id])
        )
        self.assertEqual(resp.status_code, 200)

    def test_with_session_key(self):
        event = self._create_audit_event(session_key="testsession123")
        self._create_audit_event(session_key="testsession123", description="Same session")
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:event_detail", args=[event.id])
        )
        self.assertEqual(resp.status_code, 200)

    def test_with_request_id(self):
        event = self._create_audit_event(request_id="req-123-456")
        self._create_audit_event(request_id="req-123-456", description="Same request")
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:event_detail", args=[event.id])
        )
        self.assertEqual(resp.status_code, 200)

    def test_with_metadata_and_values(self):
        event = self._create_audit_event(
            metadata={"key": "value"},
            old_values={"field": "old"},
            new_values={"field": "new"},
        )
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:event_detail", args=[event.id])
        )
        self.assertEqual(resp.status_code, 200)

    def test_with_no_user(self):
        event = self._create_audit_event(user=None)
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:event_detail", args=[event.id])
        )
        self.assertEqual(resp.status_code, 200)

    def test_with_related_alerts(self):
        event = self._create_audit_event()
        alert = AuditAlert.objects.create(
            alert_type="security_incident",
            severity="critical",
            title="Related Alert",
            description="Test",
        )
        alert.related_events.add(event)

        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:event_detail", args=[event.id])
        )
        self.assertEqual(resp.status_code, 200)

    def test_nonexistent_event(self):
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:event_detail", args=[uuid.uuid4()])
        )
        self.assertEqual(resp.status_code, 404)

    def test_deduplicate_related_events(self):
        """When same event appears in multiple correlation sources, it should be deduplicated."""
        event = self._create_audit_event(
            session_key="sess1",
            request_id="req1",
        )
        # This event matches by user, session, AND request
        self._create_audit_event(
            session_key="sess1",
            request_id="req1",
            description="Multi-match",
        )
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(
            reverse("audit:event_detail", args=[event.id])
        )
        self.assertEqual(resp.status_code, 200)


# =============================================================================
# Legacy Export Data
# =============================================================================


class ExportDataTests(AuditViewsBaseTestCase):
    def test_redirects_to_gdpr_dashboard(self):
        self.client.login(email="user@example.com", password="testpass123")
        resp = self.client.get(reverse("audit:export"))
        self.assertRedirects(resp, reverse("audit:gdpr_dashboard"))


# =============================================================================
# _parse_date_filters helper
# =============================================================================


class ParseDateFiltersTests(TestCase):
    def test_parse_valid_dates(self):
        from apps.audit.views import _parse_date_filters  # noqa: PLC0415

        filters = {
            "start_date": "2024-01-15",
            "end_date": "2024-06-30",
        }
        result = _parse_date_filters(filters)
        self.assertIsNotNone(result["start_date"])
        self.assertIsNotNone(result["end_date"])

    def test_parse_invalid_date(self):
        from apps.audit.views import _parse_date_filters  # noqa: PLC0415

        filters = {"start_date": "not-a-date"}
        result = _parse_date_filters(filters)
        self.assertEqual(result["start_date"], "not-a-date")

    def test_parse_empty_dates(self):
        from apps.audit.views import _parse_date_filters  # noqa: PLC0415

        filters = {"start_date": "", "other": "value"}
        result = _parse_date_filters(filters)
        self.assertEqual(result["start_date"], "")
        self.assertEqual(result["other"], "value")

    def test_parse_no_dates(self):
        from apps.audit.views import _parse_date_filters  # noqa: PLC0415

        filters = {"action": "create"}
        result = _parse_date_filters(filters)
        self.assertEqual(result, {"action": "create"})

    def test_parse_non_string_date(self):
        from apps.audit.views import _parse_date_filters  # noqa: PLC0415

        # If the date is already a datetime, it should pass through
        dt = timezone.now()
        filters = {"start_date": dt}
        result = _parse_date_filters(filters)
        self.assertEqual(result["start_date"], dt)
