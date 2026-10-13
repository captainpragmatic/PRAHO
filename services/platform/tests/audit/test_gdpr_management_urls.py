"""The GDPR management pages reach their routes.

The filter button and both download links were written as /app/… URLs, which no route serves. The
download links also added a UUID to a string with `|add:`, which renders an empty string.
"""

from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import DataExport
from apps.users.models import User


class GDPRManagementUrlTests(TestCase):
    def setUp(self) -> None:
        self.staff = User.objects.create_user(email="gdpr-links@example.test", is_staff=True, staff_role="admin")
        self.client.force_login(self.staff)

    def completed_export(self) -> DataExport:
        return DataExport.objects.create(
            requested_by=self.staff,
            export_type="gdpr",
            scope={},
            status="completed",
            file_path="exports/gdpr-links.json",
            expires_at=timezone.now() + timedelta(days=7),
        )

    def test_the_filter_button_loads_the_request_list(self) -> None:
        response = self.client.get(reverse("audit:gdpr_management_dashboard"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, f'hx-get="{reverse("audit:gdpr_export_requests_list")}"')
        self.assertNotContains(response, "/app/")

    def test_a_completed_export_links_to_its_download_in_the_list(self) -> None:
        export = self.completed_export()

        response = self.client.get(reverse("audit:gdpr_export_requests_list"))

        self.assertContains(response, f'href="{reverse("audit:download_user_export", args=[export.pk])}"')

    def test_a_completed_export_links_to_its_download_on_its_page(self) -> None:
        export = self.completed_export()

        with patch("apps.audit.views.default_storage.exists", return_value=True):
            response = self.client.get(reverse("audit:gdpr_export_detail", args=[export.pk]))

        self.assertContains(response, f'href="{reverse("audit:download_user_export", args=[export.pk])}"')
