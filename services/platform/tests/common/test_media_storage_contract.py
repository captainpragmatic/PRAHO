"""Every media flow works on a storage that has no local paths, as S3 has none.

S3Storage.path() raises NotImplementedError, so code that asks a stored file for its filesystem
path breaks the moment media moves to a bucket (ADR-0057). These flows run against a storage that
delegates to the filesystem but refuses path(), and a scan keeps new code off local paths.
"""

from __future__ import annotations

import re
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import IO, Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files.base import File
from django.core.files.storage import FileSystemStorage, Storage, default_storage
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse

from apps.audit.export_files import delete_export_file, read_export_file, write_export_file
from apps.audit.services import GDPRExportService
from apps.customers.models import Customer
from apps.tickets.models import SupportCategory, Ticket, TicketAttachment
from apps.users.models import CustomerMembership

User = get_user_model()
LOCAL_PATH = re.compile(r"\.(?:file|pdf_file|xml_file|response_archive)\.path\b|storage\.path\(|settings\.MEDIA_ROOT")


class PathlessStorage(Storage):
    """The filesystem underneath, but no path(): the contract S3Storage gives media code."""

    def __init__(self, location: str) -> None:
        self._inner = FileSystemStorage(location=location)

    def _open(self, name: str, mode: str = "rb") -> File[Any]:
        return self._inner._open(name, mode)

    def _save(self, name: str, content: IO[Any]) -> str:
        return self._inner._save(name, content)

    def delete(self, name: str) -> None:
        self._inner.delete(name)

    def exists(self, name: str) -> bool:
        return self._inner.exists(name)

    def size(self, name: str) -> int:
        return self._inner.size(name)

    def listdir(self, path: str) -> tuple[list[str], list[str]]:
        return self._inner.listdir(path)

    def get_modified_time(self, name: str) -> datetime:
        return self._inner.get_modified_time(name)


@override_settings(DISABLE_AUDIT_SIGNALS=True)
class PathlessMediaTests(TestCase):
    def setUp(self) -> None:
        location = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, location, ignore_errors=True)
        storages = override_settings(
            STORAGES={
                "default": {"BACKEND": f"{__name__}.PathlessStorage", "OPTIONS": {"location": location}},
                "staticfiles": settings.STORAGES["staticfiles"],
            }
        )
        storages.enable()
        self.addCleanup(storages.disable)
        with self.assertRaises(NotImplementedError):
            default_storage.path("anything")
        self.user = User.objects.create_user(email="media@example.test", password="pass12345")

    def test_a_ticket_attachment_is_downloaded_without_a_local_path(self) -> None:
        customer = Customer.objects.create(
            name="Media SRL", company_name="Media SRL", customer_type="company", status="active",
            primary_email="media-co@example.test",
        )
        CustomerMembership.objects.create(user=self.user, customer=customer, role="owner", is_primary=True)
        ticket = Ticket.objects.create(
            title="Attachment", description="d", customer=customer, contact_email="media-co@example.test",
            category=SupportCategory.objects.create(name="Support", name_en="Support"), priority="normal",
            created_by=self.user,
        )
        attachment = TicketAttachment.objects.create(
            ticket=ticket, file=SimpleUploadedFile("log.txt", b"server log", content_type="text/plain"),
            filename="log.txt", file_size=10, content_type="text/plain", uploaded_by=self.user,
        )
        self.client.force_login(self.user)

        response = self.client.get(reverse("tickets:download_attachment", kwargs={"attachment_id": attachment.id}))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"server log")

    def test_a_gdpr_export_is_written_read_and_deleted_without_a_local_path(self) -> None:
        export = GDPRExportService.create_data_export_request(self.user).unwrap()

        path = write_export_file(export, '{"user_profile": {}}')
        export.file_path = path
        self.assertEqual(read_export_file(export), '{"user_profile": {}}')
        delete_export_file(path)

        self.assertFalse(default_storage.exists(path))


class NoLocalMediaPathsTests(TestCase):
    def test_no_application_code_asks_for_a_local_media_path(self) -> None:
        apps = Path(settings.BASE_DIR) / "apps"
        offenders = [
            f"{source.relative_to(apps)}:{number}"
            for source in sorted(apps.rglob("*.py"))
            for number, line in enumerate(source.read_text().splitlines(), 1)
            if LOCAL_PATH.search(line)
        ]
        self.assertEqual(offenders, [])
