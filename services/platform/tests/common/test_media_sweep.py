"""The sweeper deletes only its own old files that no row names, and keeps everything else.

It owns ticket attachments and GDPR exports, the two kinds of file a crash or a failed commit can
leave without a row. It runs on a storage with no local paths, as S3 has none, and on S3 itself
with listings that come back in pages.
"""

from __future__ import annotations

import os
import re
import shutil
import tempfile
import uuid
from datetime import timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch

from botocore.exceptions import ClientError
from botocore.stub import Stubber
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone
from storages.backends.s3 import S3Storage

from apps.audit.export_files import write_export_file
from apps.audit.models import AuditEvent, DataExport
from apps.common.media_sweep import (
    GRACE_PERIOD,
    PAUSE_SETTING,
    sweep_orphaned_media,
    validate_sweep_configuration,
)
from apps.customers.models import Customer
from apps.settings.services import SettingsService
from apps.tickets.models import Ticket, TicketAttachment
from tests.common.test_media_storage_contract import PathlessStorage

OLD = timedelta(days=2)
ATTACHMENT = "tickets/attachments/ticket_20260101_120000_{}.pdf"


def _attachment_name(token: str) -> str:
    return ATTACHMENT.format(token * 32)


class MediaSweepTests(TestCase):
    def setUp(self) -> None:
        self.location = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.location, ignore_errors=True)
        storages = override_settings(
            STORAGES={
                "default": {
                    "BACKEND": "tests.common.test_media_storage_contract.PathlessStorage",
                    "OPTIONS": {"location": str(self.location)},
                },
                "staticfiles": settings.STORAGES["staticfiles"],
            }
        )
        storages.enable()
        self.addCleanup(storages.disable)
        customer = Customer.objects.create(name="Sweep SRL", status="active")
        self.ticket = Ticket.objects.create(customer=customer, title="Files", description="x", status="open")

    def _store(self, name: str, *, age: timedelta = OLD) -> str:
        stored = default_storage.save(name, ContentFile(b"bytes"))
        self.assertEqual(stored, name)
        moment = (timezone.now() - age).timestamp()
        os.utime(self.location / name, (moment, moment))
        return name

    def _exists(self, name: str) -> bool:
        return (self.location / name).exists()

    def test_sweeper_deletes_unreferenced_old_files_and_keeps_young_or_referenced(self) -> None:
        orphan = self._store(_attachment_name("a"))
        young = self._store(_attachment_name("b"), age=GRACE_PERIOD - timedelta(hours=1))
        referenced = self._store(_attachment_name("c"))
        TicketAttachment.objects.create(ticket=self.ticket, file=referenced, filename="c.pdf", file_size=5)

        result = sweep_orphaned_media()

        self.assertFalse(self._exists(orphan))
        self.assertTrue(self._exists(young))
        self.assertTrue(self._exists(referenced))
        self.assertEqual(
            result,
            {"deleted": 1, "kept_young": 1, "kept_referenced": 1, "kept_unknown": 0, "failed": 0, "paused": False},
        )
        event = AuditEvent.objects.get(action="delete", metadata__path=orphan)
        self.assertEqual(event.metadata["reason"], "orphaned_media_sweep")

    def test_sweeper_keeps_a_file_whose_row_commits_mid_scan(self) -> None:
        name = self._store(_attachment_name("d"))
        original = PathlessStorage.get_modified_time

        def row_commits_after_the_listing(storage: PathlessStorage, file_name: str) -> Any:
            # A writer that held the file past the grace period commits its row after the listing.
            TicketAttachment.objects.create(ticket=self.ticket, file=file_name, filename="d.pdf", file_size=5)
            return original(storage, file_name)

        with patch.object(PathlessStorage, "get_modified_time", row_commits_after_the_listing):
            result = sweep_orphaned_media()

        self.assertTrue(self._exists(name))
        self.assertEqual((result["deleted"], result["kept_referenced"]), (0, 1))

    def test_sweeper_removes_a_crashed_export_file(self) -> None:
        crashed = DataExport.objects.create(
            export_type="gdpr", status="processing", expires_at=timezone.now() + timedelta(days=7)
        )
        live = DataExport.objects.create(export_type="gdpr", status="completed", expires_at=timezone.now())
        crashed_path = write_export_file(crashed, "{}")  # The row never learned its path
        live.file_path = write_export_file(live, "{}")
        live.save(update_fields=["file_path"])
        for path in (crashed_path, live.file_path):
            moment = (timezone.now() - OLD).timestamp()
            os.utime(self.location / path, (moment, moment))

        result = sweep_orphaned_media()

        self.assertFalse(self._exists(crashed_path))
        self.assertTrue(self._exists(live.file_path))
        self.assertEqual((result["deleted"], result["kept_referenced"]), (1, 1))

    def test_sweeper_never_deletes_outside_its_owner_patterns(self) -> None:
        names = [
            self._store("tickets/attachments/invoice.pdf"),  # A name stored before names were random
            self._store(f"tickets/attachments/nested/{_attachment_name('e').rsplit('/', 1)[1]}"),
            self._store(_attachment_name("f").replace(".pdf", ".PDF")),
            self._store("gdpr_exports/notauuid.enc"),
            self._store(f"gdpr_exports/{uuid.uuid4()}.json"),
            self._store("efactura/xml/2026/01/invoice_1.xml"),
            self._store("invoices/pdf/invoice_1.pdf"),
        ]

        result = sweep_orphaned_media()

        self.assertEqual([name for name in names if not self._exists(name)], [])
        self.assertEqual(result["deleted"], 0)

    def test_a_file_whose_age_is_unknown_is_kept_and_reported(self) -> None:
        name = self._store(_attachment_name("9"))
        # No modification time, a file gone since the listing, and S3's answer for an object gone since it.
        gone_from_s3 = ClientError({"Error": {"Code": "404"}, "ResponseMetadata": {"HTTPStatusCode": 404}}, "HeadObject")
        for failure in (NotImplementedError(), FileNotFoundError(), gone_from_s3):
            with self.subTest(failure=type(failure).__name__):
                with patch.object(PathlessStorage, "get_modified_time", side_effect=failure):
                    result = sweep_orphaned_media()

                self.assertTrue(self._exists(name))
                self.assertEqual((result["deleted"], result["kept_unknown"]), (0, 1))

    def test_a_paused_sweeper_deletes_nothing(self) -> None:
        name = self._store(_attachment_name("1"))
        until = (timezone.now() + timedelta(days=7)).isoformat()
        self.assertTrue(SettingsService.update_setting(PAUSE_SETTING, until).is_ok())

        call_command("setup_default_settings", verbosity=0)  # Every platform start runs the catalog sync
        result = sweep_orphaned_media()

        self.assertTrue(self._exists(name))
        self.assertTrue(result["paused"])

        self.assertTrue(SettingsService.update_setting(PAUSE_SETTING, timezone.now().isoformat()).is_ok())
        self.assertEqual(sweep_orphaned_media()["deleted"], 1, "an expired pause no longer holds the sweep")


class S3MediaSweepTests(TestCase):
    """S3 lists a prefix in pages, and names keys with the storage location in front."""

    def test_sweeper_deletes_across_s3_listing_pages_by_storage_relative_name(self) -> None:
        storage = S3Storage(
            bucket_name="media", location="praho", access_key="test", secret_key="test", region_name="eu-west-1"
        )
        first, second = _attachment_name("a"), _attachment_name("b")
        old = timezone.now() - OLD
        client = storage.connection.meta.client
        with Stubber(client) as stub:
            listing = {"Bucket": "media", "Delimiter": "/", "Prefix": "praho/tickets/attachments/"}
            stub.add_response(
                "list_objects",
                {"IsTruncated": True, "NextMarker": f"praho/{first}", "Contents": [{"Key": f"praho/{first}"}]},
                listing,
            )
            stub.add_response(
                "list_objects",
                {"IsTruncated": False, "Contents": [{"Key": f"praho/{second}"}]},
                {**listing, "Marker": f"praho/{first}"},
            )
            for name in (first, second):
                stub.add_response("head_object", {"LastModified": old}, {"Bucket": "media", "Key": f"praho/{name}"})
                stub.add_response("delete_object", {}, {"Bucket": "media", "Key": f"praho/{name}"})
            stub.add_response(
                "list_objects", {"IsTruncated": False}, {**listing, "Prefix": "praho/gdpr_exports/"}
            )

            result = sweep_orphaned_media(storage=storage)

            stub.assert_no_pending_responses()
        self.assertEqual(result["deleted"], 2)
        self.assertEqual(
            sorted(AuditEvent.objects.filter(action="delete").values_list("metadata__path", flat=True)),
            [first, second],
        )


class SweepConfigurationTests(TestCase):
    def test_xml_path_setting_cannot_point_into_a_swept_prefix(self) -> None:
        key = "efactura.storage.xml_path"
        for value in ("tickets/attachments/", "gdpr_exports/%Y/", "efactura/../tickets/attachments/", "/efactura/"):
            with self.subTest(value=value):
                self.assertTrue(SettingsService.update_setting(key, value).is_err())
        for value in ("efactura/xml/%Y/%m/", "efactura/archive/", ""):
            with self.subTest(value=value):
                self.assertTrue(SettingsService.update_setting(key, value).is_ok())

        validate_sweep_configuration()
        with (
            override_settings(EFACTURA_STORAGE_XML_PATH="gdpr_exports/"),
            self.assertRaisesRegex(ImproperlyConfigured, re.escape(key)),
        ):
            validate_sweep_configuration()

    def test_grace_period_must_outlast_every_task_budget(self) -> None:
        hours = int(GRACE_PERIOD.total_seconds() // 3600)
        with (
            override_settings(Q_CLUSTER={**settings.Q_CLUSTER, "retry": hours * 3600}),
            self.assertRaisesRegex(ImproperlyConfigured, "grace"),
        ):
            validate_sweep_configuration()
