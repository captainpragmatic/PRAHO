"""Restore admission with the real backup service and a stubbed S3 transport."""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from io import BytesIO
from unittest.mock import patch

import boto3
from botocore.response import StreamingBody
from botocore.stub import Stubber
from django.urls import reverse
from django.utils import timezone

from tests.provisioning.test_virtualmin_qa_closeout import VirtualminQATestBase


class VirtualminQAS3ViewsTests(VirtualminQATestBase):
    @contextmanager
    def s3_metadata(self) -> Iterator[None]:
        self.setting("backup.s3_bucket_name", "qa-backups")
        client = boto3.client(
            "s3", region_name="eu-west-1", aws_access_key_id="qa-access", aws_secret_access_key="qa-secret"
        )
        metadata = {
            "backup_id": "qa-backup-1",
            "domain": self.account.domain,
            "praho_service_id": str(self.service.pk),
            "backup_type": "full",
            "created_at": timezone.now().isoformat(),
            "status": "completed",
            "include_files": True,
            "size_mb": 12,
        }
        key = "virtualmin-backups/qa-backup-1/metadata.json"
        body = json.dumps(metadata).encode()
        stubber = Stubber(client)
        stubber.add_response(
            "list_objects_v2",
            {"Contents": [{"Key": key}]},
            {"Bucket": "qa-backups", "Prefix": "virtualmin-backups/"},
        )
        stubber.add_response(
            "get_object", {"Body": StreamingBody(BytesIO(body), len(body))}, {"Bucket": "qa-backups", "Key": key}
        )
        with stubber, patch("apps.provisioning.virtualmin_backup_service.boto3.client", return_value=client):
            yield
        stubber.assert_no_pending_responses()

    def test_restore_admission_redirects_to_registered_job_page(self) -> None:
        with self.s3_metadata():
            response = self.client.post(
                reverse("provisioning:virtualmin_account_restore", args=[self.account.pk]),
                {"backup_id": "qa-backup-1", "restore_files": "on", "confirm_restore": "on", "force_restore": "on"},
            )
        self.assert_admitted("restore_domain", response.status_code, response.headers.get("Location"))
