"""#431: the backup pipeline transports archives honestly.

The archive is written on the REMOTE node by backup-domain, fetched into the
controller spool by the transport playbook (which deletes the remote temp copy
after a validated transfer), verified against the remote checksum, and only
then published to S3 — with the manifest finalized BEFORE publication. These
tests pin the transport contract and the fail-closed guards around it.
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import MagicMock, patch

from django.test import TestCase

from apps.billing.models import Currency
from apps.common.types import Err, Ok
from apps.customers.models import Customer
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_backup_service import BackupConfig, VirtualminBackupService
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer


class BackupRemoteHonestyTests(TestCase):
    """Backup verify/upload fail honestly for a remote archive; dest is recorded."""

    def setUp(self) -> None:
        self.customer = Customer.objects.create(
            name="Backup Customer", primary_email="bk@example.com", customer_type="individual"
        )
        self.plan = ServicePlan.objects.create(
            name="BK Plan", plan_type="shared_hosting", price_monthly=Decimal("10.00"), setup_fee=Decimal("0.00")
        )
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name="bk-svc",
            username="bkuser",
            price=Decimal("10.00"),
            status="active",
        )
        self.server = VirtualminServer.objects.create(
            name="bk-server", hostname="bk.example.com", api_username="api", max_domains=1000
        )
        self.server.set_api_password("pw")
        self.server.save()
        self.account = VirtualminAccount.objects.create(
            domain="bk.example.com",
            service=self.service,
            server=self.server,
            virtualmin_username="bkacct",
            status="active",
            praho_customer_id=self.customer.id,
            praho_service_id=self.service.id,
        )
        self.svc = VirtualminBackupService(self.server)

    def test_verify_refuses_unfetched_archive(self) -> None:
        """Verification requires a fetched spool archive; remote-only is refused."""
        metadata = {
            "backup_location": "remote",
            "backup_path": "/tmp/virtualmin_backup_x.tar.gz",  # noqa: S108  # Remote node path
            "backup_host": "bk.example.com",
        }
        result = self.svc._verify_backup_integrity("bk-1", metadata)
        self.assertTrue(result.is_err())
        msg = result.unwrap_err().lower()
        self.assertIn("spool", msg)
        self.assertNotIn("not found", msg)

    def test_upload_refuses_unfetched_archive(self) -> None:
        """Publication must refuse anything not fetched into the spool."""
        with patch.object(self.svc, "_get_s3_client", return_value=MagicMock()), patch.object(
            self.svc, "_get_backup_bucket", return_value="bucket"
        ):
            result = self.svc._upload_backup_to_s3(
                "bk-1", {"backup_location": "remote", "backup_path": "/tmp/x.tar.gz"}  # noqa: S108  # Remote node path
            )
        self.assertTrue(result.is_err())
        self.assertIn("spool", result.unwrap_err())

    def test_workflow_fetches_then_verifies_then_publishes(self) -> None:
        """The chain stamps the remote dest, fetches to spool, and publishes a finalized manifest."""
        metadata: dict = {}
        remote_dest = "/tmp/virtualmin_backup_abcd.tar.gz"  # noqa: S108  # Remote node path

        def fake_fetch(md: dict) -> Ok[None]:
            md["backup_location"] = "spool"
            md["backup_path"] = "/spool/virtualmin_backup_abcd.tar.gz"
            md["checksum_sha256_remote"] = "a" * 64
            return Ok(None)

        with (
            patch.object(self.svc, "_validate_backup_preconditions", return_value=Ok(None)),
            patch.object(self.svc, "_execute_backup_by_type", return_value=Ok(remote_dest)),
            patch.object(self.svc, "_fetch_archive_to_spool", side_effect=fake_fetch) as fetch,
            patch.object(self.svc, "_verify_backup_integrity", return_value=Ok(None)),
            patch.object(self.svc, "_upload_backup_to_s3", return_value=Ok({"s3_key": "k"})) as upload,
            patch.object(self.svc, "_release_spool_artifacts") as cleanup,
            patch.object(self.svc, "_update_backup_progress"),
        ):
            result = self.svc._backup_workflow_chain(self.account, "bk-1", metadata, BackupConfig())

        self.assertTrue(result.is_ok(), result)
        fetch.assert_called_once()
        upload.assert_called_once()
        cleanup.assert_called_once()
        # The manifest was finalized BEFORE publication.
        self.assertEqual(metadata["status"], "completed")
        self.assertIn("completed_at", metadata)
        self.assertEqual(metadata["backup_host"], self.server.hostname)

    def test_fetch_failure_stops_the_chain(self) -> None:
        """A failed transport must fail the backup with no publication."""
        with (
            patch.object(self.svc, "_validate_backup_preconditions", return_value=Ok(None)),
            patch.object(self.svc, "_execute_backup_by_type", return_value=Ok("/tmp/x.tar.gz")),  # noqa: S108
            patch.object(
                self.svc, "_fetch_archive_to_spool", return_value=Err("Backup archive fetch failed: timeout")
            ),
            patch.object(self.svc, "_upload_backup_to_s3") as upload,
            patch.object(self.svc, "_update_backup_progress"),
        ):
            result = self.svc._backup_workflow_chain(self.account, "bk-1", {}, BackupConfig())
        self.assertTrue(result.is_err())
        self.assertIn("fetch failed", result.unwrap_err())
        upload.assert_not_called()
