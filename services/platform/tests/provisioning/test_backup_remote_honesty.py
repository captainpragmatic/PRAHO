"""#326: the backup pipeline must be honest about the remote archive location.

_execute_full_backup writes the archive on the REMOTE Virtualmin host (the dest is
passed to the backup-domain API), but the returned dest was discarded and verify/upload
did local os.path.exists on a reconstructed token-less path — every backup failed with a
misleading "Backup file not found" and nothing reached S3. These tests pin the honest
behaviour: the real dest is recorded and marked remote, and verify/upload fail with an
explicit remote-not-implemented error rather than a local file-not-found.
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import MagicMock, patch

from django.test import TestCase

from apps.billing.models import Currency
from apps.common.types import Ok
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

    def test_verify_fails_honestly_for_remote_archive(self) -> None:
        """A remote-located archive must fail with an explicit remote error, not 'file not found'."""
        metadata = {
            "backup_location": "remote",
            "backup_path": "/srv/vm/virtualmin_backup_x.tar.gz",
            "backup_host": "bk.example.com",
        }
        result = self.svc._verify_backup_integrity("bk-1", metadata)
        self.assertTrue(result.is_err())
        msg = result.unwrap_err().lower()
        self.assertIn("remote", msg)
        self.assertNotIn("not found", msg)

    def test_upload_refuses_remote_archive(self) -> None:
        """Upload must refuse a remote archive rather than reconstruct a local path."""
        with patch.object(self.svc, "_get_s3_client", return_value=MagicMock()), patch.object(
            self.svc, "_get_backup_bucket", return_value="bucket"
        ):
            result = self.svc._upload_backup_to_s3(
                "bk-1", {"backup_location": "remote", "backup_path": "/srv/vm/x.tar.gz"}
            )
        self.assertTrue(result.is_err())
        self.assertIn("remote transfer is not implemented", result.unwrap_err())

    def test_workflow_records_real_dest_and_marks_remote(self) -> None:
        """The dest returned by the backup step is stored in metadata and marked remote."""
        metadata: dict = {}
        remote_dest = "/srv/vm/virtualmin_backup_bk-1_abcd.tar.gz"

        with (
            patch.object(self.svc, "_validate_backup_preconditions", return_value=Ok(None)),
            patch.object(self.svc, "_execute_backup_by_type", return_value=Ok(remote_dest)),
            patch.object(self.svc, "_update_backup_progress"),
        ):
            # Verification will now fail honestly (remote), which is the point — but metadata
            # must first be stamped with the real dest and remote markers.
            result = self.svc._backup_workflow_chain(self.account, "bk-1", metadata, BackupConfig())

        self.assertEqual(metadata["backup_path"], remote_dest)
        self.assertEqual(metadata["backup_location"], "remote")
        self.assertEqual(metadata["backup_host"], self.server.hostname)
        # The workflow surfaces the honest remote failure rather than a false success.
        self.assertTrue(result.is_err())
        self.assertIn("remote", result.unwrap_err().lower())
