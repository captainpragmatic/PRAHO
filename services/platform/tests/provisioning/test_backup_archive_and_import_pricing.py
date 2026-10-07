"""Behaviour regressions for the fourth provisioning review round."""

from __future__ import annotations

import hashlib
import io
import tarfile
from decimal import Decimal
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.urls import reverse
from django.utils import timezone

from apps.billing.models import Currency, FXRate
from apps.provisioning.models import Server, Service, ServicePlanPrice
from apps.provisioning.provisioning_service import ProvisioningService
from apps.provisioning.virtualmin_backup_service import VirtualminBackupService
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob
from apps.provisioning.virtualmin_service import VirtualminProvisioningService
from apps.settings.services import SettingsService
from tests.helpers.fsm_helpers import force_status
from tests.provisioning.test_cov_virtualmin_gateway_listing import http_response
from tests.provisioning.test_cov_virtualmin_views_servers import VirtualminViewsFixture
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase


class ArchiveFormatRegressionTests(VirtualminTaskTestBase):
    def archive(self, prefix: str, features: tuple[str, ...]) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for feature in features:
                member = tarfile.TarInfo(f"{prefix}{self.account.domain}_{feature}")
                member.size = 4
                archive.addfile(member, io.BytesIO(b"data"))
        return buffer.getvalue()

    def test_native_and_legacy_archives_require_exactly_the_requested_features(self) -> None:
        backups = VirtualminBackupService(self.server)
        with TemporaryDirectory() as directory:
            path = Path(directory) / "backup.tar.gz"
            for prefix in ("", ".backup/", "./.backup/"):
                for backup_type, features in (
                    ("full", ("virtualmin", "mail", "mysql", "dir", "ssl")),
                    ("config_only", ("virtualmin", "dir")),
                ):
                    with self.subTest(prefix=prefix, backup_type=backup_type):
                        data = self.archive(prefix, features)
                        path.write_bytes(data)
                        metadata: dict[str, object] = {
                            "backup_path": str(path),
                            "backup_location": "spool",
                            "domain": self.account.domain,
                            "backup_type": backup_type,
                            "include_email": True,
                            "include_databases": True,
                            "include_files": True,
                            "include_ssl": True,
                            "checksum_sha256_remote": hashlib.sha256(data).hexdigest(),
                        }
                        verified = backups._verify_backup_integrity("native", metadata)
                        self.assertTrue(verified.is_ok(), verified)
                        self.assertEqual(metadata["verification_status"], "passed")
                        self.assertEqual(metadata["file_count"], len(features))
                        missing = features[-1]
                        data = self.archive(prefix, features[:-1])
                        path.write_bytes(data)
                        metadata["checksum_sha256_remote"] = hashlib.sha256(data).hexdigest()
                        metadata.pop("verification_status")
                        refused = backups._verify_backup_integrity("missing", metadata)
                        self.assertEqual(
                            refused.unwrap_err(), f"Backup is missing requested feature members: {missing}"
                        )
                        self.assertNotIn("verification_status", metadata)


class VirtualminServerContractTests(VirtualminTaskTestBase):
    def test_native_server_connects_and_generic_virtualmin_server_stays_manual(self) -> None:
        with patch(
            "apps.provisioning.virtualmin_gateway.safe_request",
            return_value=http_response({"status": "success", "data": []}),
        ):
            gateway = VirtualminProvisioningService(self.server)._get_gateway()
            self.assertTrue(gateway.test_connection().is_ok())
            server = Server.objects.create(
                name="Generic Virtualmin host",
                hostname="generic.example.com",
                server_type="shared",
                primary_ip="203.0.113.8",
                cpu_cores=4,
                ram_gb=8,
                disk_capacity_gb=100,
                control_panel="Virtualmin",
                management_api_url="https://generic.example.com:10000/virtual-server/remote.cgi",
            )
            self.service.server = server
            force_status(self.service, "pending")
            self.service.save(update_fields=["server"])
            result = ProvisioningService.provision_service(self.service)
        self.assertEqual(result["status"], "pending_manual")
        self.service.refresh_from_db()
        self.assertEqual(self.service.status, "provisioning")
        self.assertTrue(result["requires_action"])
        self.assertIn("VirtualminServer", self.service.provisioning_errors)


class VirtualminSyncPriceTests(VirtualminViewsFixture):
    def currency_prices(self) -> None:
        eur, _ = Currency.objects.get_or_create(code="EUR", defaults={"symbol": "€", "decimals": 2})
        ServicePlanPrice.objects.update_or_create(
            service_plan=self.plan, currency=eur, defaults={"monthly_price_cents": 200, "is_active": True}
        )
        FXRate.objects.create(
            base_code=eur,
            quote_code=self.currency,
            rate=Decimal("5.00"),
            as_of=timezone.localdate(),
            source=FXRate.Source.BNR,
            source_reference="review regression",
            fetched_at=timezone.now(),
        )

    def listing(self, username: str) -> None:
        self.payload["data"] = [
            {"name": f"{username}.example.com", "values": {"Username": [username], "Status": ["Enabled"]}}
        ]

    def test_sync_uses_distinct_active_ron_and_eur_monthly_prices(self) -> None:
        self.currency_prices()
        for code, expected in (("RON", Decimal("10.00")), ("EUR", Decimal("2.00"))):
            with self.subTest(currency=code):
                changed = SettingsService.update_setting("billing.default_currency", code)
                self.assertTrue(changed.is_ok(), changed)
                username = f"import{code.lower()}"
                self.listing(username)
                response = self.client.post(reverse("provisioning:virtualmin_accounts_sync"))
                self.assertEqual(response.status_code, 302)
                service = Service.objects.get(username=username)
                self.assertEqual(service.currency_id, code)
                self.assertEqual(service.price, expected)
                self.assertEqual(VirtualminAccount.objects.get(service=service).server_id, self.server.pk)

    def test_sync_refuses_inactive_and_missing_prices_without_creating_service_or_account(self) -> None:
        self.currency_prices()
        changed = SettingsService.update_setting("billing.default_currency", "EUR")
        self.assertTrue(changed.is_ok(), changed)
        prices = ServicePlanPrice.objects.filter(service_plan=self.plan, currency_id="EUR")
        prices.update(is_active=False)
        for state in ("inactive", "missing"):
            with self.subTest(state=state):
                if state == "missing":
                    prices.delete()
                username = f"import{state}"
                self.listing(username)
                response = self.client.post(reverse("provisioning:virtualmin_accounts_sync"))
                self.assertEqual(response.status_code, 302)
                self.assertFalse(Service.objects.filter(username=username).exists())
                self.assertFalse(VirtualminAccount.objects.filter(virtualmin_username=username).exists())
                self.assertIn("1 errors occurred", self.messages(response))
        self.account.delete()
        self.listing(self.service.username)
        existing = self.client.post(reverse("provisioning:virtualmin_accounts_sync"))
        self.assertEqual(existing.status_code, 302)
        self.service.refresh_from_db()
        self.assertEqual(self.service.currency_id, "RON")
        self.assertEqual(self.service.price, Decimal("10.00"))
        self.assertEqual(VirtualminAccount.objects.get(service=self.service).server_id, self.server.pk)


class VirtualminJobOutcomeTests(VirtualminViewsFixture):
    def test_failed_backup_and_restore_render_persisted_failure_reason(self) -> None:
        for operation in ("backup_domain", "restore_domain"):
            with self.subTest(operation=operation):
                reason = f"{operation}: remote archive verification refused"
                job = VirtualminProvisioningJob.objects.create(
                    server=self.server,
                    account=self.account,
                    operation=operation,
                    status="failed",
                    status_message=reason,
                    result={"diagnostic": f"{operation}-partial-42"},
                )
                response = self.client.get(reverse("provisioning:virtualmin_job_status", args=[job.pk]))
                self.assertContains(response, reason)
                self.assertContains(response, f"{operation}-partial-42")

    def test_completed_backup_and_restore_render_persisted_result_and_message(self) -> None:
        for operation in ("backup_domain", "restore_domain"):
            with self.subTest(operation=operation):
                outcome = f"{operation}-published-42"
                message = f"{operation}: completed successfully"
                job = VirtualminProvisioningJob.objects.create(
                    server=self.server,
                    account=self.account,
                    operation=operation,
                    status="completed",
                    status_message=message,
                    result={"archive": outcome},
                )
                response = self.client.get(reverse("provisioning:virtualmin_job_status", args=[job.pk]))
                self.assertContains(response, outcome)
                self.assertContains(response, message)
