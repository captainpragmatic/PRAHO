"""Coverage additions for Virtualmin account creation through the real HTTP gateway."""

from __future__ import annotations

from requests import Response

from apps.common.types import Retriability, retriability_of
from apps.provisioning.virtualmin_gateway import VirtualminGateway
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from apps.provisioning.virtualmin_service import VirtualminAccountCreationData, VirtualminProvisioningService
from apps.settings.services import SettingsService
from tests.provisioning.test_cov_virtualmin_gateway_listing import http_response
from tests.provisioning.test_cov_virtualmin_tasks_signals import VirtualminCoverageCase


class VirtualminServiceCoverageCase(VirtualminCoverageCase):
    def setUp(self) -> None:
        self.payloads: dict[str, dict[str, object]] = {
            "list-templates": {"status": "success", "templates": ["Default"]},
            "create-domain": {"status": "success", "message": "Domain created"},
        }
        super().setUp()
        self.provisioning = VirtualminProvisioningService(self.server, task_budget_seconds=777)

    def _http(
        self,
        gateway: VirtualminGateway,
        params: dict[str, object],
        auth: tuple[str, str] | None = None,
        timeout_seconds: int | None = None,
    ) -> Response:
        program = str(params["program"])
        if program in self.payloads:
            self.requests.append(dict(params))
            return http_response(self.payloads[program])
        return super()._http(gateway, params, auth, timeout_seconds)

    def _creation(self) -> VirtualminAccountCreationData:
        return VirtualminAccountCreationData(
            service=self.service,
            domain=self.service.domain,
            username=self.service.username,
            password="CoveragePass123!",
            server=self.server,
        )

    def _programs(self) -> list[str]:
        return [str(request["program"]) for request in self.requests]


class VirtualminCreationCoverageTests(VirtualminServiceCoverageCase):
    def test_creation_persists_account_job_and_remote_parameters(self) -> None:
        result = self.provisioning.create_virtualmin_account(self._creation())
        account = result.unwrap()
        account.refresh_from_db()
        self.server.refresh_from_db()
        self.assertEqual(account.status, "active")
        self.assertIsNotNone(account.provisioned_at)
        self.assertEqual(account.service_id, self.service.pk)
        self.assertEqual(account.praho_customer_id, self.customer.pk)
        self.assertEqual(account.get_password(), "CoveragePass123!")
        self.assertEqual(self.server.current_domains, 4)
        job = VirtualminProvisioningJob.objects.get(account=account, operation="create_domain")
        self.assertEqual(job.status, "completed")
        self.assertEqual(job.parameters["task_budget_seconds"], 777)
        self.assertEqual(
            {key: value for key, value in self.requests[-1].items() if key != "comment"},
            {
                "program": "create-domain",
                "domain": account.domain,
                "user": account.virtualmin_username,
                "pass": "CoveragePass123!",
                "template": "Default",
                "json": "1",
            },
        )

    def test_automatic_credentials_are_persisted_and_sent_to_remote(self) -> None:
        data = self._creation()
        data.username = None
        data.password = None
        account = self.provisioning.create_virtualmin_account(data).unwrap()
        self.assertEqual(account.virtualmin_username, "coverage")
        password = account.get_password()
        self.assertEqual(len(password), 16)
        self.assertTrue(any(character.islower() for character in password))
        self.assertTrue(any(character.isupper() for character in password))
        self.assertTrue(any(character.isdigit() for character in password))
        self.assertEqual(self.requests[-1]["pass"], password)
        self.assertEqual(self.requests[-1]["user"], account.virtualmin_username)

    def test_invalid_creation_inputs_leave_no_account_job_or_remote_request(self) -> None:
        for field, value in (
            ("domain", "bad/domain.example.com"),
            ("username", "Bad User"),
            ("password", "weak"),
            ("template", "../Default"),
        ):
            with self.subTest(field=field):
                data = self._creation()
                setattr(data, field, value)
                result = self.provisioning.create_virtualmin_account(data)
                self.assertIn("Validation error:", result.unwrap_err())
                self.assertFalse(VirtualminAccount.objects.exists())
                self.assertFalse(VirtualminProvisioningJob.objects.exists())
                self.assertEqual(self.requests, [])

    def test_duplicate_domain_is_rejected_before_job_or_remote_request(self) -> None:
        existing = self._account()
        result = self.provisioning.create_virtualmin_account(self._creation())
        self.assertEqual(result.unwrap_err(), f"Domain {existing.domain} already exists in PRAHO")
        self.assertEqual(list(VirtualminAccount.objects.values_list("pk", flat=True)), [existing.pk])
        self.assertFalse(VirtualminProvisioningJob.objects.exists())
        self.assertEqual(self.requests, [])

    def test_no_available_server_refuses_creation_without_rows(self) -> None:
        VirtualminServer.objects.filter(pk=self.server.pk).update(current_domains=100)
        data = self._creation()
        data.server = None
        result = self.provisioning.create_virtualmin_account(data)
        self.assertIn("Server selection failed: No available servers", result.unwrap_err())
        self.assertFalse(VirtualminAccount.objects.exists())
        self.assertFalse(VirtualminProvisioningJob.objects.exists())
        self.assertEqual(self.requests, [])

    def test_draining_explicit_server_records_retriable_failed_job(self) -> None:
        VirtualminServer.objects.filter(pk=self.server.pk).update(is_draining=True)
        result = self.provisioning.create_virtualmin_account(self._creation())
        self.assertEqual(result.unwrap_err(), "Target server is draining")
        self.assertEqual(retriability_of(result), Retriability.RETRIABLE)
        account = VirtualminAccount.objects.get(service=self.service)
        self.assertEqual(account.status, "error")
        job = VirtualminProvisioningJob.objects.get(account=account)
        self.assertEqual(job.status, "failed")
        self.assertIsNotNone(job.next_retry_at)
        self.assertEqual(self.requests, [])

    def test_capacity_preflight_failure_preserves_counter_and_avoids_creation(self) -> None:
        VirtualminServer.objects.filter(pk=self.server.pk).update(current_domains=100)
        self.server.refresh_from_db()
        result = self.provisioning.create_virtualmin_account(self._creation())
        self.assertIn("at capacity (100/100 domains)", result.unwrap_err())
        self.server.refresh_from_db()
        self.assertEqual(self.server.current_domains, 100)
        account = VirtualminAccount.objects.get(service=self.service)
        self.assertEqual(account.status, "error")
        self.assertEqual(VirtualminProvisioningJob.objects.get(account=account).status, "failed")
        self.assertEqual(self._programs(), ["info"])

    def test_username_conflict_fails_preflight_without_create_request(self) -> None:
        self.payloads["list-domains"] = {
            "status": "success",
            "data": [{"name": "another.example.com", "values": {"Username": self.service.username}}],
        }
        result = self.provisioning.create_virtualmin_account(self._creation())
        self.assertIn(f"Username {self.service.username} already exists on server", result.unwrap_err())
        self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)
        job = VirtualminProvisioningJob.objects.get(operation="create_domain")
        self.assertEqual(job.status, "failed")
        self.assertIsNone(job.next_retry_at)
        self.assertNotIn("create-domain", self._programs())

    def test_template_listing_failure_fails_closed_without_create_request(self) -> None:
        self.payloads["list-templates"] = {"status": "failure", "error": "permission denied"}
        result = self.provisioning.create_virtualmin_account(self._creation())
        self.assertIn("Template availability check failed:", result.unwrap_err())
        self.assertEqual(VirtualminAccount.objects.get(service=self.service).status, "error")
        self.assertEqual(VirtualminProvisioningJob.objects.get(operation="create_domain").status, "failed")
        self.assertNotIn("create-domain", self._programs())

    def test_remote_creation_rejection_persists_error_without_incrementing_counter(self) -> None:
        self.payloads["create-domain"] = {"status": "failure", "error": "quota exceeded"}
        result = self.provisioning.create_virtualmin_account(self._creation())
        self.assertEqual(result.unwrap_err(), "quota exceeded")
        self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)
        account = VirtualminAccount.objects.get(service=self.service)
        self.assertEqual(account.status, "error")
        self.assertEqual(account.status_message, "quota exceeded")
        job = VirtualminProvisioningJob.objects.get(account=account)
        self.assertEqual(job.status, "failed")
        self.assertEqual(job.status_message, "quota exceeded")
        self.assertIsNone(job.next_retry_at)
        self.server.refresh_from_db()
        self.assertEqual(self.server.current_domains, 3)

    def test_reprovision_reuses_account_rotates_password_and_records_job(self) -> None:
        account = self._account("error")
        account.set_password("BeforeRecovery123!")
        account.save(update_fields=["encrypted_password"])
        result = self.provisioning.reprovision_virtualmin_account(account)
        self.assertEqual(result.unwrap().pk, account.pk)
        account.refresh_from_db()
        self.assertEqual(account.status, "active")
        self.assertNotEqual(account.get_password(), "BeforeRecovery123!")
        self.assertEqual(self.requests[-1]["pass"], account.get_password())
        self.assertEqual(VirtualminAccount.objects.count(), 1)
        job = VirtualminProvisioningJob.objects.get(account=account)
        self.assertEqual(job.correlation_id, f"reprovision_domain_{account.pk}")
        self.assertEqual(job.status, "completed")

    def test_reprovision_failure_preserves_account_identity_and_persists_error(self) -> None:
        account = self._account("error")
        self.payloads["create-domain"] = {"status": "failure", "error": "quota exceeded"}
        result = self.provisioning.reprovision_virtualmin_account(account)
        self.assertEqual(result.unwrap_err(), "quota exceeded")
        self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)
        account.refresh_from_db()
        self.assertEqual(account.status, "error")
        self.assertEqual(account.status_message, "quota exceeded")
        self.assertEqual(VirtualminAccount.objects.count(), 1)
        self.assertEqual(VirtualminProvisioningJob.objects.get(account=account).status, "failed")

    def test_stored_quotas_persist_and_use_virtualmin_units(self) -> None:
        self.assertTrue(SettingsService.update_setting("virtualmin.domain_quota_default_mb", 25).is_ok())
        self.assertTrue(SettingsService.update_setting("virtualmin.bandwidth_quota_default_mb", 50).is_ok())
        account = self.provisioning.create_virtualmin_account(self._creation()).unwrap()
        account.refresh_from_db()
        self.assertEqual(account.disk_quota_mb, 25)
        self.assertEqual(account.bandwidth_quota_mb, 50)
        self.assertEqual(self.requests[-1]["quota"], str(25 * 1024))
        self.assertEqual(self.requests[-1]["bandwidth"], str(50 * 1024 * 1024))
        self.assertEqual(account.status, "active")

    def test_insufficient_remote_disk_fails_preflight_and_keeps_quota_snapshot(self) -> None:
        self.assertTrue(SettingsService.update_setting("virtualmin.domain_quota_default_mb", 25).is_ok())
        self.payloads["info"] = {"status": "success", "output": f"disk_free: {10 * 1024 * 1024}\n"}
        result = self.provisioning.create_virtualmin_account(self._creation())
        self.assertIn("Insufficient disk space: 10MB available, 25MB requested", result.unwrap_err())
        account = VirtualminAccount.objects.get(service=self.service)
        self.assertEqual(account.status, "error")
        self.assertEqual(account.disk_quota_mb, 25)
        self.assertEqual(self._programs(), ["info"])
        self.server.refresh_from_db()
        self.assertEqual(self.server.current_domains, 3)

    def test_unhealthy_server_fails_preflight_without_domain_creation(self) -> None:
        self.rejections["info"] = "permission denied"
        result = self.provisioning.create_virtualmin_account(self._creation())
        self.assertIn("Server reported unhealthy:", result.unwrap_err())
        account = VirtualminAccount.objects.get(service=self.service)
        self.assertEqual(account.status, "error")
        self.assertEqual(VirtualminProvisioningJob.objects.get(account=account).status, "failed")
        self.assertEqual(self._programs(), ["info"])

    def test_domain_listing_failure_fails_closed_without_domain_creation(self) -> None:
        self.payloads["list-domains"] = {"status": "failure", "error": "permission denied"}
        result = self.provisioning.create_virtualmin_account(self._creation())
        self.assertIn("Domain conflict check failed:", result.unwrap_err())
        self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)
        self.assertEqual(VirtualminAccount.objects.get(service=self.service).status, "error")
        self.assertNotIn("create-domain", self._programs())

    def test_missing_template_fails_preflight_without_domain_creation(self) -> None:
        self.payloads["list-templates"] = {"status": "success", "templates": ["Other"]}
        result = self.provisioning.create_virtualmin_account(self._creation())
        self.assertIn("Template Default not found on server", result.unwrap_err())
        self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)
        self.assertEqual(VirtualminAccount.objects.get(service=self.service).status, "error")
        self.assertNotIn("create-domain", self._programs())
