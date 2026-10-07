"""WP17 coverage additions for provisioning parameter rejection and dispatch."""

from __future__ import annotations

from dataclasses import replace
from unittest.mock import patch

from apps.provisioning import virtualmin_tasks
from apps.provisioning.security_utils import SecureTaskParameters
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob
from tests.provisioning.test_cov_virtualmin_tasks_signals import VirtualminCoverageCase

VALID_UUID = "11111111-1111-4111-8111-111111111111"


class ProvisioningParameterEffectsTests(VirtualminCoverageCase):
    def _params(self) -> virtualmin_tasks.VirtualminProvisioningParams:
        return {"service_id": VALID_UUID, "domain": self.service.domain}

    def test_missing_core_parameter_returns_processing_error_without_rows(self) -> None:
        result = virtualmin_tasks.provision_virtualmin_account({"service_id": VALID_UUID})
        self.assertEqual(result, {"success": False, "error": "Parameter processing failed"})
        self.assertFalse(VirtualminAccount.objects.exists())
        self.assertFalse(VirtualminProvisioningJob.objects.exists())

    def test_tampered_secure_payload_is_rejected_before_provisioning(self) -> None:
        secure = SecureTaskParameters.create(dict(self._params()))
        result = virtualmin_tasks.provision_virtualmin_account(replace(secure, parameter_hash="0" * 64))
        self.assertEqual(result, {"success": False, "error": "Parameter processing failed"})
        self.assertFalse(VirtualminAccount.objects.exists())
        self.assertEqual(self.requests, [])

    def test_invalid_parameters_return_validation_error_without_remote_work(self) -> None:
        cases: tuple[virtualmin_tasks.VirtualminProvisioningParams, ...] = (
            {"service_id": "invalid-id"},
            {"domain": "bad/domain.example.com"},
            {"username": "Bad User"},
            {"template": "../Default"},
        )
        for invalid in cases:
            with self.subTest(parameters=invalid):
                params = self._params()
                params.update(invalid)
                result = virtualmin_tasks.provision_virtualmin_account(params)
                self.assertEqual(result, {"success": False, "error": "Validation failed"})
                self.assertFalse(VirtualminAccount.objects.exists())
                self.assertFalse(VirtualminProvisioningJob.objects.exists())
                self.assertEqual(self.requests, [])

    def test_encrypted_invalid_domain_is_decrypted_and_rejected_without_rows(self) -> None:
        params = self._params()
        params["domain"] = "bad/domain.example.com"
        result = virtualmin_tasks.provision_virtualmin_account(SecureTaskParameters.create(dict(params)))
        self.assertEqual(result, {"success": False, "error": "Validation failed"})
        self.assertFalse(VirtualminAccount.objects.exists())
        self.assertFalse(VirtualminProvisioningJob.objects.exists())
        self.assertEqual(self.requests, [])

    def test_legacy_dispatch_failure_raises_without_a_queued_payload(self) -> None:
        with (
            patch.object(self.broker, "enqueue", side_effect=ConnectionError("broker unavailable")),
            self.assertRaisesMessage(ConnectionError, "broker unavailable"),
        ):
            virtualmin_tasks.provision_virtualmin_account_async(self._params())
        self.assertEqual(self.broker.queued(), [])

    def test_secure_dispatch_failure_raises_without_a_queued_payload(self) -> None:
        secure = SecureTaskParameters.create(dict(self._params()))
        with (
            patch.object(self.broker, "enqueue", side_effect=ConnectionError("broker unavailable")),
            self.assertRaisesMessage(ConnectionError, "broker unavailable"),
        ):
            virtualmin_tasks.provision_virtualmin_account_async(secure)
        self.assertEqual(self.broker.queued(), [])

    def test_secure_dispatch_preserves_encrypted_parameters_and_task_budget(self) -> None:
        secure = SecureTaskParameters.create(dict(self._params()))
        task_id = virtualmin_tasks.provision_virtualmin_account_async(secure)
        self.assertEqual(
            self.broker.queued(), [("apps.provisioning.virtualmin_tasks.provision_virtualmin_account", secure)]
        )
        package = self._packages()[0]
        self.assertEqual(package["id"], task_id)
        self.assertEqual(package["timeout"], 900)
        self.assertEqual(package["kwargs"], {"task_budget_seconds": 900})
