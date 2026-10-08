"""WP17 coverage additions for provisioning parameter rejection and dispatch."""

from __future__ import annotations

from dataclasses import replace
from unittest.mock import patch

from django.core.cache import cache
from django.db import transaction

from apps.provisioning import virtualmin_tasks
from apps.provisioning.security_utils import ProvisioningParametersValidator, SecureTaskParameters
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob
from tests.provisioning.test_cov_virtualmin_tasks_signals import VirtualminCoverageCase

VALID_UUID = "11111111-1111-4111-8111-111111111111"


class ProvisioningParameterEffectsTests(VirtualminCoverageCase):
    def _params(self) -> virtualmin_tasks.VirtualminProvisioningParams:
        return {"service_id": str(self.service.pk), "domain": self.service.domain}

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

    def _assert_validation_rejection(
        self, params: virtualmin_tasks.VirtualminProvisioningParams | SecureTaskParameters
    ) -> None:
        result = virtualmin_tasks.provision_virtualmin_account(params)
        self.assertEqual(result, {"success": False, "error": "Validation failed"})
        self.assertFalse(VirtualminAccount.objects.exists())
        self.assertFalse(VirtualminProvisioningJob.objects.exists())
        self.assertEqual(self.requests, [])

    def test_invalid_parameters_return_validation_error_without_remote_work(self) -> None:
        cases: tuple[virtualmin_tasks.VirtualminProvisioningParams, ...] = (
            {"service_id": "invalid-id"},
            {"service_id": VALID_UUID},
            {"domain": "bad/domain.example.com"},
            {"username": "Bad User"},
            {"template": "../Default"},
        )
        for invalid in cases:
            with self.subTest(parameters=invalid):
                params = self._params()
                params.update(invalid)
                self._assert_validation_rejection(params)

    def test_encrypted_invalid_domain_is_decrypted_and_rejected_without_rows(self) -> None:
        params = self._params()
        params["domain"] = "bad/domain.example.com"
        self._assert_validation_rejection(SecureTaskParameters.create(dict(params)))

    def test_each_negative_case_detects_bypassing_its_own_validator(self) -> None:
        cases: tuple[tuple[str, virtualmin_tasks.VirtualminProvisioningParams, bool], ...] = (
            ("validate_service_id", {"service_id": "invalid-id"}, False),
            ("validate_service_id", {"service_id": VALID_UUID}, False),
            ("validate_domain", {"domain": "bad/domain.example.com"}, False),
            ("validate_username", {"username": "Bad User"}, False),
            ("validate_template", {"template": "../Default"}, False),
            ("validate_domain", {"domain": "bad/domain.example.com"}, True),
        )
        for validator, invalid, encrypted in cases:
            with self.subTest(validator=validator, invalid=invalid, encrypted=encrypted):
                params = self._params()
                params.update(invalid)
                payload = SecureTaskParameters.create(dict(params)) if encrypted else params
                # This is an intentional mutation probe, not a mock of the behavior under test.
                # Roll back any downstream work reached after bypassing this one validator.
                with transaction.atomic():
                    with (
                        patch.object(ProvisioningParametersValidator, validator, side_effect=lambda value: value),
                        self.assertRaises(AssertionError) as failure,
                    ):
                        self._assert_validation_rejection(payload)
                    self.assertIn("Validation failed", str(failure.exception))
                    transaction.set_rollback(True)
                self.requests.clear()
                cache.clear()

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
