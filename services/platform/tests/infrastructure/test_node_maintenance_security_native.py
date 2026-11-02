"""Managed power commands and reviewed hardening preserve each other's owners."""

import json
from copy import deepcopy
from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

import requests
from django.core.exceptions import ValidationError
from django.db import connection
from django.test import TransactionTestCase, override_settings

from apps.common.credential_vault import CredentialData, get_credential_vault
from apps.common.types import Ok
from apps.infrastructure.deployment_service import NodeDeploymentService
from apps.infrastructure.node_maintenance_models import NodeMaintenanceExecution
from apps.infrastructure.provider_config import ProviderCommandResult
from apps.provisioning.virtualmin_security import record_inspection
from apps.provisioning.virtualmin_security_execution import complete_hardening, park_hardening
from apps.provisioning.virtualmin_security_models import NodeSecurityExecution
from tests.fixtures.virtualmin.responses.info import server_info
from tests.infrastructure.maintenance_security_fixtures import MaintenanceSecurityFixture
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment
from tests.provisioning.test_node_security_policy import OPERATOR_KEY


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    Q_CLUSTER={"name": "maintenance-hardening-native", "orm": "default", "retry": 100000},
)
class NodeMaintenanceSecurityNativeTests(MaintenanceSecurityFixture, TransactionTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.deployment = _create_deployment("completed", external_node_id="owned-hardening-power-fixture")
        self.deployment.virtualmin_server = self.node
        self.deployment.ssh_host_keys = OPERATOR_KEY
        self.deployment.save(update_fields=["virtualmin_server", "ssh_host_keys"])
        self.node.refresh_from_db()
        self.evidence = self.inspect(self.node)
        self.review = record_inspection(self.node, self.evidence)

    def reboot(self):
        return NodeDeploymentService().reboot_node(self.deployment, {}, user=self.actor)

    def test_native_ack_retains_ownership_and_refuses_new_hardening(self):
        observations = []

        def provider(**values):
            self.assertFalse(connection.in_atomic_block)
            issued = NodeMaintenanceExecution.objects.get(deployment=self.deployment, phase="issued")
            self.assertEqual(values["server_id"], self.deployment.external_node_id)
            observations.append(issued.pk)
            return Ok(ProviderCommandResult(True, "", "", 0, "fixture"))

        with patch("apps.infrastructure.deployment_service.run_provider_command", side_effect=provider) as boundary:
            self.assertTrue(self.reboot().is_ok())
            with self.assertRaisesMessage(ValidationError, "Maintenance"):
                self.harden()
        boundary.assert_called_once()
        self.assertEqual(len(observations), 1)
        self.assertEqual(NodeMaintenanceExecution.objects.get(pk=observations[0]).phase, "awaiting_recovery")
        self.assertFalse(NodeSecurityExecution.objects.exists())

    def test_parked_hardening_keeps_both_manual_and_power_work_fenced_after_time_passes(self):
        window = self.window(future=True)
        owner = self.harden()
        park_hardening(owner.pk)
        with (
            patch("apps.infrastructure.deployment_service.run_provider_command") as provider,
            patch("django.utils.timezone.now", return_value=window.starts_at + timedelta(seconds=1)),
        ):
            result = self.reboot()
            self.assertTrue(result.is_err(), result)
            self.assertIn("hardening", result.unwrap_err())
            with self.assertRaisesMessage(ValidationError, "hardening"):
                self.start(window)
        provider.assert_not_called()
        self.node.refresh_from_db()
        self.assertEqual(self.node.security_operation, owner.pk)
        self.assertEqual(NodeSecurityExecution.objects.get(pk=owner.pk).status, "needs_review")
        self.assertFalse(NodeMaintenanceExecution.objects.exists())

    def test_unknown_hardening_token_is_not_treated_as_an_idle_node(self):
        unknown = uuid4()
        type(self.node).objects.filter(pk=self.node.pk).update(security_operation=unknown)
        self.assertFalse(NodeSecurityExecution.objects.filter(pk=unknown).exists())
        with patch("apps.infrastructure.deployment_service.run_provider_command") as provider:
            result = self.reboot()
        self.assertTrue(result.is_err(), result)
        self.assertIn("hardening", result.unwrap_err())
        provider.assert_not_called()
        self.assertFalse(NodeMaintenanceExecution.objects.exists())

    def test_only_current_full_verification_releases_hardening_before_native_power(self):
        owner = self.harden()
        park_hardening(owner.pk)
        self.node.api_username = "praho-api"
        self.node.save(update_fields=["api_username"])
        stored = get_credential_vault().store_credential(
            CredentialData(
                service_type="virtualmin",
                service_identifier=self.node.hostname,
                username="praho-api",
                password="dedicated-native-fixture-password",
            )
        )
        self.assertTrue(stored.is_ok(), stored)
        evidence = self.inspect(self.node)
        stale = deepcopy(evidence)
        stale["identity"] = "0" * 64
        response = requests.Response()
        response.status_code = 200
        response._content = json.dumps(server_info()).encode()
        response._content_consumed = True
        with patch(
            "apps.provisioning.virtualmin_gateway.VirtualminGateway._execute_http_request", return_value=response
        ):
            with self.assertRaises(ValidationError):
                complete_hardening(owner.pk, stale)
            self.node.refresh_from_db()
            self.assertEqual(self.node.security_operation, owner.pk)
            verified = complete_hardening(owner.pk, evidence)
        self.node.refresh_from_db()
        self.assertEqual(self.node.verified_security_review_id, verified.pk)
        self.assertIsNone(self.node.security_operation)
        self.assertEqual(NodeSecurityExecution.objects.get(pk=owner.pk).status, "verified")
        with patch(
            "apps.infrastructure.deployment_service.run_provider_command",
            return_value=Ok(ProviderCommandResult(True, "", "", 0, "fixture")),
        ) as provider:
            self.assertTrue(self.reboot().is_ok())
        provider.assert_called_once()
        self.assertEqual(NodeMaintenanceExecution.objects.get(deployment=self.deployment).phase, "awaiting_recovery")
