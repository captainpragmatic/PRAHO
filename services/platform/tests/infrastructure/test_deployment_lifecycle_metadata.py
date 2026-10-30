"""Lifecycle metadata on NodeDeployment: operation ownership, provider outcomes and the legacy backfill.

The backfill runs against rows written before this metadata existed, so it must be conservative: a
server-create call that may have reached the provider is "unknown", never "none", and a legacy failed
destroy is flagged for reconciliation rather than offered for Retry.
"""

from __future__ import annotations

import importlib

from django.apps import apps as global_apps
from django.test import TestCase

from apps.infrastructure.models import NodeDeployment, NodeDeploymentLog
from tests.infrastructure.test_deployment_state_machine import _create_deployment

backfill_module = importlib.import_module("apps.infrastructure.migrations.0005_deployment_lifecycle_metadata")


def _log(deployment: NodeDeployment, message: str, phase: str, level: str = "INFO") -> None:
    NodeDeploymentLog.objects.create(deployment=deployment, level=level, message=message, phase=phase)


def _backfill() -> None:
    backfill_module.backfill_lifecycle_metadata(global_apps, None)


class LifecycleMetadataDefaultsTests(TestCase):
    def test_new_deployment_starts_unowned_with_no_provider_outcome(self) -> None:
        deployment = _create_deployment("pending")

        deployment.refresh_from_db()
        self.assertIsNone(deployment.operation_token)
        self.assertEqual(deployment.operation_kind, "")
        self.assertEqual(deployment.server_create_state, "none")
        self.assertEqual(deployment.registration_state, "none")
        self.assertEqual(deployment.provider_token_fingerprint, "")
        self.assertFalse(deployment.needs_reconciliation)
        self.assertEqual(deployment.reconciliation_reason, "")

    def test_operation_token_is_distinct_from_correlation_id(self) -> None:
        field_names = {f.name for f in NodeDeployment._meta.get_fields()}

        self.assertIn("operation_token", field_names)
        self.assertIn("correlation_id", field_names)


class LifecycleBackfillTests(TestCase):
    def _reset(self, deployment: NodeDeployment, **fields: object) -> NodeDeployment:
        """Put a row back into the shape it had before this metadata existed."""
        legacy = {
            "server_create_state": "none",
            "registration_state": "none",
            "needs_reconciliation": False,
            "reconciliation_reason": "",
            **fields,
        }
        NodeDeployment.objects.filter(pk=deployment.pk).update(**legacy)
        return deployment

    def test_pending_row_without_provider_calls_stays_none(self) -> None:
        deployment = self._reset(_create_deployment("pending"))

        _backfill()

        deployment.refresh_from_db()
        self.assertEqual(deployment.server_create_state, "none")
        self.assertFalse(deployment.needs_reconciliation)

    def test_row_with_a_server_id_is_created(self) -> None:
        deployment = self._reset(_create_deployment("completed"), external_node_id="12345")

        _backfill()

        deployment.refresh_from_db()
        self.assertEqual(deployment.server_create_state, "created")

    def test_destroyed_row_with_post_create_logs_is_created(self) -> None:
        deployment = self._reset(_create_deployment("destroyed"))
        _log(deployment, "Firewall resource recorded: praho-fw-x", "provision_server")
        _log(deployment, "Server provisioned with IP: 192.0.2.10", "update_deployment")

        _backfill()

        deployment.refresh_from_db()
        self.assertEqual(deployment.server_create_state, "created")

    def test_create_call_reached_without_evidence_is_unknown_never_none(self) -> None:
        deployment = self._reset(_create_deployment("failed"))
        _log(deployment, "Firewall resource recorded: praho-fw-x", "provision_server")
        _log(deployment, "Server creation failed: timeout", "provision_server", level="ERROR")

        _backfill()

        deployment.refresh_from_db()
        self.assertEqual(deployment.server_create_state, "unknown")

    def test_failure_before_the_create_call_stays_none(self) -> None:
        deployment = self._reset(_create_deployment("failed"))
        _log(deployment, "SSH key generation failed; no VM was created", "ssh_key", level="ERROR")

        _backfill()

        deployment.refresh_from_db()
        self.assertEqual(deployment.server_create_state, "none")
        self.assertFalse(deployment.needs_reconciliation)

    def test_registered_row_records_its_registration(self) -> None:
        from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415

        server = VirtualminServer.objects.create(
            name="legacy", hostname="legacy.example.test", api_username="root", encrypted_api_password=b""
        )
        deployment = self._reset(_create_deployment("completed"), virtualmin_server=server, external_node_id="9")

        _backfill()

        deployment.refresh_from_db()
        self.assertEqual(deployment.registration_state, "registered")

    def test_legacy_failed_destroy_needs_reconciliation(self) -> None:
        deployment = self._reset(_create_deployment("failed"), external_node_id="777")
        _log(deployment, "Server deletion failed: 503", "destroying", level="ERROR")

        _backfill()

        deployment.refresh_from_db()
        self.assertTrue(deployment.needs_reconciliation)
        self.assertIn("destroy", deployment.reconciliation_reason)

    def test_failed_deploy_is_not_flagged_for_reconciliation(self) -> None:
        deployment = self._reset(_create_deployment("failed"))
        _log(deployment, "Ansible base.yml failed", "ansible_base", level="ERROR")

        _backfill()

        deployment.refresh_from_db()
        self.assertFalse(deployment.needs_reconciliation)
