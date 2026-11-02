"""Component bridges use exact imported-node authority and cannot precede cutover activation."""

from copy import deepcopy
from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from django.utils import timezone

from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from tests.provisioning.test_component_migration_admission import ComponentAdmissionTestBase


class ComponentBridgeTransportTests(ComponentAdmissionTestBase):
    def setUp(self):
        super().setUp()
        self.migration = self.start(self.approve(self.review()))
        self.token = uuid4()
        self.assertTrue(self.migration.acquire_lease(self.token, timedelta(minutes=5)))
        # fsm-bypass: restore completed under a previous checkpoint.
        VirtualminMigration.objects.filter(pk=self.migration.pk).update(
            status="verifying",
            archive_sha256="a" * 64,
            barrier_state={"target_domain_id": "987654321", "component_target_receipt_sha256": "b" * 64},
        )
        self.migration.refresh_from_db()

    def test_prepare_is_bound_to_source_and_admitted_addresses_without_managed_source(self):
        from apps.provisioning.component_bridge_transport import (  # noqa: PLC0415
            bridge_operation_refusal,
            bridge_operation_variables,
        )

        values = bridge_operation_variables(self.migration, self.token, "prepare")
        self.assertIsNone(bridge_operation_refusal(self.server, values))
        self.assertIsNotNone(bridge_operation_refusal(self.target, values))
        self.assertEqual(values["bridge_source_ipv4"], "192.0.2.10")
        self.assertEqual(values["bridge_target_ipv4"], "192.0.2.20")
        values["bridge_target_ipv4"] = "192.0.2.99"
        self.assertIsNotNone(bridge_operation_refusal(self.server, values))

    def test_source_bridge_install_requires_committed_seal_and_verified_target_activation(self):
        from apps.provisioning.component_bridge_transport import (  # noqa: PLC0415
            bridge_operation_refusal,
            bridge_operation_variables,
        )

        # fsm-bypass: an independently recovered worker reaches the routing phase.
        VirtualminMigration.objects.filter(pk=self.migration.pk).update(status="bridging")
        self.migration.refresh_from_db()
        values = bridge_operation_variables(self.migration, self.token, "install", origin_certificate="public fixture")
        self.assertIsNotNone(bridge_operation_refusal(self.server, values))
        VirtualminMigration.objects.filter(pk=self.migration.pk).update(
            cutover_committed_at=timezone.now(),
            barrier_state={
                **self.migration.barrier_state,
                "component_source_sealed": True,
                "component_target_sealed": True,
                "component_target_activation_complete": True,
            },
        )
        self.account.server = self.target
        self.account.save(update_fields=["server"])
        self.assertIsNone(bridge_operation_refusal(self.server, values))

    def test_origin_manifest_cannot_add_foreign_hostnames_or_change_source_identity(self):
        from apps.provisioning.component_bridge_transport import (  # noqa: PLC0415
            bridge_operation_refusal,
            bridge_operation_variables,
        )

        manifest = {
            "identity": str(self.migration.pk),
            "domain": self.account.domain,
            "source": "192.0.2.10",
            "target": "192.0.2.20",
            "account_name": "",
            "origin": "bridge-" + self.migration.pk.hex + ".invalid",
            "vhosts": [
                {
                    "name": self.account.domain,
                    "names": [self.account.domain, "www." + self.account.domain],
                    "neutral": False,
                    "port": 80,
                    "bindings": ["*"],
                    "verify_names": [self.account.domain, "www." + self.account.domain],
                }
            ],
        }
        values = bridge_operation_variables(self.migration, self.token, "origin_install", manifest=manifest)
        self.assertIsNone(bridge_operation_refusal(self.target, values))
        values["bridge_manifest"]["vhosts"][0]["names"].append("other-tenant.example.test")
        self.assertIsNotNone(bridge_operation_refusal(self.target, values))

    def test_manifest_rejects_foreign_probe_names_and_malformed_host_without_raising(self):
        from apps.provisioning.component_bridge_transport import (  # noqa: PLC0415
            bridge_operation_refusal,
            bridge_operation_variables,
        )

        manifest = {
            "identity": str(self.migration.pk),
            "domain": self.account.domain,
            "source": "192.0.2.10",
            "target": "192.0.2.20",
            "account_name": "",
            "origin": "bridge-" + self.migration.pk.hex + ".invalid",
            "vhosts": [
                {
                    "name": self.account.domain,
                    "names": [self.account.domain],
                    "neutral": False,
                    "port": 80,
                    "bindings": ["*"],
                    "verify_names": [self.account.domain],
                }
            ],
        }
        for field, value in (("name", []), ("verify_names", ["other-tenant.example.test"]), ("bindings", [[]])):
            with self.subTest(field=field):
                changed = deepcopy(manifest)
                changed["vhosts"][0][field] = value
                values = bridge_operation_variables(self.migration, self.token, "origin_install", manifest=changed)
                self.assertIsNotNone(bridge_operation_refusal(self.target, values))

    def test_bridge_transport_refuses_unadmitted_worker_before_ssh_setup(self):
        from apps.infrastructure.ansible_service import AnsibleService  # noqa: PLC0415
        from apps.provisioning.component_bridge_transport import bridge_operation_variables  # noqa: PLC0415

        values = bridge_operation_variables(self.migration, uuid4(), "prepare")
        service = object.__new__(AnsibleService)
        with patch("apps.infrastructure.ansible_service.imported_identity") as identity:
            result = service.run_server_playbook(self.server, "virtualmin_component_bridge.yml", values)
        self.assertTrue(result.is_err())
        self.assertIn("lease", result.unwrap_err())
        identity.assert_not_called()
