"""Fresh deployment authority uses actual catalog/vault/deployment records, not manifest assertions."""

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import UUID

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.common.credential_vault import get_credential_vault
from apps.common.types import Ok
from apps.infrastructure.cloud_gateway import LocationInfo, ServerTypeInfo
from apps.infrastructure.deployment_lifecycle import provider_token_fingerprint
from apps.infrastructure.models import (
    CloudProvider,
    CloudResourceOwnership,
    NodeDeployment,
    NodeDeploymentLog,
    NodeRegion,
    NodeServerLifetime,
    NodeSize,
    PanelType,
)
from apps.infrastructure.native_fresh_workflow import (
    REQUIRED_STAGES,
    bind_fresh_deployment,
    deploy_fresh_vm,
    publish_fresh_vm,
    verify_fresh_vm,
)
from apps.infrastructure.native_lab import native_authority, native_driver
from apps.infrastructure.native_workflow import require_fixture_dns, run_workflow
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.settings.services import SettingsService
from tests.infrastructure.native_dns_fixtures import published_dns


class NativeFreshFixtureTests(TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "fresh.json"
        with patch.dict(
            os.environ,
            {
                "PRAHO_NATIVE_ADMIN_CIDR": "192.0.2.17/32",
                "PRAHO_NATIVE_LOCATION": "fsn1",
                "PRAHO_NATIVE_SERVER_TYPE": "cx33",
            },
        ):
            native_driver().fresh_intent(self.path)
        self.authority = native_authority(self.path)
        self.provider = CloudProvider.objects.create(
            name="Fixture Hetzner", code="het", provider_type="hetzner", credential_identifier="fixture-native"
        )
        self.region = NodeRegion.objects.create(
            provider=self.provider,
            name="Falkenstein",
            provider_region_id="fsn1",
            normalized_code="fsn1",
            country_code="de",
            city="Falkenstein",
        )
        self.size = NodeSize.objects.create(
            provider=self.provider,
            name="Fixture cx33",
            display_name="Fixture cx33",
            provider_type_id="cx33",
            vcpus=4,
            memory_gb=8,
            disk_gb=80,
            hourly_cost_eur="0.01",
            monthly_cost_eur="7.31",
        )
        self.size.available_regions.add(self.region)
        PanelType.objects.create(name="Virtualmin GPL", panel_type="virtualmin", ansible_playbook="virtualmin.yml")

    def test_binding_keeps_original_private_key_and_creates_no_provider_vm_hint(self):
        deployment = bind_fresh_deployment(
            self.authority, dns_zone="lab.example.com", provider_token="native-fixture-token", zone_id="owned-zone"
        )
        self.assertIsNotNone(deployment, "Fresh intent did not bind the real pending deployment")
        self.assertEqual(deployment.correlation_id, UUID(self.authority.manifest["run"]))
        self.assertEqual(deployment.status, "pending")
        self.assertEqual(deployment.server_create_state, "none")
        self.assertFalse(deployment.external_node_id)
        self.assertEqual(
            (deployment.provider_id, deployment.region_id, deployment.node_size_id),
            (self.provider.pk, self.region.pk, self.size.pk),
        )
        credentials = get_credential_vault().get_credential(
            service_type="ssh", service_identifier="node-" + deployment.hostname, reason="Native fixture test"
        )
        self.assertTrue(credentials.is_ok(), credentials)
        self.assertEqual(credentials.unwrap()[1], self.authority.key.decode())
        replay = bind_fresh_deployment(
            native_authority(self.path),
            dns_zone="lab.example.com",
            provider_token="native-fixture-token",
            zone_id="owned-zone",
        )
        self.assertEqual(replay.pk, deployment.pk)
        self.assertEqual(NodeDeployment.objects.count(), 1)
        self.assertEqual(native_authority(self.path).key, self.authority.key)

    def test_existing_raw_resource_hints_cannot_start_a_second_fresh_deployment(self):
        self.authority.manifest.update({"phase": "created", "server_id": 13, "ssh_key_id": 17, "ipv4": "192.0.2.13"})
        with self.assertRaisesMessage(ValueError, "existing provider"):
            bind_fresh_deployment(
                self.authority, dns_zone="lab.example.com", provider_token="native-fixture-token", zone_id="owned-zone"
            )
        self.assertFalse(NodeDeployment.objects.exists())

    def _catalogue(self):
        provider = MagicMock()
        provider.get_locations.return_value = Ok([LocationInfo("fsn1", country="DE", city="Falkenstein")])
        provider.get_server_types.return_value = Ok(
            [
                ServerTypeInfo("cx33", vcpus=4, memory_gb=8, disk_gb=80, price_monthly=7.31, locations=("fsn1",)),
            ]
        )
        return provider

    def test_real_public_deploy_disabled_guard_keeps_the_only_intent_and_original_key(self):
        self.assertTrue(SettingsService.update_setting("node_deployment.enabled", False).is_ok())
        dns = MagicMock()
        dns.get_zone_name.return_value = Ok("example.com")
        with (
            override_settings(
                PRAHO_SSH_OPERATOR_PUBLIC_KEYS_FILE=str(
                    self.path.parent / (self.authority.manifest["run"] + ".operator.pub")
                )
            ),
            patch("apps.infrastructure.hcloud_service.get_hcloud_service", return_value=self._catalogue()),
            patch("apps.infrastructure.dns_gateway.get_dns_gateway", return_value=dns),
            patch.dict(
                os.environ,
                {
                    "HCLOUD_TOKEN": "native-fixture-token",
                    "PRAHO_NATIVE_CLOUDFLARE_TOKEN": "native-fixture-dns-token",
                    "PRAHO_NATIVE_CLOUDFLARE_ZONE_ID": "owned-zone",
                },
            ),
            self.assertRaisesMessage(ValueError, "Node deployment is disabled"),
        ):
            deploy_fresh_vm(self.authority, dns_zone="lab.example.com")
        deployment = NodeDeployment.objects.get(correlation_id=UUID(self.authority.manifest["run"]))
        self.assertEqual(deployment.status, "pending")
        self.assertEqual(deployment.server_create_state, "none")
        self.assertFalse(deployment.external_node_id)
        self.assertEqual(NodeDeployment.objects.count(), 1)
        self.assertEqual(native_authority(self.path).key, self.authority.key)
        self.assertFalse(deployment.logs.filter(phase="native_fresh_result").exists())

    def test_wrong_dns_authority_refuses_before_catalogue_or_fixture_mutation(self):
        dns = MagicMock()
        dns.get_zone_name.return_value = Ok("someone-else.example")
        with (
            patch("apps.infrastructure.hcloud_service.get_hcloud_service", side_effect=AssertionError("No sync")),
            patch("apps.infrastructure.dns_gateway.get_dns_gateway", return_value=dns),
            patch.dict(
                os.environ,
                {
                    "HCLOUD_TOKEN": "native-fixture-token",
                    "PRAHO_NATIVE_CLOUDFLARE_TOKEN": "native-fixture-dns-token",
                    "PRAHO_NATIVE_CLOUDFLARE_ZONE_ID": "foreign-zone",
                },
            ),
            self.assertRaisesMessage(ValueError, "approved DNS"),
        ):
            deploy_fresh_vm(self.authority, dns_zone="lab.example.com")
        self.assertFalse(NodeDeployment.objects.exists())

    def test_forged_success_receipt_cannot_certify_the_real_pending_deployment(self):
        deployment = bind_fresh_deployment(
            self.authority, dns_zone="lab.example.com", provider_token="native-fixture-token", zone_id="owned-zone"
        )
        manifest = self.authority.manifest
        manifest["fresh_deployment"] = {"source": "NodeDeploymentService.deploy_node", "verified": True}
        manifest["quota_acceptance"] = {"verified": True}
        native_driver().write_manifest(self.path, manifest)
        with (
            patch.object(native_driver(), "client", side_effect=AssertionError("Not a completed public deployment")),
            patch.dict(
                os.environ,
                {
                    "HCLOUD_TOKEN": "native-fixture-token",
                    "PRAHO_NATIVE_CLOUDFLARE_TOKEN": "native-fixture-dns-token",
                    "PRAHO_NATIVE_CLOUDFLARE_ZONE_ID": "owned-zone",
                },
            ),
            self.assertRaisesMessage(ValueError, "not complete"),
        ):
            verify_fresh_vm(native_authority(self.path))
        deployment.refresh_from_db()
        self.assertEqual(deployment.status, "pending")
        self.assertFalse(deployment.external_node_id)

    def test_dual_stack_dns_accepts_only_the_exact_recorded_node_addresses(self):
        deployment = bind_fresh_deployment(
            self.authority, dns_zone="lab.example.com", provider_token="native-fixture-token", zone_id="owned-zone"
        )
        deployment.ipv4_address, deployment.ipv6_address = "192.0.2.13", "2001:db8::13"
        with published_dns("192.0.2.13", "2001:db8::13"):
            require_fixture_dns(deployment, "192.0.2.13")
        with (
            published_dns("192.0.2.13", "2001:db8::99"),
            self.assertRaisesMessage(ValueError, "exact owned VM"),
        ):
            require_fixture_dns(deployment, "192.0.2.13")

    def test_expired_authority_is_readable_for_cleanup_only_and_cannot_deploy(self):
        manifest = self.authority.manifest
        manifest["expires_at"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
        native_driver().write_manifest(self.path, manifest)
        with self.assertRaisesMessage(ValueError, "expired"):
            native_authority(self.path)
        self.assertEqual(native_authority(self.path, cleanup=True).key, self.authority.key)
        with (
            patch.dict(os.environ, {"PRAHO_NATIVE_CLEANUP_ONLY": "1"}),
            self.assertRaisesMessage(ValueError, "only run exact public teardown"),
        ):
            run_workflow(self.path, "fresh-deploy", dns_zone="lab.example.com")
        self.assertFalse(NodeDeployment.objects.exists())

    def test_only_exact_public_creation_records_can_publish_the_same_vm_and_keep_private_identity(self):
        """Contract fixture: public-deployment happy-path execution still needs the real native gate."""
        deployment = bind_fresh_deployment(
            self.authority, dns_zone="lab.example.com", provider_token="native-fixture-token", zone_id="owned-zone"
        )
        server = VirtualminServer.objects.create(
            name="Native contract",
            hostname=deployment.fqdn,
            api_username="fixture",
            encrypted_api_password=b"",
            status="active",
        )
        fingerprint = provider_token_fingerprint("native-fixture-token")
        NodeDeployment.objects.filter(pk=deployment.pk).update(
            status="completed",
            server_create_state="created",
            registration_state="activated",
            virtualmin_server=server,
            external_node_id="13",
            ipv4_address="192.0.2.13",
            ssh_port=9876,
            ssh_host_keys=self.authority.public_key,
            provider_token_fingerprint=fingerprint,
        )
        NodeDeploymentLog.objects.create(
            deployment=deployment,
            level="INFO",
            phase="native_fresh_result",
            message="Contract fixture",
            details={
                "source": "NodeDeploymentService.deploy_node",
                "success": True,
                "stages": sorted(REQUIRED_STAGES),
                "validation_passed": True,
                "validation_checks": ["ssh", "ports", "virtualmin", "ssl"],
            },
        )
        provider = MagicMock()
        live_server = SimpleNamespace(
            name=deployment.hostname,
            public_net=SimpleNamespace(ipv4=SimpleNamespace(ip="192.0.2.13")),
            labels={"managed-by": "praho", "praho-deployment": self.authority.manifest["run"]},
            update=MagicMock(),
        )
        live_key = SimpleNamespace(labels=dict(live_server.labels), public_key=self.authority.public_key)
        provider.servers.get_by_id.return_value = live_server
        provider.ssh_keys.get_by_id.return_value = live_key
        with (
            patch.object(native_driver(), "client", return_value=provider),
            published_dns("192.0.2.13"),
        ):
            with self.assertRaisesMessage(ValueError, "creation records"):
                publish_fresh_vm(self.authority, provider_token="native-fixture-token", zone_id="owned-zone")
            provider.servers.get_by_id.assert_not_called()
            for kind, identity in (("server", "13"), ("ssh_key", "17")):
                CloudResourceOwnership.objects.create(
                    deployment=deployment,
                    provider=self.provider,
                    token_fingerprint=fingerprint,
                    deployment_correlation_id=deployment.correlation_id,
                    kind=kind,
                    resource_id=identity,
                    provenance="create_response",
                )
            NodeServerLifetime.objects.create(
                deployment=deployment,
                server_id="13",
                correlation_id=deployment.correlation_id,
                node_size=self.size,
                monthly_cost_eur=self.size.monthly_cost_eur,
                started_at=timezone.now(),
            )
            publish_fresh_vm(self.authority, provider_token="native-fixture-token", zone_id="owned-zone")
        exported = native_authority(self.path)
        self.assertEqual(
            (exported.manifest["server_id"], exported.manifest["ssh_key_id"], exported.manifest["ssh_port"]),
            (13, 17, 9876),
        )
        self.assertEqual(exported.key, self.authority.key)
        self.assertEqual(exported.manifest["phase"], "prepared")
        _private, trust = native_driver().paths(self.path, exported.manifest)
        self.assertIn("[192.0.2.13]:9876 " + self.authority.public_key, trust.read_text())
        live_server.update.assert_called_once_with(
            labels={
                **live_server.labels,
                "praho-native-run": self.authority.manifest["run"],
                "praho-native-owner": "praho-quota-776",
            }
        )
