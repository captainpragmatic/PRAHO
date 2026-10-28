"""Central Virtualmin backup admission must not retire another panel's backups."""

from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase

from apps.infrastructure.ansible_service import AnsibleService


class PanelBackupPolicyTests(SimpleTestCase):
    def test_panel_storage_and_enabled_matrix(self) -> None:
        for panel in ("virtualmin", "blesta"):
            deployment = SimpleNamespace(
                id=1, hostname="fixture", dns_zone=None, fqdn="fixture.hosting.test", ssh_port=9876,
                panel_type=SimpleNamespace(panel_type=panel),
            )
            for storage in ("platform", "local", "s3"):
                for enabled in (True, False):
                    values = {"node_deployment.backup_enabled": enabled, "node_deployment.backup_storage": storage}
                    with self.subTest(panel=panel, storage=storage, enabled=enabled), patch(
                        "apps.infrastructure.ansible_service.SettingsService.get_setting",
                        side_effect=lambda key, default=None, values=values: values.get(key, default),
                    ):
                        variables = AnsibleService()._build_vars(deployment)
                    central = storage == "platform" and panel == "virtualmin"
                    self.assertEqual(variables["backup_enabled"], enabled and not central)
                    effective_storage = "local" if storage == "platform" and panel != "virtualmin" else storage
                    self.assertEqual(variables["backup_storage"], effective_storage)
