"""
Tests for dynamic panel support in AnsibleService and deployment pipeline.
"""

from unittest.mock import Mock, patch

from django.test import TestCase

from apps.infrastructure.ansible_service import AnsibleService


class AnsibleServicePanelPlaybooksTestCase(TestCase):
    """Test panel-aware playbook selection."""

    @patch("apps.infrastructure.ansible_service.shutil.which", return_value="/usr/bin/ansible-playbook")
    def test_default_playbook_order_is_virtualmin(self, mock_which):
        """Default PLAYBOOK_ORDER should be virtualmin playbooks."""
        service = AnsibleService()
        self.assertEqual(
            service.PLAYBOOK_ORDER,
            ["common_base.yml", "virtualmin.yml", "virtualmin_harden.yml", "virtualmin_backup.yml"],
        )

    @patch("apps.infrastructure.ansible_service.shutil.which", return_value="/usr/bin/ansible-playbook")
    def test_get_playbook_order_virtualmin(self, mock_which):
        """get_playbook_order('virtualmin') returns virtualmin playbooks."""
        service = AnsibleService()
        order = service.get_playbook_order("virtualmin")
        self.assertEqual(order[0], "common_base.yml")
        self.assertIn("virtualmin.yml", order)

    @patch("apps.infrastructure.ansible_service.shutil.which", return_value="/usr/bin/ansible-playbook")
    def test_get_playbook_order_blesta(self, mock_which):
        """get_playbook_order('blesta') returns blesta playbooks."""
        service = AnsibleService()
        order = service.get_playbook_order("blesta")
        self.assertEqual(order[0], "common_base.yml")
        self.assertIn("blesta.yml", order)
        self.assertIn("blesta_harden.yml", order)
        self.assertIn("blesta_backup.yml", order)

    @patch("apps.infrastructure.ansible_service.shutil.which", return_value="/usr/bin/ansible-playbook")
    def test_get_playbook_order_unknown_falls_back_to_virtualmin(self, mock_which):
        """Unknown panel type should fall back to virtualmin."""
        service = AnsibleService()
        order = service.get_playbook_order("unknown_panel")
        self.assertIn("virtualmin.yml", order)

    @patch("apps.infrastructure.ansible_service.shutil.which", return_value="/usr/bin/ansible-playbook")
    def test_common_base_shared_across_panels(self, mock_which):
        """common_base.yml should be first for all panel types."""
        service = AnsibleService()
        for panel_type in service.PANEL_PLAYBOOKS:
            order = service.get_playbook_order(panel_type)
            self.assertEqual(order[0], "common_base.yml", f"common_base.yml not first for {panel_type}")

    @patch("apps.infrastructure.ansible_service.shutil.which", return_value="/usr/bin/ansible-playbook")
    def test_panel_playbooks_exist_on_disk(self, mock_which):
        """All configured playbooks should exist as files."""
        from apps.infrastructure.ansible_service import PLAYBOOKS_PATH

        service = AnsibleService()
        for panel_type, playbooks in service.PANEL_PLAYBOOKS.items():
            for playbook in playbooks:
                self.assertTrue(
                    (PLAYBOOKS_PATH / playbook).exists(),
                    f"Playbook {playbook} missing for panel type {panel_type}",
                )


class AnsibleServiceBuildVarsTestCase(TestCase):
    """Test _build_vars with S3 backup settings."""

    @patch("apps.infrastructure.ansible_service.shutil.which", return_value="/usr/bin/ansible-playbook")
    @patch("apps.settings.services.SettingsService.get_setting")
    def test_build_vars_local_backup_no_s3_keys(self, mock_get_setting, mock_which):
        """With local backup, S3 keys should not be in vars."""

        def settings_side_effect(key, default=None):
            settings_map = {
                "node_deployment.backup_enabled": True,
                "node_deployment.backup_storage": "local",
                "node_deployment.backup_retention_days": 7,
                "node_deployment.backup_schedule": "0 2 * * *",
            }
            return settings_map.get(key, default)

        mock_get_setting.side_effect = settings_side_effect

        service = AnsibleService()
        deployment = Mock()
        deployment.id = "test-123"
        deployment.hostname = "test-host"
        deployment.dns_zone = None

        vars_dict = service._build_vars(deployment)
        self.assertEqual(vars_dict["backup_storage"], "local")
        self.assertNotIn("backup_s3_bucket", vars_dict)

    @patch("apps.infrastructure.ansible_service.shutil.which", return_value="/usr/bin/ansible-playbook")
    @patch("apps.settings.services.SettingsService.get_setting")
    def test_build_vars_s3_backup_includes_s3_keys(self, mock_get_setting, mock_which):
        """With S3 backup, S3 keys should be included in vars."""

        def settings_side_effect(key, default=None):
            settings_map = {
                "node_deployment.backup_enabled": True,
                "node_deployment.backup_storage": "s3",
                "node_deployment.backup_retention_days": 7,
                "node_deployment.backup_schedule": "0 2 * * *",
                "node_deployment.backup_s3_bucket": "my-backups",
                "node_deployment.backup_s3_region": "eu-central-1",
                "node_deployment.backup_s3_prefix": "nodes/",
            }
            return settings_map.get(key, default)

        mock_get_setting.side_effect = settings_side_effect

        service = AnsibleService()
        deployment = Mock()
        deployment.id = "test-123"
        deployment.hostname = "test-host"
        deployment.dns_zone = None

        vars_dict = service._build_vars(deployment)
        self.assertEqual(vars_dict["backup_storage"], "s3")
        self.assertEqual(vars_dict["backup_s3_bucket"], "my-backups")
        self.assertEqual(vars_dict["backup_s3_region"], "eu-central-1")
        self.assertEqual(vars_dict["backup_s3_prefix"], "nodes/")


class DeploymentServiceStagesTestCase(TestCase):
    """Test deployment service stage naming."""

    def test_stages_include_generic_panel_name(self):
        """Stages should use 'ansible_panel' not 'ansible_virtualmin'."""
        from apps.infrastructure.deployment_service import NodeDeploymentService

        service = NodeDeploymentService.__new__(NodeDeploymentService)
        self.assertIn("ansible_panel", service.STAGES)
        self.assertNotIn("ansible_virtualmin", service.STAGES)
