"""Exercise the executable bridge playbook's admission and verification contract."""

from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase

from apps.common.types import Err
from apps.infrastructure.ansible_service import AnsibleService


class BridgePlaybookContractTests(SimpleTestCase):
    def test_real_ansible_boundary_accepts_the_bridge_playbook(self) -> None:
        with patch.object(AnsibleService, "_find_ansible", return_value="/usr/bin/ansible-playbook"):
            runner = AnsibleService()
        with (
            patch.object(runner._ssh_manager, "get_private_key_file", return_value=Err("test credential absent")),
            patch.object(runner._ssh_manager, "get_master_key_file", return_value=Err("test fallback absent")),
        ):
            result = runner.run_playbook(SimpleNamespace(ipv4_address="192.0.2.2"), "virtualmin_bridge.yml")
        self.assertIn("Could not get SSH key", result.unwrap_err())
