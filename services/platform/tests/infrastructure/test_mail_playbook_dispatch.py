"""The fixed native mail entrypoint uses the enrolled node transport."""

from types import SimpleNamespace
from unittest.mock import Mock

from django.test import SimpleTestCase

from apps.common.types import Err
from apps.infrastructure.ansible_service import AnsibleService


class MailPlaybookDispatchTests(SimpleTestCase):
    def setUp(self) -> None:
        self.service = object.__new__(AnsibleService)
        self.service.timeout = 1800
        self.service._ssh_manager = Mock()
        self.service._ssh_manager.get_private_key_file.return_value = Err("enrolled key unavailable")
        self.deployment = SimpleNamespace(ipv4_address="192.0.2.15")

    def test_fixed_mail_playbook_reaches_enrolled_key_lookup_without_replacing_the_key(self) -> None:
        result = self.service.run_playbook(self.deployment, "virtualmin_mail.yml")

        self.assertEqual(
            result.unwrap_err(),
            "Could not retrieve the node's enrolled authentication key; refusing key replacement",
        )
        self.service._ssh_manager.get_private_key_file.assert_called_once_with(
            self.deployment, reason="Ansible playbook: virtualmin_mail.yml"
        )
        self.service._ssh_manager.generate_key_pair.assert_not_called()

    def test_unknown_mail_playbook_and_caller_transport_overrides_stop_before_key_access(self) -> None:
        for playbook, variables, expected in (
            ("virtualmin_mail_custom.yml", {}, "Playbook not allowed: virtualmin_mail_custom.yml"),
            ("../virtualmin_mail.yml", {}, "Playbook not allowed: ../virtualmin_mail.yml"),
            (
                "virtualmin_mail.yml",
                {"ansible_host": "198.51.100.2"},
                "Connection and SSH policy variables are owned by the verified node transport",
            ),
            (
                "virtualmin_mail.yml",
                {"ssh_port": 22},
                "Connection and SSH policy variables are owned by the verified node transport",
            ),
        ):
            with self.subTest(playbook=playbook, variables=variables):
                result = self.service.run_playbook(self.deployment, playbook, variables)
                self.assertEqual(result.unwrap_err(), expected)
                self.service._ssh_manager.get_private_key_file.assert_not_called()
