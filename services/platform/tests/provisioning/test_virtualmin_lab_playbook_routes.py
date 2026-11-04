"""Installed Docker nodes exercise shared API/firewall tasks, not Ubuntu installation.

Only database lookup and node/process/network boundaries are doubled. The lab
command's actual API mutation, master backup/restore and firewall assertions run.
Actual Debian-container execution remains a separate Virtualmin lab gate.
"""

from __future__ import annotations

import io
import subprocess
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

from django.core.management.base import CommandError
from django.test import SimpleTestCase

from apps.common.types import Ok
from apps.infrastructure.ansible_service import AnsibleResult
from apps.provisioning.management.commands._virtualmin_lab import LabNode
from apps.provisioning.management.commands.virtualmin_lab_checks import CHECK_DOMAIN, Command
from apps.provisioning.virtualmin_backup_service import CHAIN_ROLE_STANDALONE, differential_flags, restore_domain_params

COMMAND = "apps.provisioning.management.commands.virtualmin_lab_checks"


class InstalledPanelLabRouteTests(SimpleTestCase):
    def setUp(self) -> None:
        self.command = Command(stdout=io.StringIO())
        self.server = SimpleNamespace(
            pk="installed-node", api_username="praho-api", node_deployment=object(), get_api_password=lambda: "x" * 32
        )
        self.node = LabNode("vm-b", "vmlab-b", "vm-b.praho.test", "vm-b", 10102, 2622)
        self.gateway = MagicMock()
        self.gateway.call.return_value = Ok(SimpleNamespace(success=True))
        self.gateway.list_templates.return_value = Ok(["Default Settings"])
        self.ansible = self.enterContext(patch("apps.infrastructure.ansible_service.AnsibleService", autospec=True))
        self.ansible.return_value.run_playbook.return_value = Ok(AnsibleResult(True, "contract", "", "", 0))

    def test_installed_api_enrollment_retains_real_mutation_and_master_backup_restore_controls(self) -> None:
        api_server = MagicMock()
        with (
            patch("apps.provisioning.virtualmin_models.VirtualminServer.objects.get", return_value=api_server),
            patch("apps.provisioning.virtualmin_gateway.VirtualminGateway", return_value=self.gateway),
            patch(f"{COMMAND}.load_state", return_value=SimpleNamespace(node=lambda _: self.node)),
            patch(f"{COMMAND}.node_exec", side_effect=lambda *args: "700 root" if "stat" in args else ""),
        ):
            user, password, gateway = self.command._check_node_deploy_playbook(self.server)

        self.ansible.return_value.run_playbook.assert_called_once_with(
            self.server.node_deployment,
            "virtualmin_security_enroll.yml",
            {"security_hardening_approved": True, "praho_api_user": "praho-api", "praho_api_password": "x" * 32},
            timeout_seconds=1800,
        )
        self.assertEqual((user, password, gateway), ("praho-api", "x" * 32, self.gateway))
        api_server.set_api_password.assert_called_once_with(password)
        api_server.save.assert_not_called()
        calls = self.gateway.call.call_args_list
        self.assertEqual(
            [entry.args[0] for entry in calls],
            ["list-domains", "disable-domain", "enable-domain", "backup-domain", "restore-domain"],
        )
        self.assertEqual(
            calls[1:3],
            [
                call("disable-domain", {"domain": CHECK_DOMAIN}, timeout_seconds=600),
                call("enable-domain", {"domain": CHECK_DOMAIN}, timeout_seconds=600),
            ],
        )
        archive = calls[3].args[1]["dest"]
        self.assertEqual(
            calls[3],
            call(
                "backup-domain",
                {
                    "domain": CHECK_DOMAIN,
                    "dest": archive,
                    "all-features": "",
                    "mkdir": "",
                    **differential_flags(CHAIN_ROLE_STANDALONE),
                },
                timeout_seconds=900,
            ),
        )
        self.assertEqual(
            calls[4],
            call("restore-domain", restore_domain_params(domain=CHECK_DOMAIN, source=archive), timeout_seconds=900),
        )
        self.gateway.list_templates.assert_called_once_with()

    def test_failed_enrollment_stops_before_api_mutation(self) -> None:
        self.ansible.return_value.run_playbook.return_value = Ok(AnsibleResult(False, "contract", "refused", "", 1))
        with (
            patch("apps.provisioning.virtualmin_gateway.VirtualminGateway") as gateway,
            self.assertRaises(CommandError),
        ):
            self.command._check_node_deploy_playbook(self.server)
        gateway.assert_not_called()

    def test_firewall_contract_runs_the_shared_policy_twice_and_checks_real_reachability(self) -> None:
        with (
            patch(f"{COMMAND}.container_address", return_value="172.20.0.3"),
            patch(f"{COMMAND}.node_exec"),
            patch.object(
                self.command,
                "_docker",
                side_effect=[
                    subprocess.CompletedProcess([], 0, "200", ""),
                    subprocess.CompletedProcess([], 0, "000", ""),
                    subprocess.CompletedProcess([], 0, "404", ""),
                ],
            ) as docker,
        ):
            self.command._check_firewall(self.server, self.node, self.gateway)

        self.assertEqual(
            self.ansible.return_value.run_playbook.call_args_list,
            [
                call(self.server.node_deployment, "virtualmin_firewall.yml", None, timeout_seconds=1800),
                call(self.server.node_deployment, "virtualmin_firewall.yml", None, timeout_seconds=1800),
            ],
        )
        self.assertEqual(
            [entry.args[-1] for entry in docker.call_args_list],
            ["https://172.20.0.3:10000/", "https://172.20.0.3:10000/", "http://172.20.0.3:80/"],
        )
        self.gateway.call.assert_called_once_with("list-domains", {"multiline": ""})

    def test_firewall_contract_refuses_missing_baseline_denial_web_access_or_platform_api(self) -> None:
        cases = (
            (("000", "000", "404"), True, "before the play"),
            (("200", "200", "404"), True, "after the play"),
            (("200", "000", "000"), True, "port 80 stays open"),
            (("200", "000", "404"), False, "Platform still reaches the API"),
        )
        for replies, api_success, expected in cases:
            with (
                self.subTest(replies=replies, api=api_success),
                patch(f"{COMMAND}.container_address", return_value="172.20.0.3"),
                patch(f"{COMMAND}.node_exec"),
                patch.object(
                    self.command,
                    "_docker",
                    side_effect=[subprocess.CompletedProcess([], 0, reply, "") for reply in replies],
                ),
                self.assertRaisesRegex(CommandError, expected),
            ):
                self.gateway.call.return_value = Ok(SimpleNamespace(success=api_success))
                self.command._check_firewall(self.server, self.node, self.gateway)
