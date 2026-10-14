"""The panel installer and its Let's Encrypt steps use the node FQDN (ADR-0061 P0.2).

``inventory_hostname`` is the short inventory name ("prd-sha-het-de-fsn1-001") and Ansible's magic
variables outrank the extra vars PRAHO passes, so ``inventory_hostname=<fqdn>`` never took effect.
virtualmin.yml asked Let's Encrypt for a certificate for a name that has no DNS record, so the panel
certificate never issued. The FQDN now travels as ``node_fqdn``.
"""

from __future__ import annotations

import re
from types import SimpleNamespace
from typing import Any

from django.test import SimpleTestCase, TestCase

from apps.infrastructure.ansible_service import AnsibleService
from tests.provisioning.test_virtualmin_transfer_playbooks import command_text, task_named, tasks


def deployment(dns_zone: str | None) -> Any:
    fqdn = f"prd-sha-het-de-fsn1-001.{dns_zone}" if dns_zone else "prd-sha-het-de-fsn1-001"
    return SimpleNamespace(id=1, hostname="prd-sha-het-de-fsn1-001", dns_zone=dns_zone, fqdn=fqdn)


class NodeFqdnVarTests(TestCase):
    def test_the_fqdn_is_passed_as_node_fqdn(self) -> None:
        built = AnsibleService()._build_vars(deployment("hosting.example.net"))
        self.assertEqual(built["node_fqdn"], "prd-sha-het-de-fsn1-001.hosting.example.net")

    def test_without_a_dns_zone_node_fqdn_is_the_hostname(self) -> None:
        self.assertEqual(AnsibleService()._build_vars(deployment(None))["node_fqdn"], "prd-sha-het-de-fsn1-001")

    def test_a_caller_may_still_override_it_through_extra_vars(self) -> None:
        built = AnsibleService()._build_vars(deployment(None), {"node_fqdn": "override.example.net"})
        self.assertEqual(built["node_fqdn"], "override.example.net")


class PanelPlaybookUsesNodeFqdnTests(SimpleTestCase):
    def test_no_task_command_names_the_node_by_inventory_hostname(self) -> None:
        for task in tasks("virtualmin.yml"):
            with self.subTest(task=task.get("name")):
                self.assertNotIn("inventory_hostname", command_text(task))
                self.assertNotIn("inventory_hostname", str(task.get("args", "")))

    def test_installer_and_both_letsencrypt_steps_get_the_fqdn(self) -> None:
        install = command_text(task_named("virtualmin.yml", "Run Virtualmin installation"))
        generate = command_text(task_named("virtualmin.yml", "Generate Let's Encrypt certificate for Virtualmin"))
        self.assertRegex(install, r"--hostname \{\{ node_fqdn \}\}")
        self.assertRegex(generate, r"--host \{\{ node_fqdn \}\}")
        installs = [task for task in tasks("virtualmin.yml") if "letsencrypt.cgi" in command_text(task)]
        self.assertTrue(installs)
        for task in installs:
            self.assertRegex(command_text(task), r"--host \{\{ node_fqdn \}\}")

    def test_the_certificate_marker_path_uses_the_fqdn(self) -> None:
        text = " ".join(str(task) for task in tasks("virtualmin.yml"))
        self.assertIsNone(re.search(r"letsencrypt-cert-\{\{ inventory_hostname", text))
        self.assertIn("letsencrypt-cert-{{ node_fqdn }}", text)

    def test_the_play_refuses_to_run_without_a_fqdn(self) -> None:
        guard = task_named("virtualmin.yml", "Refuse a missing node FQDN")
        self.assertIn("node_fqdn is defined", " ".join(guard["ansible.builtin.assert"]["that"]))
        titles = [task.get("name") for task in tasks("virtualmin.yml")]
        self.assertEqual(titles.index("Refuse a missing node FQDN"), 0)
