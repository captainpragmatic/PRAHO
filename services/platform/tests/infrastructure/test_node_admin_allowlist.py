"""The node admin allowlist: who may reach a node's SSH and Webmin.

`infrastructure.node_admin_allowed_cidrs` holds Platform's egress addresses
plus the operators' admin networks. Node playbooks lock the Virtualmin API
user and the firewall for ports 22 and 10000 to it (ADR-0060), so a malformed
or catch-all entry must never be stored, and the playbooks must receive the
entries in a form Webmin and UFW both match exactly.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from django.core.cache import cache
from django.test import TestCase

from apps.infrastructure.ansible_service import AnsibleService, node_admin_allowed_cidrs
from apps.settings.services import SettingsService

KEY = "infrastructure.node_admin_allowed_cidrs"


class AllowlistValidationTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    def test_addresses_and_networks_are_accepted(self) -> None:
        value = ["203.0.113.7", "198.51.100.0/24", "2001:db8::/48", "2001:db8:1::5"]
        result = SettingsService.update_setting(KEY, value)
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(SettingsService.get_setting(KEY), value)

    def test_malformed_or_catch_all_entries_are_refused(self) -> None:
        for bad in (
            ["not-an-address"],
            ["10.0.0.1/8"],  # host bits set: the intended network is ambiguous
            ["0.0.0.0/0"],
            ["::/0"],
            ["203.0.113.7", "203.0.113.7"],
            [7],
            ["203.0.113.7 198.51.100.1"],
            [""],
        ):
            with self.subTest(value=bad):
                result = SettingsService.update_setting(KEY, bad)
                self.assertTrue(result.is_err(), bad)
                self.assertEqual(SettingsService.get_setting(KEY), [])


class AllowlistReachesThePlaybooksTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    @staticmethod
    def _deployment() -> Any:
        return SimpleNamespace(
            id=1, hostname="prd-sha-het-de-fsn1-001", dns_zone=None, fqdn="", ssh_port=9876,
            panel_type=SimpleNamespace(panel_type="virtualmin"),
        )

    def test_every_playbook_gets_the_entries_as_networks(self) -> None:
        SettingsService.update_setting(KEY, ["203.0.113.7", "198.51.100.0/24", "2001:DB8::/48"]).unwrap()
        built = AnsibleService()._build_vars(self._deployment())
        # Explicit prefixes: Webmin reads a bare "203.0.113.0" as the whole
        # 203.0.113.x range, and lower-case IPv6 is the only form it compares.
        self.assertEqual(built["node_admin_allowed_cidrs"], ["203.0.113.7/32", "198.51.100.0/24", "2001:db8::/48"])

    def test_an_unset_allowlist_reaches_the_playbooks_empty(self) -> None:
        # Empty is passed on as empty; the playbooks refuse to run with it.
        self.assertEqual(node_admin_allowed_cidrs(), [])
        self.assertEqual(AnsibleService()._build_vars(self._deployment())["node_admin_allowed_cidrs"], [])
