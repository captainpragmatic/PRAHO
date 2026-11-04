"""The node admin allowlist: who may reach a node's SSH and Webmin.

`infrastructure.node_admin_allowed_cidrs` holds Platform's egress addresses
plus the operators' admin networks. Node playbooks lock the Virtualmin API
user and the firewall for ports 22 and 10000 to it (ADR-0060), so a malformed
or catch-all entry must never be stored, and the playbooks must receive the
entries in a form Webmin and UFW both match exactly.
"""

from __future__ import annotations

import socket
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, call, patch

from django.core.cache import cache
from django.test import SimpleTestCase, TestCase, override_settings

from apps.infrastructure import ansible_service
from apps.infrastructure.ansible_service import AnsibleService, node_admin_allowed_cidrs
from apps.settings.services import SettingsService

KEY = "infrastructure.node_admin_allowed_cidrs"


class PlatformSourceAddressTests(SimpleTestCase):
    def _discover(self, ipv4="8.8.8.8", *, ipv6_error=False):
        v4, v6 = MagicMock(), MagicMock()
        v4.getsockname.return_value = (ipv4, 12345)
        v6.getsockname.return_value = ("2a01:4f9:c015:4d96::1", 12345, 0, 0)
        if ipv6_error:
            v6.connect.side_effect = OSError("No IPv6 route")
        with patch("apps.infrastructure.ansible_service.socket.socket", side_effect=[v4, v6]) as factory:
            result = ansible_service.platform_source_addresses()
        self.assertEqual(
            factory.call_args_list,
            [call(socket.AF_INET, socket.SOCK_DGRAM), call(socket.AF_INET6, socket.SOCK_DGRAM)],
        )
        v4.connect.assert_called_once_with(("1.1.1.1", 53))
        v6.connect.assert_called_once_with(("2606:4700:4700::1111", 53))
        for connection in (v4, v6):
            connection.close.assert_called_once_with()
            connection.send.assert_not_called()
            connection.sendto.assert_not_called()
        return result

    def test_global_addresses_from_both_families_are_retained(self):
        self.assertEqual(self._discover(), ["8.8.8.8", "2a01:4f9:c015:4d96::1"])

    def test_a_family_without_a_route_is_ignored_and_closed(self):
        self.assertEqual(self._discover(ipv6_error=True), ["8.8.8.8"])

    def test_private_source_addresses_are_dropped(self):
        self.assertEqual(self._discover("10.0.0.5"), ["2a01:4f9:c015:4d96::1"])


@override_settings(NODE_ADMIN_EGRESS_CHECK=True)
class UncoveredPlatformEgressTests(SimpleTestCase):
    def test_ipv6_missing_from_allowlist_is_reported(self):
        with (
            patch(
                "apps.infrastructure.ansible_service.platform_source_addresses",
                return_value=["8.8.8.8", "2a01:4f9:c015:4d96::1"],
                create=True,
            ),
            patch(
                "apps.infrastructure.ansible_service.node_admin_allowed_cidrs",
                return_value=["8.8.8.8/32", "not-a-network"],
            ),
        ):
            self.assertEqual(ansible_service.uncovered_platform_egress(), ["2a01:4f9:c015:4d96::1"])

    def test_ipv6_covered_by_a_64_is_not_reported(self):
        with (
            patch(
                "apps.infrastructure.ansible_service.platform_source_addresses",
                return_value=["2a01:4f9:c015:4d96::1"],
                create=True,
            ),
            patch(
                "apps.infrastructure.ansible_service.node_admin_allowed_cidrs",
                return_value=["2a01:4f9:c015:4d96::1234/64"],
            ),
        ):
            self.assertEqual(ansible_service.uncovered_platform_egress(), [])

    @override_settings(NODE_ADMIN_EGRESS_CHECK=False)
    def test_disabled_check_does_not_touch_sockets_or_policy(self):
        with (
            patch("apps.infrastructure.ansible_service.socket.socket") as factory,
            patch("apps.infrastructure.ansible_service.node_admin_allowed_cidrs") as allowed,
        ):
            self.assertEqual(ansible_service.uncovered_platform_egress(), [])
        factory.assert_not_called()
        allowed.assert_not_called()

    def test_invalid_allowlist_is_left_to_the_existing_prerequisite(self):
        with (
            patch("apps.infrastructure.ansible_service.node_admin_allowed_cidrs", side_effect=ValueError("invalid")),
            patch("apps.infrastructure.ansible_service.socket.socket") as factory,
        ):
            self.assertEqual(ansible_service.uncovered_platform_egress(), [])
        factory.assert_not_called()


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
            panel_type=SimpleNamespace(panel_type="virtualmin"), virtualmin_server_id=None,
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
