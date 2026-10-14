"""Production transport stays fail-closed; the lab adaptations stay in the lab.

The Docker lab publishes its nodes on 127.0.0.1 and non-22 SSH ports, so
`_virtualmin_lab.lab_transport()` relaxes four production assumptions. These
tests pin that, outside the lab settings:
- the Virtualmin gateway refuses private, loopback and link-local API hosts
  (by name and as IP literals) before any HTTP request leaves;
- Ansible gets no port override, and the SSH wait probes port 22;
- `lab_transport()` itself refuses to run, and patches nothing.
"""

from __future__ import annotations

import inspect
import socket
from pathlib import Path
from typing import Any
from unittest.mock import patch

from django.conf import settings
from django.core.cache import cache
from django.core.management.base import CommandError
from django.test import SimpleTestCase, override_settings

from apps.common import outbound_http
from apps.infrastructure.ansible_service import AnsibleService
from apps.provisioning.management.commands._virtualmin_lab import LabNode, LabState, lab_transport
from apps.provisioning.virtualmin_gateway import VirtualminConfig, VirtualminGateway
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase

PRIVATE_ADDRESSES = ("127.0.0.1", "10.0.0.5", "172.22.0.2", "192.168.1.10", "169.254.169.254", "::1", "fd00::1")


def lab_state() -> LabState:
    return LabState(
        state_dir="/nonexistent",
        nodes=(LabNode("vm-a", "vmlab-a", "vm-a.praho.test", "dev-sha-lab-ro-vmla-001", 10101, 2522),),
        known_hosts="/nonexistent/known_hosts",
        s3_endpoint="http://127.0.0.1:19000",
        bucket="praho-backups",
        domain="roundtrip.praho.test",
        domain_user="roundtrip",
    )


def addrinfo(address: str) -> list[Any]:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    return [(family, socket.SOCK_STREAM, 6, "", (address, 10000))]


@override_settings(
    DEBUG=False,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class GatewayPrivateHostTests(VirtualminTaskTestBase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)

    def _call_with_host(self, hostname: str, resolved: str | None) -> Any:
        self.server.hostname = hostname
        self.server.save(update_fields=["hostname"])
        gateway = VirtualminGateway(VirtualminConfig(server=self.server))
        with (
            patch.object(outbound_http.socket, "getaddrinfo", return_value=addrinfo(resolved or hostname)),
            patch("requests.adapters.HTTPAdapter.send", side_effect=AssertionError("request sent")) as send,
        ):
            result = gateway.call("list-domains", {"multiline": ""})
        send.assert_not_called()
        return result

    def test_private_names_and_literals_are_refused_before_any_request(self) -> None:
        for address in PRIVATE_ADDRESSES:
            # IPv6 only by name: a server hostname is a host name, not a bracketed literal.
            literals = () if ":" in address else (address,)
            for hostname in ("vm-a.praho.test", *literals):
                with self.subTest(hostname=hostname, address=address):
                    result = self._call_with_host(hostname, address)
                    self.assertTrue(result.is_err())
                    self.assertIn("Outbound security policy rejected", str(result.unwrap_err()))

    def test_the_lab_names_get_no_exemption_outside_the_lab(self) -> None:
        result = self._call_with_host("vm-b.praho.test", "127.0.0.1")
        self.assertTrue(result.is_err())


class AnsibleProductionPortTests(SimpleTestCase):
    def test_ssh_wait_probes_port_22_and_inventory_names_no_port(self) -> None:
        self.assertEqual(inspect.signature(AnsibleService._wait_for_ssh).parameters["port"].default, 22)
        source = inspect.getsource(AnsibleService._generate_inventory)
        self.assertNotIn("ansible_port", source)
        self.assertNotIn("ansible_port", inspect.getsource(AnsibleService._build_vars))


class LabTransportRefusalTests(SimpleTestCase):
    def test_refuses_outside_the_lab_settings_and_patches_nothing(self) -> None:
        real_resolve = outbound_http._resolve_dns
        real_build_vars = AnsibleService._build_vars
        for module, debug in (
            ("config.settings.prod", False),
            ("config.settings.staging", False),
            ("config.settings.test", False),
            ("config.settings.dev", True),
            ("config.settings.lab", False),
        ):
            with (
                self.subTest(module=module, debug=debug),
                override_settings(SETTINGS_MODULE=module, DEBUG=debug),
                self.assertRaisesMessage(CommandError, "Refusing to run"),
                lab_transport(lab_state()),
            ):
                self.fail("lab_transport entered outside the lab")
            self.assertIs(outbound_http._resolve_dns, real_resolve)
            self.assertIs(AnsibleService._build_vars, real_build_vars)

    def test_only_the_lab_settings_name_the_lab(self) -> None:
        settings_dir = Path(settings.BASE_DIR) / "config" / "settings"
        naming = sorted(
            path.name for path in settings_dir.glob("*.py") if "VIRTUALMIN_LAB_STATE_DIR" in path.read_text()
        )
        self.assertEqual(naming, ["lab.py"])
