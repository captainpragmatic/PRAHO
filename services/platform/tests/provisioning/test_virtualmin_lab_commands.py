"""The Virtualmin lab commands refuse non-lab settings, and the lab transport
adapts only the lab node names."""

from __future__ import annotations

from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase, override_settings

from apps.common import outbound_http
from apps.provisioning.management.commands._virtualmin_lab import LabNode, LabState, lab_transport


def _state() -> LabState:
    return LabState(
        state_dir="/nonexistent",
        nodes=(LabNode("vm-a", "vmlab-a", "vm-a.praho.test", "dev-sha-lab-ro-vmla-001", 10101, 2522),),
        known_hosts="/nonexistent/known_hosts",
        s3_endpoint="http://127.0.0.1:19000",
        bucket="praho-backups",
        domain="roundtrip.praho.test",
        domain_user="roundtrip",
    )


class LabCommandRefusalTests(SimpleTestCase):
    def test_commands_refuse_outside_lab_settings(self) -> None:
        for command in ("virtualmin_lab_bootstrap", "virtualmin_lab_roundtrip", "virtualmin_lab_checks"):
            for module, debug in (
                ("config.settings.prod", False),
                ("config.settings.staging", False),
                ("config.settings.dev", True),
                ("config.settings.lab", False),
            ):
                with (
                    self.subTest(command=command, module=module, debug=debug),
                    override_settings(SETTINGS_MODULE=module, DEBUG=debug),
                    self.assertRaisesMessage(CommandError, "Refusing to run"),
                ):
                    call_command(command)


@override_settings(SETTINGS_MODULE="config.settings.lab", DEBUG=True)
class LabTransportScopeTests(SimpleTestCase):
    def test_only_lab_names_resolve_to_loopback(self) -> None:
        with patch.object(outbound_http, "_resolve_dns", return_value=["203.0.113.9"]) as real:
            with lab_transport(_state()):
                self.assertEqual(outbound_http._resolve_dns("vm-a.praho.test", 10101), ["127.0.0.1"])
                self.assertEqual(outbound_http._resolve_dns("vm-a.praho.test.evil", 10101), ["203.0.113.9"])
            real.assert_called_once_with("vm-a.praho.test.evil", 10101)
            # Restored on exit.
            self.assertEqual(outbound_http._resolve_dns("vm-a.praho.test", 10101), ["203.0.113.9"])
