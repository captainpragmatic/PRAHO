"""The authentication health check probes with a command Virtualmin accepts, and reads a refusal as unhealthy.

`health_check_all_methods` sent list-domains {"multiline": True}. remote.cgi turns a value into an argument,
so True arrived as `--multiline True` and Virtualmin 8.3 refused it ("Unknown parameter True", HTTP 200, a
failure envelope). The check counted any non-error result as healthy, so every API method reported working
while the probe itself was refused. The bare flag is an empty string, as everywhere else in PRAHO.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from django.test import TestCase

from apps.common.types import Ok
from apps.provisioning.virtualmin_auth_manager import AuthMethod, VirtualminAuthenticationManager
from tests.helpers.recorded_virtualmin import recorded_response


class HealthProbeTests(TestCase):
    def setUp(self) -> None:
        server = MagicMock()
        server.hostname = "test.example.com"
        server.id = 1
        self.manager = VirtualminAuthenticationManager(server)

    def test_the_probe_sends_the_flag_the_way_remote_cgi_takes_it(self) -> None:
        sent: list[tuple[AuthMethod, str, dict[str, Any]]] = []

        def execute(method: AuthMethod, program: str, parameters: dict[str, Any]) -> Any:
            sent.append((method, program, parameters))
            return Ok(recorded_response("list-domains", "one_domain"))

        with patch.object(self.manager, "_execute_with_method", side_effect=execute):
            self.manager.health_check_all_methods()

        self.assertEqual([entry[0] for entry in sent], [AuthMethod.ACL, AuthMethod.MASTER_PROXY, AuthMethod.SSH_SUDO])
        for _method, program, parameters in sent:
            self.assertEqual(program, "list-domains")
            self.assertEqual(parameters, {"multiline": ""})

    def test_a_refused_probe_is_not_a_healthy_method(self) -> None:
        refusal = Ok(recorded_response("list-domains", "unknown_parameter"))
        with patch.object(self.manager, "_execute_with_method", return_value=refusal):
            results = self.manager.health_check_all_methods()

        for method in (AuthMethod.ACL, AuthMethod.MASTER_PROXY):
            self.assertFalse(results[method.value].success, method)

    def test_an_accepted_probe_is_healthy(self) -> None:
        accepted = Ok(recorded_response("list-domains", "one_domain"))
        with patch.object(self.manager, "_execute_with_method", return_value=accepted):
            results = self.manager.health_check_all_methods()

        self.assertTrue(all(result.success for result in results.values()))

    def test_the_ssh_path_sends_the_empty_flag_as_a_bare_option(self) -> None:
        with patch.object(self.manager, "_execute_ssh_command", return_value=Ok("ok")) as run:
            self.manager._execute_ssh_sudo("list-domains", {"multiline": ""})

        run.assert_called_once_with("sudo /usr/sbin/virtualmin list-domains --multiline")
