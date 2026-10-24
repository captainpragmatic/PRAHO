"""Master and SSH credentials go only to a node whose own credential resolves (#751 follow-up, M19).

The escalation loop already refused master after the node's own credential failed to resolve, but two paths
skipped that step: a cached "master worked last time" ordering tried master first, and the health check tried
every method regardless. A node renamed in the database to a host its writer controls, with its own password
now unreadable (bound to the old hostname), would have been sent the global master credentials.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings
from requests import Response

from apps.provisioning.virtualmin_auth_manager import AuthMethod, VirtualminAuthenticationManager
from apps.provisioning.virtualmin_models import VirtualminServer

MASTER = {"VIRTUALMIN_MASTER_USERNAME": "master-root", "VIRTUALMIN_MASTER_PASSWORD": "master-secret-value"}


@override_settings(**MASTER)
class PrivilegedAuthGateTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.server = VirtualminServer.objects.create(name="node", hostname="node.example.com", api_username="acl")
        self.server.set_api_password("node-password")
        self.server.save()
        self.sent: list[str] = []
        transport = patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=self._respond)
        transport.start()
        self.addCleanup(transport.stop)
        self.ssh: list[str] = []

    def _respond(self, method: str, url: str, **kwargs: Any) -> Response:
        self.sent.append(repr(kwargs.get("auth")))
        response = Response()
        response.status_code = 401
        response.headers["Content-Type"] = "application/json"
        response._content = json.dumps({"status": "failure"}).encode()
        response._content_consumed = True
        return response

    def _renamed_in_the_database(self) -> VirtualminServer:
        VirtualminServer._base_manager.filter(pk=self.server.pk).update(hostname="attacker.example.net")
        return VirtualminServer.objects.get(pk=self.server.pk)

    def _master_requests(self) -> list[str]:
        return [auth for auth in self.sent if "master-root" in auth]

    def _manager(self, server: VirtualminServer) -> VirtualminAuthenticationManager:
        manager = VirtualminAuthenticationManager(server)
        patcher = patch.object(manager, "_execute_ssh_command", side_effect=self.ssh.append)
        patcher.start()
        self.addCleanup(patcher.stop)
        return manager

    def test_control_a_resolvable_node_still_reaches_master_in_the_health_check(self) -> None:
        self._manager(VirtualminServer.objects.get(pk=self.server.pk)).health_check_all_methods()
        self.assertTrue(self._master_requests(), "the recorder sees master requests")

    def test_the_health_check_never_sends_master_to_a_node_whose_credential_does_not_resolve(self) -> None:
        results = self._manager(self._renamed_in_the_database()).health_check_all_methods()
        self.assertEqual(self._master_requests(), [])
        self.assertEqual(self.ssh, [])
        self.assertFalse(results[AuthMethod.MASTER_PROXY.value].success)

    def test_a_cached_master_ordering_never_sends_master_to_such_a_node(self) -> None:
        server = self._renamed_in_the_database()
        manager = self._manager(server)
        # What _get_auth_method_priority returns once master is cached as the method that worked last
        cached = [AuthMethod.MASTER_PROXY, AuthMethod.ACL, AuthMethod.SSH_SUDO]
        with patch.object(manager, "_get_auth_method_priority", return_value=cached):
            result = manager.execute_virtualmin_command("list-domains", {"multiline": ""})
        self.assertTrue(result.is_err())
        self.assertEqual(self._master_requests(), [])
        self.assertEqual(self.ssh, [])
