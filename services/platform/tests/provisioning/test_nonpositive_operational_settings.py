"""Legacy zero settings must still dispatch usable worker and HTTP requests."""

from io import BytesIO
from typing import cast
from unittest.mock import patch

import requests
from django.core.cache import cache
from django.test import TestCase, override_settings
from django_q.models import OrmQ
from django_q.signing import SignedPackage

from apps.provisioning.virtualmin_auth_manager import VirtualminAuthenticationManager
from apps.provisioning.virtualmin_gateway import VirtualminConfig, VirtualminGateway
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.provisioning.virtualmin_tasks import (
    delete_virtualmin_account_async,
    suspend_virtualmin_account_async,
)
from tests.helpers.legacy_settings import store_legacy_integer


class SuccessfulChannel:
    def recv_exit_status(self) -> int:
        return 0


class SSHOutput(BytesIO):
    channel = SuccessfulChannel()


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    VIRTUALMIN_TIMEOUTS={},
)
class NonpositiveVirtualminSettingsTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)

    def test_legacy_nonpositive_worker_budgets_enqueue_with_defaults(self) -> None:
        operations = (
            (
                "provisioning.task_soft_time_limit",
                600,
                suspend_virtualmin_account_async,
            ),
            ("provisioning.task_time_limit", 900, delete_virtualmin_account_async),
        )
        for key, default, enqueue in operations:
            for stored in (0, -1, 1, 17):
                with self.subTest(key=key, stored=stored):
                    store_legacy_integer(key, stored)
                    cache.clear()
                    task_id = enqueue("account-id")
                    packages = [
                        cast("dict[str, object]", SignedPackage.loads(row.payload)) for row in OrmQ.objects.all()
                    ]
                    task = next(package for package in packages if package["id"] == task_id)
                    self.assertEqual(task["timeout"], default if stored <= 0 else stored)
                    self.assertEqual(cast("tuple[object, ...]", task["args"])[0], "account-id")

    def test_legacy_nonpositive_attempts_still_return_the_healthy_transport_response(
        self,
    ) -> None:
        server = VirtualminServer.objects.create(
            name="positive-attempts",
            hostname="positive-attempts.example.test",
            api_username="acl-user",
            status="active",
        )
        server.set_api_password("acl-password")
        server.save(update_fields=["encrypted_api_password"])
        gateway = VirtualminGateway(VirtualminConfig(server=server, use_credential_vault=False))
        response = requests.Response()
        response.status_code = 200
        response._content = b'{"status": "success", "message": "usable transport"}'
        response._content_consumed = True
        for stored in (0, -1, 1):
            with self.subTest(stored=stored):
                store_legacy_integer("virtualmin.max_retries", stored)
                cache.clear()
                with patch(
                    "apps.provisioning.virtualmin_gateway.safe_request",
                    return_value=response,
                ):
                    result = gateway.call("info")
                self.assertTrue(result.is_ok(), result)
                self.assertTrue(result.unwrap().success)
                self.assertEqual(result.unwrap().raw_response, response.text)

    @override_settings(VIRTUALMIN_SSH_PASSWORD="fixture-password", VIRTUALMIN_SSH_PRIVATE_KEY_PATH=None)
    def test_legacy_nonpositive_ssh_timeouts_reach_the_transports_as_defaults(
        self,
    ) -> None:
        connect_timeouts: list[object] = []
        command_timeouts: list[object] = []
        server = VirtualminServer(hostname="ssh-timeout.example.test")

        def connect(**kwargs: object) -> None:
            connect_timeouts.append(kwargs["timeout"])

        def execute(command: str, *, timeout: int) -> tuple[BytesIO, SSHOutput, BytesIO]:
            command_timeouts.append(timeout)
            return BytesIO(), SSHOutput(b"healthy ssh output"), BytesIO()

        with (
            patch("paramiko.SSHClient.connect", side_effect=connect),
            patch("paramiko.SSHClient.exec_command", side_effect=execute),
        ):
            for stored in (0, -1, 1):
                store_legacy_integer("provisioning.ssh_timeout", stored)
                store_legacy_integer("provisioning.sudo_command_timeout", stored)
                cache.clear()
                manager = VirtualminAuthenticationManager(server)
                self.addCleanup(manager._disconnect_ssh)
                result = manager._execute_ssh_command("virtualmin info")
                self.assertTrue(result.is_ok(), result)
                self.assertEqual(result.unwrap(), "healthy ssh output")
        self.assertEqual(connect_timeouts, [30, 30, 1])
        self.assertEqual(command_timeouts, [60, 60, 1])
