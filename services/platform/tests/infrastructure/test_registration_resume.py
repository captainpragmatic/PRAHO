"""Registration failures keep the provisioned node, and Retry resumes registration alone.

Before this, a failed registration was logged and the deployment still reached "completed", so the node
was never registered and nothing offered to finish it. Once registration has started the VM, its DNS and
its panel are all in place: failing the row must not delete them, and Retry must not run provisioning,
DNS or Ansible again. It registers with the API credential stored before the panel install, or, when the
node is already registered, only activates and completes.
"""

from __future__ import annotations

from typing import Any
from unittest import mock

from django.test import TestCase

from apps.common.types import Err, Ok
from apps.infrastructure.deployment_lifecycle import provider_token_fingerprint
from apps.infrastructure.models import NodeDeployment
from apps.provisioning.virtualmin_models import VirtualminServer
from tests.infrastructure.test_deployment_operation_ownership import _gateway, _pipeline_service
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment, _ok_dns_gateway

_VAULT = "apps.common.credential_vault.get_credential_vault"


def _vault(stored: tuple[str, str, dict[str, Any]] | None = None) -> mock.Mock:
    vault = mock.Mock()
    vault.get_credential.return_value = Ok(stored) if stored else Err("not found")
    vault.store_credential.return_value = Ok(mock.Mock())
    return vault


def _deploy(service: Any, deployment: NodeDeployment, vault: mock.Mock, gateway: mock.Mock | None = None) -> Any:
    cloud = gateway or _gateway()
    cloud.upload_owned_ssh_key.return_value = Ok("praho-key")
    with (
        mock.patch("apps.infrastructure.deployment_service.SettingsService.get_setting", return_value=True),
        mock.patch("apps.infrastructure.deployment_service.get_dns_gateway", return_value=_ok_dns_gateway()),
        mock.patch("apps.infrastructure.deployment_service.get_cloud_gateway", return_value=cloud),
        mock.patch(_VAULT, return_value=vault),
    ):
        result = service.deploy_node(deployment=deployment, credentials={"api_token": "tok"})
    deployment.refresh_from_db()
    return result


class RegistrationFailureKeepsTheNodeTests(TestCase):
    def test_a_failed_registration_fails_the_row_without_deleting_the_vm(self) -> None:
        deployment = _create_deployment("pending")
        service = _pipeline_service()
        service._registration.register_node.return_value = Err("panel certificate not trusted")
        gateway = _gateway()

        result = _deploy(service, deployment, _vault(), gateway)

        self.assertTrue(result.is_err())
        self.assertEqual((deployment.status, deployment.registration_state), ("failed", "started"))
        self.assertEqual(deployment.external_node_id, "srv-1")
        gateway.delete_server.assert_not_called()

    def test_an_exception_after_registration_started_keeps_the_vm(self) -> None:
        deployment = _create_deployment("pending")
        service = _pipeline_service()
        service._registration.register_node.side_effect = RuntimeError("database hiccup")
        gateway = _gateway()

        _deploy(service, deployment, _vault(), gateway)

        self.assertEqual(deployment.status, "failed")
        gateway.delete_server.assert_not_called()

    def test_the_api_credential_is_stored_before_the_panel_install(self) -> None:
        deployment = _create_deployment("pending")
        service = _pipeline_service()
        vault = _vault()
        order: list[str] = []

        def store(*_args: Any, **_kwargs: Any) -> Ok[mock.Mock]:
            order.append("store")
            return Ok(mock.Mock())

        def run_playbook(**_kwargs: Any) -> Ok[mock.Mock]:
            order.append("ansible")
            return Ok(mock.Mock(success=True, stderr=""))

        vault.store_credential.side_effect = store
        service._ansible.run_playbook.side_effect = run_playbook

        _deploy(service, deployment, vault)

        self.assertEqual(order[:2], ["store", "ansible"])


def _failed_after_registration(registration_state: str, *, linked: bool) -> NodeDeployment:
    deployment = _create_deployment("pending", external_node_id="srv-1")
    fields: dict[str, Any] = {
        "status": "failed",
        "registration_state": registration_state,
        "server_create_state": "created",
        "provider_token_fingerprint": provider_token_fingerprint("tok"),
        "ipv4_address": "1.2.3.4",
    }
    if linked:
        fields["virtualmin_server"] = VirtualminServer.objects.create(
            name=f"resume-{registration_state}",
            hostname=f"{deployment.hostname}.test.example.com",
            api_username="praho-api",
            encrypted_api_password=b"",
            status="active" if registration_state == "activated" else "disabled",
        )
    NodeDeployment.objects.filter(pk=deployment.pk).update(**fields)
    deployment.refresh_from_db()
    return deployment


class RegistrationOnlyResumeTests(TestCase):
    def _retry(self, deployment: NodeDeployment, vault: mock.Mock) -> tuple[Any, Any, mock.Mock]:
        service = _pipeline_service()
        service._registration.verify_and_activate.return_value = Ok(mock.Mock())
        with (
            mock.patch("apps.infrastructure.deployment_service.get_cloud_gateway") as get_gateway,
            mock.patch("apps.infrastructure.deployment_service.get_dns_gateway") as get_dns,
            mock.patch("apps.infrastructure.deployment_service.SettingsService.get_setting", return_value=True),
            mock.patch(_VAULT, return_value=vault),
        ):
            result = service.retry_deployment(deployment, credentials={"api_token": "tok"})
            get_dns.assert_not_called()
        deployment.refresh_from_db()
        return result, service, get_gateway

    def _assert_nothing_reprovisioned(self, service: Any, get_gateway: mock.Mock) -> None:
        get_gateway.assert_not_called()
        service._ansible.run_playbook.assert_not_called()
        service._validation.validate_node.assert_not_called()
        service._ssh_manager.generate_deployment_key.assert_not_called()

    def test_a_crash_after_registration_only_activates_and_completes(self) -> None:
        deployment = _failed_after_registration("registered", linked=True)

        result, service, get_gateway = self._retry(deployment, _vault())

        self.assertTrue(result.is_ok(), result)
        self.assertEqual((deployment.status, deployment.registration_state), ("completed", "activated"))
        service._registration.register_node.assert_not_called()
        service._registration.verify_and_activate.assert_called_once()
        self._assert_nothing_reprovisioned(service, get_gateway)

    def test_a_crash_after_activation_only_completes(self) -> None:
        deployment = _failed_after_registration("activated", linked=True)

        result, service, get_gateway = self._retry(deployment, _vault())

        self.assertTrue(result.is_ok(), result)
        self.assertEqual(deployment.status, "completed")
        service._registration.verify_and_activate.assert_not_called()
        self._assert_nothing_reprovisioned(service, get_gateway)

    def test_an_unregistered_node_registers_with_the_stored_credential(self) -> None:
        deployment = _failed_after_registration("started", linked=False)

        result, service, get_gateway = self._retry(deployment, _vault(("praho-api", "s3cret", {})))

        self.assertTrue(result.is_ok(), result)
        kwargs = service._registration.register_node.call_args.kwargs
        self.assertEqual((kwargs["admin_username"], kwargs["admin_password"]), ("praho-api", "s3cret"))
        self._assert_nothing_reprovisioned(service, get_gateway)

    def test_without_the_stored_credential_resume_fails_closed(self) -> None:
        deployment = _failed_after_registration("started", linked=False)

        result, service, get_gateway = self._retry(deployment, _vault())

        self.assertTrue(result.is_err())
        self.assertEqual(deployment.status, "failed")
        service._registration.register_node.assert_not_called()
        self._assert_nothing_reprovisioned(service, get_gateway)
