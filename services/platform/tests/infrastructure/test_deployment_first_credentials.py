"""A deployment keeps the provider token and SSH key it first used.

A retry under a different provider token cannot see resources the first token created: its "not found"
proves nothing, and creating again could bill a second server in another project. So when the row may
hold resources and the stored fingerprint is not the current token's (or was never recorded), the retry
is refused and the row is flagged for reconciliation before any provider call. Likewise a row that
already has a vault key reuses it: a regenerated key would lock Ansible out of a server adopted by label.
"""

from __future__ import annotations

from typing import Any
from unittest import mock

from django.test import TestCase

from apps.common.types import Ok
from apps.infrastructure.deployment_lifecycle import provider_token_fingerprint
from apps.infrastructure.models import NodeDeployment
from tests.infrastructure.test_deployment_operation_ownership import _gateway, _pipeline_service
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment, _ok_dns_gateway


def _row(**fields: Any) -> NodeDeployment:
    deployment = _create_deployment("pending", external_node_id=str(fields.pop("external_node_id", "")))
    NodeDeployment.objects.filter(pk=deployment.pk).update(**fields)
    deployment.refresh_from_db()
    return deployment


def _deploy(deployment: NodeDeployment, token: str = "token-b") -> tuple[Any, mock.Mock, Any]:  # noqa: S107  # A fake provider token
    gateway = _gateway()
    gateway.upload_owned_ssh_key.return_value = Ok("praho-key")
    gateway.get_server.return_value = Ok(None)
    service = _pipeline_service()
    with (
        mock.patch("apps.infrastructure.deployment_service.SettingsService.get_setting", return_value=True),
        mock.patch("apps.infrastructure.deployment_service.get_dns_gateway", return_value=_ok_dns_gateway()),
        mock.patch("apps.infrastructure.deployment_service.get_cloud_gateway", return_value=gateway),
    ):
        result = service.deploy_node(deployment=deployment, credentials={"api_token": token})
    deployment.refresh_from_db()
    return result, gateway, service


class ProvenanceTests(TestCase):
    def test_a_rotated_token_cannot_retry_a_row_that_may_hold_resources(self) -> None:
        deployment = _row(server_create_state="unknown", provider_token_fingerprint=provider_token_fingerprint("a"))

        result, gateway, _service = _deploy(deployment, token="token-b")

        self.assertTrue(result.is_err())
        self.assertTrue(deployment.needs_reconciliation)
        self.assertEqual(deployment.provider_token_fingerprint, provider_token_fingerprint("a"))
        gateway.create_server.assert_not_called()
        gateway.upload_owned_ssh_key.assert_not_called()

    def test_an_unknown_provenance_cannot_trust_not_found_for_a_stored_server(self) -> None:
        deployment = _row(external_node_id="srv-old", server_create_state="created")

        result, gateway, _service = _deploy(deployment)

        self.assertTrue(result.is_err())
        self.assertTrue(deployment.needs_reconciliation)
        self.assertEqual(deployment.external_node_id, "srv-old")
        gateway.get_server.assert_not_called()
        gateway.create_server.assert_not_called()

    def test_a_row_that_never_reached_the_provider_records_the_first_token(self) -> None:
        deployment = _row()

        result, gateway, _service = _deploy(deployment, token="token-b")

        self.assertTrue(result.is_ok(), result)
        self.assertEqual(deployment.provider_token_fingerprint, provider_token_fingerprint("token-b"))
        gateway.create_server.assert_called_once()

    def test_a_row_holding_nothing_takes_the_current_token(self) -> None:
        # A refused create under token A left nothing behind, so the retry's resources are token B's.
        deployment = _row(provider_token_fingerprint=provider_token_fingerprint("token-a"))

        result, _gateway_used, _service = _deploy(deployment, token="token-b")

        self.assertTrue(result.is_ok(), result)
        self.assertEqual(deployment.provider_token_fingerprint, provider_token_fingerprint("token-b"))

    def test_a_matching_token_still_trusts_not_found(self) -> None:
        deployment = _row(
            external_node_id="srv-old",
            server_create_state="created",
            provider_token_fingerprint=provider_token_fingerprint("token-b"),
        )

        result, gateway, _service = _deploy(deployment, token="token-b")

        self.assertTrue(result.is_ok(), result)
        gateway.get_server.assert_called_once_with("srv-old")
        gateway.create_server.assert_called_once()


class FirstKeyTests(TestCase):
    def test_a_row_with_a_vault_key_reuses_it_even_without_a_server_id(self) -> None:
        deployment = _row(ssh_key_credential_id="vault-key-1")

        _result, _gateway_used, service = _deploy(deployment)

        service._ssh_manager.generate_deployment_key.assert_not_called()
        service._ssh_manager.get_deployment_key.assert_called_once()
