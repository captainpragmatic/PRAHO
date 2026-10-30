"""Re-deploy keeps the hostname: a failed or destroyed deployment that never got a server is deployed again.

Scope (until costs track separate server lifetimes): only rows that never got a server, either a create
state of "none" or a reconciled, evidence-backed never-created attestation. A failed row must also never
have reached the provider (otherwise destroy it first). The row keeps its hostname, number, logs, audit
and costs. Everything that described the old attempt is reset, including the correlation id, so nothing
left under the old labels can ever be adopted. Re-deploy needs the destroy permission at the service.
"""

from __future__ import annotations

import itertools
from typing import Any
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase

from apps.common.types import Ok
from apps.infrastructure.deployment_lifecycle import provider_token_fingerprint
from apps.infrastructure.models import DriftCheck, DriftRemediationRequest, DriftReport, NodeDeployment, NodeSize
from apps.provisioning.virtualmin_models import VirtualminServer
from tests.helpers.node_catalogue import make_size
from tests.infrastructure.test_deployment_operation_ownership import _gateway, _pipeline_service
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment, _ok_dns_gateway

User = get_user_model()
_EMAILS = itertools.count(1)


def operator() -> Any:
    return User.objects.create_superuser(email=f"redeploy{next(_EMAILS)}@example.com", password="x")


def destroyed_row(**fields: Any) -> NodeDeployment:
    deployment = _create_deployment("destroyed")
    values: dict[str, Any] = {"server_create_state": "none", "ipv4_address": None, **fields}
    NodeDeployment.objects.filter(pk=deployment.pk).update(**values)
    deployment.refresh_from_db()
    return deployment


def new_size(deployment: NodeDeployment, type_id: str = "cx23", **kwargs: Any) -> NodeSize:
    return make_size(deployment.provider, type_id, deployment.region, **kwargs)


def redeploy(deployment: NodeDeployment, size: NodeSize, user: Any = None) -> tuple[Any, mock.Mock]:
    service = _pipeline_service()
    gateway = _gateway()
    gateway.upload_owned_ssh_key.return_value = Ok("praho-key")
    with (
        mock.patch("apps.infrastructure.deployment_service.SettingsService.get_setting", return_value=True),
        mock.patch("apps.infrastructure.deployment_service.get_dns_gateway", return_value=_ok_dns_gateway()),
        mock.patch("apps.infrastructure.deployment_service.get_cloud_gateway", return_value=gateway),
        mock.patch.object(service, "_check_orderable", return_value=Ok(True)),
    ):
        result = service.redeploy_node(deployment, size, credentials={"api_token": "tok"}, user=user or operator())
    deployment.refresh_from_db()
    return result, gateway


class RedeployTests(TestCase):
    def test_a_destroyed_row_that_never_got_a_server_is_deployed_again_under_its_hostname(self) -> None:
        deployment = destroyed_row()
        hostname, old_correlation, retries = deployment.hostname, deployment.correlation_id, deployment.retry_count
        size = new_size(deployment)

        result, gateway = redeploy(deployment, size)

        self.assertTrue(result.is_ok(), result)
        self.assertEqual((deployment.status, deployment.hostname), ("completed", hostname))
        self.assertNotEqual(deployment.correlation_id, old_correlation)
        self.assertEqual(deployment.retry_count, retries + 1)
        self.assertEqual(deployment.node_size_id, size.pk)
        request = gateway.create_server.call_args.args[0]
        self.assertEqual(request.server_type, "cx23")
        self.assertEqual(request.labels["praho-deployment"], str(deployment.correlation_id))

    def test_the_reset_clears_everything_that_described_the_old_attempt(self) -> None:
        deployment = destroyed_row(ssh_port=2222, ssh_host_keys="old-keys", status_message="old", provider_token_fingerprint="")
        service = _pipeline_service()
        with mock.patch.object(service, "deploy_node", return_value=Ok(mock.Mock())), mock.patch.object(
            service, "_check_orderable", return_value=Ok(True)
        ):
            service.redeploy_node(deployment, new_size(deployment), credentials={"api_token": "tok"}, user=operator())

        deployment.refresh_from_db()
        self.assertEqual(
            (deployment.status, deployment.ssh_port, deployment.ssh_host_keys, deployment.destroyed_at),
            ("pending", 22, None, None),
        )
        self.assertEqual((deployment.server_create_state, deployment.registration_state), ("none", "none"))
        self.assertEqual((deployment.dns_record_ids, deployment.ssh_key_credential_id), ([], ""))

    def test_the_provider_resources_are_named_after_the_new_attempt(self) -> None:
        deployment = destroyed_row()

        _result, gateway = redeploy(deployment, new_size(deployment))

        suffix = str(deployment.correlation_id)[:8]
        self.assertTrue(gateway.upload_owned_ssh_key.call_args.args[0].endswith(suffix))
        self.assertTrue(gateway.create_firewall.call_args.kwargs["name"].endswith(suffix))

    def test_a_reconciled_never_created_row_is_eligible(self) -> None:
        deployment = destroyed_row(
            server_create_state="unknown", reconciliation_record={"never_created_attested": True}
        )

        result, _gateway_used = redeploy(deployment, new_size(deployment))

        self.assertTrue(result.is_ok(), result)


class RedeployRefusalTests(TestCase):
    def test_each_guard_refuses_with_nothing_changed(self) -> None:
        cases: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {
            "completed": ({"status": "completed"}, {}),
            "flagged": ({"needs_reconciliation": True}, {}),
            "billed before": ({"server_create_state": "created"}, {}),
            "unknown, not attested": ({"server_create_state": "unknown"}, {}),
            "server id": ({"external_node_id": "srv-1"}, {}),
            "dns left": ({"dns_record_ids": [{"zone_id": "z", "record_id": "r"}]}, {}),
            "failed after reaching the provider": (
                {"status": "failed", "provider_token_fingerprint": provider_token_fingerprint("tok")},
                {},
            ),
            "inactive size": ({}, {"active": False}),
        }
        for name, (fields, size_kwargs) in cases.items():
            with self.subTest(name):
                deployment = destroyed_row(**fields)
                before = NodeDeployment.objects.get(pk=deployment.pk)

                result, gateway = redeploy(deployment, new_size(deployment, f"cx{next(_EMAILS) + 100}", **size_kwargs))

                self.assertTrue(result.is_err(), name)
                gateway.create_server.assert_not_called()
                self.assertEqual(
                    (deployment.status, deployment.correlation_id, deployment.retry_count),
                    (before.status, before.correlation_id, before.retry_count),
                )

    def test_a_size_not_sold_in_the_region_is_refused(self) -> None:
        deployment = destroyed_row()
        unsold = make_size(deployment.provider, "cpx11")

        self.assertTrue(redeploy(deployment, unsold)[0].is_err())

    def test_a_node_registered_under_the_hostname_is_refused(self) -> None:
        deployment = destroyed_row()
        VirtualminServer.objects.create(
            name="taken", hostname=deployment.fqdn, api_username="api", encrypted_api_password=b""
        )

        self.assertTrue(redeploy(deployment, new_size(deployment))[0].is_err())

    def test_an_open_remediation_is_refused(self) -> None:
        deployment = destroyed_row()
        check = DriftCheck.objects.create(deployment=deployment, check_type="cloud", status="completed")
        report = DriftReport.objects.create(
            drift_check=check, deployment=deployment, severity="high", category="server_state",
            field_name="server_type", expected_value="cx11", actual_value="cx23",
        )
        DriftRemediationRequest.objects.create(
            deployment=deployment, report=report, action_type="accept_actual", status="pending_approval"
        )

        self.assertTrue(redeploy(deployment, new_size(deployment))[0].is_err())

    def test_a_user_without_the_destroy_permission_is_refused(self) -> None:
        deployment = destroyed_row()
        viewer = User.objects.create_user(email="viewer@example.com", password="x", is_staff=True)

        self.assertTrue(redeploy(deployment, new_size(deployment), user=viewer)[0].is_err())


class DestroyedIsTerminalExceptForRedeployTests(TestCase):
    def test_destroyed_moves_only_to_pending(self) -> None:
        for target in ["failed", "completed", "destroying"]:
            with self.subTest(target=target), self.assertRaises(ValidationError):
                _create_deployment("destroyed").transition_to(target)
        self.assertTrue(_create_deployment("destroyed").is_valid_transition("pending"))
