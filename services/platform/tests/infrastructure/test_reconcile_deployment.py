"""Reconciling a deployment flagged for reconciliation: prove or attest that nothing it owned remains.

A flagged row is refused by Retry, the sweeps and re-deploy. Reconciliation is the operator's way out:
- it runs only on a quiet row (unwritten for longer than any lifecycle task can run), with no server id
  and no linked node;
- it searches the provider project by label, name, recorded id and key fingerprint, and the DNS zones by
  record id, stored name, current name and the deployment's own tag;
- a match, an unreadable zone or a failed lookup refuses;
- legacy rows with no recorded provider token need an evidence-backed attestation.

Success settles the row destroyed, unflagged and with no DNS ids, in one transaction with its log and
audit event. The creator provenance and the create state stay as history.
"""

from __future__ import annotations

import base64
import itertools
from datetime import timedelta
from typing import Any
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.common.types import Err, Ok
from apps.infrastructure.deployment_lifecycle import provider_token_fingerprint
from apps.infrastructure.models import NodeDeployment, NodeDeploymentLog
from apps.infrastructure.reconciliation import ReconcileRequest, reconcile_deployment
from apps.provisioning.virtualmin_models import VirtualminServer
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment

User = get_user_model()
TOKEN = "reconcile-token"
_OPERATORS = itertools.count(1)
KEY_BLOB = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519" + bytes(36)).decode()
EVIDENCE = "Hetzner console, project praho-staging: no server, firewall or key for this node; ticket OPS-1"


def legacy_row(**fields: Any) -> NodeDeployment:
    """The shape of staging -002: the create was refused after a firewall was recorded; nothing stored."""
    deployment = _create_deployment("failed")
    NodeDeploymentLog.objects.create(
        deployment=deployment,
        level="INFO",
        message="Firewall resource recorded: praho-fw-x",
        phase="provision_server",
        details={"firewall_id": "fw-old"},
    )
    NodeDeploymentLog.objects.create(
        deployment=deployment, level="ERROR", message="Server creation failed: unsupported location", phase="x"
    )
    values: dict[str, Any] = {
        "needs_reconciliation": True,
        "reconciliation_reason": "Server-create outcome unknown and provider token never recorded",
        "server_create_state": "unknown",
        "provider_token_fingerprint": "",
        "ipv4_address": None,
        "updated_at": timezone.now() - timedelta(hours=4),
        **fields,
    }
    NodeDeployment.objects.filter(pk=deployment.pk).update(**values)
    deployment.refresh_from_db()
    return deployment


def clean_cloud() -> mock.Mock:
    cloud = mock.Mock()
    for lookup in (
        "find_servers_by_label",
        "find_servers_by_name",
        "find_firewalls_by_label",
        "find_firewalls_by_name",
        "find_ssh_keys_by_label",
        "find_ssh_keys_by_name",
        "find_ssh_keys_by_fingerprint",
    ):
        getattr(cloud, lookup).return_value = Ok([])
    cloud.firewall_exists.return_value = Ok(False)
    return cloud


def clean_dns() -> mock.Mock:
    dns = mock.Mock()
    dns.get_zone_name.return_value = Ok("test.example.com")
    dns.get_record.return_value = Ok(None)
    dns.find_records_by_name.return_value = Ok([])
    dns.confirm_no_owned_records.return_value = Ok(True)
    return dns


class Harness:
    def __init__(self) -> None:
        self.operator = User.objects.create_superuser(email=f"ops{next(_OPERATORS)}@example.com", password="x")
        self.cloud = clean_cloud()
        self.dns = clean_dns()
        self.ssh_manager = mock.Mock()
        self.ssh_manager.get_deployment_key.return_value = Err("no key stored")
        self.ssh_manager.delete_deployment_key.return_value = Ok(True)

    def run(self, deployment: NodeDeployment, **options: Any) -> Any:
        request = ReconcileRequest(
            hostname=deployment.hostname,
            operator_email=options.pop("operator_email", self.operator.email),
            evidence=options.pop("evidence", EVIDENCE),
            invoker={"os_user": "ops", "host": "platform-1"},
            **options,
        )
        settings = {"node_deployment.dns_cloudflare_api_token": "dns-tok", "node_deployment.dns_cloudflare_zone_id": "z1"}
        with (
            mock.patch("apps.infrastructure.reconciliation.get_cloud_gateway", return_value=self.cloud),
            mock.patch("apps.infrastructure.reconciliation.get_dns_gateway", return_value=self.dns),
            mock.patch("apps.infrastructure.reconciliation.get_provider_token", return_value=Ok(TOKEN)),
            mock.patch("apps.infrastructure.reconciliation.get_ssh_key_manager", return_value=self.ssh_manager),
            mock.patch(
                "apps.infrastructure.reconciliation.SettingsService.get_setting",
                side_effect=lambda key, default=None: settings.get(key, default),
            ),
        ):
            return reconcile_deployment(request)


def unchanged(test: TestCase, deployment: NodeDeployment, status: str = "failed") -> None:
    row = NodeDeployment.objects.get(pk=deployment.pk)
    test.assertEqual((row.status, row.needs_reconciliation, row.operation_token), (status, True, None))


class SuccessTests(TestCase):
    def test_an_attested_legacy_row_is_settled_destroyed_with_its_history_kept(self) -> None:
        h = Harness()
        deployment = legacy_row()

        result = h.run(deployment, attest_no_resources=True)

        self.assertTrue(result.is_ok(), result)
        row = NodeDeployment.objects.get(pk=deployment.pk)
        self.assertEqual((row.status, row.needs_reconciliation, row.dns_record_ids), ("destroyed", False, []))
        self.assertIsNone(row.operation_token)
        self.assertEqual((row.server_create_state, row.provider_token_fingerprint), ("unknown", ""))
        record = row.reconciliation_record
        self.assertEqual((record["operator"], record["evidence"], record["provenance"]), (h.operator.email, EVIDENCE, "attested"))
        self.assertEqual(record["invoker"], {"os_user": "ops", "host": "platform-1"})
        self.assertEqual(record["credential_fingerprint"], provider_token_fingerprint(TOKEN))
        event = AuditEvent.objects.filter(action="node_destroy_completed").latest("timestamp")
        self.assertEqual(event.metadata["mode"], "reconcile")
        h.ssh_manager.delete_deployment_key.assert_called_once()

    def test_a_row_created_under_the_current_token_needs_no_attestation(self) -> None:
        h = Harness()
        deployment = legacy_row(provider_token_fingerprint=provider_token_fingerprint(TOKEN))

        result = h.run(deployment, evidence="")

        self.assertTrue(result.is_ok(), result)
        self.assertEqual(NodeDeployment.objects.get(pk=deployment.pk).reconciliation_record["provenance"], "matched")


class RefusedBeforeAnyWriteTests(TestCase):
    def test_each_precondition_refuses_with_nothing_written(self) -> None:
        cases: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {
            "not flagged": ({"needs_reconciliation": False}, {"attest_no_resources": True}),
            "server id": ({"external_node_id": "srv-1"}, {"attest_no_resources": True}),
            "written recently": ({"updated_at": timezone.now()}, {"attest_no_resources": True}),
            "other token": ({"provider_token_fingerprint": provider_token_fingerprint("other")}, {}),
            "no attestation": ({}, {}),
            "no evidence": ({}, {"attest_no_resources": True, "evidence": ""}),
        }
        for name, (fields, options) in cases.items():
            with self.subTest(name):
                h = Harness()
                deployment = legacy_row(**fields)
                expected = NodeDeployment.objects.get(pk=deployment.pk)

                self.assertTrue(h.run(deployment, **options).is_err(), name)

                row = NodeDeployment.objects.get(pk=deployment.pk)
                self.assertEqual(
                    (row.status, row.needs_reconciliation, row.operation_token),
                    (expected.status, expected.needs_reconciliation, None),
                )
                h.cloud.find_servers_by_label.assert_not_called()

    def test_a_linked_node_is_refused(self) -> None:
        h = Harness()
        server = VirtualminServer.objects.create(
            name="linked", hostname="linked.example.test", api_username="api", encrypted_api_password=b""
        )
        deployment = legacy_row(virtualmin_server=server)

        self.assertTrue(h.run(deployment, attest_no_resources=True).is_err())
        unchanged(self, deployment)

    def test_an_operator_without_destroy_permission_is_refused(self) -> None:
        h = Harness()
        User.objects.create_user(email="viewer@example.com", password="x", is_staff=True)
        deployment = legacy_row()

        self.assertTrue(h.run(deployment, attest_no_resources=True, operator_email="viewer@example.com").is_err())
        unchanged(self, deployment)

    def test_a_dry_run_writes_nothing(self) -> None:
        h = Harness()
        deployment = legacy_row()

        self.assertTrue(h.run(deployment, attest_no_resources=True, dry_run=True).is_ok())
        unchanged(self, deployment)


class SearchRefusesTests(TestCase):
    def test_anything_found_refuses_and_leaves_the_row_flagged(self) -> None:
        hits = {
            "server by label": ("find_servers_by_label", Ok([mock.Mock(server_id="1", labels={})])),
            "server by name": ("find_servers_by_name", Ok([mock.Mock(server_id="2", labels={})])),
            "firewall by label": ("find_firewalls_by_label", Ok(["3"])),
            "firewall by name": ("find_firewalls_by_name", Ok(["4"])),
            "recorded firewall": ("firewall_exists", Ok(True)),
            "key by label": ("find_ssh_keys_by_label", Ok(["5"])),
            "key by name": ("find_ssh_keys_by_name", Ok(["6"])),
            "lookup error": ("find_servers_by_name", Err("api down")),
        }
        for name, (lookup, answer) in hits.items():
            with self.subTest(name):
                h = Harness()
                getattr(h.cloud, lookup).return_value = answer
                deployment = legacy_row()

                self.assertTrue(h.run(deployment, attest_no_resources=True).is_err(), name)

                unchanged(self, deployment, status="destroying")
                h.ssh_manager.delete_deployment_key.assert_not_called()

    def test_a_key_is_searched_by_the_vault_key_fingerprint(self) -> None:
        h = Harness()
        h.ssh_manager.get_deployment_key.return_value = Ok(mock.Mock(public_key=f"ssh-ed25519 {KEY_BLOB} key"))
        h.cloud.find_ssh_keys_by_fingerprint.return_value = Ok(["7"])
        deployment = legacy_row(ssh_key_credential_id="vault-1")

        self.assertTrue(h.run(deployment, attest_no_resources=True).is_err())
        fingerprint = h.cloud.find_ssh_keys_by_fingerprint.call_args.args[0]
        self.assertRegex(fingerprint, r"^([0-9a-f]{2}:){15}[0-9a-f]{2}$")


class DnsProofTests(TestCase):
    def _entry(self, deployment: NodeDeployment, **fields: str) -> dict[str, str]:
        return {"zone_id": "z1", "record_id": "rA", "type": "A", "name": "old.test.example.com",
                "owner_tag": "praho:node-deploy:5", **fields}

    def test_each_unproven_record_refuses(self) -> None:
        cases = {
            "record id still present": ({}, ("get_record", Ok({"id": "rA"}))),
            "record under a stored name": ({}, ("find_records_by_name", Ok([{"id": "x", "type": "A"}]))),
            "unreadable zone": ({}, ("get_zone_name", Err("forbidden"))),
            "own tag still present": ({}, ("confirm_no_owned_records", Ok(False))),
            "malformed entry": ({"zone_id": ""}, ("get_record", Ok(None))),
        }
        for name, (entry_fields, (lookup, answer)) in cases.items():
            with self.subTest(name):
                h = Harness()
                getattr(h.dns, lookup).return_value = answer
                deployment = legacy_row()
                NodeDeployment.objects.filter(pk=deployment.pk).update(
                    dns_record_ids=[self._entry(deployment, **entry_fields)]
                )
                deployment.refresh_from_db()

                self.assertTrue(h.run(deployment, attest_no_resources=True).is_err(), name)

                row = NodeDeployment.objects.get(pk=deployment.pk)
                self.assertEqual((row.status, row.needs_reconciliation, len(row.dns_record_ids)), ("destroying", True, 1))

    def test_every_stored_name_and_the_current_name_are_searched(self) -> None:
        h = Harness()
        deployment = legacy_row()
        NodeDeployment.objects.filter(pk=deployment.pk).update(dns_record_ids=[self._entry(deployment, record_id="")])
        deployment.refresh_from_db()

        self.assertTrue(h.run(deployment, attest_no_resources=True).is_ok())

        names = {call.args[1] for call in h.dns.find_records_by_name.call_args_list}
        self.assertEqual(names, {"old.test.example.com", deployment.fqdn})


class NeverCreatedTests(TestCase):
    def test_the_legacy_shape_can_be_attested_never_created_without_rewriting_history(self) -> None:
        h = Harness()
        deployment = legacy_row()

        self.assertTrue(h.run(deployment, attest_no_resources=True, attest_never_created=True).is_ok())

        row = NodeDeployment.objects.get(pk=deployment.pk)
        self.assertTrue(row.reconciliation_record["never_created_attested"])
        self.assertEqual(row.server_create_state, "unknown")

    def test_creation_evidence_refuses_the_attestation(self) -> None:
        cases = {
            "created state": {"server_create_state": "created"},
            "an address": {"ipv4_address": "198.51.100.7"},
        }
        for name, fields in cases.items():
            with self.subTest(name):
                h = Harness()
                deployment = legacy_row(**fields)

                self.assertTrue(h.run(deployment, attest_no_resources=True, attest_never_created=True).is_err())
                unchanged(self, deployment)


class SettlementIsAtomicTests(TestCase):
    def test_an_audit_failure_leaves_the_row_flagged(self) -> None:
        h = Harness()
        deployment = legacy_row()

        with mock.patch(
            "apps.infrastructure.reconciliation.InfrastructureAuditService.log_destroy_completed",
            side_effect=RuntimeError("audit down"),
        ):
            self.assertTrue(h.run(deployment, attest_no_resources=True).is_err())

        row = NodeDeployment.objects.get(pk=deployment.pk)
        self.assertEqual((row.status, row.needs_reconciliation), ("destroying", True))
        self.assertEqual(row.reconciliation_record, {})

    def test_a_second_reconcile_right_after_the_first_claimed_is_refused(self) -> None:
        h = Harness()
        deployment = legacy_row()
        h.cloud.find_servers_by_name.return_value = Ok([mock.Mock(server_id="9", labels={})])
        self.assertTrue(h.run(deployment, attest_no_resources=True).is_err())  # claimed, then refused
        h.cloud.find_servers_by_name.return_value = Ok([])

        self.assertTrue(h.run(deployment, attest_no_resources=True).is_err())  # inside the quiet window
        self.assertEqual(NodeDeployment.objects.get(pk=deployment.pk).status, "destroying")


class CommandTests(TestCase):
    def test_the_command_records_the_invoking_os_user_and_exits_non_zero_on_refusal(self) -> None:
        from io import StringIO  # noqa: PLC0415

        from django.core.management import call_command  # noqa: PLC0415
        from django.core.management.base import CommandError  # noqa: PLC0415

        h = Harness()
        deployment = legacy_row()
        with mock.patch(
            "apps.infrastructure.management.commands.reconcile_deployment.reconcile_deployment",
            return_value=Err("found servers named x"),
        ) as reconcile, self.assertRaises(CommandError):
            call_command("reconcile_deployment", deployment.hostname, "--operator", h.operator.email, stdout=StringIO())

        request = reconcile.call_args.args[0]
        self.assertEqual(request.operator_email, h.operator.email)
        self.assertTrue(request.invoker["os_user"])
