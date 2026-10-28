"""Account-name HTTP policy requires a fresh, identity-bound native receipt."""

from __future__ import annotations

import base64
import json
from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.test import SimpleTestCase

from apps.common.types import Err, Ok, Retriability, retriability_of
from apps.infrastructure.ansible_service import AnsibleService
from apps.provisioning import account_name_node as node

ZONE = "accounts.example.net"
NAME = "a1234567." + ZONE
DIGEST = "a" * 64
USER = "customer"


class NeutralSiteReceiptTests(SimpleTestCase):
    def setUp(self) -> None:
        self.server = SimpleNamespace(hostname="node.example.net", node_deployment=object())
        self.runner = Mock()
        self.enterContext(patch("apps.infrastructure.ansible_service.AnsibleService", return_value=self.runner))
        self.runner.run_playbook.side_effect = self.answer
        self.changes: dict[str, object] = {}
        self.success = True

    def answer(self, deployment, playbook, variables, **kwargs):
        self.variables = variables
        payload = {
            "version": 1,
            "identity": variables["account_name_guard_id"],
            "action": variables["account_name_guard_action"],
            "zone": ZONE,
            "name": NAME,
            "config_sha256": DIGEST,
            "neutral": True,
            **self.changes,
        }
        receipt = base64.b64encode(json.dumps(payload).encode()).decode()
        return Ok(SimpleNamespace(success=self.success, stdout="NEUTRAL_RESULT=" + receipt))

    def test_fresh_proof_binds_the_zone_name_and_enrolled_node_transport(self) -> None:
        result = node.ensure_account_name_neutral(self.server, zone=ZONE, name=NAME, customer_user=USER)
        self.assertEqual(result.unwrap(), DIGEST)
        call = self.runner.run_playbook.call_args
        self.assertIs(call.args[0], self.server.node_deployment)
        self.assertEqual(call.args[1], "virtualmin_account_name_neutral.yml")
        self.assertEqual(self.variables["account_name_zone"], ZONE)
        self.assertEqual(self.variables["account_name_fqdn"], NAME)
        self.assertEqual(self.variables["customer_user"], USER)
        self.assertEqual(self.variables["account_name_guard_action"], "ensure")
        self.assertTrue(self.variables["account_name_guard_id"])
        self.assertGreater(call.kwargs["timeout_seconds"], 0)
        first = self.variables["account_name_guard_id"]
        node.ensure_account_name_neutral(self.server, zone=ZONE, name=NAME, customer_user=USER).unwrap()
        self.assertNotEqual(self.variables["account_name_guard_id"], first, "a cached receipt is not fresh proof")

    def test_foreign_or_incomplete_proof_never_makes_a_name_ready(self) -> None:
        for changes in (
            {"version": True},
            {"identity": "another-operation"},
            {"action": "retire"},
            {"zone": "another.example.net"},
            {"name": "b1234567." + ZONE},
            {"config_sha256": ""},
            {"config_sha256": "z" * 64},
            {"neutral": False},
            {"neutral": 1},
        ):
            with self.subTest(changes=changes):
                self.changes = changes
                result = node.ensure_account_name_neutral(self.server, zone=ZONE, name=NAME, customer_user=USER)
                self.assertTrue(result.is_err())
                self.assertEqual(retriability_of(result), Retriability.UNKNOWN)

    def test_failed_or_ambiguous_execution_cannot_reuse_a_valid_receipt(self) -> None:
        self.success = False
        self.assertTrue(
            node.ensure_account_name_neutral(self.server, zone=ZONE, name=NAME, customer_user=USER).is_err()
        )
        for result in (
            Err("transport interrupted"),
            Ok(SimpleNamespace(success=True, stdout="")),
            Ok(SimpleNamespace(success=True, stdout="NEUTRAL_RESULT=not-base64")),
            Ok(SimpleNamespace(success=True, stdout="x" * 65537)),
        ):
            with self.subTest(result=result):
                self.runner.run_playbook.side_effect = None
                self.runner.run_playbook.return_value = result
                self.assertTrue(
                    node.ensure_account_name_neutral(self.server, zone=ZONE, name=NAME, customer_user=USER).is_err()
                )

    def test_invalid_names_and_unmanaged_nodes_stop_before_any_dispatch(self) -> None:
        for zone, name in (
            ("example.net\nInclude /tmp/other", NAME),
            ("accounts..example.net", NAME),
            (ZONE, "other.example.net"),
            (ZONE, "notopaque." + ZONE),
            (ZONE, ZONE),
        ):
            with self.subTest(zone=zone, name=name):
                result = node.ensure_account_name_neutral(self.server, zone=zone, name=name, customer_user=USER)
                self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)
                self.runner.run_playbook.assert_not_called()
        self.server.node_deployment = None
        result = node.ensure_account_name_neutral(self.server, zone=ZONE, name=NAME, customer_user=USER)
        self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)
        self.runner.run_playbook.assert_not_called()

    def test_certificate_install_requires_the_exact_freshly_served_leaf_fingerprint(self) -> None:
        for fingerprint in (None, "b" * 64):
            with self.subTest(fingerprint=fingerprint):
                self.changes = {"certificate_sha256": fingerprint}
                result = node.ensure_account_name_neutral(
                    self.server, zone=ZONE, name=NAME, customer_user=USER, expected_certificate_sha256=DIGEST
                )
                self.assertTrue(result.is_err())
        self.changes = {"certificate_sha256": DIGEST}
        self.assertEqual(
            node.ensure_account_name_neutral(
                self.server, zone=ZONE, name=NAME, customer_user=USER, expected_certificate_sha256=DIGEST
            ).unwrap(),
            DIGEST,
        )

    def test_only_a_complete_bound_leaf_mismatch_is_a_definite_certificate_mismatch(self) -> None:
        self.changes = {"certificate_sha256": "b" * 64}
        result = node.ensure_account_name_neutral(
            self.server, zone=ZONE, name=NAME, customer_user=USER, expected_certificate_sha256=DIGEST
        )
        self.assertEqual(result.unwrap_err(), "account_name_certificate_mismatch")
        self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)
        for changes in (
            {"certificate_sha256": None},
            {"certificate_sha256": "malformed"},
            {"certificate_sha256": "b" * 64, "identity": "foreign"},
            {"certificate_sha256": "b" * 64, "neutral": False},
        ):
            with self.subTest(changes=changes):
                self.changes = changes
                result = node.ensure_account_name_neutral(
                    self.server, zone=ZONE, name=NAME, customer_user=USER, expected_certificate_sha256=DIGEST
                )
                self.assertEqual(retriability_of(result), Retriability.UNKNOWN)
                self.assertNotEqual(result.unwrap_err(), "account_name_certificate_mismatch")

    def test_only_retirement_can_use_absence_proof_without_a_remaining_account_owner(self) -> None:
        result = node.retire_account_name_neutral(self.server, zone=ZONE, name=NAME, customer_user="")
        self.assertEqual(result.unwrap(), DIGEST)
        self.assertEqual(self.variables["account_name_guard_action"], "retire")
        self.assertEqual(self.variables["customer_user"], "")
        self.runner.reset_mock()
        result = node.ensure_account_name_neutral(self.server, zone=ZONE, name=NAME, customer_user="")
        self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)
        self.runner.run_playbook.assert_not_called()

    def test_privacy_preparation_is_distinct_from_strict_certificate_readiness(self) -> None:
        result = node.prepare_account_name_neutral(self.server, zone=ZONE, name=NAME, customer_user=USER)
        self.assertEqual(result.unwrap(), DIGEST)
        self.assertEqual(self.variables["account_name_guard_action"], "prepare")
        self.changes = {"action": "prepare", "certificate_sha256": DIGEST}
        result = node.ensure_account_name_neutral(
            self.server, zone=ZONE, name=NAME, customer_user=USER, expected_certificate_sha256=DIGEST
        )
        self.assertTrue(result.is_err(), "a privacy/bootstrap receipt cannot record an installed certificate")


class NeutralPlaybookDispatchTests(SimpleTestCase):
    def test_fixed_guard_playbook_reaches_enrolled_key_lookup_and_never_replaces_the_key(self) -> None:
        service = object.__new__(AnsibleService)
        service.timeout = 1800
        service._ssh_manager = Mock()
        service._ssh_manager.get_private_key_file.return_value = Err("enrolled key unavailable")
        deployment = SimpleNamespace(ipv4_address="192.0.2.15")
        result = service.run_playbook(deployment, "virtualmin_account_name_neutral.yml")
        self.assertEqual(
            result.unwrap_err(),
            "Could not retrieve the node's enrolled authentication key; refusing key replacement",
        )
        service._ssh_manager.get_private_key_file.assert_called_once_with(
            deployment, reason="Ansible playbook: virtualmin_account_name_neutral.yml"
        )
        service._ssh_manager.generate_key_pair.assert_not_called()
