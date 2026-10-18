"""Linking an account name's web root (ADR-0061 P1.15).

The playbook runs every filesystem step as the customer, never as root, and refuses a path that a
symlink or another owner could redirect. The node-side behaviour is proven in the Virtualmin lab
(docs/domain/virtualmin-account-subserver-contract.md, "P1.15"); these tests hold the playbook's
shape and the wrapper's reading of its outcome.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase

from apps.common.types import Err, Ok, Result, Retriability, retriability_of
from apps.infrastructure.ansible_service import AnsibleResult, AnsibleService
from apps.provisioning.account_name_node import LINK_PLAYBOOK, link_account_name_web_root
from tests.provisioning.test_virtualmin_transfer_playbooks import PLAYBOOKS, command_text, task_named

HOME = "/home/customer/domains/h7k3p2q9.acct.example.net"
RECAP = "PLAY RECAP ****\nnode : ok=2    changed={changed}    unreachable=0    failed={failed}\n"


def _result(stdout: str, success: bool = True) -> AnsibleResult:
    return AnsibleResult(success=success, playbook=LINK_PLAYBOOK, stdout=stdout, stderr="", return_code=0)


class LinkPlaybookShapeTests(SimpleTestCase):
    def test_the_playbook_is_allowlisted(self) -> None:
        self.assertIn(LINK_PLAYBOOK, AnsibleService.ALLOWED_PLAYBOOKS)

    def test_the_link_runs_as_the_customer_with_the_script_on_stdin(self) -> None:
        task = task_named(LINK_PLAYBOOK, "Link the web root as the customer")
        self.assertTrue(command_text(task).startswith("runuser -u {{ customer_user }} -- /bin/bash -s --"))
        self.assertIn("files/praho-account-name-link.sh", str(task["ansible.builtin.command"]["stdin"]))
        self.assertNotIn("become", task)

    def test_the_inputs_are_checked_before_anything_runs(self) -> None:
        checks = " ".join(
            task_named(LINK_PLAYBOOK, "Validate single-host link inputs")["ansible.builtin.assert"]["that"]
        )
        for fragment in ("ansible_play_hosts_all | length == 1", "customer_user is match", "startswith('/home/'"):
            self.assertIn(fragment, checks)

    def test_the_script_checks_every_directory_and_never_follows_a_link(self) -> None:
        script = (PLAYBOOKS / "files" / "praho-account-name-link.sh").read_text()
        for fragment in ("set -euo pipefail", "! -L $1", "stat -c %u", "not_running_as_the_customer", "mv -T"):
            self.assertIn(fragment, script)


class LinkWrapperTests(SimpleTestCase):
    server = SimpleNamespace(hostname="node1.example.com", node_deployment=object())

    def _link(self, result: object) -> Result[bool, str]:
        with (
            patch.object(AnsibleService, "__init__", lambda self, *a, **k: None),
            patch.object(AnsibleService, "run_playbook", return_value=result) as run,
        ):
            outcome = link_account_name_web_root(self.server, home=HOME, customer_user="customer")  # type: ignore[arg-type]  # a stand-in
        if run.called:
            self.assertEqual(run.call_args.args[2], {"account_name_home": HOME, "customer_user": "customer"})
        return outcome

    def test_a_new_link_and_an_unchanged_one_are_both_success(self) -> None:
        self.assertEqual(self._link(Ok(_result(RECAP.format(changed=1, failed=0)))), Ok(True))
        self.assertEqual(self._link(Ok(_result(RECAP.format(changed=0, failed=0)))), Ok(False))

    def test_a_refusal_is_definite_and_changes_nothing(self) -> None:
        fatal = 'fatal: [node]: FAILED! => {"rc": 3, "stdout": "LINK=refused:unsafe_path"}\n'
        outcome = self._link(Ok(_result(fatal + RECAP.format(changed=0, failed=1), success=False)))
        self.assertIsInstance(outcome, Err)
        self.assertIn("unsafe_path", outcome.unwrap_err())
        self.assertIs(retriability_of(outcome), Retriability.NOT_RETRIABLE)

    def test_inputs_the_playbook_refuses_are_a_definite_refusal(self) -> None:
        for fatal in (
            "fatal: [node]: FAILED! => \n    msg: Assertion failed\n",  # ansible-core 2.20, recorded in the lab
            'fatal: [node]: FAILED! => {"changed": false, "msg": "Assertion failed"}\n',
        ):
            with self.subTest(fatal=fatal):
                outcome = self._link(Ok(_result(fatal + RECAP.format(changed=0, failed=1), success=False)))
                self.assertIs(retriability_of(outcome), Retriability.NOT_RETRIABLE)

    def test_anything_else_is_ambiguous_never_success(self) -> None:
        for result in (
            Err("ssh timed out"),
            Ok(_result("fatal: [node]: UNREACHABLE!\n" + RECAP.format(changed=0, failed=1), success=False)),
            Ok(_result("no recap at all")),
        ):
            with self.subTest(result=str(result)[:40]):
                outcome = self._link(result)
                self.assertIsInstance(outcome, Err)
                self.assertIs(retriability_of(outcome), Retriability.UNKNOWN)

    def test_a_server_without_a_managed_node_is_refused(self) -> None:
        outcome = link_account_name_web_root(
            SimpleNamespace(hostname="manual.example.com", node_deployment=None),  # type: ignore[arg-type]  # a stand-in
            home=HOME,
            customer_user="customer",
        )
        self.assertIs(retriability_of(outcome), Retriability.NOT_RETRIABLE)
