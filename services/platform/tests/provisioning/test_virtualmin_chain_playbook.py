"""The node-side chain step: allowlisting, shape of the playbook and script, result parsing.

The behaviour of the script itself (locking, fingerprints, cancel markers, the
backup flags) is proved against a real node by `make test-virtualmin-lab`; these
tests pin what can be pinned without one.
"""

from __future__ import annotations

import base64
import json
import re
import subprocess
from pathlib import Path
from typing import Any

from django.conf import settings
from django.test import SimpleTestCase

from apps.common.types import Retriability, retriability_of
from apps.infrastructure.ansible_service import AnsibleService
from apps.provisioning import virtualmin_backup_service as backup_service
from apps.provisioning import virtualmin_chain
from tests.provisioning.test_virtualmin_transfer_playbooks import PLAYBOOKS, load, task_named, tasks

PLAYBOOK = "virtualmin_chain_backup.yml"
SCRIPT = Path(settings.BASE_DIR) / "infrastructure" / "ansible" / "playbooks" / "files" / "praho-chain-backup.sh"

TOKEN = "0b5f1c7e-3c1d-4f0a-9a52-6d1b3a8c2e44"
SNAP_A = "a" * 64 + ":7555"
SNAP_B = "b" * 64 + ":7542"


def result_line(**overrides: Any) -> str:
    payload: dict[str, Any] = {
        "outcome": "ok",
        "reason": "completed",
        "ran": True,
        "mode": "base",
        "domain_id": "17919754553303",
        "token": TOKEN,
        "archive": "virtualmin_backup_" + "c" * 32 + ".tar.gz",
        "fp_before": SNAP_B,
        "fp_after": SNAP_A,
        "backup_rc": 0,
        "sha256": "d" * 64,
        "size": 238717,
        "detail": "",
    }
    payload.update(overrides)
    return "CHAIN_RESULT=" + base64.b64encode(json.dumps(payload).encode()).decode()


class ChainPlaybookShapeTests(SimpleTestCase):
    def test_the_playbook_is_allowlisted_and_exists(self) -> None:
        self.assertIn(PLAYBOOK, AnsibleService.ALLOWED_PLAYBOOKS)
        self.assertTrue((PLAYBOOKS / PLAYBOOK).is_file())
        self.assertTrue(SCRIPT.is_file())

    def test_it_stages_in_the_private_directory_and_never_ignores_errors(self) -> None:
        text = (PLAYBOOKS / PLAYBOOK).read_text()
        self.assertEqual(load(PLAYBOOK)[0]["vars"]["remote_archive_dir"], backup_service.REMOTE_ARCHIVE_DIR)
        self.assertNotIn("/tmp/", text)  # noqa: S108  # Asserting the node path is NOT /tmp
        for forbidden in ("failed_when", "ignore_errors", "ansible.builtin.shell"):
            self.assertNotIn(forbidden, text)
        directory = task_named(PLAYBOOK, "Ensure the private staging directory")["ansible.builtin.file"]
        self.assertEqual((directory["owner"], directory["mode"]), ("root", "0700"))

    def test_inputs_are_validated_and_reach_the_script_only_as_environment(self) -> None:
        checks = " ".join(task_named(PLAYBOOK, "Validate chain step inputs")["ansible.builtin.assert"]["that"])
        for pattern in ("chain_domain_id is match('^[0-9]{1,30}$')", "chain_token is match(", "virtualmin_backup_"):
            self.assertIn(pattern, checks)
        step = task_named(PLAYBOOK, "Run the step under the per-domain lock")
        self.assertEqual(step["ansible.builtin.script"], {"cmd": "files/praho-chain-backup.sh"})
        self.assertEqual(
            set(step["environment"]),
            {
                "PRAHO_CHAIN_ACTION",
                "PRAHO_CHAIN_MODE",
                "PRAHO_DOMAIN",
                "PRAHO_DOMAIN_ID",
                "PRAHO_CHAIN_TOKEN",
                "PRAHO_ARCHIVE",
                "PRAHO_EXPECTED_FP",
                "PRAHO_LOCK_WAIT",
                "PRAHO_STAGING_DIR",
            },
        )
        titles = [task.get("name") for task in tasks(PLAYBOOK)]
        self.assertLess(titles.index("Validate chain step inputs"), titles.index("Run the step under the per-domain lock"))

    def test_the_script_parses_and_orders_its_steps_under_the_lock(self) -> None:
        parsed = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True, check=False)  # noqa: S603, S607  # Fixed argv
        self.assertEqual(parsed.returncode, 0, parsed.stderr)
        text = SCRIPT.read_text()
        self.assertIn("set -euo pipefail", text)

        def at(needle: str) -> int:
            self.assertEqual(text.count(needle), 1, needle)
            return text.index(needle)

        order = [
            at('flock -w "$lock_wait" 9'),
            at('if [[ -e $cancel_marker ]]'),
            at("fp_before=$(fingerprint)"),
            at("emit refused fingerprint_mismatch"),
            at('virtualmin backup-domain "${backup_args[@]}"'),
            at("fp_after=$(fingerprint)"),
        ]
        self.assertEqual(order, sorted(order))

    def test_only_a_differential_sends_a_flag_and_a_base_never_sends_no_differential(self) -> None:
        text = SCRIPT.read_text()
        self.assertEqual(len(re.findall(r"--differential", text)), 1)
        self.assertNotIn("--no-differential", text)
        self.assertIn("backup_args+=(--differential)", text)


class ChainInputPatternsAgreeTests(SimpleTestCase):
    """The playbook, the node script and the Python pre-dispatch check accept exactly the same inputs."""

    def playbook_assertions(self) -> str:
        return " ".join(task_named(PLAYBOOK, "Validate chain step inputs")["ansible.builtin.assert"]["that"])

    def test_every_pattern_is_the_same_string_in_the_playbook_and_in_python(self) -> None:
        checks = self.playbook_assertions()
        for name, pattern in (
            ("chain_domain", virtualmin_chain.CHAIN_DOMAIN_PATTERN),
            ("chain_domain_id", virtualmin_chain.CHAIN_DOMAIN_ID_PATTERN),
            ("chain_token", virtualmin_chain.CHAIN_RUN_ID_PATTERN),
            ("chain_archive", virtualmin_chain.CHAIN_ARCHIVE_PATTERN),
            ("chain_expected_fp", virtualmin_chain.CHAIN_EXPECTED_FP_PATTERN),
        ):
            with self.subTest(name=name):
                self.assertIn(f"{name} is match('{pattern}')", checks)

    def test_every_pattern_is_the_same_string_in_the_node_script(self) -> None:
        text = SCRIPT.read_text()
        for name, pattern in (
            ("domain", virtualmin_chain.CHAIN_DOMAIN_PATTERN),
            ("domain_id", virtualmin_chain.CHAIN_DOMAIN_ID_PATTERN),
            ("token", virtualmin_chain.CHAIN_RUN_ID_PATTERN),
            ("archive", virtualmin_chain.CHAIN_ARCHIVE_PATTERN),
            ("expected_fp", virtualmin_chain.CHAIN_EXPECTED_FP_PATTERN),
        ):
            with self.subTest(name=name):
                self.assertIn(f"[[ ${name} =~ {pattern} ]]", text)

    def test_a_differential_cannot_expect_an_absent_snapshot_anywhere(self) -> None:
        self.assertNotIn("ABSENT", self.playbook_assertions())
        differential_check = next(line for line in SCRIPT.read_text().splitlines() if "expected_fp =~" in line)
        self.assertNotIn("ABSENT", differential_check)
        error = virtualmin_chain.chain_step_input_error(
            {
                "chain_action": "run",
                "chain_mode": "differential",
                "chain_domain": "example.com",
                "chain_domain_id": "17",
                "chain_token": TOKEN,
                "chain_archive": "virtualmin_backup_" + "c" * 32 + ".tar.gz",
                "chain_expected_fp": "ABSENT",
            }
        )
        self.assertIn("chain_expected_fp", str(error))


class ChainResultParsingTests(SimpleTestCase):
    def parse(self, stdout: str, **expect: str) -> Any:
        return backup_service.parse_chain_step_result(
            stdout, token=TOKEN, mode=expect.get("mode", "base"), domain_id="17919754553303"
        )

    def test_a_valid_result_round_trips(self) -> None:
        step = self.parse(f'ok: [node] => {{\n    "msg": "{result_line()}"\n}}').unwrap()
        self.assertEqual((step.outcome, step.ran, step.fp_before, step.fp_after), ("ok", True, SNAP_B, SNAP_A))
        self.assertEqual(step.sha256, "d" * 64)
        self.assertEqual(step.size, 238717)

    def test_the_same_line_printed_twice_is_one_result(self) -> None:
        line = result_line()
        self.assertTrue(self.parse(f"{line}\nmsg: {line}\n").is_ok())

    def test_missing_conflicting_or_malformed_results_are_uncertain(self) -> None:
        cases = {
            "none": "PLAY RECAP ok=3",
            "two": f"{result_line()}\n{result_line(size=1)}",
            "not-base64": "CHAIN_RESULT=!!!!",
            "not-json": "CHAIN_RESULT=" + base64.b64encode(b"nope").decode(),
            "wrong-token": result_line(token="1" * 8 + TOKEN[8:]),
            "wrong-mode": result_line(mode="differential"),
            "wrong-domain": result_line(domain_id="1"),
            "unknown-outcome": result_line(outcome="maybe"),
            "bad-fingerprint": result_line(fp_after="not-a-fingerprint"),
            "bad-sha": result_line(sha256="zz"),
        }
        for label, stdout in cases.items():
            with self.subTest(case=label):
                result = self.parse(stdout)
                self.assertTrue(result.is_err(), result)
                self.assertEqual(retriability_of(result), Retriability.UNKNOWN)

    def test_a_refusal_ran_nothing_and_a_failure_ran_the_backup(self) -> None:
        refused = self.parse(result_line(outcome="refused", reason="cancelled", ran=False, fp_after="")).unwrap()
        self.assertFalse(refused.ran)
        failed = self.parse(result_line(outcome="failed", reason="backup_command_failed", backup_rc=2)).unwrap()
        self.assertTrue(failed.ran)
        self.assertEqual(failed.backup_rc, 2)
