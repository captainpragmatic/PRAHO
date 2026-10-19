"""Static contract of the account-name certificate install playbook (ADR-0061 P1.10).

The behaviour on a node is proven in the Virtualmin lab; these tests keep the playbook from drifting
into leaking the key (a command line, a log, a disk file, a leftover) without needing the lab.
"""

from __future__ import annotations

from typing import Any

from django.test import SimpleTestCase

from apps.infrastructure.ansible_service import AnsibleService
from apps.provisioning.account_name_certificates import INSTALL_PLAYBOOK
from tests.provisioning.test_virtualmin_transfer_playbooks import PLAYBOOKS, command_text, load

PLAYBOOK = "virtualmin_install_account_cert.yml"
SECRET_VARS = ("private_key_pem", "certificate_pem", "chain_pem")


def walk(tasks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every task of a list, with the tasks of its blocks (block, rescue, always) flattened in."""
    found: list[dict[str, Any]] = []
    for task in tasks:
        found.append(task)
        for section in ("block", "rescue", "always"):
            found += walk(task.get(section, []))
    return found


def all_tasks() -> list[dict[str, Any]]:
    return walk([task for play in load(PLAYBOOK) for task in play.get("tasks", [])])


def titled(title: str) -> dict[str, Any]:
    matches = [task for task in all_tasks() if task.get("name") == title]
    assert len(matches) == 1, f"{title!r}: {len(matches)} matches"
    return matches[0]


class AccountCertPlaybookTests(SimpleTestCase):
    def test_the_playbook_exists_and_is_the_one_the_issuer_runs(self) -> None:
        self.assertEqual(INSTALL_PLAYBOOK, PLAYBOOK)
        self.assertTrue((PLAYBOOKS / PLAYBOOK).is_file())
        self.assertIn(PLAYBOOK, AnsibleService.ALLOWED_PLAYBOOKS)

    def test_every_task_that_touches_pem_variables_is_no_log(self) -> None:
        def reads_pem(task: dict[str, Any]) -> bool:
            # Whether a task uses a PEM's content; asking only for its length reveals nothing.
            text = str({k: v for k, v in task.items() if k != "block"}).replace("chain_pem | length", "")
            return any(var in text for var in SECRET_VARS)

        touching = [task for task in all_tasks() if reads_pem(task)]
        self.assertGreaterEqual(len(touching), 4)
        for task in touching:
            with self.subTest(task=task.get("name")):
                self.assertIs(task.get("no_log"), True)

    def test_no_pem_reaches_a_command_line(self) -> None:
        commands = [command_text(task) for task in all_tasks() if command_text(task).strip()]
        self.assertTrue(commands)
        for command in commands:
            for var in SECRET_VARS:
                self.assertNotIn(var, command)

    def test_the_files_live_in_a_private_directory_on_a_memory_filesystem(self) -> None:
        directory = titled("Create a root-only temporary directory")["ansible.builtin.tempfile"]
        self.assertEqual(directory["state"], "directory")
        self.assertEqual(directory["path"], "/run")
        text = (PLAYBOOKS / PLAYBOOK).read_text()
        self.assertNotIn("/tmp", text)  # noqa: S108  # Asserting the node path is NOT /tmp
        checks = titled("Require a private temporary directory")["ansible.builtin.assert"]["that"]
        self.assertIn("cert_dir_stat.stat.mode == '0700'", checks)
        self.assertIn("cert_dir_stat.stat.uid == 0", checks)

    def test_each_pem_is_written_root_only_after_the_directory_is_proven_private(self) -> None:
        titles = [task.get("name") for task in all_tasks()]
        for title in ("Write the private key", "Write the certificate", "Write the intermediate chain"):
            with self.subTest(title=title):
                copy = titled(title)["ansible.builtin.copy"]
                self.assertEqual((copy["owner"], copy["group"], copy["mode"]), ("root", "root", "0600"))
                self.assertLess(titles.index("Require a private temporary directory"), titles.index(title))

    def test_install_cert_gets_paths_not_pem_and_runs_after_the_files_exist(self) -> None:
        install = titled("Install the certificate into the account name's virtual server")
        argv = install["ansible.builtin.command"]["argv"]
        for part in (
            "virtualmin",
            "install-cert",
            "--domain",
            "account_name",
            "--cert",
            "--key",
            "cert.pem",
            "key.pem",
        ):
            self.assertIn(part, argv)
        titles = [task.get("name") for task in all_tasks()]
        self.assertLess(titles.index("Write the private key"), titles.index(install["name"]))
        self.assertLess(titles.index("Write the certificate"), titles.index(install["name"]))
        self.assertNotIn("ignore_errors", install)
        self.assertNotIn("failed_when", install)

    def test_the_files_are_deleted_in_the_same_play_even_when_the_install_fails(self) -> None:
        blocks = [task for task in all_tasks() if "block" in task]
        self.assertEqual(len(blocks), 1)
        block = blocks[0]
        cleanup = block["always"][0]["ansible.builtin.file"]
        self.assertEqual(cleanup["state"], "absent")
        self.assertEqual(cleanup["path"], "{{ cert_dir.path }}")
        # The install is inside the block that the cleanup guards.
        self.assertIn(
            "Install the certificate into the account name's virtual server", [t.get("name") for t in block["block"]]
        )
        for task in all_tasks():
            self.assertNotIn(task.get("ignore_errors"), (True, "yes"))

    def test_the_account_name_is_validated_before_anything_is_written(self) -> None:
        validate = titled("Validate single-host certificate inputs")
        self.assertIs(validate["no_log"], True)
        checks = " ".join(validate["ansible.builtin.assert"]["that"])
        self.assertIn("account_name is match(", checks)
        self.assertIn("BEGIN CERTIFICATE", checks)
        self.assertIn("PRIVATE KEY", checks)
        titles = [task.get("name") for task in all_tasks()]
        self.assertEqual(titles.index(validate["name"]), 0)
