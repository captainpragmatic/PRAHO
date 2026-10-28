"""Archives move between PRAHO and a node through a private staging directory.

Virtualmin writes backup archives and their .dom/.info sidecars 0644 whatever
the destination (observed against 8.3.0 in deploy/virtualmin-lab), and the
.dom sidecar holds the domain's database passwords. These tests keep the
transfer playbooks on a root-owned 0700 directory and the sidecars removed,
without needing the lab. The helpers are shared with the node playbook tests.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

import yaml
from django.conf import settings
from django.test import SimpleTestCase

from apps.provisioning.virtualmin_backup_service import REMOTE_ARCHIVE_DIR

PLAYBOOKS = Path(settings.BASE_DIR) / "infrastructure" / "ansible" / "playbooks"
TRANSFER_PLAYBOOKS = (
    "virtualmin_backup_fetch.yml",
    "virtualmin_backup_push.yml",
    "virtualmin_remote_cleanup.yml",
    "virtualmin_migrate_fetch.yml",
    "virtualmin_migrate_push.yml",
)


def load(name: str) -> list[dict[str, Any]]:
    plays = yaml.safe_load((PLAYBOOKS / name).read_text())
    assert isinstance(plays, list)
    return plays


def tasks(name: str) -> list[dict[str, Any]]:
    return [task for play in load(name) for task in play.get("tasks", [])]


def command_text(task: dict[str, Any]) -> str:
    """The command line a command/shell task runs, as one string."""
    for module in ("ansible.builtin.command", "ansible.builtin.shell", "command", "shell"):
        spec = task.get(module)
        if isinstance(spec, str):
            return spec
        if isinstance(spec, dict):
            return " ".join(str(arg) for arg in spec.get("argv", [])) + " " + str(spec.get("cmd", ""))
    return ""


def task_named(name: str, title: str) -> dict[str, Any]:
    matches = [task for task in tasks(name) if task.get("name") == title]
    assert len(matches) == 1, f"{title!r} in {name}: {len(matches)} matches"
    return matches[0]


class TransferPlaybookTests(SimpleTestCase):
    """Archives move through a root-owned 0700 directory, never /tmp."""

    def test_cleanup_accepts_only_backup_names_and_canonical_migration_uuid_archives(self) -> None:
        checks = task_named("virtualmin_remote_cleanup.yml", "Validate single-host cleanup inputs")["ansible.builtin.assert"]["that"]
        expression = next(check for check in checks if check.startswith("archive_name is match("))
        pattern = ast.literal_eval(expression.removeprefix("archive_name is match(").removesuffix(")"))
        valid = ("virtualmin_backup_" + "a" * 32 + ".tar.gz", "migration_11111111-2222-4333-8444-555555555555.tar.gz")
        invalid = ("../migration_11111111-2222-4333-8444-555555555555.tar.gz", "migration_" + "-" * 36 + ".tar.gz",
                   valid[1] + ".info", "migration_*.tar.gz", "customer.tar.gz")
        for name in valid:
            self.assertRegex(name, pattern)
        for name in invalid:
            self.assertIsNone(re.fullmatch(pattern, name))

    def test_every_transfer_playbook_uses_the_private_directory(self) -> None:
        for name in TRANSFER_PLAYBOOKS:
            with self.subTest(playbook=name):
                self.assertEqual(load(name)[0]["vars"]["remote_archive_dir"], REMOTE_ARCHIVE_DIR)
                self.assertNotIn("/tmp/", (PLAYBOOKS / name).read_text())  # noqa: S108  # Asserting the node path is NOT /tmp
        self.assertFalse(REMOTE_ARCHIVE_DIR.startswith("/tmp"))  # noqa: S108  # Asserting the node path is NOT /tmp

    def test_fetches_refuse_a_staging_directory_others_can_read(self) -> None:
        for name in ("virtualmin_backup_fetch.yml", "virtualmin_migrate_fetch.yml"):
            with self.subTest(playbook=name):
                checks = task_named(name, "Require a private staging directory")["ansible.builtin.assert"]["that"]
                self.assertIn("staging_dir.stat.mode == '0700'", checks)
                self.assertIn("staging_dir.stat.uid == 0", checks)
                titles = [task.get("name") for task in tasks(name)]
                self.assertLess(
                    titles.index("Require a private staging directory"),
                    titles.index("Fetch archive directly to the private controller spool"),
                )

    def test_pushes_create_the_directory_private(self) -> None:
        for name in ("virtualmin_backup_push.yml", "virtualmin_migrate_push.yml"):
            with self.subTest(playbook=name):
                ensure = task_named(name, "Ensure the private staging directory")["ansible.builtin.file"]
                self.assertEqual((ensure["mode"], ensure["owner"], ensure["state"]), ("0700", "root", "directory"))

    def test_sidecars_are_removed_after_fetch_and_on_cleanup(self) -> None:
        cases = {
            "virtualmin_backup_fetch.yml": (
                "Remove the remote temporary archive and its sidecars",
                ["", ".dom", ".info"],
            ),
            "virtualmin_remote_cleanup.yml": (
                "Remove the remote temporary archive and its sidecars",
                ["", ".dom", ".info"],
            ),
            "virtualmin_migrate_fetch.yml": ("Remove the archive's sidecars", [".dom", ".info"]),
        }
        for name, (title, suffixes) in cases.items():
            with self.subTest(playbook=name):
                task = task_named(name, title)
                self.assertEqual(task["loop"], suffixes)
                self.assertEqual(task["ansible.builtin.file"]["state"], "absent")
                self.assertTrue(task["ansible.builtin.file"]["path"].endswith("{{ item }}"))
