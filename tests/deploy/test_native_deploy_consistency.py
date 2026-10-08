"""The native deploy's supporting pieces must agree with each other.

Three drifts surfaced once the Docker role was retired (#633):

- `playbooks/backup.yml` targeted a host group only the deleted two-server inventory defined, and its
  download globbed the controller's disk (`with_fileglob`) for `.sql.gz` files while the native script
  writes `.dump` files on the server, so `-e fetch_backup=true` fetched nothing and reported success.
  `-e` also passes the flag as a string, so `fetch_backup=false` counted as true.
- `requirements.yml` lacked `ansible.posix`, which the native role's `synchronize` needs, while the guide
  installed collections from a list of its own.
- Terraform provisioned Ubuntu 22.04 by default, which the native playbook refuses.

A database dump must also never be committable from the checkout or copied to a server with the code.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ANSIBLE = PROJECT_ROOT / "deploy/ansible"
BACKUP_PLAYBOOK = ANSIBLE / "playbooks/backup.yml"
NATIVE_PLAYBOOK = ANSIBLE / "playbooks/native-single-server.yml"
NATIVE_TASKS = ANSIBLE / "roles/praho-native/tasks/main.yml"
NATIVE_BACKUP_SCRIPT = ANSIBLE / "roles/praho-native/templates/backup-native.sh.j2"
REQUIREMENTS = ANSIBLE / "requirements.yml"
GUIDE = PROJECT_ROOT / "docs/deployment/DEPLOYMENT.md"
# Modules outside ansible.builtin that the playbooks and roles use.
EXTERNAL_SHORT_NAME = re.compile(r"^\s*-?\s*(synchronize|ufw|timezone|postgresql_\w+):", re.MULTILINE)
QUALIFIED_MODULE = re.compile(r"^\s*-?\s*([a-z_]+\.[a-z_]+)\.[a-z_]+:", re.MULTILINE)


def _flat_tasks(tasks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every task, with a block's own `when` carried onto the tasks inside it."""
    flat: list[dict[str, Any]] = []
    for task in tasks:
        if "block" in task:
            flat.extend({**inner, "block_when": task.get("when")} for inner in _flat_tasks(task["block"]))
        else:
            flat.append(task)
    return flat


def _backup_tasks() -> list[dict[str, Any]]:
    return _flat_tasks(yaml.safe_load(BACKUP_PLAYBOOK.read_text())[0]["tasks"])


def _version(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in text.split("."))


class TestBackupPlaybook:
    @pytest.mark.integration
    def test_it_targets_a_group_every_inventory_defines(self) -> None:
        play = yaml.safe_load(BACKUP_PLAYBOOK.read_text())[0]
        groups = {group.strip() for group in str(play["hosts"]).split(",")}
        for inventory in ("native-single-server.yml", "dev.yml"):
            children = yaml.safe_load((ANSIBLE / "inventory" / inventory).read_text())["all"]["children"]
            assert groups <= set(children), (inventory, sorted(groups))

    @pytest.mark.integration
    def test_the_download_reads_the_server_not_the_controller(self) -> None:
        # with_fileglob expands on the machine running Ansible, never on the server.
        assert "with_fileglob" not in BACKUP_PLAYBOOK.read_text()

    @pytest.mark.integration
    def test_the_flag_is_read_as_a_boolean(self) -> None:
        conditions = [
            str(task.get("when") or task.get("block_when"))
            for task in _backup_tasks()
            if "fetch_backup" in str(task.get("when") or task.get("block_when") or "")
        ]
        assert conditions
        for condition in conditions:
            assert re.search(r"fetch_backup\s*\|\s*default\(false\)\s*\|\s*bool", condition), condition

    @pytest.mark.integration
    def test_it_fetches_the_file_this_run_reported(self) -> None:
        # The script prints this line only after a complete, non-empty dump. Picking the newest file
        # instead could take a cron run's dump while it is still being written.
        assert 'Backup created: ${BACKUP_FILE}"' in NATIVE_BACKUP_SCRIPT.read_text()
        playbook = BACKUP_PLAYBOOK.read_text()
        assert "Backup created: " in playbook
        assert "find:" not in playbook

    @pytest.mark.integration
    def test_the_download_is_private_and_outside_the_checkout(self) -> None:
        tasks = _backup_tasks()
        playbook = BACKUP_PLAYBOOK.read_text()
        assert "lookup('env', 'HOME')" in playbook
        (fetch,) = [task for task in tasks if "fetch" in task or "ansible.builtin.fetch" in task]
        # With become, fetch reads the whole dump into memory on both sides (slurp).
        assert fetch.get("become") is False
        modes = {str((task.get("file") or task.get("ansible.builtin.file") or {}).get("mode")) for task in tasks}
        assert {"0700", "0600"} <= modes, modes


class TestDumpsStayOutOfTheCheckout:
    @pytest.mark.integration
    @pytest.mark.parametrize(
        "path",
        [
            "backups/praho_backup_20261008_020000.dump",
            "backups/praho_backup_20261008_020000.sql.gz",
            "deploy/ansible/playbooks/backups/praho_backup_20261008_020000.dump",
        ],
    )
    def test_git_ignores_a_database_dump(self, tmp_path: Path, path: str) -> None:
        # Only the repository's own rules: a developer's global excludes must not hide a missing one.
        shutil.copy(PROJECT_ROOT / ".gitignore", tmp_path / ".gitignore")
        subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)  # noqa: S607
        result = subprocess.run(  # noqa: S603
            ["git", "-c", "core.excludesFile=/dev/null", "check-ignore", "-q", path],  # noqa: S607
            cwd=tmp_path,
            check=False,
        )
        assert result.returncode == 0, path

    @pytest.mark.integration
    def test_the_native_rsync_leaves_dumps_behind(self) -> None:
        (task,) = [t for t in yaml.safe_load(NATIVE_TASKS.read_text()) if t.get("name") == "Deploy code via rsync"]
        module = next(value for key, value in task.items() if key.endswith("synchronize"))
        # Anchored: only the checkout's own backups/ (deploy/scripts/backup.sh), never a source directory.
        assert {"--exclude=/backups/", "--exclude=praho_backup_*"} <= set(module["rsync_opts"])


class TestAnsibleCollections:
    @pytest.mark.integration
    def test_modules_outside_the_builtin_set_are_fully_qualified(self) -> None:
        offenders = [
            f"{path.relative_to(ANSIBLE)}:{number}"
            for path in sorted(ANSIBLE.rglob("*.yml"))
            for number, line in enumerate(path.read_text().splitlines(), 1)
            if EXTERNAL_SHORT_NAME.match(line)
        ]
        assert offenders == []

    @pytest.mark.integration
    def test_requirements_list_every_collection_used(self) -> None:
        used = {
            match.group(1)
            for path in ANSIBLE.rglob("*.yml")
            if path != REQUIREMENTS
            for match in QUALIFIED_MODULE.finditer(path.read_text())
        } - {"ansible.builtin"}
        listed = {collection["name"] for collection in yaml.safe_load(REQUIREMENTS.read_text())["collections"]}
        assert used
        assert sorted(used - listed) == []

    @pytest.mark.integration
    def test_the_guide_installs_from_the_requirements_file(self) -> None:
        guide = GUIDE.read_text()
        assert "ansible-galaxy collection install -r deploy/ansible/requirements.yml" in guide
        assert not re.search(r"ansible-galaxy collection install (?!-r )", guide)


class TestUbuntuVersion:
    @pytest.mark.integration
    def test_terraform_provisions_what_the_native_playbook_accepts(self) -> None:
        match = re.search(r"version\('(\d+\.\d+)', '>='\)", NATIVE_PLAYBOOK.read_text())
        assert match
        minimum = _version(match.group(1))
        variables = (PROJECT_ROOT / "deploy/terraform/variables.tf").read_text()
        default = re.search(r'variable "server_image".*?default\s*=\s*"ubuntu-(\d+\.\d+)"', variables, re.DOTALL)
        example = re.search(
            r'^server_image\s*=\s*"ubuntu-(\d+\.\d+)"',
            (PROJECT_ROOT / "deploy/terraform/terraform.tfvars.example").read_text(),
            re.MULTILINE,
        )
        assert default and example
        assert _version(default.group(1)) >= minimum, default.group(1)
        assert _version(example.group(1)) >= minimum, example.group(1)

    @pytest.mark.integration
    def test_the_readme_states_the_same_minimum(self) -> None:
        match = re.search(r"version\('(\d+\.\d+)', '>='\)", NATIVE_PLAYBOOK.read_text())
        assert match
        assert f"Ubuntu {match.group(1)}+" in (PROJECT_ROOT / "README.md").read_text()
