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

import os
import re
import shutil
import subprocess
import time
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


# Resolved rather than spelled "make", as in test_e2e_stack: the recipe is what is under test.
MAKE = shutil.which("make") or "make"


def _make(target: str, *args: str, path_prefix: Path | None = None) -> subprocess.CompletedProcess[str]:
    # This suite runs under make itself; its MAKEFLAGS would leak into the inner call. The recipes
    # resolve the env file through $(PWD), the environment variable, which `cwd` leaves alone.
    env = {key: value for key, value in os.environ.items() if key not in {"MAKELEVEL", "MAKEFLAGS", "MFLAGS"}}
    env["PWD"] = str(PROJECT_ROOT)
    if path_prefix:
        env["PATH"] = f"{path_prefix}{os.pathsep}{env['PATH']}"
    return subprocess.run(  # noqa: S603 -- a fixed make target with fixed variables
        [MAKE, target, *args],
        cwd=PROJECT_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def _dry_run(target: str, *variables: str) -> str:
    result = _make(target, "-n", *variables)
    assert result.returncode == 0, result.stderr
    return result.stdout


class TestBackupMakeTarget:
    @pytest.mark.integration
    def test_fetch_true_asks_the_playbook_to_download(self) -> None:
        assert "-e fetch_backup=true" in _dry_run("ansible-backup", "ENV=staging", "FETCH=true")

    @pytest.mark.integration
    def test_without_fetch_it_only_backs_up(self) -> None:
        assert "fetch_backup" not in _dry_run("ansible-backup", "ENV=staging")

    @pytest.mark.integration
    def test_it_loads_the_environments_connection_settings(self) -> None:
        # The inventory reads PRAHO_SERVER_IP and the SSH settings from the environment; without the
        # file, Ansible connects to an empty host.
        assert "/.env.staging && set +a" in _dry_run("ansible-backup", "ENV=staging")


class TestSingleServerMakeTarget:
    # It ran the deploy playbook without the env file, so the inventory's host was empty. It now
    # runs deploy-staging or deploy-prod, and `make -n` follows that call into the sub-make.
    @pytest.mark.integration
    def test_it_deploys_through_the_environments_own_target(self) -> None:
        dry_run = _dry_run("ansible-single-server", "ENV=staging")
        assert "/.env.staging && set +a" in dry_run
        assert "-e env_file_path=" in dry_run
        assert "playbooks/native-single-server.yml" in dry_run

    @pytest.mark.integration
    def test_a_production_version_reaches_the_playbook(self) -> None:
        assert "-e cli_version=v9.9.9" in _dry_run("ansible-single-server", "ENV=prod", "VERSION=v9.9.9")


class TestNativeMakeTargets:
    @pytest.mark.integration
    @pytest.mark.parametrize("target", ["ansible-backup", "ansible-single-server"])
    @pytest.mark.parametrize("variables", [[], ["ENV=dev"]])
    def test_they_refuse_to_run_without_a_deployment_environment(
        self, tmp_path: Path, target: str, variables: list[str]
    ) -> None:
        marker = tmp_path / "ran"
        stub = tmp_path / "ansible-playbook"
        stub.write_text(f'#!/bin/sh\ntouch "{marker}"\n')
        stub.chmod(0o755)
        result = _make(target, *variables, path_prefix=tmp_path)
        assert result.returncode != 0
        assert not marker.exists()
        assert "ENV=staging|prod" in result.stdout + result.stderr

    @pytest.mark.integration
    def test_every_recipe_using_the_native_inventory_loads_an_env_file(self) -> None:
        recipes = re.findall(r"^([\w-]+):.*\n((?:\t.*\n)+)", (PROJECT_ROOT / "Makefile").read_text(), re.MULTILINE)
        users = {name: body for name, body in recipes if "inventory/native-single-server.yml" in body}
        assert users
        assert sorted(name for name, body in users.items() if r". $(PWD)/.env." not in body) == []


class TestNativeBackupScript:
    PG_DUMP_WRITES = '#!/bin/sh\nwhile [ "$#" -gt 0 ]; do [ "$1" = -f ] && echo dump > "$2"; shift; done\n'

    @staticmethod
    def _render(backups: Path) -> str:
        """The template with its placeholders filled; a new placeholder fails here, not silently."""
        values = {"backup_directory": str(backups), "backup_retention_days": "7"}

        def fill(match: re.Match[str]) -> str:
            expression = match.group(1)
            # Database name, user and credential: the stub pg_dump ignores them.
            return "praho" if expression.startswith("deployed_env.") else values[expression]

        return re.sub(r"\{\{\s*(.+?)\s*\}\}", fill, NATIVE_BACKUP_SCRIPT.read_text())

    def _script(self, tmp_path: Path, pg_dump: str) -> tuple[Path, dict[str, str]]:
        """The rendered script, and an environment whose `date` is pinned and `pg_dump` is a stub."""
        stubs = tmp_path / "bin"
        stubs.mkdir()
        (stubs / "date").write_text("#!/bin/sh\necho 20261008_020000\n")
        (stubs / "pg_dump").write_text(pg_dump)
        for stub in stubs.iterdir():
            stub.chmod(0o755)
        script = tmp_path / "backup.sh"
        script.write_text(self._render(tmp_path / "backups"))
        return script, {**os.environ, "PATH": f"{stubs}{os.pathsep}{os.environ['PATH']}"}

    @staticmethod
    def _run(script: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 -- the rendered script in this test's tmp_path
            ["bash", str(script)],  # noqa: S607
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    @pytest.mark.integration
    def test_two_runs_in_the_same_second_write_different_files(self, tmp_path: Path) -> None:
        # A manual backup started in the same second as the nightly cron run used to get the same
        # name, so two pg_dump processes wrote one file and the download could copy either.
        script, env = self._script(tmp_path, self.PG_DUMP_WRITES)
        created = []
        for _ in range(2):
            result = self._run(script, env)
            assert result.returncode == 0, result.stdout + result.stderr
            created += re.findall(r"Backup created: (\S+)", result.stdout)

        assert len(created) == 2
        assert created[0] != created[1], created
        backups = tmp_path / "backups"
        assert len(list(backups.glob("praho_backup_*.dump"))) == 2
        assert list(backups.glob("*.partial")) == []

    @pytest.mark.integration
    def test_retention_removes_an_abandoned_partial_but_not_one_being_written(self, tmp_path: Path) -> None:
        # A killed backup skips its EXIT trap, and the partial matched neither retention pattern.
        script, env = self._script(tmp_path, self.PG_DUMP_WRITES)
        backups = tmp_path / "backups"
        backups.mkdir()
        abandoned = backups / "praho_backup_20261001_020000_111.dump.partial"
        being_written = backups / "praho_backup_20261008_020000_222.dump.partial"
        for partial in (abandoned, being_written):
            partial.write_bytes(b"x")
        # A slow dump may not have written for some minutes; only a day of silence means abandoned.
        for partial, age in ((abandoned, 2 * 86400), (being_written, 600)):
            os.utime(partial, (time.time() - age, time.time() - age))
        result = self._run(script, env)
        assert result.returncode == 0, result.stdout + result.stderr
        assert not abandoned.exists()
        assert being_written.exists()

    @pytest.mark.integration
    def test_a_failed_dump_leaves_nothing_a_restore_could_pick(self, tmp_path: Path) -> None:
        # pg_dump creates its output file before it connects, so a refused connection left an empty
        # dump behind, and restore --latest drops the database before pg_restore rejects that file.
        script, env = self._script(
            tmp_path, '#!/bin/sh\nwhile [ "$#" -gt 0 ]; do [ "$1" = -f ] && : > "$2"; shift; done\nexit 1\n'
        )
        result = self._run(script, env)
        assert result.returncode != 0
        assert list((tmp_path / "backups").glob("praho_backup_*")) == []


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
