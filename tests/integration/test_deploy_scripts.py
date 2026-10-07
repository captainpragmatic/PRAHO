"""The standalone deployment scripts must hand the operator's env file to every Compose call.

The compose files live in deploy/, so a bare `docker compose -f deploy/...` reads deploy/.env, which
no documented step creates: every ${VAR:?} failed before a container started. The script also
health-checked host ports the stacks never publish. These tests run copies of the scripts against a
recording `docker` stub, so they need no Docker daemon and never touch a real env file; the Compose
tests run the real `docker compose config`.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = PROJECT_ROOT / "deploy/scripts"
PRODUCTION_KEYS = "DJANGO_ENCRYPTION_KEY=test-encryption-key\nCREDENTIAL_VAULT_MASTER_KEY=test-vault-key\n"
PROD_ENV = "DJANGO_SETTINGS_MODULE=config.settings.prod\n" + PRODUCTION_KEYS
STAGING_ENV = "DJANGO_SETTINGS_MODULE=config.settings.staging\n"
RECORDED_ENV = ("PRAHO_ENV_FILE", "DB_HOST", "DB_SSLMODE", "VERSION", "DJANGO_SETTINGS_MODULE")

DOCKER_STUB = """#!{python}
import json, os, sys
argv = sys.argv[1:]
with open(os.environ["DOCKER_LOG"], "a") as log:
    log.write(json.dumps({{"argv": argv, "env": {{k: os.environ.get(k) for k in {recorded!r}}}}}) + "\\n")
if argv[:1] == ["ps"]:
    print("praho_db\\npraho_platform\\npraho_portal\\npraho_caddy")
elif argv[:1] == ["inspect"]:
    print("healthy")
elif argv[:1] == ["start"] and os.environ.get("DOCKER_START_FAILS"):
    sys.exit(1)
"""


class Project:
    """A temporary checkout holding copies of deploy/ and the operator's env files."""

    def __init__(self, root: Path) -> None:
        self.root = root
        shutil.copytree(PROJECT_ROOT / "deploy", root / "deploy", ignore=shutil.ignore_patterns("ansible"))
        bin_dir = root / "bin"
        bin_dir.mkdir()
        stub = bin_dir / "docker"
        stub.write_text(DOCKER_STUB.format(python=sys.executable, recorded=RECORDED_ENV))
        curl = bin_dir / "curl"
        curl.write_text("#!/bin/sh\necho curl >> \"$DOCKER_LOG\"\nexit 7\n")
        for tool in (stub, curl):
            tool.chmod(0o755)
        self.log = root / "docker.log"
        self.log.touch()
        self.env = {
            "PATH": f"{bin_dir}:/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": str(root),
            "DOCKER_LOG": str(self.log),
            "BACKUP_DIR": str(root / "backups"),
        }

    def write_env(self, name: str, content: str) -> Path:
        path = self.root / name
        path.write_text(content)
        return path

    def run(self, script: str, *args: str, stdin: str = "", **env: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603  # Fixed script paths and test arguments.
            ["/bin/bash", str(self.root / "deploy/scripts" / script), *args],
            cwd=self.root,
            env={**self.env, **env},
            input=stdin,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    def calls(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.log.read_text().splitlines() if line.startswith("{")]

    def compose_calls(self) -> list[dict[str, Any]]:
        return [c for c in self.calls() if c["argv"][:1] == ["compose"] and c["argv"][1:2] != ["version"]]

    def compose_file(self, type_: str) -> str:
        return str(self.root / "deploy" / f"docker-compose.{type_}.yml")


@pytest.fixture
def project(tmp_path: Path) -> Project:
    return Project(tmp_path.resolve())


def _subcommand(call: dict[str, Any]) -> list[str]:
    """The Compose arguments after the global --env-file/-f/--profile options."""
    argv = call["argv"][1:]
    while argv and argv[0] in ("--env-file", "-f", "--profile"):
        argv = argv[2:]
    return argv


class TestDeployScript:
    @pytest.mark.integration
    @pytest.mark.parametrize("args", [("--help",), ("single-server", "--help")])
    def test_help_needs_no_env_file(self, project: Project, args: tuple[str, ...]) -> None:
        result = project.run("deploy.sh", *args)
        assert result.returncode == 0, result.stderr
        assert "Usage" in result.stdout
        assert project.compose_calls() == []

    @pytest.mark.integration
    @pytest.mark.parametrize(("env_name", "content"), [("prod", PROD_ENV), ("staging", STAGING_ENV)])
    def test_every_compose_call_reads_the_named_env_file(self, project: Project, env_name: str, content: str) -> None:
        env_file = project.write_env(f".env.{env_name}", content)
        project.write_env(".env.prod" if env_name == "staging" else ".env.staging", "SENTINEL=other\n")
        result = project.run("deploy.sh", "single-server", "--env", env_name)
        assert result.returncode == 0, result.stderr
        calls = project.compose_calls()
        assert calls, result.stdout
        for call in calls:
            assert call["argv"][1:5] == ["--env-file", str(env_file), "-f", project.compose_file("single-server")]
            assert call["env"]["PRAHO_ENV_FILE"] == str(env_file)
        up = next(c for c in calls if _subcommand(c)[:1] == ["up"])
        assert "--wait" in _subcommand(up)

    @pytest.mark.integration
    def test_prod_is_the_default(self, project: Project) -> None:
        env_file = project.write_env(".env.prod", PROD_ENV)
        assert project.run("deploy.sh", "single-server").returncode == 0
        assert {c["argv"][2] for c in project.compose_calls()} == {str(env_file)}

    @pytest.mark.integration
    @pytest.mark.parametrize("spelling", [".env", "./deploy/../.env", "linked-env"])
    def test_the_development_env_file_is_refused(self, project: Project, spelling: str) -> None:
        project.write_env(".env", PROD_ENV)
        (project.root / "linked-env").symlink_to(project.root / ".env")
        result = project.run("deploy.sh", "single-server", "--env-file", spelling)
        assert result.returncode != 0
        assert "development env file" in result.stderr
        assert project.compose_calls() == []

    @pytest.mark.integration
    def test_a_settings_module_the_images_do_not_run_is_refused(self, project: Project) -> None:
        project.write_env(".env.prod", PRODUCTION_KEYS + "DJANGO_SETTINGS_MODULE=config.settings.dev\n")
        result = project.run("deploy.sh", "single-server")
        assert result.returncode != 0
        assert "config.settings.dev" in result.stderr
        assert project.compose_calls() == []

    @pytest.mark.integration
    def test_a_settings_module_in_the_shell_does_not_override_the_file(self, project: Project) -> None:
        # Compose lets a shell variable beat --env-file, so a developer's exported module would win.
        project.write_env(".env.staging", STAGING_ENV)
        result = project.run("deploy.sh", "single-server", "--env", "staging", DJANGO_SETTINGS_MODULE="config.settings.dev")
        assert result.returncode == 0, result.stderr
        assert {c["env"]["DJANGO_SETTINGS_MODULE"] for c in project.compose_calls()} == {None}

    @pytest.mark.integration
    def test_the_env_name_must_match_the_settings_it_selects(self, project: Project) -> None:
        project.write_env(".env.staging", PROD_ENV)
        result = project.run("deploy.sh", "single-server", "--env", "staging")
        assert result.returncode != 0
        assert "config.settings.staging" in result.stderr
        assert project.compose_calls() == []

    @pytest.mark.integration
    @pytest.mark.parametrize(
        "encryption_line",
        ["", "DJANGO_ENCRYPTION_KEY=\n", 'DJANGO_ENCRYPTION_KEY="" # fill in\n', "DJANGO_ENCRYPTION_KEY= # fill in\n"],
    )
    def test_production_refuses_to_deploy_without_its_keys(self, project: Project, encryption_line: str) -> None:
        project.write_env(
            ".env.prod", "DJANGO_SETTINGS_MODULE=config.settings.prod\nCREDENTIAL_VAULT_MASTER_KEY=k\n" + encryption_line
        )
        result = project.run("deploy.sh", "single-server")
        assert result.returncode != 0
        assert "DJANGO_ENCRYPTION_KEY" in result.stderr
        assert project.compose_calls() == []

    @pytest.mark.integration
    @pytest.mark.parametrize("value", ["abc#def", "'abc # def'", '"abc"  # comment', "abc # comment"])
    def test_production_accepts_any_spelling_of_a_set_key(self, project: Project, value: str) -> None:
        project.write_env(".env.prod", f"DJANGO_SETTINGS_MODULE=config.settings.prod\nCREDENTIAL_VAULT_MASTER_KEY=k\nDJANGO_ENCRYPTION_KEY={value}\n")
        result = project.run("deploy.sh", "single-server")
        assert result.returncode == 0, result.stderr

    @pytest.mark.integration
    def test_staging_deploys_without_the_production_keys(self, project: Project) -> None:
        project.write_env(".env.staging", STAGING_ENV)
        assert project.run("deploy.sh", "single-server", "--env", "staging").returncode == 0

    @pytest.mark.integration
    def test_profiles_precede_the_subcommand_and_the_bundled_database_skips_tls(self, project: Project) -> None:
        project.write_env(".env.prod", PROD_ENV)
        result = project.run("deploy.sh", "platform-only", "--with-db", "--with-caddy")
        assert result.returncode == 0, result.stderr
        up = next(c for c in project.compose_calls() if "up" in c["argv"])
        argv = up["argv"]
        assert argv[5 : argv.index("up")] == ["--profile", "with-db", "--profile", "with-caddy"]
        assert up["env"]["DB_SSLMODE"] == "disable"

    @pytest.mark.integration
    @pytest.mark.parametrize("flag", ["--with-db", "--full"])
    def test_the_bundled_database_overrides_the_files_database_settings(self, project: Project, flag: str) -> None:
        # .env.prod is shared with native deploys, whose example sets DB_HOST=localhost and require.
        project.write_env(".env.prod", PROD_ENV + "DB_HOST=localhost\nDB_SSLMODE=require\n")
        assert project.run("deploy.sh", "platform-only", flag).returncode == 0
        assert {(c["env"]["DB_HOST"], c["env"]["DB_SSLMODE"]) for c in project.compose_calls()} == {("db", "disable")}

    @pytest.mark.integration
    def test_an_external_database_keeps_the_files_settings(self, project: Project) -> None:
        project.write_env(".env.prod", PROD_ENV + "DB_HOST=db.example.com\nDB_SSLMODE=require\n")
        assert project.run("deploy.sh", "platform-only").returncode == 0
        assert {(c["env"]["DB_HOST"], c["env"]["DB_SSLMODE"]) for c in project.compose_calls()} == {(None, None)}

    @pytest.mark.integration
    def test_no_cache_builds_then_starts(self, project: Project) -> None:
        project.write_env(".env.prod", PROD_ENV)
        assert project.run("deploy.sh", "single-server", "--build", "--no-cache").returncode == 0
        subcommands = [_subcommand(c) for c in project.compose_calls()]
        build = subcommands.index(["build", "--no-cache"])
        up = next(i for i, s in enumerate(subcommands) if s[:1] == ["up"])
        assert build < up
        assert "--no-cache" not in subcommands[up]

    @pytest.mark.integration
    def test_portal_only_reads_the_platform_url_from_the_env_file(self, project: Project) -> None:
        project.write_env(".env.prod", PROD_ENV + "PLATFORM_API_BASE_URL=https://platform.example.com/api\n")
        result = project.run("deploy.sh", "portal-only")
        assert result.returncode == 0, result.stderr
        assert any(_subcommand(c)[:1] == ["up"] for c in project.compose_calls())

    @pytest.mark.integration
    @pytest.mark.parametrize(("flag", "subcommand"), [("--stop", "down"), ("--logs", "logs")])
    def test_stop_and_logs_read_the_env_file_without_the_key_check(
        self, project: Project, flag: str, subcommand: str
    ) -> None:
        env_file = project.write_env(".env.prod", "DJANGO_SETTINGS_MODULE=config.settings.prod\n")
        result = project.run("deploy.sh", "single-server", flag)
        assert result.returncode == 0, result.stderr
        (call,) = project.compose_calls()
        assert call["argv"][2] == str(env_file)
        assert _subcommand(call)[0] == subcommand


class TestEveryComposeCallUsesTheHelper:
    @pytest.mark.integration
    def test_makefile_deploy_targets(self) -> None:
        recipes = re.findall(r"^deploy-[\w-]+:.*\n((?:\t.*\n)+)", (PROJECT_ROOT / "Makefile").read_text(), re.MULTILINE)
        assert recipes
        assert [r for r in recipes if re.search(r"\bdocker[ -]compose\b", r)] == []


def _compose_config(env_file: Path, compose_file: str, *args: str) -> dict[str, Any]:
    result = subprocess.run(  # noqa: S603  # Fixed docker invocation.
        [shutil.which("docker") or "docker", "compose", "--env-file", str(env_file), "-f", compose_file, *args,
         "config", "--format", "json"],
        # Only what the docker CLI needs: a shell variable would beat the env file.
        env={
            **{k: v for k, v in os.environ.items() if k in ("PATH", "HOME") or k.startswith("DOCKER_")},
            "PRAHO_ENV_FILE": str(env_file),
        },
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert result.returncode == 0, result.stderr
    services: dict[str, Any] = json.loads(result.stdout)["services"]
    return services


class TestComposeReadsTheChosenFile:
    """Real `docker compose config` (no daemon needed): the platform gets the chosen file's values."""

    @pytest.mark.integration
    def test_the_single_server_stack_keeps_its_own_database_and_proxy_settings(self, project: Project) -> None:
        # An operator copies .env.example.prod, which is shared with native deploys: its DB_SSLMODE and
        # PORTAL_TRUSTED_PROXY_CIDRS describe a host database and a host Caddy, not this stack's own.
        example = (PROJECT_ROOT / ".env.example.prod").read_text()
        filled = re.sub(r"^([A-Z_]+)=$", r"\1=dummy-\1", example, flags=re.MULTILINE)
        env_file = project.write_env(".env.prod", filled)
        services = _compose_config(env_file, project.compose_file("single-server"))
        assert services["platform"]["environment"]["DB_SSLMODE"] == "disable"
        assert services["portal"]["environment"]["PORTAL_TRUSTED_PROXY_CIDRS"] == "10.200.250.0/24"

    @pytest.mark.integration
    def test_staging_values_reach_the_platform_and_secrets_stay_off_the_portal(self, project: Project) -> None:
        common = (
            "DJANGO_SECRET_KEY=s\nDB_PASSWORD=p\nPLATFORM_API_SECRET=h\nPLATFORM_TO_PORTAL_WEBHOOK_SECRET=w\n"
            "PLATFORM_DOMAIN=platform.example.com\nPORTAL_DOMAIN=portal.example.com\nACME_EMAIL=ops@example.com\n"
        )
        project.write_env(".env.prod", PROD_ENV + common + "SENTINEL_SETTING=from-prod\n")
        staging = project.write_env(
            ".env.staging", STAGING_ENV + common + "SENTINEL_SETTING=from-staging\nLITERAL='a$b#c'\n"
        )
        services = _compose_config(staging, project.compose_file("single-server"))
        platform, portal = services["platform"]["environment"], services["portal"]["environment"]
        assert platform["SENTINEL_SETTING"] == "from-staging"
        assert platform["DJANGO_SETTINGS_MODULE"] == "config.settings.staging"
        # Single quotes keep `$` and `#` literal; `config` prints `$` as `$$` so its output stays valid input.
        assert platform["LITERAL"] == "a$$b#c"
        assert platform["DB_HOST"] == "db"
        assert "SENTINEL_SETTING" not in portal
        denied = {"DJANGO_ENCRYPTION_KEY", "CREDENTIAL_VAULT_MASTER_KEY", "DB_PASSWORD", "DB_HOST", "DATABASE_URL"}
        assert sorted(denied & set(portal)) == []


class TestComposeHeaders:
    @pytest.mark.integration
    @pytest.mark.parametrize("name", ["single-server", "platform-only", "portal-only", "container-service"])
    def test_the_header_names_every_variable_compose_requires(self, name: str) -> None:
        text = (PROJECT_ROOT / f"deploy/docker-compose.{name}.yml").read_text()
        header = text[: text.index("\nservices:")]
        required = sorted(set(re.findall(r"\$\{([A-Z_]+):\?", text)))
        assert required
        assert [v for v in required if v not in header] == []
