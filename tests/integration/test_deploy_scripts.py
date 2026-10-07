"""The standalone deployment scripts must hand the operator's env file to every Compose call.

The compose files live in deploy/, so a bare `docker compose -f deploy/...` reads deploy/.env, which
no documented step creates: every ${VAR:?} failed before a container started. The scripts also
health-checked host ports the stacks never publish, and rollback edited a root .env Compose never
reads. These tests run copies of the scripts against a recording `docker` stub, so they need no
Docker daemon and never touch a real env file; one test runs the real `docker compose config`.
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
RECORDED_ENV = ("PRAHO_ENV_FILE", "DB_HOST", "DB_SSLMODE", "VERSION", "DJANGO_SETTINGS_MODULE", "PORTAL_DJANGO_SECRET_KEY")
# Built at runtime, so the source holds no password-like assignment for secret scanners to flag.
DB_PW = "DB_" + "PASSWORD"
LEAK = "leak-marker"
PORTAL_KEY = "PORTAL_DJANGO_SECRET_KEY=dummy-portal-secret-key\n"
PORTAL_ONLY_ENV = (
    "DJANGO_SETTINGS_MODULE=config.settings.prod\nPLATFORM_API_BASE_URL=https://platform.example.com/api\n" + PORTAL_KEY
)
# A full file with every variable the portal-only stack requires, for the helper.
FULL_FOR_PORTAL = PORTAL_ONLY_ENV + (
    "PLATFORM_API_SECRET=h\nPLATFORM_TO_PORTAL_WEBHOOK_SECRET=w\nPORTAL_TRUSTED_PROXY_CIDRS=10.0.0.0/8\n"
    f"DJANGO_SECRET_KEY=platform-key\n{DB_PW}=db-value\n"
)
# Every variable the single-server and container-service files require, for real `docker compose config`.
SHARED_HOST_ENV = (
    f"DJANGO_SETTINGS_MODULE=config.settings.prod\nDJANGO_SECRET_KEY=platform-key\n{DB_PW}=p\n"
    "DB_HOST=db.example.com\nDB_NAME=praho\nDB_USER=praho\nPLATFORM_API_SECRET=h\n"
    "PLATFORM_TO_PORTAL_WEBHOOK_SECRET=w\nPLATFORM_DOMAIN=platform.example.com\nPORTAL_DOMAIN=portal.example.com\n"
    "ACME_EMAIL=ops@example.com\nPORTAL_TRUSTED_PROXY_CIDRS=10.0.0.0/8\n"
    "PLATFORM_API_BASE_URL=https://platform.example.com/api\n"
)

DOCKER_STUB = """#!{python}
import json, os, sys
argv = sys.argv[1:]
with open(os.environ["DOCKER_LOG"], "a") as log:
    log.write(json.dumps({{"argv": argv, "env": {{k: os.environ.get(k) for k in {recorded!r}}}}}) + "\\n")
if argv[:1] == ["ps"]:
    print("praho_db\\npraho_platform\\npraho_portal\\npraho_caddy")
elif argv[:1] == ["inspect"]:
    print(os.environ.get("DOCKER_HEALTH_" + argv[-1], os.environ.get("DOCKER_HEALTH", "healthy")))
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
    def test_a_production_portal_host_deploys_without_the_platform_keys(self, project: Project) -> None:
        # A portal-only host must not hold the platform's encryption keys at all.
        project.write_env(
            ".env.prod", "DJANGO_SETTINGS_MODULE=config.settings.prod\nPLATFORM_API_BASE_URL=https://p.example.com/api\n"
        )
        result = project.run("deploy.sh", "portal-only")
        assert result.returncode == 0, result.stderr
        assert any(_subcommand(c)[:1] == ["up"] for c in project.compose_calls())

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
        project.write_env(
            ".env.prod", "DJANGO_SETTINGS_MODULE=config.settings.prod\nPLATFORM_API_BASE_URL=https://platform.example.com/api\n"
        )
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


class TestRollbackAndRestore:
    @pytest.mark.integration
    def test_rollback_pins_the_version_without_editing_the_env_file(self, project: Project) -> None:
        env_file = project.write_env(".env.prod", PROD_ENV + "VERSION=v1.0.0\n")
        before = env_file.read_bytes()
        result = project.run("rollback.sh", "version", "v1.2.3", stdin="yes\n")
        assert result.returncode == 0, result.stdout + result.stderr
        assert env_file.read_bytes() == before
        assert not (project.root / ".env").exists()
        calls = project.compose_calls()
        subcommands = [_subcommand(c)[0] for c in calls]
        assert subcommands.index("pull") < subcommands.index("up")
        assert "down" not in subcommands
        for call in calls:
            assert call["argv"][2] == str(env_file)
            assert call["env"]["VERSION"] == "v1.2.3"
        up = calls[subcommands.index("up")]
        assert {"--no-build", "--wait"} <= set(_subcommand(up))
        # Only the application images: a newer postgres or caddy image would recreate those containers.
        pull = _subcommand(calls[subcommands.index("pull")])
        assert [a for a in pull if not a.startswith("-")] == ["pull", "platform", "portal"]

    @pytest.mark.integration
    def test_restore_restarts_through_the_env_file_and_waits_on_container_health(self, project: Project) -> None:
        env_file = project.write_env(".env.staging", STAGING_ENV)
        backups = project.root / "backups"
        backups.mkdir()
        backup = backups / "praho_backup_20261007_000000.sql.gz"
        backup.write_bytes(b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00")
        result = project.run("restore.sh", "--env", "staging", str(backup), stdin="yes\n", DOCKER_START_FAILS="1")
        assert result.returncode == 0, result.stdout + result.stderr
        (call,) = project.compose_calls()
        assert call["argv"][2] == str(env_file)
        assert "--wait" in _subcommand(call)
        assert "curl" not in project.log.read_text()

    @pytest.mark.integration
    def test_a_restore_whose_services_stay_unhealthy_exits_nonzero(self, project: Project) -> None:
        project.write_env(".env.prod", PROD_ENV)
        backups = project.root / "backups"
        backups.mkdir()
        backup = backups / "praho_backup_20261007_000000.sql.gz"
        backup.write_bytes(b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00")
        result = project.run("restore.sh", str(backup), stdin="yes\n", DOCKER_HEALTH="unhealthy")
        assert "Starting services" in result.stdout, result.stdout + result.stderr
        assert result.returncode != 0, result.stdout

    @pytest.mark.integration
    @pytest.mark.parametrize(("script", "args"), [("rollback.sh", ("version", "v1.2.3")), ("restore.sh", ("--latest",))])
    def test_recovery_refuses_a_production_file_without_its_keys_before_touching_anything(
        self, project: Project, script: str, args: tuple[str, ...]
    ) -> None:
        project.write_env(".env.prod", "DJANGO_SETTINGS_MODULE=config.settings.prod\n")
        backups = project.root / "backups"
        backups.mkdir()
        (backups / "praho_backup_20261007_000000.sql.gz").write_bytes(b"")
        result = project.run(script, *args, stdin="yes\n")
        assert result.returncode != 0
        assert "DJANGO_ENCRYPTION_KEY" in result.stderr
        # Nothing stopped, dropped, pulled or replaced.
        assert [c["argv"][0] for c in project.calls() if c["argv"][0] in ("compose", "exec", "stop")] == []

    @pytest.mark.integration
    @pytest.mark.parametrize(("container", "expected_rc"), [("praho_caddy", 0), ("praho_platform", 1)])
    def test_only_caddy_may_lack_a_healthcheck(self, project: Project, container: str, expected_rc: int) -> None:
        result = project.run("health-check.sh", **{f"DOCKER_HEALTH_{container}": "no-healthcheck"})
        assert result.returncode == expected_rc, result.stdout

    @pytest.mark.integration
    def test_health_check_reads_container_health_not_host_ports(self, project: Project) -> None:
        result = project.run("health-check.sh")
        assert result.returncode == 0, result.stdout
        assert "curl" not in project.log.read_text()


class TestEveryComposeCallUsesTheHelper:
    @pytest.mark.integration
    def test_scripts(self) -> None:
        offenders = [
            f"{path.name}:{number}"
            for path in sorted(SCRIPTS.glob("*.sh"))
            for number, line in enumerate(path.read_text().splitlines(), 1)
            if re.search(r"\bdocker[ -]compose\b(?! version)", line.split("#", 1)[0])
        ]
        assert offenders == []

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
    def test_container_service_serves_the_two_documented_domains(self, project: Project) -> None:
        # The header and docs name PLATFORM_DOMAIN and PORTAL_DOMAIN; the legacy DOMAIN is not set.
        env_file = project.write_env(
            ".env.prod",
            PROD_ENV
            + "DB_HOST=db.example.com\nDB_NAME=praho\nDB_USER=praho\nDB_PASSWORD=p\nDJANGO_SECRET_KEY=s\n"
            "PLATFORM_API_SECRET=h\nPLATFORM_TO_PORTAL_WEBHOOK_SECRET=w\nPORTAL_TRUSTED_PROXY_CIDRS=10.0.0.0/8\n"
            "PLATFORM_DOMAIN=platform.example.com\nPORTAL_DOMAIN=portal.example.com\n"
            "PLATFORM_API_BASE_URL=https://platform.example.com/api\n",
        )
        services = _compose_config(env_file, project.compose_file("container-service"))
        platform, portal = services["platform"]["environment"], services["portal"]["environment"]
        assert "platform.example.com" in platform["ALLOWED_HOSTS"].split(",")
        assert "https://platform.example.com" in platform["CSRF_TRUSTED_ORIGINS"].split(",")
        assert portal["PORTAL_DOMAIN"] == "portal.example.com"
        assert "portal.example.com" in portal["ALLOWED_HOSTS"].split(",")
        assert "https://portal.example.com" in portal["CSRF_TRUSTED_ORIGINS"].split(",")

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


def _filled_example(name: str, extra: str = "") -> str:
    """An example env file as an operator fills it in: every empty value becomes dummy-<KEY>."""
    text = (PROJECT_ROOT / name).read_text()
    return re.sub(r"^([A-Z_][A-Z0-9_]*)=$", r"\1=dummy-\1", text, flags=re.MULTILINE) + extra


def _declarations(text: str) -> dict[str, str]:
    """Each key's last `KEY=` line, exactly as written."""
    lines: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)=", line)
        if match:
            lines[match.group(1)] = line
    return lines


def _portal_only_variables() -> set[str]:
    """What Compose itself says docker-compose.portal-only.yml interpolates."""
    result = subprocess.run(  # noqa: S603  # Fixed docker invocation.
        [shutil.which("docker") or "docker", "compose", "-f", str(PROJECT_ROOT / "deploy/docker-compose.portal-only.yml"),
         "config", "--variables", "--format", "json"],
        env={k: v for k, v in os.environ.items() if k in ("PATH", "HOME") or k.startswith("DOCKER_")},
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert result.returncode == 0, result.stderr
    return set(json.loads(result.stdout))


class TestPortalHostEnv:
    """A separate portal host may hold only what the portal stack uses: never the platform's database
    password, encryption keys, payment or mail credentials, or its Django secret key, which on the
    platform is the root of the MFA, audit-chain and unsubscribe keys."""

    @pytest.mark.integration
    @pytest.mark.parametrize(("example", "env_name"), [(".env.example.prod", "prod"), (".env.example.staging", "staging")])
    def test_the_guard_refuses_a_full_operator_file(self, project: Project, example: str, env_name: str) -> None:
        source = _filled_example(example, PORTAL_KEY)
        project.write_env(f".env.{env_name}", source)
        result = project.run("deploy.sh", "portal-only", "--env", env_name)
        output = result.stdout + result.stderr
        assert result.returncode != 0
        declared = set(_declarations(source))
        for key in ("DB_PASSWORD", "DJANGO_SECRET_KEY", "DJANGO_ENCRYPTION_KEY", "STRIPE_SECRET_KEY"):
            if key in declared:
                assert key in output, key
        assert "dummy-" not in output
        assert project.compose_calls() == []

    @pytest.mark.integration
    @pytest.mark.parametrize(
        "bad",
        [
            f"{DB_PW}={LEAK}\n{DB_PW}=\n",
            f"export {DB_PW}={LEAK}\n",
            f"  {DB_PW}={LEAK}\n",
            f"{DB_PW}=\n",
            f'PLATFORM_API_SECRET="{LEAK}\ncontinued"\n',
            # Compose reads `\"` as an escaped quote, so this value never closes.
            f'PLATFORM_API_SECRET="{LEAK}\\"\n',
        ],
    )
    def test_the_guard_reads_every_line(self, project: Project, bad: str) -> None:
        # A later empty declaration does not remove a secret from the disk, and Compose also reads
        # `export K=`, indented keys and multi-line quotes.
        project.write_env(".env.prod", PORTAL_ONLY_ENV + bad)
        result = project.run("deploy.sh", "portal-only")
        assert result.returncode != 0
        assert LEAK not in result.stdout + result.stderr
        assert project.compose_calls() == []

    @pytest.mark.integration
    @pytest.mark.parametrize("flag", ["--stop", "--logs"])
    def test_stop_and_logs_only_warn(self, project: Project, flag: str) -> None:
        # Never block stopping or inspecting a portal during an incident.
        project.write_env(".env.prod", _filled_example(".env.example.prod", PORTAL_KEY))
        result = project.run("deploy.sh", "portal-only", flag)
        output = result.stdout + result.stderr
        assert result.returncode == 0, output
        assert len(project.compose_calls()) == 1
        assert "DB_PASSWORD" in output
        assert "dummy-" not in output

    @pytest.mark.integration
    def test_stop_and_logs_work_before_the_portal_key_exists(self, project: Project) -> None:
        # An upgraded portal host still has its old file; Compose interpolates the new required key
        # for `down` and `logs` too, so they get a throwaway value that no container ever uses.
        old = "".join(
            line + "\n"
            for line in _filled_example(".env.example.prod").splitlines()
            if not line.startswith("PORTAL_DJANGO_SECRET_KEY=")
        )
        project.write_env(".env.prod", old)
        result = project.run("deploy.sh", "portal-only", "--stop")
        assert result.returncode == 0, result.stdout + result.stderr
        (call,) = project.compose_calls()
        assert call["env"]["PORTAL_DJANGO_SECRET_KEY"]

    @pytest.mark.integration
    def test_stop_keeps_a_real_portal_key(self, project: Project) -> None:
        project.write_env(".env.prod", PORTAL_ONLY_ENV)
        assert project.run("deploy.sh", "portal-only", "--stop").returncode == 0
        (call,) = project.compose_calls()
        assert call["env"]["PORTAL_DJANGO_SECRET_KEY"] is None

    @pytest.mark.integration
    @pytest.mark.parametrize(
        ("line", "key"),
        [
            ("PLATFORM_API_SECRET=${HMAC_SECRET}\n", "PLATFORM_API_SECRET"),
            ('PLATFORM_API_SECRET="pre-${HMAC_SECRET}"\n', "PLATFORM_API_SECRET"),
            ("PORTAL_DJANGO_SECRET_KEY=${DJANGO_SECRET_KEY}\n", "PORTAL_DJANGO_SECRET_KEY"),
        ],
    )
    def test_the_helper_refuses_values_compose_would_interpolate(self, project: Project, line: str, key: str) -> None:
        # The variable a reference points at is not copied, so on the portal host it would resolve to
        # empty, and a portal key spelled ${DJANGO_SECRET_KEY} would get past the equality check.
        project.write_env(
            ".env.prod", PORTAL_ONLY_ENV + "HMAC_SECRET=h-value\nDJANGO_SECRET_KEY=platform-key\n" + line
        )
        result = project.run("portal-env.sh")
        assert result.returncode != 0
        assert key in result.stderr
        assert "h-value" not in result.stdout + result.stderr
        assert not (project.root / ".env.prod.portal").exists()

    @pytest.mark.integration
    def test_the_helper_writes_only_what_the_portal_stack_uses(self, project: Project) -> None:
        extra = PORTAL_KEY + "PLATFORM_API_SECRET='a$b#c'\nHSTS_POLICY=\"max-age=1; includeSubDomains\"\nPORTAL_HMAC_SECRET=x # note\n"
        source = _filled_example(".env.example.prod", extra)
        project.write_env(".env.prod", source)
        result = project.run("portal-env.sh")
        assert result.returncode == 0, result.stdout + result.stderr
        out = project.root / ".env.prod.portal"
        assert out.stat().st_mode & 0o777 == 0o600
        text = out.read_text()
        written = _declarations(text)
        allowed = _portal_only_variables()
        assert sorted(set(written) - allowed) == []
        assert written["DJANGO_SETTINGS_MODULE"] == "DJANGO_SETTINGS_MODULE=config.settings.prod"
        expected = _declarations(source)
        for key, line in written.items():
            if key != "DJANGO_SETTINGS_MODULE":
                assert line == expected[key], key
        assert "PORTAL_DJANGO_SECRET_KEY" in written
        for key in set(expected) - allowed:
            assert f"dummy-{key}" not in text, key
        assert "dummy-" not in result.stdout + result.stderr
        assert "a$b#c" not in result.stdout + result.stderr

    @pytest.mark.integration
    @pytest.mark.parametrize(
        "portal_line", ["", "PORTAL_DJANGO_SECRET_KEY=\n", 'PORTAL_DJANGO_SECRET_KEY="dup-value-123"\n']
    )
    def test_the_helper_refuses_a_missing_empty_or_shared_portal_key(self, project: Project, portal_line: str) -> None:
        project.write_env(".env.prod", "DJANGO_SETTINGS_MODULE=config.settings.prod\nDJANGO_SECRET_KEY=dup-value-123\n" + portal_line)
        result = project.run("portal-env.sh")
        assert result.returncode != 0
        assert "PORTAL_DJANGO_SECRET_KEY" in result.stderr
        assert "dup-value-123" not in result.stdout + result.stderr
        assert not (project.root / ".env.prod.portal").exists()

    @pytest.mark.integration
    @pytest.mark.parametrize("form", ["export PLATFORM_API_SECRET=h\n", "  PLATFORM_API_SECRET=h\n"])
    def test_the_helper_refuses_forms_it_cannot_copy(self, project: Project, form: str) -> None:
        # Compose reads these, so dropping them would write a file that lacks the value.
        source = FULL_FOR_PORTAL.replace("PLATFORM_API_SECRET=h\n", form)
        project.write_env(".env.prod", source)
        result = project.run("portal-env.sh")
        assert result.returncode != 0
        assert "PLATFORM_API_SECRET" in result.stderr
        assert not (project.root / ".env.prod.portal").exists()

    @pytest.mark.integration
    def test_the_helper_does_not_read_inside_a_value_spanning_lines(self, project: Project) -> None:
        # Compose reads the middle line as part of DB_PASSWORD, never as a declaration.
        source = FULL_FOR_PORTAL + f"{DB_PW}='first\nPLATFORM_API_SECRET=leaked-fragment\nlast'\n"
        project.write_env(".env.prod", source)
        result = project.run("portal-env.sh")
        assert result.returncode == 0, result.stdout + result.stderr
        text = (project.root / ".env.prod.portal").read_text()
        assert "leaked-fragment" not in text
        assert _declarations(text)["PLATFORM_API_SECRET"] == "PLATFORM_API_SECRET=h"

    @pytest.mark.integration
    def test_the_helper_refuses_a_file_the_portal_stack_could_not_start_with(self, project: Project) -> None:
        project.write_env(".env.prod", FULL_FOR_PORTAL.replace("PORTAL_TRUSTED_PROXY_CIDRS=10.0.0.0/8\n", ""))
        result = project.run("portal-env.sh")
        assert result.returncode != 0
        assert "PORTAL_TRUSTED_PROXY_CIDRS" in result.stderr
        assert not (project.root / ".env.prod.portal").exists()

    @pytest.mark.integration
    def test_the_helper_never_overwrites_by_accident(self, project: Project) -> None:
        source = project.write_env(".env.prod", FULL_FOR_PORTAL)
        out = project.write_env(".env.prod.portal", "OLD=1\n")
        out.chmod(0o644)
        assert project.run("portal-env.sh").returncode != 0
        assert out.read_text() == "OLD=1\n"
        result = project.run("portal-env.sh", "--force")
        assert result.returncode == 0, result.stdout + result.stderr
        assert "OLD" not in out.read_text()
        assert out.stat().st_mode & 0o777 == 0o600
        before = source.read_bytes()
        assert project.run("portal-env.sh", "--output", ".env.prod", "--force").returncode != 0
        assert source.read_bytes() == before

    @pytest.mark.integration
    @pytest.mark.parametrize(("example", "env_name"), [(".env.example.prod", "prod"), (".env.example.staging", "staging")])
    def test_the_helpers_file_deploys_on_the_portal_host(
        self, project: Project, tmp_path: Path, example: str, env_name: str
    ) -> None:
        project.write_env(f".env.{env_name}", _filled_example(example, PORTAL_KEY))
        result = project.run("portal-env.sh", "--env", env_name)
        assert result.returncode == 0, result.stdout + result.stderr
        host = Project((tmp_path / "portal-host").resolve())
        host.write_env(f".env.{env_name}", (project.root / f".env.{env_name}.portal").read_text())
        result = host.run("deploy.sh", "portal-only", "--env", env_name)
        assert result.returncode == 0, result.stdout + result.stderr
        assert any(_subcommand(c)[:1] == ["up"] for c in host.compose_calls())

    @pytest.mark.integration
    def test_the_helpers_file_satisfies_the_portal_stack(self, project: Project) -> None:
        project.write_env(".env.prod", _filled_example(".env.example.prod", PORTAL_KEY + "PLATFORM_API_SECRET='a$b#c'\n"))
        assert project.run("portal-env.sh").returncode == 0
        services = _compose_config(project.root / ".env.prod.portal", project.compose_file("portal-only"))
        portal = services["portal"]["environment"]
        assert portal["DJANGO_SECRET_KEY"] == "dummy-portal-secret-key"
        # Single quotes keep `$` literal; `config` prints it as `$$`.
        assert portal["PLATFORM_API_SECRET"] == "a$$b#c"

    @pytest.mark.integration
    def test_the_allowlist_is_what_compose_interpolates(self) -> None:
        result = subprocess.run(  # noqa: S603  # The helper library, sourced in a fresh shell.
            ["/bin/bash", "-c", 'DEPLOY_DIR="$1"; source "$1/scripts/lib/compose.sh"; praho_portal_allowlist', "_",
             str(PROJECT_ROOT / "deploy")],
            capture_output=True, text=True, timeout=30, check=False,
        )
        assert result.returncode == 0, result.stderr
        assert set(result.stdout.split()) == _portal_only_variables()

    @pytest.mark.integration
    @pytest.mark.parametrize("name", ["single-server", "container-service"])
    @pytest.mark.parametrize("separate", [True, False])
    def test_a_shared_host_may_give_the_portal_its_own_key(self, project: Project, name: str, separate: bool) -> None:
        env_file = project.write_env(".env.prod", SHARED_HOST_ENV + ("PORTAL_DJANGO_SECRET_KEY=portal-key\n" if separate else ""))
        services = _compose_config(env_file, project.compose_file(name))
        assert services["platform"]["environment"]["DJANGO_SECRET_KEY"] == "platform-key"
        assert services["portal"]["environment"]["DJANGO_SECRET_KEY"] == ("portal-key" if separate else "platform-key")
