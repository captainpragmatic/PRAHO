"""Production settings must reach the Docker containers that need them, and the images must run.

`prod.py` refuses to start without `DJANGO_ENCRYPTION_KEY`, `CREDENTIAL_VAULT_MASTER_KEY`,
`PORTAL_DOMAIN` and `PLATFORM_DOMAIN`, and the portal without `PORTAL_TRUSTED_PROXY_CIDRS`. No standalone
Compose file delivered all of them, the images could not start Gunicorn or render shared templates,
and the first boot outlasted the platform healthcheck. The portal must never receive the platform's
database credentials or encryption keys, so the checks run in both directions.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml
from jinja2 import Environment

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEPLOY = PROJECT_ROOT / "deploy"

STANDALONE = ("single-server", "platform-only", "portal-only", "container-service")
PLATFORM_KEYS = ("DJANGO_ENCRYPTION_KEY", "CREDENTIAL_VAULT_MASTER_KEY")
# What the portal container must never hold: the platform's database credentials and keys.
DENIED_TO_PORTAL = (
    "DJANGO_ENCRYPTION_KEY",
    "DJANGO_ENCRYPTION_KEY_PREVIOUS",
    "CREDENTIAL_VAULT_MASTER_KEY",
    "DB_HOST",
    "DB_NAME",
    "DB_USER",
    "DB_PASSWORD",
    "DATABASE_URL",
)

# (deploy_platform, deploy_portal, deploy_database, deploy_caddy): the inventories' topologies.
# Values the repo itself provides (group_vars/all.yml) and facts Ansible gathers. A template that
# starts using another repo-defined variable fails the render until it is added here.


def _environment(service: dict[str, Any]) -> dict[str, str]:
    return dict(str(entry).split("=", 1) for entry in service.get("environment", []))


def _services(name: str) -> dict[str, Any]:
    return yaml.safe_load((DEPLOY / f"docker-compose.{name}.yml").read_text())["services"]


class TestStandaloneComposeDeliversProductionKeys:
    @pytest.mark.integration
    @pytest.mark.parametrize("name", [n for n in STANDALONE if "platform" in _services(n)])
    def test_the_platform_requires_both_keys(self, name: str) -> None:
        environment = _environment(_services(name)["platform"])
        for key in PLATFORM_KEYS:
            assert environment.get(key, "").startswith(f"${{{key}:?"), (name, key, environment.get(key))

    @pytest.mark.integration
    @pytest.mark.parametrize(
        ("name", "default"),
        [
            # The bundled Postgres has no TLS on the internal network; production's own default,
            # sslmode=require (prod.py), refuses it, so the platform could not reach its database.
            ("single-server", "disable"),
            # An external database keeps production's default.
            ("platform-only", "require"),
            ("container-service", "require"),
        ],
    )
    def test_the_platform_gets_an_sslmode_that_fits_its_database(self, name: str, default: str) -> None:
        assert _environment(_services(name)["platform"]).get("DB_SSLMODE") == f"${{DB_SSLMODE:-{default}}}"

    @pytest.mark.integration
    def test_container_service_gives_the_platform_both_domains(self) -> None:
        environment = _environment(_services("container-service")["platform"])
        for key in ("PLATFORM_DOMAIN", "PORTAL_DOMAIN"):
            assert key in environment, key

    @pytest.mark.integration
    @pytest.mark.parametrize("name", [n for n in STANDALONE if "portal" in _services(n)])
    def test_the_portal_holds_no_platform_secret(self, name: str) -> None:
        portal = _services(name)["portal"]
        leaked = sorted(set(_environment(portal)) & set(DENIED_TO_PORTAL))
        assert leaked == [], (name, leaked)
        assert "env_file" not in portal, name


class TestProductionImages:
    """What the images ship must match where the code looks for it.

    Both were broken in every production image: the builder made the venv at /build/.venv and the
    runtime copied it to /app/.venv, so `gunicorn` kept the shebang `#!/build/.venv/bin/python` and
    could not start (exit 127 after migrations); and shared/ui, which both services' settings load
    templates and static files from (REPO_ROOT/shared/ui, and REPO_ROOT is / in the image), was not
    copied, so any page using a shared component failed.
    """

    @pytest.mark.integration
    @pytest.mark.parametrize("service", ["platform", "portal"])
    def test_the_venv_is_built_where_it_runs(self, service: str) -> None:
        dockerfile = (DEPLOY / service / "Dockerfile").read_text()
        stages = re.split(r"^FROM ", dockerfile, flags=re.MULTILINE)[1:]
        builder = next(stage for stage in stages if stage.split("\n", 1)[0].endswith(" AS builder"))
        assert "ENV UV_PROJECT_ENVIRONMENT=/app/.venv" in builder
        assert "COPY --from=builder /app/.venv /app/.venv" in dockerfile

    @pytest.mark.integration
    @pytest.mark.parametrize("service", ["platform", "portal"])
    def test_the_image_ships_the_shared_ui(self, service: str) -> None:
        dockerfile = (DEPLOY / service / "Dockerfile").read_text()
        assert "COPY shared/ui /shared/ui" in dockerfile
        settings = (PROJECT_ROOT / "services" / service / "config/settings/base.py").read_text()
        assert 'REPO_ROOT / "shared" / "ui" / "templates"' in settings
        assert "REPO_ROOT = BASE_DIR.parent.parent" in settings


# A native env that satisfies every check except the two production keys.
NATIVE_BASE_ENV = {"PORTAL_DOMAIN": "p", "PLATFORM_DOMAIN": "q", "DJANGO_SECRET_KEY": "s", "DB_PASSWORD": "d", "HMAC_SECRET": "h"}
PRODUCTION_KEY_VALUES = {"DJANGO_ENCRYPTION_KEY": "e", "CREDENTIAL_VAULT_MASTER_KEY": "v"}


class TestNativeProductionKeys:
    """The native path needs the same two keys: `.env.example.prod` didn't list them, and the playbook's
    preflight didn't check them, so a production deploy from the example passed preflight and then
    crashed at service start. Staging settings don't require them, so the check is production-only."""

    PLAYBOOK = DEPLOY / "ansible/playbooks/native-single-server.yml"

    def _preflight_conditions(self) -> list[str]:
        pre_tasks = yaml.safe_load(self.PLAYBOOK.read_text())[0]["pre_tasks"]
        task = next(t for t in pre_tasks if t.get("name") == "Validate required env vars")
        return task["assert"]["that"]

    def _passes(self, praho_env: str, env: dict[str, str]) -> bool:
        jinja = Environment(autoescape=False)  # noqa: S701  # Ansible conditions, not HTML.
        return all(jinja.compile_expression(c)(praho_env=praho_env, preflight_env=env) for c in self._preflight_conditions())

    @pytest.mark.integration
    def test_the_production_example_declares_both_keys(self) -> None:
        lines = (PROJECT_ROOT / ".env.example.prod").read_text().splitlines()
        for key in PRODUCTION_KEY_VALUES:
            index = next((i for i, line in enumerate(lines) if line.startswith(f"{key}=")), None)
            assert index is not None, key
            assert lines[index - 1].startswith("# [REQUIRED]"), (key, lines[index - 1])

    @pytest.mark.integration
    def test_preflight_requires_the_keys_for_production(self) -> None:
        assert not self._passes("prod", NATIVE_BASE_ENV)
        assert self._passes("prod", {**NATIVE_BASE_ENV, **PRODUCTION_KEY_VALUES})

    @pytest.mark.integration
    def test_preflight_does_not_require_them_for_staging(self) -> None:
        assert self._passes("staging", NATIVE_BASE_ENV)


class TestPortalTrustsItsProxy:
    """Production portal settings refuse to start without PORTAL_TRUSTED_PROXY_CIDRS, and every Docker
    path left it empty, so the portal container crash-looped. Where Caddy shares the `web` network with
    the portal, that network now has a known subnet and the portal trusts it by default. Where the proxy
    is outside the stack, Compose refuses to start until the operator names it."""

    WEB_SUBNET = "10.200.250.0/24"

    @pytest.mark.integration
    def test_single_server_trusts_its_pinned_web_network(self) -> None:
        config = yaml.safe_load((DEPLOY / "docker-compose.single-server.yml").read_text())
        subnet = config["networks"]["web"]["ipam"]["config"][0]["subnet"]
        assert subnet == f"${{PRAHO_WEB_SUBNET:-{self.WEB_SUBNET}}}"
        portal = _environment(config["services"]["portal"])
        assert portal["PORTAL_TRUSTED_PROXY_CIDRS"] == f"${{PORTAL_TRUSTED_PROXY_CIDRS:-{subnet}}}"

    @pytest.mark.integration
    @pytest.mark.parametrize("name", ["portal-only", "container-service"])
    def test_an_external_proxy_must_be_named(self, name: str) -> None:
        portal = _environment(_services(name)["portal"])
        assert portal["PORTAL_TRUSTED_PROXY_CIDRS"].startswith("${PORTAL_TRUSTED_PROXY_CIDRS:?"), portal


class TestFirstBootFitsTheHealthcheck:
    """A first boot runs every migration and the initial setup before Gunicorn listens: 124 s measured on
    a fast laptop. The platform healthcheck allowed 40 s plus three 30 s retries, so a first deploy
    marked the platform unhealthy mid-migration, and `up` refused to start the portal that depends on
    it. The start period now covers a slow first boot; checks during it still run, so a healthy
    platform reports healthy as soon as Gunicorn answers."""

    MIN_SECONDS = 300

    @staticmethod
    def _seconds(value: str) -> int:
        number, unit = re.fullmatch(r"(\d+)([sm])", value).groups()  # type: ignore[union-attr]
        return int(number) * (60 if unit == "m" else 1)

    @pytest.mark.integration
    @pytest.mark.parametrize("name", [n for n in STANDALONE if "platform" in _services(n)])
    def test_standalone_platform_start_period(self, name: str) -> None:
        healthcheck = _services(name)["platform"]["healthcheck"]
        assert self._seconds(healthcheck["start_period"]) >= self.MIN_SECONDS, healthcheck


    @pytest.mark.integration
    def test_image_start_period(self) -> None:
        match = re.search(r"--start-period=(\d+[sm])", (DEPLOY / "platform/Dockerfile").read_text())
        assert match and self._seconds(match.group(1)) >= self.MIN_SECONDS
