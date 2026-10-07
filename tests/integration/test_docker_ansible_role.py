"""The Ansible Docker role must render, deliver what production requires, and wait on real health.

Its templates needed operator variables that nothing in the repo defined or documented (`secret_key`,
`db_password`, `hmac_secret`, `db_name`, `debug`, …), so the role could not even render. It never gave
the platform `DJANGO_ENCRYPTION_KEY` or `CREDENTIAL_VAULT_MASTER_KEY`, which production requires, nor
either service the webhook secret; it wrote the database password onto portal-only hosts; and it waited
for health on a host port its compose file never publishes.

The role's required inputs are checked against what its templates actually use: per topology, every
template renders from the repo defaults plus exactly the declared inputs, and dropping any one of them
breaks a render, so the list can be neither short nor padded. The portal must never receive the
platform's database credentials or keys, so those checks run in both directions.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

import pytest
import yaml
from jinja2 import Environment, StrictUndefined, UndefinedError

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEPLOY = PROJECT_ROOT / "deploy"
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
WEB_SUBNET = "10.200.250.0/24"
FIRST_BOOT_SECONDS = 300


def _environment(service: dict[str, Any]) -> dict[str, str]:
    return dict(str(entry).split("=", 1) for entry in service.get("environment", []))


def _seconds(value: str) -> int:
    number, unit = re.fullmatch(r"(\d+)([sm])", value).groups()  # type: ignore[union-attr]
    return int(number) * (60 if unit == "m" else 1)


ROLE = DEPLOY / "ansible/roles/praho"
WEBHOOK = "PLATFORM_TO_PORTAL_WEBHOOK_SECRET"
TOPOLOGIES = {
    "combined": (True, True, True, True),  # inventory/dev.yml, playbooks/single-server.yml
    "platform-host": (True, False, True, True),  # inventory/two-servers.yml, platform host
    "portal-host": (False, True, False, True),  # inventory/two-servers.yml, portal host
    "external-db": (True, True, False, True),
}
REPO_CONTEXT: dict[str, Any] = {
    "project_root": "/opt/praho",
    "platform_port": 8700,
    "portal_port": 8701,
    "backup_directory": "/opt/praho/backups",
    "backup_retention_days": 7,
    "backup_enabled": True,
    "praho_env": "prod",
    "ansible_date_time": {"iso8601": "2026-10-07T00:00:00Z"},
    "ansible_default_ipv4": {"address": "192.0.2.10"},
}
def _jinja() -> Environment:
    # Ansible renders templates with trim_blocks on; match it so the rendered YAML parses the same.
    return Environment(undefined=StrictUndefined, trim_blocks=True, autoescape=False)  # noqa: S701  # YAML/shell, not HTML.
def _role_context(topology: str) -> dict[str, Any]:
    deploy_platform, deploy_portal, deploy_database, deploy_caddy = TOPOLOGIES[topology]
    context: dict[str, Any] = {
        **REPO_CONTEXT,
        "deploy_platform": deploy_platform,
        "deploy_portal": deploy_portal,
        "deploy_database": deploy_database,
        "deploy_caddy": deploy_caddy,
    }
    defaults = yaml.safe_load((ROLE / "defaults/main.yml").read_text())
    for name, value in defaults.items():
        if name != "praho_required_inputs":
            context[name] = _jinja().from_string(value).render(context) if isinstance(value, str) else value
    return context
def _required_inputs(topology: str) -> list[str]:
    expression = yaml.safe_load((ROLE / "defaults/main.yml").read_text())["praho_required_inputs"]
    return ast.literal_eval(_jinja().from_string(expression).render(_role_context(topology)))
def _render_role(topology: str, inputs: dict[str, str]) -> dict[str, str]:
    context = {**_role_context(topology), **inputs}
    templates = ["env.j2", "docker-compose.yml.j2", "rollback.sh.j2"]
    if context["deploy_caddy"]:
        templates.append("Caddyfile.j2")
    if context["deploy_database"]:
        templates.append("restore.sh.j2")
        if context["backup_enabled"]:
            templates.append("backup.sh.j2")
    env = _jinja()
    return {name: env.from_string((ROLE / "templates" / name).read_text()).render(context) for name in templates}
def _dummy_inputs(topology: str) -> dict[str, str]:
    return {name: f"dummy-{name}" for name in _required_inputs(topology)}
class TestAnsibleDockerRole:
    @pytest.mark.integration
    @pytest.mark.parametrize("topology", TOPOLOGIES)
    def test_templates_render_from_the_declared_inputs(self, topology: str) -> None:
        _render_role(topology, _dummy_inputs(topology))

    @pytest.mark.integration
    @pytest.mark.parametrize("topology", TOPOLOGIES)
    def test_every_declared_input_is_needed(self, topology: str) -> None:
        inputs = _dummy_inputs(topology)
        for name in inputs:
            with pytest.raises(UndefinedError):
                _render_role(topology, {k: v for k, v in inputs.items() if k != name})

    @pytest.mark.integration
    def test_a_portal_host_holds_no_platform_secret(self) -> None:
        rendered = _render_role("portal-host", _dummy_inputs("portal-host"))
        env_keys = {line.split("=", 1)[0] for line in rendered["env.j2"].splitlines() if "=" in line}
        assert sorted(env_keys & set(DENIED_TO_PORTAL)) == []
        assert "platform" not in yaml.safe_load(rendered["docker-compose.yml.j2"])["services"]

    @pytest.mark.integration
    def test_the_containers_get_what_production_requires(self) -> None:
        rendered = _render_role("combined", _dummy_inputs("combined"))
        services = yaml.safe_load(rendered["docker-compose.yml.j2"])["services"]
        platform, portal = _environment(services["platform"]), _environment(services["portal"])
        for key in (*PLATFORM_KEYS, WEBHOOK):
            assert key in platform, key
        assert WEBHOOK in portal
        assert sorted(set(portal) & set(DENIED_TO_PORTAL)) == []
        env_values = dict(line.split("=", 1) for line in rendered["env.j2"].splitlines() if "=" in line)
        for key, variable in (
            ("DJANGO_ENCRYPTION_KEY", "django_encryption_key"),
            ("CREDENTIAL_VAULT_MASTER_KEY", "credential_vault_master_key"),
            (WEBHOOK, "platform_to_portal_webhook_secret"),
        ):
            assert env_values.get(key) == f"dummy-{variable}", key

    @pytest.mark.integration
    @pytest.mark.parametrize(("topology", "sslmode"), [("combined", "disable"), ("external-db", "require")])
    def test_the_platform_gets_an_sslmode_that_fits_its_database(self, topology: str, sslmode: str) -> None:
        rendered = _render_role(topology, _dummy_inputs(topology))
        env_values = dict(line.split("=", 1) for line in rendered["env.j2"].splitlines() if "=" in line)
        assert env_values["DB_SSLMODE"] == sslmode
        platform = _environment(yaml.safe_load(rendered["docker-compose.yml.j2"])["services"]["platform"])
        assert platform.get("DB_SSLMODE") == "${DB_SSLMODE}"

    @pytest.mark.integration
    def test_the_role_checks_its_inputs_before_anything_else(self) -> None:
        tasks = yaml.safe_load((ROLE / "tasks/main.yml").read_text())
        collect, stop = tasks[0], tasks[1]
        assert collect["loop"] == "{{ praho_required_inputs }}"
        assert collect.get("no_log") is True
        # The failure names the missing variables only, never a value.
        assert "fail" in stop
        assert "praho_missing_inputs" in stop["fail"]["msg"]
        assert "lookup(" not in stop["fail"]["msg"]

    @pytest.mark.integration
    def test_health_is_read_from_the_containers_not_a_host_port(self) -> None:
        tasks_text = (ROLE / "tasks/main.yml").read_text()
        assert not re.search(r"localhost:\{\{ *platform_port *\}\}", tasks_text)
        assert "docker_container_info" in tasks_text
        rollback = (ROLE / "templates/rollback.sh.j2").read_text()
        assert not re.search(r"localhost:\{\{ *platform_port *\}\}", rollback)
        assert "--wait" in rollback

    @pytest.mark.integration
    def test_the_portal_trusts_its_pinned_web_network(self) -> None:
        # Production portal settings refuse to start without PORTAL_TRUSTED_PROXY_CIDRS. Caddy shares
        # the `web` network with the portal, so that network has a known subnet and is trusted by default.
        rendered = _render_role("combined", _dummy_inputs("combined"))
        config = yaml.safe_load(rendered["docker-compose.yml.j2"])
        assert config["networks"]["web"]["ipam"]["config"][0]["subnet"] == WEB_SUBNET
        env_values = dict(line.split("=", 1) for line in rendered["env.j2"].splitlines() if "=" in line)
        assert env_values["PORTAL_TRUSTED_PROXY_CIDRS"] == WEB_SUBNET

    @pytest.mark.integration
    def test_the_platform_start_period_covers_a_first_boot(self) -> None:
        # A first boot runs every migration before Gunicorn listens (124 s measured); a shorter start
        # period marks the platform unhealthy mid-migration and `up` never starts the portal.
        rendered = _render_role("combined", _dummy_inputs("combined"))
        healthcheck = yaml.safe_load(rendered["docker-compose.yml.j2"])["services"]["platform"]["healthcheck"]
        assert _seconds(healthcheck["start_period"]) >= FIRST_BOOT_SECONDS, healthcheck
