"""A deployment runs the Django settings module of its environment, not always production's.

Every Docker path hardcoded `DJANGO_SETTINGS_MODULE=config.settings.prod`: the standalone Compose files in
their `environment:` lists, and the Ansible Docker role in its rendered compose file and `.env`. A
staging deployment therefore ran production settings, and every staging-only Django setting was
ignored there, even though `.env.example.staging` sets `config.settings.staging`.

The Compose files now take the module from the environment, with production as the default when
it is unset. The Ansible Docker role uses its own `docker_django_settings_module`: staging for
staging, production for everything else. It cannot follow the group vars' `django_settings_module`,
because the images are built without the dev dependency group and `config.settings.dev` adds
debug_toolbar, so the dev inventory's containers would fail at startup.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from jinja2 import Environment, StrictUndefined

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEPLOY = PROJECT_ROOT / "deploy"
FROM_ENVIRONMENT = "${DJANGO_SETTINGS_MODULE:-config.settings.prod}"
FROM_ANSIBLE = "{{ docker_django_settings_module }}"

# The production-family Compose files: each must let `.env` choose staging. The dev and local
# all-in-Docker stacks pin config.settings.dev on purpose and are not listed.
PRODUCTION_FAMILY_COMPOSE = (
    "docker-compose.single-server.yml",
    "docker-compose.platform-only.yml",
    "docker-compose.portal-only.yml",
    "docker-compose.container-service.yml",
)
DOCKER_ROLE_TEMPLATES = (
    "ansible/roles/praho/templates/docker-compose.yml.j2",
    "ansible/roles/praho/templates/env.j2",
)
# An active assignment only: a Compose list item or an env line, never a commented-out one. The
# value runs to the end of the line, so `{{ docker_django_settings_module }}` is read intact.
_MODULE_VALUE = re.compile(r"^[ \t]*(?:-[ \t]+)?DJANGO_SETTINGS_MODULE[=:][ \t]*(.+?)[ \t]*$", re.MULTILINE)
_ROLE_DEFAULT = re.compile(r'^docker_django_settings_module: "(.+)"$', re.MULTILINE)


def _module_values(path: Path) -> list[str]:
    return _MODULE_VALUE.findall(path.read_text())


def _docker_role_module(praho_env: str | None) -> str:
    defaults = (DEPLOY / "ansible/roles/praho/defaults/main.yml").read_text()
    match = _ROLE_DEFAULT.search(defaults)
    assert match, "the Docker role has no docker_django_settings_module default"
    context = {} if praho_env is None else {"praho_env": praho_env}
    env = Environment(undefined=StrictUndefined, autoescape=False)  # noqa: S701  # A YAML value, not HTML.
    return env.from_string(match.group(1)).render(context)


class TestSettingsModuleSelection:
    @pytest.mark.integration
    @pytest.mark.parametrize("name", PRODUCTION_FAMILY_COMPOSE)
    def test_compose_takes_the_module_from_the_environment(self, name: str) -> None:
        values = _module_values(DEPLOY / name)
        assert values, f"{name} sets no DJANGO_SETTINGS_MODULE at all"
        assert set(values) == {FROM_ENVIRONMENT}, values

    @pytest.mark.integration
    @pytest.mark.parametrize("name", DOCKER_ROLE_TEMPLATES)
    def test_ansible_docker_role_uses_its_own_module(self, name: str) -> None:
        values = _module_values(DEPLOY / name)
        assert values, f"{name} sets no DJANGO_SETTINGS_MODULE at all"
        assert set(values) == {FROM_ANSIBLE}, values

    @pytest.mark.integration
    @pytest.mark.parametrize(
        ("praho_env", "module"),
        [
            ("staging", "config.settings.staging"),
            ("prod", "config.settings.prod"),
            # inventory/dev.yml: the images lack the dev dependency group, so dev settings cannot start
            ("dev", "config.settings.prod"),
            (None, "config.settings.prod"),
        ],
    )
    def test_the_docker_role_runs_only_settings_its_images_support(self, praho_env: str | None, module: str) -> None:
        assert _docker_role_module(praho_env) == module

    @pytest.mark.integration
    def test_a_commented_out_assignment_does_not_count(self) -> None:
        text = (
            "    environment:\n"
            "      # - DJANGO_SETTINGS_MODULE=config.settings.prod\n"
            "      - DJANGO_SETTINGS_MODULE=${DJANGO_SETTINGS_MODULE:-config.settings.prod}\n"
            "#DJANGO_SETTINGS_MODULE=config.settings.dev\n"
            "DJANGO_SETTINGS_MODULE={{ docker_django_settings_module }}\n"
        )
        assert _MODULE_VALUE.findall(text) == [FROM_ENVIRONMENT, FROM_ANSIBLE]

    @pytest.mark.integration
    @pytest.mark.parametrize(("environment", "module"), [("staging", "staging"), ("prod", "prod")])
    def test_env_examples_name_their_own_module(self, environment: str, module: str) -> None:
        example = (PROJECT_ROOT / f".env.example.{environment}").read_text()
        assert re.search(rf"^DJANGO_SETTINGS_MODULE=config\.settings\.{module}\b", example, re.MULTILINE)
