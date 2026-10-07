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

Staging settings default `STATIC_ROOT` to the native layout's `/opt/praho/static`, which the image's
non-root user cannot create, and the platform entrypoint runs collectstatic on every start. So each
platform container sets `STATIC_ROOT` to the image's own `/app/staticfiles`.
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
CONTAINER_STATIC_ROOT = "/app/staticfiles"

# The production-family Compose files and the Django services in each: every one must let the env
# file choose staging. The dev stack (`make docker-dev`) pins config.settings.dev on purpose and is
# not listed.
PRODUCTION_FAMILY_COMPOSE = {
    "docker-compose.single-server.yml": ("platform", "portal"),
    "docker-compose.platform-only.yml": ("platform",),
    "docker-compose.portal-only.yml": ("portal",),
    "docker-compose.container-service.yml": ("platform", "portal"),
}
ANSIBLE_COMPOSE = "ansible/roles/praho/templates/docker-compose.yml.j2"
ANSIBLE_ENV = "ansible/roles/praho/templates/env.j2"
PLATFORM_COMPOSE = (*(name for name, services in PRODUCTION_FAMILY_COMPOSE.items() if "platform" in services), ANSIBLE_COMPOSE)

# An active assignment only: a Compose list item or an env line, never a commented-out one. The
# value runs to the end of the line, so `{{ docker_django_settings_module }}` is read intact.
_MODULE_VALUE = re.compile(r"^[ \t]*(?:-[ \t]+)?DJANGO_SETTINGS_MODULE[=:][ \t]*(.+?)[ \t]*$", re.MULTILINE)
_STATIC_ROOT = re.compile(r"^[ \t]*-[ \t]+STATIC_ROOT=(.+?)[ \t]*$", re.MULTILINE)
_ROLE_DEFAULT = re.compile(r'^docker_django_settings_module: "(.+)"$', re.MULTILINE)


def _service(name: str, service: str) -> str:
    """One service's block: up to the next top-level key or banner. Template tags do not end it."""
    text = (DEPLOY / name).read_text()
    match = re.search(rf"^  {service}:\n.*?(?=^ {{0,2}}[a-z#]|\Z)", text, re.MULTILINE | re.DOTALL)
    assert match, f"{name} has no {service} service"
    return match.group(0)


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
        services = PRODUCTION_FAMILY_COMPOSE[name]
        for service in services:
            assert _MODULE_VALUE.findall(_service(name, service)) == [FROM_ENVIRONMENT], service
        assert _MODULE_VALUE.findall((DEPLOY / name).read_text()) == [FROM_ENVIRONMENT] * len(services)

    @pytest.mark.integration
    def test_ansible_docker_role_uses_its_own_module(self) -> None:
        for service in ("platform", "portal"):
            assert _MODULE_VALUE.findall(_service(ANSIBLE_COMPOSE, service)) == [FROM_ANSIBLE], service
        assert _MODULE_VALUE.findall((DEPLOY / ANSIBLE_COMPOSE).read_text()) == [FROM_ANSIBLE] * 2
        assert _MODULE_VALUE.findall((DEPLOY / ANSIBLE_ENV).read_text()) == [FROM_ANSIBLE]

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
    @pytest.mark.parametrize("name", PLATFORM_COMPOSE)
    def test_platform_containers_collect_static_into_the_image(self, name: str) -> None:
        assert _STATIC_ROOT.findall(_service(name, "platform")) == [CONTAINER_STATIC_ROOT]

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
        # The module must end the value; only whitespace or an inline comment may follow it.
        pattern = rf"^DJANGO_SETTINGS_MODULE=config\.settings\.{module}(?=[ \t]*(?:#|$))"
        assert re.search(pattern, example, re.MULTILINE)
