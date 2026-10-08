"""A deployment runs the Django settings module of its environment, not always production's.

The Compose files hardcoded `DJANGO_SETTINGS_MODULE=config.settings.prod` in their `environment:` lists, so
a staging deployment ran production settings and every staging-only Django setting was ignored there,
even though `.env.example.staging` sets `config.settings.staging`. They now take the module from the
environment, with production as the default when it is unset.

Staging settings default `STATIC_ROOT` to the native layout's `/opt/praho/static`, which the image's
non-root user cannot create, and the platform entrypoint runs collectstatic on every start. So each
platform container sets `STATIC_ROOT` to the image's own `/app/staticfiles`.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEPLOY = PROJECT_ROOT / "deploy"
FROM_ENVIRONMENT = "${DJANGO_SETTINGS_MODULE:-config.settings.prod}"
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
PLATFORM_COMPOSE = tuple(name for name, services in PRODUCTION_FAMILY_COMPOSE.items() if "platform" in services)

# An active assignment only: a Compose list item or an env line, never a commented-out one.
_MODULE_VALUE = re.compile(r"^[ \t]*(?:-[ \t]+)?DJANGO_SETTINGS_MODULE[=:][ \t]*(.+?)[ \t]*$", re.MULTILINE)
_STATIC_ROOT = re.compile(r"^[ \t]*-[ \t]+STATIC_ROOT=(.+?)[ \t]*$", re.MULTILINE)


def _service(name: str, service: str) -> str:
    """One service's block: up to the next top-level key or banner. Template tags do not end it."""
    text = (DEPLOY / name).read_text()
    match = re.search(rf"^  {service}:\n.*?(?=^ {{0,2}}[a-z#]|\Z)", text, re.MULTILINE | re.DOTALL)
    assert match, f"{name} has no {service} service"
    return match.group(0)


class TestSettingsModuleSelection:
    @pytest.mark.integration
    @pytest.mark.parametrize("name", PRODUCTION_FAMILY_COMPOSE)
    def test_compose_takes_the_module_from_the_environment(self, name: str) -> None:
        services = PRODUCTION_FAMILY_COMPOSE[name]
        for service in services:
            assert _MODULE_VALUE.findall(_service(name, service)) == [FROM_ENVIRONMENT], service
        assert _MODULE_VALUE.findall((DEPLOY / name).read_text()) == [FROM_ENVIRONMENT] * len(services)

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
            "DJANGO_SETTINGS_MODULE=config.settings.staging\n"
        )
        assert _MODULE_VALUE.findall(text) == [FROM_ENVIRONMENT, "config.settings.staging"]

    @pytest.mark.integration
    @pytest.mark.parametrize(("environment", "module"), [("staging", "staging"), ("prod", "prod")])
    def test_env_examples_name_their_own_module(self, environment: str, module: str) -> None:
        example = (PROJECT_ROOT / f".env.example.{environment}").read_text()
        # The module must end the value; only whitespace or an inline comment may follow it.
        pattern = rf"^DJANGO_SETTINGS_MODULE=config\.settings\.{module}(?=[ \t]*(?:#|$))"
        assert re.search(pattern, example, re.MULTILINE)
