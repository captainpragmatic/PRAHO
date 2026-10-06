"""A deployment runs the Django settings module of its environment, not always production's.

Every Docker path hardcoded `DJANGO_SETTINGS_MODULE=config.settings.prod`: the standalone Compose files in
their `environment:` lists, and the Ansible Docker role in its rendered compose file and `.env`. A
staging deployment therefore ran production settings, and every staging-only Django setting was
ignored there, even though `.env.example.staging` sets `config.settings.staging` and the Ansible
group vars already derive `django_settings_module` from `praho_env` (which the native role uses).

The Compose files now take the module from the environment, with production as the default when
it is unset, and the Ansible Docker role uses `django_settings_module`.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEPLOY = PROJECT_ROOT / "deploy"
FROM_ENVIRONMENT = "${DJANGO_SETTINGS_MODULE:-config.settings.prod}"
FROM_ANSIBLE = "{{ django_settings_module }}"

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
# The whole value to the end of the line, so `{{ django_settings_module }}` is read intact.
_MODULE_VALUE = re.compile(r"DJANGO_SETTINGS_MODULE[=:][ \t]*(.+?)[ \t]*$", re.MULTILINE)


def _module_values(path: Path) -> list[str]:
    return _MODULE_VALUE.findall(path.read_text())


class TestSettingsModuleSelection:
    @pytest.mark.integration
    @pytest.mark.parametrize("name", PRODUCTION_FAMILY_COMPOSE)
    def test_compose_takes_the_module_from_the_environment(self, name: str) -> None:
        values = _module_values(DEPLOY / name)
        assert values, f"{name} sets no DJANGO_SETTINGS_MODULE at all"
        assert set(values) == {FROM_ENVIRONMENT}, values

    @pytest.mark.integration
    @pytest.mark.parametrize("name", DOCKER_ROLE_TEMPLATES)
    def test_ansible_docker_role_uses_the_derived_module(self, name: str) -> None:
        values = _module_values(DEPLOY / name)
        assert values, f"{name} sets no DJANGO_SETTINGS_MODULE at all"
        assert set(values) == {FROM_ANSIBLE}, values

    @pytest.mark.integration
    def test_the_docker_role_can_derive_the_module_on_its_own(self) -> None:
        defaults = (DEPLOY / "ansible/roles/praho/defaults/main.yml").read_text()
        assert "django_settings_module: \"config.settings.{{ praho_env | default('prod') }}\"" in defaults

    @pytest.mark.integration
    @pytest.mark.parametrize(("environment", "module"), [("staging", "staging"), ("prod", "prod")])
    def test_env_examples_name_their_own_module(self, environment: str, module: str) -> None:
        example = (PROJECT_ROOT / f".env.example.{environment}").read_text()
        assert re.search(rf"^DJANGO_SETTINGS_MODULE=config\.settings\.{module}\b", example, re.MULTILINE)
