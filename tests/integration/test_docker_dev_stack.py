"""`make docker-dev` must start: dev images whose venv survives the source mount, Postgres for the platform.

The dev stack built the production images and mounted the source over /app, which hid the image's
venv and entrypoint; the production venv lacks the debug toolbar and colorlog that config.settings.dev
imports; the platform was never told to use Postgres; and the portal wrote its session database into
the mounted checkout. The images are proven by real builds; these tests hold the stack's wiring.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEV_COMPOSE = PROJECT_ROOT / "deploy/docker-compose.dev.yml"


def _service(name: str) -> dict[str, Any]:
    service: dict[str, Any] = yaml.safe_load(DEV_COMPOSE.read_text())["services"][name]
    return service


def _environment(name: str) -> dict[str, str]:
    return dict(str(entry).split("=", 1) for entry in _service(name)["environment"])


class TestDevStack:
    @pytest.mark.integration
    @pytest.mark.parametrize("name", ["platform", "portal"])
    def test_each_service_builds_the_dev_target_with_its_venv_outside_the_mount(self, name: str) -> None:
        assert _service(name)["build"]["target"] == "dev"
        dockerfile = (PROJECT_ROOT / "deploy" / name / "Dockerfile").read_text()
        stages = re.split(r"^FROM ", dockerfile, flags=re.MULTILINE)[1:]
        dev_builder = next(s for s in stages if s.split("\n", 1)[0].endswith(" AS dev-builder"))
        assert "ENV UV_PROJECT_ENVIRONMENT=/opt/venv" in dev_builder
        assert "--no-dev" not in dev_builder
        assert any(f"../services/{name}:/app" in str(v) for v in _service(name)["volumes"])

    @pytest.mark.integration
    def test_the_platform_uses_the_stack_postgres(self) -> None:
        environment = _environment("platform")
        assert environment["USE_POSTGRES"] == "true"
        assert environment["DB_HOST"] == "db"

    @pytest.mark.integration
    def test_the_portal_keeps_its_session_database_out_of_the_checkout(self) -> None:
        path = _environment("portal")["SESSION_DB_PATH"]
        assert not path.startswith("/app/")
        mounts = {str(v).split(":")[1]: str(v).split(":")[0] for v in _service("portal")["volumes"]}
        directory = str(Path(path).parent)
        assert directory in mounts and not mounts[directory].startswith(".")

    @pytest.mark.integration
    def test_the_make_targets_use_compose_v2(self) -> None:
        recipes = re.findall(
            r"^docker-(?:dev|stop|clean):.*\n((?:\t.*\n)+)", (PROJECT_ROOT / "Makefile").read_text(), re.MULTILINE
        )
        assert len(recipes) == 3
        assert [r for r in recipes if "docker-compose " in r] == []

    @pytest.mark.integration
    @pytest.mark.parametrize("name", ["platform", "portal"])
    def test_debug_is_spelled_the_way_the_settings_parse_it(self, name: str) -> None:
        # The portal's base.py reads DEBUG as `.lower() == "true"`; "1" made it derive production values
        # (secure-only session cookies, an https redirect, the production cache) before dev.py ran.
        settings = (PROJECT_ROOT / "services/portal/config/settings/base.py").read_text()
        assert 'DEBUG = os.environ.get("DEBUG", "True").lower() == "true"' in settings
        assert _environment(name)["DEBUG"].lower() == "true"
