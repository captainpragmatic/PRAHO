"""The native unit and management commands use one filtered Portal environment."""

from __future__ import annotations

import os
import secrets
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from jinja2 import Environment, StrictUndefined

ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "deploy/ansible/roles/praho-native"
PORTAL_KEY = secrets.token_urlsafe(64)
API_KEY = secrets.token_urlsafe(48)
PORTAL_SIGNING_KEY = secrets.token_urlsafe(48)  # A portal's own key, never the platform secret


def portal_environment(root: Path, profile: str) -> dict[str, str]:
    tasks = yaml.safe_load((ROLE / "tasks/main.yml").read_text())
    task = next(task for task in tasks if task["name"] == "Set Portal Django environment")
    template = Environment(undefined=StrictUndefined)  # noqa: S701 -- Ansible env values, not HTML.
    context = {
        "project_root": str(root), "platform_port": 8700, "portal_state_directory": str(root / "portal-state"),
        "django_settings_module": f"config.settings.{profile}",
        "deployed_env": {"PORTAL_DOMAIN": "portal.example.test", "PORTAL_DJANGO_SECRET_KEY": PORTAL_KEY,
                         "DJANGO_SECRET_KEY": "s" * 60, "DB_PASSWORD": "private-platform-password",
                         "HMAC_SECRET": API_KEY, "PORTAL_HMAC_SECRET": PORTAL_SIGNING_KEY,
                         "PORTAL_ID": "portal-001"},
    }
    base = {key: template.from_string(str(value)).render(context)
            for key, value in task["vars"]["praho_portal_env_base"].items()}
    passthrough = {key: value for key, value in context["deployed_env"].items()
                   if key in task["vars"]["praho_passthrough"]}
    return {**base, **passthrough}


@pytest.mark.parametrize("profile", ["prod", "staging"])
def test_collectstatic_and_rendered_portal_use_the_caddy_directory(tmp_path: Path, profile: str) -> None:
    environment = portal_environment(tmp_path, profile)
    assert environment["STATIC_ROOT"] == str(tmp_path / "portal-static")
    assert environment["DJANGO_SECRET_KEY"] == PORTAL_KEY
    assert not {"DB_PASSWORD", "CREDENTIAL_VAULT_MASTER_KEY", "DJANGO_ENCRYPTION_KEY", "HMAC_SECRET"} & environment.keys()
    environment["PORTAL_LOG_DIR"] = ""
    environment["PLATFORM_TO_PORTAL_WEBHOOK_SECRET"] = "w" * 48
    code = '''
import django
from django.core.management import call_command
from django.template.loader import render_to_string
from django.contrib.staticfiles.storage import staticfiles_storage
from django.test import RequestFactory
django.setup()
call_command("collectstatic", interactive=False, verbosity=0)
request = RequestFactory().get("/")
request.session = {}
url = staticfiles_storage.url("js/csp-actions.js")
assert url in render_to_string("base.html", request=request)
print(url)
'''
    completed = subprocess.run(  # noqa: S603 -- fixed test program and a temporary artifact directory.
        [sys.executable, "-c", code], cwd=ROOT / "services/portal",
        env={key: value for key, value in {**os.environ, **environment, "PYTHONDONTWRITEBYTECODE": "1",
                                         "PRAHO_SKIP_DOTENV": "1", "PYTHONPATH": ""}.items()
             if key not in {"DB_PASSWORD", "CREDENTIAL_VAULT_MASTER_KEY", "DJANGO_ENCRYPTION_KEY"}},
        capture_output=True, text=True, timeout=90, check=False,
    )
    assert completed.returncode == 0, completed.stderr[-3000:]
    url = completed.stdout.strip().splitlines()[-1]
    assert url.startswith("/static/js/csp-actions")
    assert (tmp_path / "portal-static" / url.removeprefix("/static/")).is_file()
    assert not (tmp_path / "static/js/csp-actions.js").exists()
    assert "root * {{ project_root }}/portal-static" in (ROLE / "templates/Caddyfile.native.j2").read_text()


def test_unit_and_counter_cron_only_read_filtered_environment() -> None:
    unit = (ROLE / "templates/praho-portal.service.j2").read_text()
    assert "EnvironmentFile={{ project_root }}/.portal.env" in unit
    assert "EnvironmentFile={{ project_root }}/.env\n" not in unit
    tasks = yaml.safe_load((ROLE / "tasks/main.yml").read_text())
    install = next(task for task in tasks if task["name"] == "Install filtered Portal runtime environment")
    assert install["copy"]["content"] == "{{ portal_django_env | native_systemd_env }}"
    assert install["no_log"] and install["diff"] is False and install["copy"]["mode"] == "0640"
    cron = next(task for task in tasks if task["name"] == "Setup Portal counter cull cron job")
    assert ".portal.env" in cron["cron"]["job"]
    assert ". {{ project_root }}/.env " not in cron["cron"]["job"]
