"""The portal's dev settings must run in the Docker dev container, not only from the repo.

There the settings live at /app/config/settings/, so the repo-root `.env` lookup must not assume four
parents; and the container reaches the platform at `http://platform:8700/api`, which dev.py used to
overwrite with a hardcoded localhost URL.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

from django.test import SimpleTestCase

PORTAL_ROOT = Path(__file__).resolve().parents[2]


class TestRepoDotenvPath(SimpleTestCase):
    def test_the_container_layout_gives_no_path(self) -> None:
        from config.dotenv_path import repo_dotenv_path  # noqa: PLC0415

        self.assertIsNone(repo_dotenv_path(Path("/app/config/settings/dev.py")))

    def test_the_repo_layout_finds_the_root_env(self) -> None:
        from config.dotenv_path import repo_dotenv_path  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()  # macOS: /var is /private/var
            (root / ".env").write_text("KEY=value\n")
            settings_file = root / "services" / "portal" / "config" / "settings" / "dev.py"
            settings_file.parent.mkdir(parents=True)
            settings_file.write_text("")
            self.assertEqual(repo_dotenv_path(settings_file), root / ".env")


class TestPlatformApiBaseUrl(SimpleTestCase):
    def _dev_setting(self, name: str, extra_env: dict[str, str]) -> str:
        env = {
            key: value for key, value in os.environ.items() if not key.startswith(("DJANGO_", "PYTEST", "PLATFORM_API"))
        }
        env.update(DJANGO_SETTINGS_MODULE="config.settings.dev", PRAHO_SKIP_DOTENV="1", PYTHONPATH=str(PORTAL_ROOT))
        env.update(extra_env)
        code = f"import django; django.setup(); from django.conf import settings; print(settings.{name})"
        result = subprocess.run(  # noqa: S603  # the portal's own settings, imported in a fresh interpreter
            [sys.executable, "-c", code], cwd=PORTAL_ROOT, env=env, capture_output=True, text=True, check=False
        )
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        return result.stdout.strip().splitlines()[-1]

    def test_the_environment_sets_the_platform_url(self) -> None:
        url = self._dev_setting("PLATFORM_API_BASE_URL", {"PLATFORM_API_BASE_URL": "http://platform:8700/api"})
        self.assertEqual(url, "http://platform:8700/api")

    def test_localhost_stays_the_default(self) -> None:
        self.assertEqual(self._dev_setting("PLATFORM_API_BASE_URL", {}), "http://localhost:8700/api")
