"""The payment webhook URL the platform is configured with must exist on the portal.

The platform tells the portal a payment settled by POSTing to ``PORTAL_PAYMENT_WEBHOOK_URL``.
The dev and e2e defaults named paths the portal does not mount, so every notification got a
404 that the sender logs and moves on from. The portal mounts the orders app at ``order/``.

Both services own a top-level ``apps`` package, so the portal URLconf is resolved in its own
process, the way ``test_portal_signature_verifies_on_platform`` runs the portal client.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PLATFORM_SETTINGS = REPO_ROOT / "services" / "platform" / "config" / "settings"
PORTAL = REPO_ROOT / "services" / "portal"
SETTING = "PORTAL_PAYMENT_WEBHOOK_URL"
# Every platform settings module that defines the setting. The count is pinned so a new
# definition is added here on purpose instead of going unchecked.
DEFINING_MODULES = ("dev.py", "e2e.py")

RESOLVER = """
import sys
import django
django.setup()
from django.urls import resolve
match = resolve(sys.argv[1])
print(match.url_name, match.func.__name__)
"""


def _default_url(module: str) -> str:
    """The URL a settings module falls back to, read from source without importing it."""
    tree = ast.parse((PLATFORM_SETTINGS / module).read_text())
    found: list[str] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Assign) and any(getattr(t, "id", "") == SETTING for t in node.targets)):
            continue
        value = node.value
        if isinstance(value, ast.Call):  # os.environ.get(NAME, default)
            value = value.args[1]
        assert isinstance(value, ast.Constant) and isinstance(value.value, str), (module, ast.dump(node))
        found.append(value.value)
    assert len(found) == 1, f"{module} must define {SETTING} exactly once, found {found}"
    return found[0]


def _resolve_on_portal(path: str) -> str:
    env = {**os.environ, "DJANGO_SETTINGS_MODULE": "config.settings.dev", "PYTHONPATH": ""}
    result = subprocess.run(  # noqa: S603  # fixed interpreter and fixed script
        [sys.executable, "-c", RESOLVER, path],
        cwd=PORTAL,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if result.returncode != 0:
        return f"UNRESOLVED {path}: {result.stderr.strip().splitlines()[-1:]}"
    return result.stdout.strip()


@pytest.mark.integration
class TestPaymentWebhookUrlDefaults:
    def test_the_defining_modules_are_the_ones_checked(self) -> None:
        defining = sorted(
            p.name for p in PLATFORM_SETTINGS.glob("*.py") if f"{SETTING} =" in p.read_text()
        )
        assert defining == sorted(DEFINING_MODULES)

    @pytest.mark.parametrize("module", DEFINING_MODULES)
    def test_the_default_path_is_the_portal_payment_webhook(self, module: str) -> None:
        path = urlparse(_default_url(module)).path

        assert _resolve_on_portal(path) == "payment_webhook payment_success_webhook"
