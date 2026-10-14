"""Importing an environment's settings never changes the base settings it builds on.

dev.py inserted the debug toolbar into MIDDLEWARE with `.insert()`, and `from .base import *`
binds the very same list, so base's MIDDLEWARE changed too. A test that copies base's middleware
to stand for production then got the toolbar whenever an earlier test in the same worker had
imported the dev settings. Under the parallel runner that made tests.users.test_staff_mfa_policy
fail now and then with "debug_toolbar.models.HistoryEntry isn't in INSTALLED_APPS".

Each module is imported in a fresh interpreter, so the check never depends on what this process
imported before.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase

PROBE = textwrap.dedent(
    """
    import copy, importlib, json, sys
    base = importlib.import_module("config.settings.base")
    snapshot = {k: copy.deepcopy(v) for k, v in vars(base).items() if k.isupper()}
    importlib.import_module(sys.argv[1])
    print(json.dumps(sorted(k for k, v in snapshot.items() if getattr(base, k) != v)))
    """
)


class SettingsModulesLeaveBaseAloneTests(SimpleTestCase):
    def test_importing_each_environment_leaves_base_unchanged(self) -> None:
        env = {**os.environ, "DJANGO_SECRET_KEY": "k" * 64}
        env.pop("DJANGO_SETTINGS_MODULE", None)
        for module in ("config.settings.dev", "config.settings.e2e", "config.settings.ci", "config.settings.test"):
            with self.subTest(module=module):
                completed = subprocess.run(  # noqa: S603  # fixed interpreter and arguments
                    [sys.executable, "-c", PROBE, module],
                    cwd=Path(settings.BASE_DIR),
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr[-2000:])
                changed = json.loads(completed.stdout.strip().splitlines()[-1])
                self.assertEqual(changed, [], f"{module} changed base settings in place")
