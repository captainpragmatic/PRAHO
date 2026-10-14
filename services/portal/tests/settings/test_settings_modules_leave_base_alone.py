"""Importing the dev settings never changes the base settings they build on.

`from .base import *` binds base's own lists and dicts, so an in-place `.insert()`, `+=` or a
nested `LOGGING[...] = ...` in dev.py also changed base. Anything that reads base to stand for
production then saw development values, depending on what the same process imported first.
The module is imported in a fresh interpreter, so the check never depends on this process.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

PORTAL_ROOT = Path(__file__).resolve().parents[2]

PROBE = textwrap.dedent(
    """
    import copy, importlib, json, sys
    base = importlib.import_module("config.settings.base")
    snapshot = {k: copy.deepcopy(v) for k, v in vars(base).items() if k.isupper()}
    importlib.import_module(sys.argv[1])
    print(json.dumps(sorted(k for k, v in snapshot.items() if getattr(base, k) != v)))
    """
)


def test_importing_the_dev_settings_leaves_base_unchanged() -> None:
    env = {k: v for k, v in os.environ.items() if k != "DJANGO_SETTINGS_MODULE"}
    completed = subprocess.run(  # noqa: S603  # fixed interpreter and arguments
        [sys.executable, "-c", PROBE, "config.settings.dev"],
        cwd=PORTAL_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    assert json.loads(completed.stdout.strip().splitlines()[-1]) == []
