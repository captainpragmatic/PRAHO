"""
Virtualmin lab settings (deploy/virtualmin-lab): development settings with a
dedicated SQLite database, so lab runs never touch the developer's dev data.

Keys come from deploy/virtualmin-lab/.state/django.env, which `lab.sh up`
generates once per checkout. Local only; never used by any deployment.

`VIRTUALMIN_LAB_DATABASE` points the settings at another SQLite file. The browser smoke tests
(`make test-virtualmin-e2e`) run against a copy of the lab database, so the server they start and the
test process share one file while the lab database itself, and the suites that use it, stay untouched.
"""

from __future__ import annotations

import os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured
from dotenv import dotenv_values

_LAB_STATE_DIR = Path(__file__).resolve().parents[4] / "deploy" / "virtualmin-lab" / ".state"
_LAB_ENV_FILE = _LAB_STATE_DIR / "django.env"
if not _LAB_ENV_FILE.is_file():
    raise ImproperlyConfigured(f"{_LAB_ENV_FILE} is missing; run `make virtualmin-lab-up` first")
for _key, _value in dotenv_values(_LAB_ENV_FILE).items():
    if _value is not None:
        os.environ[_key] = _value
os.environ["PRAHO_SKIP_DOTENV"] = "1"

from .dev import *  # noqa: E402, F403  # Django settings pattern

VIRTUALMIN_LAB_STATE_DIR = _LAB_STATE_DIR
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.environ.get("VIRTUALMIN_LAB_DATABASE") or str(BASE_DIR / "db-virtualmin-lab.sqlite3"),
        "OPTIONS": {"timeout": 30},
    }
}
