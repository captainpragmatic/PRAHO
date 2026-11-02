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

import base64
import hashlib
import json
import os
import stat
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured
from dotenv import dotenv_values

_PRIVATE_AUTHORITY_MODE = 0o600
_MAX_AUTHORITY_BYTES = 4096
_MIN_AUTHORITY_SECRET_LENGTH = 50
_MIN_LAB_PORT = 1024
_MAX_LAB_PORT = 65535

_LAB_STATE_DIR = Path(__file__).resolve().parents[4] / "deploy" / "virtualmin-lab" / ".state"
_LAB_ENV_FILE = _LAB_STATE_DIR / "django.env"
_MAINTENANCE_MODE = os.environ.get("VIRTUALMIN_MAINTENANCE_LAB") == "1"
if _MAINTENANCE_MODE:
    try:
        _authority_path = Path(os.environ["VIRTUALMIN_MAINTENANCE_AUTHORITY"])
        _authority_stat = _authority_path.lstat()
        if (
            not stat.S_ISREG(_authority_stat.st_mode)
            or stat.S_IMODE(_authority_stat.st_mode) != _PRIVATE_AUTHORITY_MODE
        ):
            raise ValueError("Authority must be a private regular file")
        if _authority_stat.st_uid != os.getuid() or _authority_stat.st_size > _MAX_AUTHORITY_BYTES:
            raise ValueError("Authority must be small and locally owned")
        _authority = json.loads(_authority_path.read_text())
        if set(_authority) != {"secret", "platform_port", "portal_port"}:
            raise ValueError("Unknown authority fields")
        if not isinstance(_authority["secret"], str) or len(_authority["secret"]) < _MIN_AUTHORITY_SECRET_LENGTH:
            raise ValueError("A fresh authority is required")
        if any(
            type(_authority[_name]) is not int or not _MIN_LAB_PORT <= _authority[_name] <= _MAX_LAB_PORT
            for _name in ("platform_port", "portal_port")
        ):
            raise ValueError("Invalid local listener ports")
        if _authority["platform_port"] == _authority["portal_port"]:
            raise ValueError("Two distinct listeners are required")
        _run_dir = _authority_path.resolve().parent
        _database = Path(os.environ["VIRTUALMIN_LAB_DATABASE"]).resolve()
        if _database.parent != _run_dir or _database.name not in {"seed.sqlite3", "platform.sqlite3"}:
            raise ValueError("Only the owned acceptance database may be opened")
    except (KeyError, OSError, TypeError, ValueError) as _error:
        raise ImproperlyConfigured("A private maintenance lab authority and owned database are required") from _error
    os.environ["DJANGO_ENCRYPTION_KEY"] = base64.urlsafe_b64encode(
        hashlib.sha256((_authority["secret"] + ":encryption").encode()).digest()
    ).decode()
else:
    if not _LAB_ENV_FILE.is_file():
        raise ImproperlyConfigured(f"{_LAB_ENV_FILE} is missing; run `make virtualmin-lab-up` first")
    for _key, _value in dotenv_values(_LAB_ENV_FILE).items():
        if _value is not None:
            os.environ[_key] = _value
os.environ["PRAHO_SKIP_DOTENV"] = "1"

from .dev import *  # noqa: E402, F403  # Django settings pattern

VIRTUALMIN_LAB_STATE_DIR = _LAB_STATE_DIR
PRAHO_SSH_OPERATOR_PUBLIC_KEYS_FILE = str(_LAB_STATE_DIR / "operator_authorized_keys")
VIRTUALMIN_IMPORTED_SSH_PRIVATE_KEY_PATH = os.environ.get(
    "VIRTUALMIN_IMPORTED_SSH_PRIVATE_KEY_PATH", str(_LAB_STATE_DIR / "component-source" / "identity")
)
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.environ.get("VIRTUALMIN_LAB_DATABASE") or str(BASE_DIR / "db-virtualmin-lab.sqlite3"),
        "OPTIONS": {"timeout": 30},
    }
}

if _MAINTENANCE_MODE:
    # HTTP and the scoped worker share this owned file. Reserve short writes
    # before their reads so SQLite cannot fail a later read-to-write upgrade.
    DATABASES["default"]["OPTIONS"]["transaction_mode"] = "IMMEDIATE"
    VIRTUALMIN_MAINTENANCE_LAB = True
    VIRTUALMIN_MAINTENANCE_MANIFEST = _run_dir / "manifest.json"
    VIRTUALMIN_MAINTENANCE_PLATFORM_ADDRESS = f"127.0.0.1:{_authority['platform_port']}"
    SECRET_KEY = hashlib.sha256((_authority["secret"] + ":platform").encode()).hexdigest()
    PLATFORM_API_SECRET = _authority["secret"]
    PORTAL_HMAC_MODE = "enforce"
    PORTAL_HMAC_CREDENTIALS = json.dumps({"virtualmin-maintenance-lab": _authority["secret"]})
    ALLOWED_HOSTS = ["127.0.0.1"]
    PORTAL_PUBLIC_ORIGIN = f"http://127.0.0.1:{_authority['portal_port']}"
    CSRF_TRUSTED_ORIGINS = [f"http://127.0.0.1:{_authority['platform_port']}"]
    SESSION_COOKIE_NAME = "maintenance_lab_platform"
    CSRF_COOKIE_NAME = "maintenance_lab_platform_csrf"
    # Dev disables CSRF for convenience; this real HTTP acceptance mode exercises it.
    MIDDLEWARE = [middleware for middleware in MIDDLEWARE if "debug_toolbar" not in middleware]
    if "django.middleware.csrf.CsrfViewMiddleware" not in MIDDLEWARE:
        MIDDLEWARE.insert(
            MIDDLEWARE.index("django.contrib.auth.middleware.AuthenticationMiddleware"),
            "django.middleware.csrf.CsrfViewMiddleware",
        )
    EMAIL_BACKEND = "django.core.mail.backends.filebased.EmailBackend"
    EMAIL_FILE_PATH = str(_run_dir / "mail")
    Q_CLUSTER = {**Q_CLUSTER, "name": "maintenance-lab", "orm": "default", "sync": False}
