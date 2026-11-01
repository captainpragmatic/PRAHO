"""Opt-in customer Portal for the isolated two-service maintenance acceptance lab."""

import hashlib
import json
import os
import stat
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

_PRIVATE_AUTHORITY_MODE = 0o600
_MAX_AUTHORITY_BYTES = 4096
_MIN_AUTHORITY_SECRET_LENGTH = 50
_MIN_LAB_PORT = 1024
_MAX_LAB_PORT = 65535

try:
    if os.environ.get("VIRTUALMIN_MAINTENANCE_LAB") != "1":
        raise ValueError("Explicit local mode is required")
    _authority_path = Path(os.environ["VIRTUALMIN_MAINTENANCE_AUTHORITY"])
    _authority_stat = _authority_path.lstat()
    if not stat.S_ISREG(_authority_stat.st_mode) or stat.S_IMODE(_authority_stat.st_mode) != _PRIVATE_AUTHORITY_MODE:
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
except (KeyError, OSError, TypeError, ValueError) as _error:
    raise ImproperlyConfigured("A private maintenance lab authority is required") from _error

os.environ["PRAHO_SKIP_DOTENV"] = "1"

from .dev import *  # noqa: E402, F403 -- explicit lab overrides follow hardcoded dev defaults

VIRTUALMIN_MAINTENANCE_LAB = True
SECRET_KEY = hashlib.sha256((_authority["secret"] + ":portal").encode()).hexdigest()
PLATFORM_API_SECRET = _authority["secret"]
PORTAL_HMAC_SECRET = _authority["secret"]
PORTAL_ID = "virtualmin-maintenance-lab"
PLATFORM_API_BASE_URL = f"http://127.0.0.1:{_authority['platform_port']}/api"
ALLOWED_HOSTS = ["127.0.0.1"]
CSRF_TRUSTED_ORIGINS = [f"http://127.0.0.1:{_authority['portal_port']}"]
SESSION_COOKIE_NAME = "maintenance_lab_portal"
CSRF_COOKIE_NAME = "maintenance_lab_portal_csrf"
MIDDLEWARE = [middleware for middleware in MIDDLEWARE if "debug_toolbar" not in middleware]
DATABASES = {
    "default": {"ENGINE": "django.db.backends.sqlite3", "NAME": _run_dir / "portal.sqlite3", "OPTIONS": {"timeout": 30}}
}
