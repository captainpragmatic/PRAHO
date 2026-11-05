"""Opt-in real Portal for one private native UI run, with local session/counter SQLite only."""

import hashlib
import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from django.core.exceptions import ImproperlyConfigured

_FIELDS = {
    "schema",
    "owner",
    "run",
    "authority",
    "instance",
    "secret",
    "platform_port",
    "portal_port",
    "expires_at",
    "phase",
    "seal",
}
_FILE_MODE = 0o600
_MAX_BYTES = 8192
_MIN_SECRET = 64
_MIN_PORT = 1024
_MAX_PORT = 65535
_DIGEST_LENGTH = 64
try:
    if os.environ.get("PRAHO_NATIVE_UI") != "1":
        raise ValueError("Explicit native Portal mode is required")
    _ui_path = Path(os.environ["PRAHO_NATIVE_UI_AUTHORITY"])
    with os.fdopen(os.open(_ui_path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as _source:
        _info = os.fstat(_source.fileno())
        if (
            not stat.S_ISREG(_info.st_mode)
            or stat.S_IMODE(_info.st_mode) != _FILE_MODE
            or _info.st_uid != os.getuid()
            or _info.st_size > _MAX_BYTES
        ):
            raise ValueError("A private owned UI authority is required")
        _raw_ui = _source.read(_MAX_BYTES + 1)
        if hashlib.sha256(_raw_ui).hexdigest() != os.environ["PRAHO_NATIVE_UI_AUTHORITY_SHA256"]:
            raise ValueError("Native UI authority differs from the coordinator's frozen instance")
        _ui = json.loads(_raw_ui)
    if (
        not isinstance(_ui, dict)
        or set(_ui) != _FIELDS
        or type(_ui["schema"]) is not int
        or _ui["schema"] != 1
        or _ui["owner"] != "praho-native-ui"
        or _ui["phase"] != "serving"
        or not isinstance(_ui["secret"], str)
        or len(_ui["secret"]) < _MIN_SECRET
        or any(not isinstance(_ui[key], str) or str(UUID(_ui[key])) != _ui[key] for key in ("run", "instance"))
        or any(
            type(_ui[key]) is not int or not _MIN_PORT <= _ui[key] <= _MAX_PORT
            for key in ("platform_port", "portal_port")
        )
        or _ui["platform_port"] == _ui["portal_port"]
        or any(not isinstance(_ui[key], str) or len(_ui[key]) != _DIGEST_LENGTH for key in ("authority", "seal"))
    ):
        raise ValueError("Invalid UI authority scope or listeners")
    _expiry = datetime.fromisoformat(_ui["expires_at"])
    if _expiry.tzinfo is None or _expiry <= datetime.now(UTC):
        raise ValueError("UI authority expired")
    _session_path = _ui_path.with_name(_ui_path.name + ".portal.sqlite3")
    if _session_path.exists() or _session_path.is_symlink():
        _session_info = _session_path.lstat()
        if (
            not stat.S_ISREG(_session_info.st_mode)
            or stat.S_IMODE(_session_info.st_mode) != _FILE_MODE
            or _session_info.st_uid != os.getuid()
        ):
            raise ValueError("Native Portal session database must be a private owned regular file")
except (KeyError, OSError, TypeError, ValueError) as error:
    raise ImproperlyConfigured("A current private native Portal UI authority is required") from error

os.environ["PRAHO_SKIP_DOTENV"] = "1"
# This opt-in process owns private sessions and their SQLite journal/WAL files.
os.umask(0o077)

from .base import *  # noqa: E402, F403 -- No development/test profile or Platform business imports.

DEBUG = False
SECRET_KEY = hashlib.sha512((_ui["secret"] + ":native-portal-session-v1").encode()).hexdigest()
PORTAL_ID = "native-" + _ui["instance"]
PORTAL_HMAC_SECRET = _ui["secret"]
PLATFORM_API_SECRET = _ui["secret"]
PLATFORM_API_BASE_URL = f"http://127.0.0.1:{_ui['platform_port']}/api"
PLATFORM_PUBLIC_ORIGIN = f"http://127.0.0.1:{_ui['platform_port']}"
PLATFORM_API_ALLOW_INSECURE_HTTP = True
INTERNAL_SERVICE_ALLOWED_DOMAINS = ["127.0.0.1"]
ALLOWED_HOSTS = ["127.0.0.1"]
CSRF_TRUSTED_ORIGINS = [f"http://127.0.0.1:{_ui['portal_port']}"]
SESSION_COOKIE_NAME = "native_portal_" + _ui["instance"].replace("-", "")
CSRF_COOKIE_NAME = SESSION_COOKIE_NAME + "_csrf"
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SECURE_SSL_REDIRECT = False
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": _session_path,
        "OPTIONS": {"timeout": 20, "init_command": "PRAGMA journal_mode=WAL;"},
    }
}
