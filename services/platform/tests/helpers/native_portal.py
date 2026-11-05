"""Plain native profile/runner fixtures shared by unit and HTTP integration tests."""

import importlib.util
import os
import runpy
import sys
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import patch

from apps.infrastructure.native_lab import NativeAuthority

PROFILE_KEYS = (
    "MIDDLEWARE",
    "PASSWORD_HASHERS",
    "CACHES",
    "PLATFORM_API_SECRET",
    "PORTAL_HMAC_MODE",
    "PORTAL_HMAC_CREDENTIALS",
    "PORTAL_HMAC_REQUIRE_ISOLATION",
    "PORTAL_SESSION_REQUIRED",
    "RATE_LIMITING_ENABLED",
    "ALLOWED_HOSTS",
    "TESTING",
    "SESSION_ENGINE",
    "AUTHENTICATION_BACKENDS",
)


def load_profile(authority: NativeAuthority, path: Path) -> dict[str, Any]:
    with patch.dict(
        os.environ,
        {
            "PRAHO_NATIVE_LAB": "1",
            "DB_NAME": "praho_native_ui_test",
            "NATIVE_VM_MANIFEST": str(authority.path),
            "PRAHO_NATIVE_UI_AUTHORITY": str(path),
        },
    ):
        os.environ.pop("PRAHO_NATIVE_SMTP_MANIFEST", None)
        with patch.dict(sys.modules):
            sys.modules.pop("config.settings.native", None)
            return runpy.run_module("config.settings.native_portal")


def runner_module() -> ModuleType:
    root = Path(__file__).resolve().parents[4]
    spec = importlib.util.spec_from_file_location(
        "native_ui_runner_test", root / "tests/virtualmin_lab/native/portal_runner.py"
    )
    if spec is None or spec.loader is None:
        raise AssertionError("The actual native UI runner is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
