from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.db import connection

from config.import_isolation_guard import BYPASS_ENV_VAR, enforce_portal_import_isolation

REPO_ROOT = Path(__file__).resolve().parents[4]
PLATFORM_ROOT = (REPO_ROOT / "services" / "platform").resolve()
PLATFORM_APPS_ROOT = (PLATFORM_ROOT / "apps").resolve()


def _is_contaminated_path(path_entry: str) -> bool:
    if not path_entry:
        return False
    try:
        resolved = Path(path_entry).resolve()
    except OSError:
        return False

    return (
        resolved in (PLATFORM_ROOT, PLATFORM_APPS_ROOT)
        or resolved.is_relative_to(PLATFORM_ROOT)
        or resolved.is_relative_to(PLATFORM_APPS_ROOT)
    )


def _clean_sys_path() -> list[str]:
    return [entry for entry in sys.path if not _is_contaminated_path(entry)]


def _is_importable(module_name: str) -> bool:
    try:
        return importlib.util.find_spec(module_name) is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


def test_guard_allows_clean_portal_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(BYPASS_ENV_VAR, raising=False)
    monkeypatch.setattr(sys, "path", _clean_sys_path())
    enforce_portal_import_isolation()


def test_guard_blocks_platform_root_on_sys_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(BYPASS_ENV_VAR, raising=False)
    monkeypatch.setattr(sys, "path", [str(PLATFORM_ROOT), *_clean_sys_path()])

    with pytest.raises(ImproperlyConfigured, match="Portal import isolation violation detected"):
        enforce_portal_import_isolation()


def test_guard_blocks_platform_apps_root_on_sys_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(BYPASS_ENV_VAR, raising=False)
    monkeypatch.setattr(sys, "path", [str(PLATFORM_APPS_ROOT), *_clean_sys_path()])

    with pytest.raises(ImproperlyConfigured, match="Portal import isolation violation detected"):
        enforce_portal_import_isolation()


def test_guard_allows_bypass_with_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(BYPASS_ENV_VAR, "true")
    monkeypatch.setattr(sys, "path", [str(PLATFORM_ROOT), *_clean_sys_path()])

    with pytest.warns(UserWarning, match="bypassing portal import isolation"):
        enforce_portal_import_isolation()


def test_platform_modules_not_resolvable_in_portal_runtime() -> None:
    blocked_modules = [
        "apps.customers.customer_models",
        "apps.billing.invoice_models",
        "apps.orders.signals_extended",
    ]

    leaked = [module for module in blocked_modules if _is_importable(module)]
    assert not leaked, f"Portal should not resolve platform modules, found: {leaked}"


@pytest.mark.no_db
def test_db_access_blocked() -> None:
    with pytest.raises(ImproperlyConfigured, match="SECURITY VIOLATION"):
        connection.cursor()
