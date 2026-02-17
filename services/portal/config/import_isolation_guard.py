"""
Portal import isolation guard.

Fail fast when the platform service path is injected into portal runtime
imports (typically via PYTHONPATH), which would allow cross-service imports.
"""

from __future__ import annotations

import os
import sys
import warnings
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

BYPASS_ENV_VAR = "PORTAL_IMPORT_ISOLATION_BYPASS"
_TRUTHY_VALUES = {"1", "true", "yes", "on"}


def _repo_root() -> Path:
    # services/portal/config/import_isolation_guard.py -> repo root is parents[3]
    return Path(__file__).resolve().parents[3]


def _forbidden_paths() -> tuple[Path, Path]:
    root = _repo_root()
    platform_root = (root / "services" / "platform").resolve()
    platform_apps = (platform_root / "apps").resolve()
    return platform_root, platform_apps


def _normalize_path(path_entry: str) -> Path | None:
    if not path_entry:
        return None
    try:
        return Path(path_entry).expanduser().resolve()
    except OSError:
        return None


def _is_relative_to(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _find_contamination() -> list[Path]:
    forbidden_paths = _forbidden_paths()
    contaminated: list[Path] = []

    for entry in sys.path:
        normalized = _normalize_path(entry)
        if normalized is None:
            continue
        if any(normalized == forbidden or _is_relative_to(normalized, forbidden) for forbidden in forbidden_paths):
            contaminated.append(normalized)

    # Deduplicate while preserving deterministic output
    unique = sorted({str(path) for path in contaminated})
    return [Path(path) for path in unique]


def enforce_portal_import_isolation() -> None:
    """
    Ensure portal runtime cannot import from platform service paths.
    """
    contaminated = _find_contamination()
    if not contaminated:
        return

    bypass_enabled = os.environ.get(BYPASS_ENV_VAR, "").strip().lower() in _TRUTHY_VALUES
    contaminated_paths = ", ".join(str(path) for path in contaminated)

    if bypass_enabled:
        warnings.warn(
            f"{BYPASS_ENV_VAR} is enabled; bypassing portal import isolation. "
            f"Contaminated path(s): {contaminated_paths}",
            UserWarning,
            stacklevel=2,
        )
        return

    raise ImproperlyConfigured(
        "Portal import isolation violation detected. "
        f"Platform path(s) found on sys.path: {contaminated_paths}. "
        "Run portal commands from services/portal without injecting services/platform into PYTHONPATH. "
        f"For emergency recovery only, set {BYPASS_ENV_VAR}=true."
    )
