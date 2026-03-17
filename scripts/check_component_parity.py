"""
Check that shared component templates are not accidentally shadowed in service dirs.

After the unified design system migration, shared components live in
shared/ui/templates/components/ and should NOT exist in service-specific
templates/components/ directories (which would shadow the shared version).

Also verifies that all expected shared components exist in the shared directory.

Exit codes:
    0 — no shadowing detected, all shared components present
    1 — shadowing detected or shared components missing

Usage:
    python scripts/check_component_parity.py
    python scripts/check_component_parity.py --verbose
    python scripts/check_component_parity.py --list
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# ===============================================================================
# CONFIGURATION
# ===============================================================================

REPO_ROOT = Path(__file__).resolve().parents[1]

SHARED_COMPONENTS_DIR = REPO_ROOT / "shared" / "ui" / "templates" / "components"
PORTAL_COMPONENTS_DIR = REPO_ROOT / "services" / "portal" / "templates" / "components"
PLATFORM_COMPONENTS_DIR = REPO_ROOT / "services" / "platform" / "templates" / "components"

# Components that MUST live in shared/ui/templates/components/ (canonical list)
SHARED_COMPONENTS: list[str] = [
    "alert.html",
    "badge.html",
    "breadcrumb.html",
    "button.html",
    "card.html",
    "checkbox.html",
    "dangerous_action_modal.html",
    "input.html",
    "mobile_nav_item.html",
    "modal.html",
    "nav_dropdown.html",
    "pagination.html",
    "step_progress.html",
    "table.html",
    "toast.html",
]


# ===============================================================================
# CHECKS
# ===============================================================================


def check_shared_components_exist() -> list[str]:
    """Verify all expected shared components exist in the shared directory."""
    return [name for name in SHARED_COMPONENTS if not (SHARED_COMPONENTS_DIR / name).exists()]


def check_no_shadowing() -> list[tuple[str, str]]:
    """Check that shared components are not duplicated in service directories."""
    shadows: list[tuple[str, str]] = []
    for name in SHARED_COMPONENTS:
        if (PORTAL_COMPONENTS_DIR / name).exists():
            shadows.append((name, "portal"))
        if (PLATFORM_COMPONENTS_DIR / name).exists():
            shadows.append((name, "platform"))
    return shadows


# ===============================================================================
# MAIN
# ===============================================================================


def main() -> int:
    parser = argparse.ArgumentParser(description="Check shared component parity — no shadowing, all present.")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed output")
    parser.add_argument("--list", action="store_true", help="List all shared components and exit")
    args = parser.parse_args()

    if args.list:
        print(f"Shared components ({len(SHARED_COMPONENTS)}):")
        for name in SHARED_COMPONENTS:
            exists = (SHARED_COMPONENTS_DIR / name).exists()
            status = "present" if exists else "MISSING"
            print(f"  {name}: {status}")
        return 0

    print("Checking shared design system component parity")
    print("=" * 56)

    errors: list[str] = []

    # Check 1: All shared components exist
    missing = check_shared_components_exist()
    if missing:
        for name in missing:
            msg = f"MISSING: {name} not found in shared/ui/templates/components/"
            errors.append(msg)
            print(f"  {msg}")
    else:
        print(f"  All {len(SHARED_COMPONENTS)} shared components present")

    # Check 2: No shadowing in service directories
    shadows = check_no_shadowing()
    if shadows:
        for name, service in shadows:
            msg = f"SHADOW: {name} exists in {service}/templates/components/ (shadows shared version)"
            errors.append(msg)
            print(f"  {msg}")
    else:
        print("  No shadowing detected in service directories")

    print("=" * 56)

    if errors:
        print(f"\n{len(errors)} issue(s) found:")
        for err in errors:
            print(f"  - {err}")
        print("\nShared components must live ONLY in shared/ui/templates/components/")
        print("Service-specific overrides are allowed but should be documented.")
        return 1

    print("\nAll shared components are correctly placed — no drift possible.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
