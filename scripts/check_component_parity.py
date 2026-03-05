"""
Check that shared component templates are byte-identical between Portal and Platform.

Compares the 18 components that exist in both services and reports any diffs.
Intentional divergences are documented in .component-parity-ignore.

Exit codes:
    0 — all shared components match (or are documented as intentionally divergent)
    1 — unintentional drift detected

Usage:
    python scripts/check_component_parity.py
    python scripts/check_component_parity.py --verbose
    python scripts/check_component_parity.py --fix  (copies portal version → platform)
"""

from __future__ import annotations

import argparse
import difflib
import sys
from pathlib import Path

# ===============================================================================
# CONFIGURATION
# ===============================================================================

# ⚠️ Assumes script is exactly one level deep from repo root (scripts/)
REPO_ROOT = Path(__file__).resolve().parents[1]

PORTAL_COMPONENTS = REPO_ROOT / "services" / "portal" / "templates" / "components"
PLATFORM_COMPONENTS = REPO_ROOT / "services" / "platform" / "templates" / "components"

PARITY_IGNORE_FILE = REPO_ROOT / ".component-parity-ignore"

# Components that exist in both services and SHOULD be identical
# (Portal-only components like form_actions, cookie_consent, etc. are excluded)
# TODO: Keep this list in sync with actual shared components.
# Ideally this would be derived dynamically, but an explicit allowlist
# prevents accidental parity checks on portal-only components.
SHARED_COMPONENTS: list[str] = [
    "alert.html",
    "badge.html",
    "breadcrumb.html",
    "button.html",
    "card.html",
    "checkbox.html",
    "dangerous_action_modal.html",
    "input.html",
    "mobile_header.html",
    "mobile_nav_item.html",
    "modal.html",
    "nav_dropdown.html",
    "pagination.html",
    "progress_indicator.html",
    "step_navigation.html",
    "table_enhanced.html",
    "table.html",
    "toast.html",
]


# ===============================================================================
# IGNORE HANDLING
# ===============================================================================


def load_ignored_components() -> set[str]:
    """Load intentionally divergent component names from .component-parity-ignore."""
    if not PARITY_IGNORE_FILE.exists():
        return set()
    lines = PARITY_IGNORE_FILE.read_text(encoding="utf-8").splitlines()
    return {line.strip() for line in lines if line.strip() and not line.startswith("#")}


# ===============================================================================
# COMPARISON ENGINE
# ===============================================================================


def compare_component(name: str, verbose: bool = False) -> tuple[bool, str]:
    """
    Compare a single component between portal and platform.

    Returns:
        (identical: bool, diff_output: str)
    """
    portal_path = PORTAL_COMPONENTS / name
    platform_path = PLATFORM_COMPONENTS / name

    if not portal_path.exists() and not platform_path.exists():
        return True, f"⚪ {name}: not present in either service (skip)"

    if not portal_path.exists():
        return False, f"❌ {name}: exists in platform but missing in portal"

    if not platform_path.exists():
        return False, f"❌ {name}: exists in portal but missing in platform"

    try:
        portal_text = portal_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return False, f"❌ {name}: could not read portal file — {exc}"

    try:
        platform_text = platform_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return False, f"❌ {name}: could not read platform file — {exc}"

    if portal_text == platform_text:
        return True, f"✅ {name}: identical"

    # ⚡ PERFORMANCE: Build diff only when verbose or on mismatch (O(N) where N = file lines)
    diff_lines = list(
        difflib.unified_diff(
            platform_text.splitlines(keepends=True),
            portal_text.splitlines(keepends=True),
            fromfile=f"platform/templates/components/{name}",
            tofile=f"portal/templates/components/{name}",
            n=3,
        )
    )
    diff_str = "".join(diff_lines[:80])  # truncate very long diffs
    if len(diff_lines) > 80:
        diff_str += f"\n... ({len(diff_lines) - 80} more lines omitted)"

    summary = f"⚠️  {name}: DIFFERS ({len(diff_lines)} diff lines)"
    if verbose:
        summary = f"{summary}\n{diff_str}"
    return False, summary


# ===============================================================================
# FIX OPERATION
# ===============================================================================


def fix_component(name: str) -> str:
    """Copy portal version to platform (portal is canonical for design system)."""
    portal_path = PORTAL_COMPONENTS / name
    platform_path = PLATFORM_COMPONENTS / name
    if not portal_path.exists():
        return f"⚠️  {name}: portal version missing — cannot fix"
    try:
        portal_text = portal_path.read_text(encoding="utf-8")
        platform_path.write_text(portal_text, encoding="utf-8")
    except OSError as exc:
        return f"❌ {name}: write failed — {exc}"
    return f"✅ {name}: platform updated from portal"


# ===============================================================================
# MAIN
# ===============================================================================


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check that shared components are identical between Portal and Platform."
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Show full diffs for divergent components")
    parser.add_argument("--fix", action="store_true", help="Copy portal -> platform for any divergent components")
    parser.add_argument("--list", action="store_true", help="List all shared components and exit")
    args = parser.parse_args()

    if args.list:
        print(f"📋 {len(SHARED_COMPONENTS)} shared components:")
        for name in SHARED_COMPONENTS:
            print(f"  {name}")
        return 0

    ignored = load_ignored_components()
    if ignored:
        print(f"ℹ️  Ignoring {len(ignored)} intentionally divergent component(s): {', '.join(sorted(ignored))}")

    print("🔍 Checking component parity: portal ↔ platform")
    print("━" * 56)

    drifted: list[str] = []
    matched: list[str] = []
    skipped: list[str] = []

    # ⚡ PERFORMANCE: O(N) where N = number of shared components (18)
    for name in SHARED_COMPONENTS:
        if name in ignored:
            skipped.append(name)
            print(f"  ⏭️  {name}: intentionally divergent (ignored)")
            continue

        identical, message = compare_component(name, verbose=args.verbose)
        print(f"  {message}")

        if identical:
            matched.append(name)
        else:
            drifted.append(name)

    print("━" * 56)
    print(f"📊 Results: {len(matched)} identical  | {len(drifted)} divergent  | {len(skipped)} intentionally different")

    if drifted and args.fix:
        print("\n🔧 Fixing divergent components (portal → platform)...")
        for name in drifted:
            print(f"  {fix_component(name)}")
        print("✅ Fix complete — re-run to verify.")
        return 0

    if drifted:
        print(f"\n❌ {len(drifted)} component(s) have unintentional drift: {', '.join(drifted)}")
        print("   → Run with --verbose to see diffs")
        print("   → Run with --fix to sync portal → platform")
        print(f"   → Or add to {PARITY_IGNORE_FILE.name} if divergence is intentional")
        return 1

    print("\n✅ All shared components are in parity — no unintentional drift detected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
