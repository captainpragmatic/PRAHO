#!/usr/bin/env python3
"""Determine which Django test modules to run based on changed files.

Reads changed file paths from stdin (one per line) or as CLI arguments.
Outputs space-separated Django test module paths (e.g. "tests.billing tests.common")
or the literal string "FULL" if the full test suite should run.

Usage:
    git diff --name-only HEAD~1 | python scripts/affected_test_modules.py
    python scripts/affected_test_modules.py services/platform/apps/billing/services.py
    python scripts/affected_test_modules.py --verbose < changed_files.txt
    python scripts/affected_test_modules.py --json < changed_files.txt
    python scripts/affected_test_modules.py --show-graph
"""

from __future__ import annotations

import argparse
import json
import re
import sys

# ---------------------------------------------------------------------------
# Dependency graph: "When app X changes, which test modules must run?"
# Derived from actual cross-app import analysis (2026-03-18).
# ---------------------------------------------------------------------------
APP_DEPENDENCIES: dict[str, list[str]] = {
    "api": ["api", "provisioning"],
    "audit": ["*"],  # imported by 12 apps
    "billing": [
        "api",
        "billing",
        "common",
        "customers",
        "domains",
        "integrations",
        "orders",
        "products",
        "provisioning",
    ],
    "common": ["*"],  # imported by 13 apps
    "customers": [
        "api",
        "common",
        "customers",
        "domains",
        "integrations",
        "orders",
        "promotions",
        "provisioning",
        "users",
    ],
    "domains": ["common", "domains", "integrations", "orders"],
    "integrations": ["common", "integrations", "orders"],
    "notifications": [
        "audit",
        "common",
        "customers",
        "integrations",
        "notifications",
        "orders",
        "settings",
    ],
    "orders": [
        "api",
        "billing",
        "common",
        "customers",
        "domains",
        "orders",
        "promotions",
        "provisioning",
    ],
    "products": ["api", "common", "products"],
    "promotions": ["common", "promotions"],
    "provisioning": [
        "api",
        "common",
        "customers",
        "domains",
        "integrations",
        "orders",
        "provisioning",
    ],
    "settings": ["*"],  # imported by 10 apps
    "tickets": ["api", "audit", "common", "customers", "orders", "tickets"],
    "ui": ["provisioning", "ui"],
    "users": [
        "api",
        "audit",
        "common",
        "customers",
        "domains",
        "promotions",
        "provisioning",
        "settings",
        "tickets",
        "users",
    ],
}

# Apps whose change triggers the full suite — derived from the graph to prevent divergence.
FULL_SUITE_APPS: set[str] = {app for app, deps in APP_DEPENDENCIES.items() if deps == ["*"]}

# Always include these modules in any focused run.
ALWAYS_TEST: frozenset[str] = frozenset({"common"})

# If more than this many unique test modules are affected, run full suite.
# Analysis: most apps expand to 3-9 modules due to interconnected imports.
# Threshold 8 means mid-tier apps (domains=4, tickets=6, provisioning=7) get
# focused runs while heavily-connected apps (billing=9, users=10) trigger FULL.
FULL_SUITE_THRESHOLD: int = 8

# Paths outside platform apps that force a full suite.
FULL_SUITE_PATH_PATTERNS: list[str] = [
    r"^pyproject\.toml$",
    r"^uv\.lock$",
    r"^Makefile$",
    r"^shared/",
    r"^services/platform/config/",
    r"^services/platform/tests/(factories|helpers|mocks|fixtures)/",
    r"^services/platform/tests/conftest\.py$",
    r"^services/platform/tests/__init__\.py$",
    r"^services/platform/conftest\.py$",
]

# Platform app/test path extractors.
PLATFORM_APP_RE = re.compile(r"^services/platform/apps/([^/]+)/")
PLATFORM_TEST_RE = re.compile(r"^services/platform/tests/([^/]+)/")

# Compiled full-suite patterns.
_FULL_PATTERNS = [re.compile(p) for p in FULL_SUITE_PATH_PATTERNS]

# All known test module names (directories under services/platform/tests/).
ALL_TEST_MODULES: set[str] = set(APP_DEPENDENCIES.keys())


def classify_file(path: str) -> str | None:
    """Classify a changed file path.

    Returns:
        - An app name (str) if the file belongs to a platform app or test module
        - "FULL" if the file triggers the full suite
        - "UNKNOWN:name" if the app/module is not in the dependency graph
        - None if the file is irrelevant (portal, docs, etc.)
    """
    for pattern in _FULL_PATTERNS:
        if pattern.search(path):
            return "FULL"

    m = PLATFORM_APP_RE.match(path)
    if m:
        app = m.group(1)
        if app in ALL_TEST_MODULES:
            return app
        # Unknown app — not in dependency graph. Flag it so CI can warn.
        return f"UNKNOWN:{app}"

    m = PLATFORM_TEST_RE.match(path)
    if m:
        module = m.group(1)
        # Shared infra directories already caught by FULL_SUITE_PATH_PATTERNS.
        if module in ALL_TEST_MODULES:
            return module
        return f"UNKNOWN:{module}"

    return None


def expand_dependencies(changed_apps: set[str]) -> set[str] | str:
    """Expand changed apps into the full set of test modules that must run.

    Returns:
        - "FULL" if the full suite should run
        - A set of test module names otherwise
    """
    if changed_apps & FULL_SUITE_APPS:
        return "FULL"

    affected: set[str] = set()
    for app in changed_apps:
        deps = APP_DEPENDENCIES.get(app, [app])
        if "*" in deps:
            return "FULL"
        affected.update(deps)

    # Always include mandatory modules.
    affected.update(ALWAYS_TEST)

    if len(affected) > FULL_SUITE_THRESHOLD:
        return "FULL"

    return affected


def determine_modules(changed_files: list[str]) -> tuple[str, dict[str, object]]:
    """Main logic: map changed files to test modules.

    Returns:
        (result_string, debug_info)
        result_string is either "FULL" or space-separated "tests.X tests.Y"
    """
    changed_apps: set[str] = set()
    full_triggers: list[str] = []
    unknown_apps: list[str] = []
    skipped: list[str] = []

    for path in changed_files:
        path = path.strip()
        if not path:
            continue

        classification = classify_file(path)
        if classification == "FULL":
            full_triggers.append(path)
        elif classification is None:
            skipped.append(path)
        elif classification.startswith("UNKNOWN:"):
            unknown_apps.append(classification.removeprefix("UNKNOWN:"))
        else:
            changed_apps.add(classification)

    # Unknown apps trigger FULL to be safe — missing from dependency graph
    if unknown_apps:
        print(
            f"WARNING: Unknown platform apps not in dependency graph: {unknown_apps}. "
            "Update APP_DEPENDENCIES in scripts/affected_test_modules.py",
            file=sys.stderr,
        )
        full_triggers.append(f"unknown apps: {unknown_apps}")

    debug: dict[str, object] = {
        "changed_files": len(changed_files),
        "changed_apps": sorted(changed_apps),
        "full_triggers": full_triggers,
        "unknown_apps": unknown_apps,
        "skipped": len(skipped),
    }

    # Any file that forces full suite?
    if full_triggers:
        debug["reason"] = f"full suite trigger: {full_triggers[0]}"
        return "FULL", debug

    # No platform files changed at all?
    if not changed_apps:
        debug["reason"] = "no platform app changes detected"
        return "", debug

    # Expand dependencies.
    result = expand_dependencies(changed_apps)
    if result == "FULL":
        if changed_apps & FULL_SUITE_APPS:
            debug["reason"] = f"universal app changed: {changed_apps & FULL_SUITE_APPS}"
        else:
            expanded = set()
            for app in changed_apps:
                expanded.update(APP_DEPENDENCIES.get(app, [app]))
            expanded.update(ALWAYS_TEST)
            debug["reason"] = f">{FULL_SUITE_THRESHOLD} modules affected ({len(expanded)})"
            debug["expanded_modules"] = sorted(expanded)
        return "FULL", debug

    modules = sorted(result)
    debug["expanded_modules"] = modules
    debug["reason"] = f"{len(modules)} modules (within threshold)"
    module_paths = " ".join(f"tests.{m}" for m in modules)
    return module_paths, debug


def show_graph() -> None:
    """Print the dependency graph in a human-readable format."""
    print("App Dependency Graph (when app X changes, test these modules):")
    print("=" * 70)
    for app in sorted(APP_DEPENDENCIES):
        deps = APP_DEPENDENCIES[app]
        label = "FULL SUITE (universal dependency)" if deps == ["*"] else ", ".join(sorted(deps))
        marker = " ***" if app in FULL_SUITE_APPS else ""
        print(f"  {app:20s} -> {label}{marker}")
    print()
    print(f"Full suite apps: {sorted(FULL_SUITE_APPS)}")
    print(f"Always tested:   {ALWAYS_TEST}")
    print(f"Threshold:       >{FULL_SUITE_THRESHOLD} modules -> FULL")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Determine affected Django test modules from changed files.",
    )
    parser.add_argument(
        "files",
        nargs="*",
        help="Changed file paths (also reads from stdin if not a TTY)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print debug info to stderr",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output as JSON instead of plain text",
    )
    parser.add_argument(
        "--show-graph",
        action="store_true",
        help="Print the dependency graph and exit",
    )
    args = parser.parse_args()

    if args.show_graph:
        show_graph()
        return

    # Collect changed files from args and/or stdin.
    changed_files: list[str] = list(args.files)
    if not sys.stdin.isatty():
        changed_files.extend(sys.stdin.read().splitlines())

    if not changed_files:
        if args.json_output:
            print(json.dumps({"result": "", "reason": "no input files"}))
        return

    result, debug = determine_modules(changed_files)

    if args.verbose:
        print(f"Changed apps: {debug.get('changed_apps', [])}", file=sys.stderr)
        if debug.get("full_triggers"):
            print(f"Full triggers: {debug['full_triggers']}", file=sys.stderr)
        if debug.get("expanded_modules"):
            print(f"Expanded:     {debug['expanded_modules']}", file=sys.stderr)
        print(f"Reason:       {debug.get('reason', 'unknown')}", file=sys.stderr)
        print(f"Result:       {result or '(empty)'}", file=sys.stderr)

    if args.json_output:
        output = {
            "result": result,
            **debug,
        }
        print(json.dumps(output, indent=2))
    else:
        print(result)


if __name__ == "__main__":
    main()
