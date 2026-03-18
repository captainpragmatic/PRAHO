"""
Design system baseline audit — pre-migration snapshot.

Combines template component linting and parity checking into a single JSON report.
Used to verify that the unified design system migration preserves or improves
component adoption metrics.

Usage:
    python scripts/audit_design_system_baseline.py
    python scripts/audit_design_system_baseline.py --output docs/architecture/ui-ux/baseline.json
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

SERVICES = {
    "portal": REPO_ROOT / "services" / "portal" / "templates",
    "platform": REPO_ROOT / "services" / "platform" / "templates",
}

# Component template tag patterns
COMPONENT_TAGS: list[str] = [
    "button",
    "alert",
    "badge",
    "input_field",
    "modal",
    "card",
    "data_table",
    "toast",
    "breadcrumb",
    "checkbox_field",
    "icon",
]

# Raw HTML patterns that should use components
RAW_PATTERNS: dict[str, str] = {
    "raw_button": r"<button[\s>]",
    "raw_input": r"<input[\s>]",
    "raw_table": r"<table[\s>]",
    "raw_select": r"<select[\s>]",
    "raw_textarea": r"<textarea[\s>]",
    "raw_svg": r"<svg[\s>]",
    "inline_color_badge": r"bg-(green|red|yellow|blue|amber|emerald|rose)-(50|100|200)\s",
}


def count_in_templates(templates_dir: Path) -> dict[str, int]:
    """Count component tag usage and raw HTML patterns across all templates."""
    counts: Counter[str] = Counter()

    html_files = list(templates_dir.rglob("*.html"))
    counts["total_templates"] = len(html_files)

    for html_file in html_files:
        try:
            content = html_file.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue

        # Count component tag usage
        for tag in COMPONENT_TAGS:
            pattern = r"\{%\s*" + re.escape(tag) + r"\s"
            counts[f"tag_{tag}"] += len(re.findall(pattern, content))

        # Count raw HTML patterns
        for name, pattern in RAW_PATTERNS.items():
            counts[name] += len(re.findall(pattern, content, re.IGNORECASE))

        # Count inline style and script blocks
        counts["inline_style"] += len(re.findall(r"<style[\s>]", content, re.IGNORECASE))
        counts["inline_script"] += len(re.findall(r"<script[\s>]", content, re.IGNORECASE))

    return dict(counts)


def list_component_files(templates_dir: Path) -> list[str]:
    """List component template filenames."""
    comp_dir = templates_dir / "components"
    if not comp_dir.exists():
        return []
    return sorted(f.name for f in comp_dir.glob("*.html"))


def check_parity() -> dict[str, str]:
    """Check if shared components are identical between services."""
    portal_dir = SERVICES["portal"] / "components"
    platform_dir = SERVICES["platform"] / "components"
    results: dict[str, str] = {}

    shared = set()
    if portal_dir.exists():
        shared.update(f.name for f in portal_dir.glob("*.html"))
    if platform_dir.exists():
        shared &= {f.name for f in platform_dir.glob("*.html")}

    for name in sorted(shared):
        try:
            portal_text = (portal_dir / name).read_text(encoding="utf-8")
            platform_text = (platform_dir / name).read_text(encoding="utf-8")
            results[name] = "identical" if portal_text == platform_text else "diverged"
        except (OSError, UnicodeDecodeError):
            results[name] = "error"

    return results


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Design system baseline audit")
    parser.add_argument("--output", "-o", type=Path, help="Write JSON to file instead of stdout")
    args = parser.parse_args()

    # Collect typed data before building the JSON report
    portal_counts = count_in_templates(SERVICES["portal"])
    portal_files = list_component_files(SERVICES["portal"])
    platform_counts = count_in_templates(SERVICES["platform"])
    platform_files = list_component_files(SERVICES["platform"])
    parity = check_parity()

    report = {
        "_meta": {"script": "audit_design_system_baseline.py", "version": 1},
        "portal": {"counts": portal_counts, "component_files": portal_files},
        "platform": {"counts": platform_counts, "component_files": platform_files},
        "parity": parity,
        "summary": {
            "portal_component_templates": len(portal_files),
            "platform_component_templates": len(platform_files),
            "shared_components": len(parity),
            "identical_components": sum(1 for v in parity.values() if v == "identical"),
            "diverged_components": sum(1 for v in parity.values() if v == "diverged"),
            "portal_total_component_tag_usage": sum(v for k, v in portal_counts.items() if k.startswith("tag_")),
            "platform_total_component_tag_usage": sum(v for k, v in platform_counts.items() if k.startswith("tag_")),
            "portal_total_raw_html": sum(v for k, v in portal_counts.items() if k.startswith("raw_")),
            "platform_total_raw_html": sum(v for k, v in platform_counts.items() if k.startswith("raw_")),
        },
    }

    output = json.dumps(report, indent=2, sort_keys=False)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")
        print(f"Baseline written to {args.output}", file=sys.stderr)
    else:
        print(output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
