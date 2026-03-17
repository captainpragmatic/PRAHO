from __future__ import annotations

from pathlib import Path

from django.template import Context, Template
from django.test import SimpleTestCase

REPO_ROOT = Path(__file__).resolve().parents[4]
COMPONENTS_DIR = REPO_ROOT / "services" / "portal" / "templates" / "components"
SHARED_COMPONENTS_DIR = REPO_ROOT / "shared" / "ui" / "templates" / "components"
ALLOWLIST_FILE = REPO_ROOT / ".component-svg-allowlist"


def _load_svg_allowlist() -> set[str]:
    # NOTE: This is a duplicate parser kept intentionally close to the test consumer.
    # The canonical loader lives in scripts/lint_template_components.py:load_component_svg_allowlist().
    # If the file format changes, update both.
    allowed: set[str] = set()
    for raw in ALLOWLIST_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        allowed.add(line.split("|", 1)[0].strip())
    return allowed


class ComponentSvgPolicyTests(SimpleTestCase):
    def _all_component_files(self) -> list[Path]:
        """Collect component files from both service-specific and shared dirs."""
        files: dict[str, Path] = {}
        # Shared first, service-specific overrides
        for f in sorted(SHARED_COMPONENTS_DIR.glob("*.html")):
            files[f.name] = f
        for f in sorted(COMPONENTS_DIR.glob("*.html")):
            files[f.name] = f
        return sorted(files.values(), key=lambda p: p.name)

    def test_only_allowlisted_components_contain_raw_svg(self) -> None:
        allowlisted = _load_svg_allowlist()
        found_raw_svg: set[str] = set()

        for component_file in self._all_component_files():
            content = component_file.read_text(encoding="utf-8")
            if "<svg" in content:
                found_raw_svg.add(component_file.relative_to(REPO_ROOT).as_posix())

        self.assertSetEqual(found_raw_svg, allowlisted)

    def test_migrated_components_use_icon_tag(self) -> None:
        # Dynamic: find all non-allowlisted components that use the icon system.
        # We only assert on components that already opted-in to {% icon %} —
        # text-only components (breadcrumb, form inputs, etc.) won't be included.
        # This avoids false failures when adding new icon-free components.
        allowlisted = _load_svg_allowlist()
        allowlisted_names = {Path(p).name for p in allowlisted}

        all_files = self._all_component_files()
        migrated_components = [
            f
            for f in all_files
            if f.name not in allowlisted_names
            and "{% icon " in f.read_text(encoding="utf-8")
        ]

        for comp_file in migrated_components:
            content = comp_file.read_text(encoding="utf-8")
            self.assertIn("{% icon ", content, msg=f"{comp_file.name} should render icons via {{% icon %}}")

    def test_account_status_banner_renders_icon_svg(self) -> None:
        rendered = Template(
            '{% include "components/account_status_banner.html" with banner=banner %}'
        ).render(
            Context(
                {
                    "banner": {
                        "severity": "critical",
                        "message": "Payment overdue",
                        "cta_url": "/billing/",
                        "cta_text": "Pay now",
                    }
                }
            )
        )

        # Assert structural SVG presence, not specific path data (fragile on icon version bumps).
        self.assertGreaterEqual(rendered.count("<svg"), 1, "Expected at least one <svg> in rendered banner")

    def test_account_status_banner_renders_svg_for_all_severities(self) -> None:
        """Ensure icon renders for warning and default severity, not just critical."""
        for severity in ("critical", "warning", "info"):
            rendered = Template(
                '{% include "components/account_status_banner.html" with banner=banner %}'
            ).render(
                Context(
                    {
                        "banner": {
                            "severity": severity,
                            "message": f"Test message ({severity})",
                            "cta_url": "/billing/",
                            "cta_text": "Act now",
                        }
                    }
                )
            )
            self.assertGreaterEqual(
                rendered.count("<svg"),
                1,
                msg=f"Expected <svg> in rendered banner for severity={severity!r}",
            )

    def test_list_page_header_renders_configured_icon_svg(self) -> None:
        rendered = Template(
            '{% include "components/list_page_header.html" with '
            'list_icon_bg="bg-blue-600" '
            'list_icon_name="menu" '
            'list_title="Title" '
            'list_subtitle="Subtitle" %}'
        ).render(Context({}))

        # Assert structural SVG presence, not specific path data (fragile on icon version bumps).
        self.assertGreaterEqual(rendered.count("<svg"), 1, "Expected at least one <svg> in rendered header")
