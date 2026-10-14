"""A deployment restyles PRAHO through its brand folder alone (ADR-0058).

The portal's templates colour with Tailwind's blue-* and slate-* utilities. Every blue-* shade
resolves to the primary scale, so a brand.css that overrides --color-primary-* and --color-slate-*
recolours every portal page without touching a template. The compiled stylesheet is tracked, so it
must carry the same wiring as its source. Every brand file a page links must ship in PRAHO's own
brand folder, or an unbranded deployment serves a broken icon.
"""

from __future__ import annotations

import re
from pathlib import Path
from unittest import TestCase

REPO_ROOT = Path(__file__).resolve().parents[2]
BRAND_FOLDER = REPO_ROOT / "shared/ui/static/brand"
PORTAL_STYLESHEETS = (REPO_ROOT / "assets/css/portal.css", REPO_ROOT / "services/portal/static/css/tailwind.min.css")
BASE_TEMPLATES = (
    REPO_ROOT / "services/portal/templates/base.html",
    REPO_ROOT / "services/platform/templates/base.html",
    REPO_ROOT / "shared/ui/templates/components/brand_logo.html",
)
STEPS = (50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 950)


class BrandPaletteTests(TestCase):
    def test_every_portal_blue_shade_resolves_to_the_primary_scale(self) -> None:
        for path in PORTAL_STYLESHEETS:
            text = path.read_text(encoding="utf-8")
            for step in STEPS:
                with self.subTest(file=path.name, step=step):
                    self.assertRegex(text, rf"--color-blue-{step}:\s*var\(--color-primary-{step}\)")
                    self.assertRegex(text, rf"--color-slate-{step}:\s*#[0-9a-f]{{6}}")

    def test_every_linked_brand_file_ships_in_prahos_brand_folder(self) -> None:
        linked = {
            name
            for template in BASE_TEMPLATES
            for name in re.findall(r"static 'brand/([^']+)'", template.read_text(encoding="utf-8"))
        }
        self.assertGreaterEqual(linked, {"logo.svg", "favicon.svg", "favicon.ico", "apple-touch-icon.png", "brand.css"})
        self.assertEqual(sorted(name for name in linked if not (BRAND_FOLDER / name).is_file()), [])
