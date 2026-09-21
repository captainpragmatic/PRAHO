"""A template may not reference a static asset the repository does not contain.

`.gitignore` carries a blanket image block — `*.png`, `*.jpg`, `*.svg` and friends — added
to keep ad-hoc Playwright failure captures and debug screenshots out of the repository. It
does that, but it cannot tell a throwaway screenshot from a hand-authored source asset, so
it silently swallowed the portal's payment-brand icons too. `services/portal/templates/
orders/checkout.html` has been rendering two broken images at the point of payment, and
nothing failed: `git add` refuses an ignored file without an error loud enough to notice,
CI never renders the page, and a missing image is not a server error.

The fix negates the block for source assets under `static/` directories. The negations are
safe by construction because the directories holding build output and third-party files —
`staticfiles/`, `static/dist/`, `node_modules/`, `.venv-*/` — are excluded at the *directory*
level, and a file-pattern negation cannot re-include anything inside an excluded directory.

This test is the durable half. A `.gitignore` rule that strands an asset is invisible until
someone loads the page; this makes it a build failure instead.
"""

from __future__ import annotations

import re
from pathlib import Path

from django.test import SimpleTestCase

REPO_ROOT = Path(__file__).resolve().parents[4]

# Both services, because the stranded assets were the portal's while the suite runs here.
TEMPLATE_ROOTS = (
    REPO_ROOT / "services" / "platform" / "templates",
    REPO_ROOT / "services" / "portal" / "templates",
    REPO_ROOT / "shared",
)
STATIC_ROOTS = (
    REPO_ROOT / "services" / "platform" / "static",
    REPO_ROOT / "services" / "portal" / "static",
    REPO_ROOT / "shared",
)

ASSET_SUFFIXES = ("svg", "png", "jpg", "jpeg", "gif", "ico", "webp")
_EXT = "|".join(ASSET_SUFFIXES)

# `{% static 'images/visa.svg' %}` and a bare `/static/images/visa.svg`.
_STATIC_TAG = re.compile(r"\{%\s*static\s+['\"]([^'\"]+\.(?:" + _EXT + r"))['\"]", re.IGNORECASE)
_ABSOLUTE = re.compile(r"/static/([A-Za-z0-9_./-]+\.(?:" + _EXT + r"))", re.IGNORECASE)

# Canary: the reference that exposed the defect. A scan that stops seeing it is broken.
KNOWN_REFERENCE = "images/visa.svg"


def _referenced_assets() -> dict[str, list[str]]:
    """Every static asset referenced by a template, mapped to the files referencing it."""
    found: dict[str, list[str]] = {}
    for root in TEMPLATE_ROOTS:
        if not root.exists():
            continue
        for path in root.rglob("*.html"):
            text = path.read_text(encoding="utf-8", errors="ignore")
            for pattern in (_STATIC_TAG, _ABSOLUTE):
                for match in pattern.findall(text):
                    relative = match[0] if isinstance(match, tuple) else match
                    found.setdefault(relative, []).append(str(path.relative_to(REPO_ROOT)))
    return found


def _exists(relative: str) -> bool:
    return any((root / relative).exists() for root in STATIC_ROOTS if root.exists())


class StaticAssetReferencesResolveTests(SimpleTestCase):
    """Every referenced asset is in the repository."""

    def test_no_template_references_a_missing_static_asset(self) -> None:
        referenced = _referenced_assets()

        missing = {asset: sorted(set(users)) for asset, users in referenced.items() if not _exists(asset)}

        self.assertEqual(
            missing,
            {},
            msg=(
                "A template references a static asset the repository does not contain. If the file "
                "exists locally but `git add` will not take it, the blanket image block in "
                ".gitignore is swallowing it — add a negation for source assets under static/, "
                "rather than committing with --force."
            ),
        )

    def test_the_scan_still_sees_the_reference_that_exposed_this(self) -> None:
        """Structural-Helper Integrity: a scan matching nothing must fail, not pass."""
        referenced = _referenced_assets()

        self.assertGreaterEqual(len(referenced), 3)
        self.assertIn(KNOWN_REFERENCE, referenced)
        self.assertTrue(
            any("checkout.html" in user for user in referenced[KNOWN_REFERENCE]),
            msg="The payment-brand icons are no longer scanned from the checkout template.",
        )
