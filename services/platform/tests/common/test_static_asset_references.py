"""A template may not reference a static asset its own service cannot serve.

`.gitignore` carries a blanket image block — `*.png`, `*.jpg`, `*.svg` and friends — added
to keep ad-hoc Playwright failure captures and debug screenshots out of the repository. It
does that, but it cannot tell a throwaway screenshot from a hand-authored source asset, so
it silently swallowed the portal's payment-brand icons. `services/portal/templates/orders/
checkout.html` rendered two broken images at the point of payment and nothing failed:
`git add` declines an ignored path quietly, CI never renders the page, and a missing image
is not a server error.

Resolution is **per service**, mirroring `STATICFILES_DIRS` in each service's settings
(`platform/config/settings/base.py:211`, `portal/config/settings/base.py:180`). Both are
`[<own>/static, shared/ui/static]`, plus each app's own `static/` dir via the default
`AppDirectoriesFinder`. The two services deploy independently and neither can serve the
other's static tree, so merging them would let a platform template reference a portal-only
asset and still pass — which is exactly what the first version of this test did. Templates under `shared/ui/` are rendered by both services,
so their assets must resolve in every service.
"""

from __future__ import annotations

import re
from pathlib import Path

from django.test import SimpleTestCase

REPO_ROOT = Path(__file__).resolve().parents[4]
SHARED_STATIC = REPO_ROOT / "shared" / "ui" / "static"

def _static_roots(service: str) -> tuple[Path, ...]:
    """Every directory the service can actually serve a static file from.

    Django resolves through two finders and both are active — neither service overrides
    ``STATICFILES_FINDERS``, so the default ``FileSystemFinder`` + ``AppDirectoriesFinder``
    pair applies. Modelling only ``STATICFILES_DIRS`` misses ``<app>/static/``, where the
    platform keeps its favicon; the app dirs are globbed rather than listed so a new app
    needs no change here.
    """
    base = REPO_ROOT / "services" / service
    app_static = sorted((base / "apps").glob("*/static"))
    return (base / "static", SHARED_STATIC, *app_static)


# Each service's own template tree and the static roots it can actually serve.
SERVICES: dict[str, tuple[Path, tuple[Path, ...]]] = {
    service: (REPO_ROOT / "services" / service / "templates", _static_roots(service))
    for service in ("platform", "portal")
}

# Rendered by whichever service includes them, so their assets must resolve in all of them.
SHARED_TEMPLATES = REPO_ROOT / "shared" / "ui" / "templates"

ASSET_SUFFIXES = ("svg", "png", "jpg", "jpeg", "gif", "ico", "webp")
_EXT = "|".join(ASSET_SUFFIXES)
_STATIC_TAG = re.compile(r"\{%\s*static\s+['\"]([^'\"]+\.(?:" + _EXT + r"))['\"]", re.IGNORECASE)
_ABSOLUTE = re.compile(r"/static/([A-Za-z0-9_./-]+\.(?:" + _EXT + r"))", re.IGNORECASE)

# Canary: the reference that exposed the defect. A scan that stops seeing it is broken.
KNOWN_REFERENCE = ("portal", "images/visa.svg")


def _references(root: Path) -> dict[str, set[str]]:
    """Static assets referenced under a template tree, mapped to the referencing files."""
    found: dict[str, set[str]] = {}
    if not root.exists():
        return found
    for path in root.rglob("*.html"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pattern in (_STATIC_TAG, _ABSOLUTE):
            for asset in pattern.findall(text):
                found.setdefault(asset, set()).add(str(path.relative_to(REPO_ROOT)))
    return found


def _unresolvable(references: dict[str, set[str]], roots: tuple[Path, ...]) -> dict[str, list[str]]:
    return {
        asset: sorted(users)
        for asset, users in references.items()
        if not any((root / asset).exists() for root in roots)
    }


class StaticAssetReferencesResolveTests(SimpleTestCase):
    """Every referenced asset is servable by the service that renders it."""

    def test_each_service_can_serve_every_asset_its_templates_reference(self) -> None:
        offending: dict[str, dict[str, list[str]]] = {}
        for service, (templates, static_roots) in SERVICES.items():
            if missing := _unresolvable(_references(templates), static_roots):
                offending[service] = missing

        self.assertEqual(
            offending,
            {},
            msg=(
                "A template references a static asset its own service cannot serve. If the file "
                "exists locally but `git add` will not take it, the blanket image block in "
                ".gitignore is swallowing it — add a negation for source assets under static/, "
                "rather than committing with --force."
            ),
        )

    def test_shared_component_assets_resolve_in_every_service(self) -> None:
        """A shared template is rendered by both services, so one-sided is not good enough."""
        shared_refs = _references(SHARED_TEMPLATES)
        offending = {
            service: missing
            for service, (_templates, static_roots) in SERVICES.items()
            if (missing := _unresolvable(shared_refs, static_roots))
        }

        self.assertEqual(
            offending,
            {},
            msg="A shared component references an asset that only one service can serve.",
        )

    def test_the_scan_still_sees_the_reference_that_exposed_this(self) -> None:
        """Structural-Helper Integrity: a scan matching nothing must fail, not pass."""
        service, asset = KNOWN_REFERENCE
        templates, _roots = SERVICES[service]
        references = _references(templates)

        self.assertIn(asset, references)
        self.assertTrue(any("checkout.html" in user for user in references[asset]))
        self.assertGreaterEqual(sum(len(_references(t)) for t, _r in SERVICES.values()), 3)
