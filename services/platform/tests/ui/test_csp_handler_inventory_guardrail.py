r"""Freeze the platform's inline-event-handler debt so it can only shrink (#284).

The portal already migrated its inline `on*=` handlers to delegated `data-action`
dispatch and its guardrail (services/portal/tests/ui/) baselines that at ~0. The
platform still carries ~96 inline handlers pending the CSP-hardening migration; the
portal guardrail never scans `services/platform/templates`, so today a new platform
inline handler can land ungoverned. This test baselines the current count and fails
if it GROWS — new UI must use `data-action` + the delegated registry
(`shared/ui/static/js/ui-actions.js`, already served by the platform base layout).
When the migration removes handlers, lower `EXPECTED_PLATFORM_HANDLERS` in the same PR.

Regex note: the leading `\s` in the portal guardrail's `ON_HANDLER_RE` misses handlers
preceded by `%}`, `[`, or `"` (e.g. `{% if ... %}onclick="..."` in table_enhanced.html),
so this uses the sanitizer's own lookbehind form to see all of them.
"""

from __future__ import annotations

import re
from pathlib import Path

from django.test import SimpleTestCase

# services/platform/tests/ui/ -> services/platform
_PLATFORM_ROOT = Path(__file__).resolve().parents[2]
_TEMPLATES = _PLATFORM_ROOT / "templates"
# services/platform -> repo root -> shared/ui design-system JS + templates
_REPO_ROOT = _PLATFORM_ROOT.parents[1]
_SHARED_UI = _REPO_ROOT / "shared" / "ui"

# Alpine component registrations (Alpine.data("name" / 'name') and inline x-data usages.
_ALPINE_REGISTER_RE = re.compile(r"""Alpine\.data\(\s*['"]([\w$]+)['"]""")
_XDATA_RE = re.compile(r'x-data\s*=\s*"([^"]*)"')
# Leading identifier of a named x-data value (e.g. settingsForm('...') -> settingsForm).
_XDATA_NAME_RE = re.compile(r"""^\s*([A-Za-z_$][\w$]*)""")
# The JS files that register platform-visible components, in base.html load order.
_ALPINE_JS = (
    _PLATFORM_ROOT / "static" / "js" / "alpine-components.js",
    _SHARED_UI / "static" / "js" / "alpine-shared-components.js",
)

# Matches an inline DOM event-handler attribute (on<event>=) that starts an attribute
# (not the tail of a hyphenated/word attr like data-onboarding), mirroring the
# ui_components.py sanitizer's own strip pattern.
_ON_HANDLER_RE = re.compile(r"""(?<![\w-])on[a-z]+\s*=\s*['"]""", re.IGNORECASE)

# Constructs that would re-force 'unsafe-eval' after the #284 eval removal. Each must
# stay at 0 so a new hx-on / javascript: URL / new Function() sink can't quietly
# reintroduce the eval dependency the CSP drops. (Attribute forms require '=' so prose
# mentioning "hx-on" in a comment does not trip the guard.)
_EVAL_FORCING_RES = {
    "hx-on attribute": re.compile(r"""\bhx-on(?:::?)[a-z][\w:-]*\s*=\s*['"]""", re.IGNORECASE),
    "javascript: URL": re.compile(r"""=\s*['"]\s*javascript:""", re.IGNORECASE),
    "new Function()": re.compile(r"""\bnew\s+Function\s*\("""),
    "eval() call": re.compile(r"""(?<![.\w])eval\s*\("""),
}

# Current debt. This may only DECREASE — raising it means new inline-handler debt.
# The #284 handler migration is COMPLETE: every inline on*= handler is now a delegated
# data-action. 0 is the CSP-flip gate — script-src-attr 'none' can only land at 0.
EXPECTED_PLATFORM_HANDLERS = 0


class PlatformInlineHandlerFreezeTests(SimpleTestCase):
    def _scan(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for path in _TEMPLATES.rglob("*.html"):
            n = len(_ON_HANDLER_RE.findall(path.read_text()))
            if n:
                counts[str(path.relative_to(_PLATFORM_ROOT))] = n
        return counts

    def test_inline_handler_count_does_not_grow(self) -> None:
        counts = self._scan()
        total = sum(counts.values())
        self.assertLessEqual(
            total,
            EXPECTED_PLATFORM_HANDLERS,
            f"Platform inline on*= handler count grew to {total} (baseline {EXPECTED_PLATFORM_HANDLERS}). "
            f"New UI must use data-action + the delegated registry, not inline handlers. Per-file: {counts}",
        )
        # Pin the baseline exactly so a net removal is also recorded consciously (lower the constant).
        self.assertEqual(
            total,
            EXPECTED_PLATFORM_HANDLERS,
            f"Platform inline-handler count changed to {total}; update EXPECTED_PLATFORM_HANDLERS to match.",
        )

    def test_scan_actually_covers_the_template_tree(self) -> None:
        # Structural canary (not handler-dependent, so it survives to baseline 0):
        # prove the scan reads a substantial number of real templates, otherwise a
        # broken path would make the freeze vacuously pass at "0 handlers".
        n_templates = sum(1 for _ in _TEMPLATES.rglob("*.html"))
        self.assertGreater(n_templates, 100, "template scan covered too few files — path likely wrong")
        self.assertTrue((_TEMPLATES / "base.html").exists(), "base.html not found — scan root is wrong")

    def test_no_eval_forcing_constructs(self) -> None:
        # #284 eval removal: hold the line so nothing re-forces 'unsafe-eval'. Alpine
        # directive expressions are governed by the @alpinejs/csp build (its own parser),
        # not scanned here; this catches the template-level eval sinks the CSP drops.
        offenders: dict[str, list[str]] = {}
        for path in _TEMPLATES.rglob("*.html"):
            text = path.read_text()
            for label, pattern in _EVAL_FORCING_RES.items():
                if pattern.search(text):
                    offenders.setdefault(str(path.relative_to(_PLATFORM_ROOT)), []).append(label)
        self.assertEqual(
            offenders,
            {},
            "Eval-forcing constructs reintroduced (would require 'unsafe-eval'): "
            f"{offenders}. Use delegated listeners / data-action, not hx-on / javascript: / new Function.",
        )


class AlpineComponentRegistrationTests(SimpleTestCase):
    """Under the @alpinejs/csp build a NAMED x-data that isn't registered via
    Alpine.data() silently no-ops (no CSP violation, no exception, nothing a normal
    test sees) — the directive just never initializes. Codex-review + the browser
    oracle only cover the diff and the pages they visit; this scans the whole template
    tree so an unregistered component on an unvisited page fails loudly (#284).

    Inline object-literal x-data ("{ open: false }") is intentionally allowed: the
    vendored @alpinejs/csp 3.15.0 parser evaluates object literals, member access,
    string/bool literals and assignment — only the named-component form needs a
    registration to exist.
    """

    def _registered(self) -> set[str]:
        names: set[str] = set()
        for js in _ALPINE_JS:
            if js.exists():
                names.update(_ALPINE_REGISTER_RE.findall(js.read_text()))
        return names

    def _used_named_components(self) -> dict[str, set[str]]:
        """{component_name: {templates using it}} for NAMED x-data (skips inline {…})."""
        used: dict[str, set[str]] = {}
        roots = [_TEMPLATES] + ([_SHARED_UI] if _SHARED_UI.exists() else [])
        for root in roots:
            for path in root.rglob("*.html"):
                for value in _XDATA_RE.findall(path.read_text()):
                    if value.lstrip().startswith("{"):
                        continue  # inline object literal — allowed under the CSP build
                    m = _XDATA_NAME_RE.match(value)
                    if m:
                        used.setdefault(m.group(1), set()).add(str(path.relative_to(_REPO_ROOT)))
        return used

    def test_every_named_xdata_component_is_registered(self) -> None:
        registered = self._registered()
        used = self._used_named_components()
        self.assertTrue(registered, "found no Alpine.data() registrations — JS paths are wrong")
        # Canary: the scan must actually find named components, else a broken path
        # would make this pass vacuously while real breakage ships.
        self.assertGreaterEqual(len(used), 5, f"scan found too few named x-data components: {sorted(used)}")
        missing = {name: sorted(paths) for name, paths in used.items() if name not in registered}
        self.assertEqual(
            missing,
            {},
            "Named x-data components with no Alpine.data() registration — under the CSP build "
            f"these silently never initialize: {missing}. Register them (alpine-components.js / "
            "alpine-shared-components.js) or use an inline object-literal x-data.",
        )
