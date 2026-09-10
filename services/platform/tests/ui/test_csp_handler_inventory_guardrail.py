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
