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

# Current debt. This may only DECREASE — raising it means new inline-handler debt.
EXPECTED_PLATFORM_HANDLERS = 96


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

    def test_scan_reaches_the_base_layout(self) -> None:
        # Canary: the base layout's toast-dismiss handler must be seen, otherwise the
        # scan silently covers nothing and the freeze is vacuous.
        counts = self._scan()
        self.assertIn("templates/base.html", counts)
