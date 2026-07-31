"""CSP inline-handler / eval-feature inventory SNAPSHOT guardrail (#104 [M7], UNIT 0.5).

Pins the CURRENT count of inline event handlers (on*=), HTMX eval features
(hx-on), and Python-generated widget handlers across the portal-renderable
surface. Any NEW handler added during — or after — the CSP migration changes a
count and fails here, forcing a conscious inventory update instead of a silent
regression.

This does NOT assert zero. The `== 0` assertion is the EXIT gate, flipped at the
end of UNIT 2a (on*= -> 0) and UNIT 3c (hx-on -> 0). Until then this snapshot is
the tripwire. When a phase legitimately removes handlers, lower the pinned
baseline in the same commit.

No database access (portal test isolation).
"""

from __future__ import annotations

import re
from pathlib import Path

from django.test import SimpleTestCase

REPO_ROOT = Path(__file__).resolve().parents[4]
PORTAL_TEMPLATES = REPO_ROOT / "services" / "portal" / "templates"
SHARED_TEMPLATES = REPO_ROOT / "shared" / "ui" / "templates"
PORTAL_APPS = REPO_ROOT / "services" / "portal" / "apps"

# Inline DOM event handler attribute: whitespace + on<event>="  (onclick, onchange, ...).
# "on" inside hx-on is preceded by "-", so this never double-counts HTMX features.
ON_HANDLER_RE = re.compile(r'\son[a-z]+="')
# HTMX inline eval feature: hx-on::<event> / hx-on:<event>
HX_ON_RE = re.compile(r"hx-on:")
# Python-generated handler in a widget attrs dict: "on<event>":
PY_HANDLER_RE = re.compile(r'"on[a-z]+"\s*:')

# --- Pinned baseline (lower DELIBERATELY as handlers are refactored away) ---
# UNIT 2a migrations to the data-action delegated registry (was 35):
#   -6 row-navigation ("navigate"), -2 error-notification dismiss ("dismiss").
#   -3 copy-to-clipboard ("copy").
#   -2 cookie-prefs ("cookie-prefs"), -3 invoice-refund modal ("modal-open"/"modal-close").
EXPECTED_PORTAL_HANDLERS = 19
EXPECTED_SHARED_HANDLERS = 12
EXPECTED_PY_HANDLERS = 1
EXPECTED_HX_ON = 11

# Canary: the Python-generated onchange a template-only scan would miss.
CANARY_PY_HANDLER_FILE = "services/portal/apps/users/forms.py"


def _count_in_html(root: Path, pattern: re.Pattern[str]) -> int:
    total = 0
    for path in root.rglob("*.html"):
        total += len(pattern.findall(path.read_text(encoding="utf-8")))
    return total


def _find_py_handlers(root: Path) -> tuple[int, list[str]]:
    total = 0
    files: list[str] = []
    for path in root.rglob("*.py"):
        if "tests" in path.parts or path.name.startswith("test_"):
            continue
        hits = PY_HANDLER_RE.findall(path.read_text(encoding="utf-8"))
        if hits:
            total += len(hits)
            files.append(path.relative_to(REPO_ROOT).as_posix())
    return total, files


class CSPHandlerInventoryGuardrailTests(SimpleTestCase):
    def test_portal_inline_handler_count_matches_baseline(self) -> None:
        count = _count_in_html(PORTAL_TEMPLATES, ON_HANDLER_RE)
        self.assertEqual(
            count,
            EXPECTED_PORTAL_HANDLERS,
            f"Portal inline on*= handler count is {count}, baseline "
            f"{EXPECTED_PORTAL_HANDLERS}. Added one? Refactor to a delegated "
            f"data-action listener (UNIT 2a) instead of a new inline handler. "
            f"Removed one? Lower the baseline in the same commit.",
        )

    def test_shared_ui_inline_handler_count_matches_baseline(self) -> None:
        count = _count_in_html(SHARED_TEMPLATES, ON_HANDLER_RE)
        self.assertEqual(
            count,
            EXPECTED_SHARED_HANDLERS,
            f"Shared/ui inline on*= handler count is {count}, baseline "
            f"{EXPECTED_SHARED_HANDLERS}. Shared components have platform blast "
            f"radius — change deliberately.",
        )

    def test_python_generated_handler_inventory_and_canary(self) -> None:
        count, files = _find_py_handlers(PORTAL_APPS)
        self.assertEqual(
            count,
            EXPECTED_PY_HANDLERS,
            f"Python-generated on*= widget-attr handler count is {count}, "
            f"baseline {EXPECTED_PY_HANDLERS}; found in {files}.",
        )
        # A template-only regex would miss this; assert the scan still finds it.
        self.assertIn(CANARY_PY_HANDLER_FILE, files)

    def test_htmx_eval_feature_count_matches_baseline(self) -> None:
        count = _count_in_html(PORTAL_TEMPLATES, HX_ON_RE) + _count_in_html(
            SHARED_TEMPLATES, HX_ON_RE
        )
        self.assertEqual(
            count,
            EXPECTED_HX_ON,
            f"hx-on eval-feature count is {count}, baseline {EXPECTED_HX_ON}. "
            f"These collapse to 2 global listeners in UNIT 3c.",
        )
