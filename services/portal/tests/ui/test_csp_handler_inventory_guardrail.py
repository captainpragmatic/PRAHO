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

from django.template import Context, Template
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
#   -3 confirm-on-submit ("data-confirm").
#   -3 usage-period ("load-usage").
#   -1 remove-file, -1 submit-form.
#   -1 print-codes, -1 regenerate-codes, -1 reset-form.
#   -1 toggle-customer-selector, -1 toggle-mobile-menu, -1 switch-customer.
# UNIT 2a button-component migration (was 5): -1 404.html "Go Back" button
#   (bare onclick="history.back()" kwarg -> data-action="back", handled by the
#   shared ui-actions.js registry).
#   -1 styleguide open-modal ("modal-open-by-id"): styleguide/index.html "Open
#   Modal" trigger migrated to data-action -> csp-actions.js window.openModal.
# Merge of master (#459) deleted cart_error_notification.html + cart_item_updated.html
#   -> the 2 toggleMiniCart handlers are gone. Remaining 1 = the intentional e2e
#   positive-control (templates/e2e/csp_violation_positive_control.html), which
#   MUST stay inline; UNIT 2b's on*=->0 exit gate excludes that E2E-only route.
EXPECTED_PORTAL_HANDLERS = 1
# -1 badge-dismiss, -1 back (migrated to the shared ui-actions.js registry).
# -3 modal close buttons (close-modal, shared ui-actions.js: backdrop/X/Cancel),
# -1 modal primary_action inline handler (dead onclick clause -> data-action).
# -2 input.html (toggle-password, clear-input) + -4 list_page_filters.html
#   (desktop+mobile tab buttons x (onclick switch-tab + onkeydown roving-focus)),
#   all migrated to the shared ui-actions.js registry -> shared surface now zero.
EXPECTED_SHARED_HANDLERS = 0
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

    def test_button_attrs_onclick_is_stripped_not_escaped(self) -> None:
        """The button tag must STRIP an on*= handler smuggled via attrs, not just
        HTML-escape it. Escaping alone (onclick=&quot;x()&quot;) still leaves a
        native handler name in the DOM; stripping removes the CSP vector entirely.
        """
        rendered = Template(
            '{% load ui_components %}{% button "Go" attrs=\'onclick="x()"\' %}'
        ).render(Context({}))
        self.assertNotIn("onclick", rendered)
        self.assertNotIn("x()", rendered)
        # Sanity: the button itself still renders (strip did not eat the element).
        self.assertIn("Go", rendered)

    def test_modal_close_buttons_use_delegated_data_action(self) -> None:
        """The shared modal must close via the delegated `close-modal` data-action
        (dispatched by the shared ui-actions.js registry in BOTH services), not a
        native inline onclick. The inventory count only proves the on*= handlers
        were REMOVED; this proves the replacement was wired correctly — the same
        `close-modal` string and `data-modal-id` the JS switch case reads.
        """
        rendered = Template(
            '{% load ui_components %}{% modal "t" "Title" %}'
        ).render(Context({}))
        # Backdrop overlay + header X + footer Cancel all delegate to close-modal.
        self.assertEqual(rendered.count('data-action="close-modal"'), 3)
        # data-modal-id must equal the modal element id so window.closeModal(id)
        # resolves getElementById(id) and restores focus/scroll for THAT modal.
        self.assertIn('data-modal-id="modal-t"', rendered)
        self.assertIn('id="modal-t"', rendered)
        # No native inline handler survives the migration.
        self.assertNotIn("onclick", rendered)
        self.assertNotIn("closeModal(", rendered)

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
