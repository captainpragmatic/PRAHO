"""Which hand-written buttons may remain, by identity, not by count (#821).

A count lets one exemption be swapped for another without anyone noticing, so the expected markers are written out
here by hand, file by file, with the reason each one gives. They come from the per-control decisions in
docs/development/821-control-inventory.md; never regenerate this list from a scan of the tree. A marker that goes
away, appears, moves to another file or changes its reason fails the test, and the list is edited on purpose.

TMPL002 skips each service's own templates/components/ directory, so a raw button moved there would escape the
linter. The second test pins the raw buttons those directories hold today.
"""

import re
from pathlib import Path
from unittest import TestCase

REPO_ROOT = Path(__file__).resolve().parents[2]
MARKER = re.compile(r"\{#\s*tmpl-allow\s+TMPL002\s*:\s*((?:(?!#\}).)*?)\s*#\}")
RAW_BUTTON = re.compile(r"<button\b", re.IGNORECASE)
SKIPPED_DIRECTORIES = {"node_modules", "staticfiles", ".venv", ".venv-darwin", ".venv-linux"}

_TAB = (
    "@click and :class bindings drive the Alpine tab state; "
    "components accept no executable attributes (apps/ui/attributes.py)"
)
_ROLE_CHOICE = (
    "holds structured inner markup (an icon, the role name and a subtitle span) plus a current-role highlight class; "
    "the button tag renders one text and one icon"
)
_SERVER_TAB = (
    "tab button whose classes showTabAction swaps by selector, with a live count in its label; "
    "the button tag's variant classes would break the tab styling"
)
_CART_TOGGLE = (
    "cart toggle whose #cart-count badge, which later swaps update, sits beside its label; "
    "the button tag renders one label and no badge"
)

EXPECTED: dict[str, list[str]] = {
    "services/platform/templates/billing/proforma_form.html": [
        "element is built client-side inside the addLineItem() JavaScript template literal (name uses ${lineCounter}); "
        "a server-side tag cannot render it",
    ],
    "services/platform/templates/customers/detail.html": [
        "role drop-down trigger with two icons (the role icon and a trailing chevron) around the role name and "
        "@click.away on itself; the button tag renders one icon and one label",
        _ROLE_CHOICE,
        _ROLE_CHOICE,
        _ROLE_CHOICE,
        _ROLE_CHOICE,
    ],
    "services/platform/templates/customers/list.html": [
        "the active tab is marked by per-tab text and border colour classes chosen at render time; "
        "the button tag renders every tab in one variant colour",
    ],
    "services/platform/templates/provisioning/virtualmin/account_detail.html": [
        _TAB,
        _TAB,
        _TAB,
        _TAB,
        "holds a second (Protected) span beside its label; the button tag renders one text and one icon",
    ],
    "services/platform/templates/provisioning/virtualmin/server_detail.html": [_SERVER_TAB, _SERVER_TAB, _SERVER_TAB],
    "services/platform/templates/tickets/detail.html": [
        "built client-side inside a JS template literal (fileItem.innerHTML) with a per-file data-index; "
        "icon-only remove button with inline SVG, which the server-rendered button tag cannot produce",
    ],
    "services/portal/templates/e2e/csp_violation_positive_control.html": [
        "CSP positive control - a deliberately raw inline-handler button the e2e test expects CSP to block",
    ],
    "services/portal/templates/orders/partials/cart_updated.html": [_CART_TOGGLE],
    "services/portal/templates/orders/product_catalog.html": [
        _CART_TOGGLE,
        "needs button alpine_class",
        "needs button alpine_class",
    ],
}

# Raw buttons in service-local templates/components/ directories, per file.
LOCAL_COMPONENT_BUTTONS: dict[str, int] = {
    "services/platform/templates/components/mobile_header.html": 1,
    "services/portal/templates/components/clipboard_button.html": 1,
    "services/portal/templates/components/cookie_consent_banner.html": 6,
    "services/portal/templates/components/customer_selector.html": 2,
    "services/portal/templates/components/mfa_disable_button.html": 1,
    "services/portal/templates/components/mobile_header.html": 2,
    "services/portal/templates/components/order_payment_button.html": 1,
    "services/portal/templates/components/service_detail_tabs.html": 4,
}


def _templates(root: Path) -> list[Path]:
    return sorted(
        path for path in root.rglob("*.html") if not SKIPPED_DIRECTORIES.intersection(path.relative_to(root).parts)
    )


def scan_markers(repo_root: Path = REPO_ROOT) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for top in ("services", "shared"):
        for path in _templates(repo_root / top):
            reasons = MARKER.findall(path.read_text(encoding="utf-8"))
            if reasons:
                found[path.relative_to(repo_root).as_posix()] = reasons
    return found


def scan_local_component_buttons(repo_root: Path = REPO_ROOT) -> dict[str, int]:
    found: dict[str, int] = {}
    for components in sorted((repo_root / "services").glob("*/templates/components")):
        for path in _templates(components):
            count = len(RAW_BUTTON.findall(path.read_text(encoding="utf-8")))
            if count:
                found[path.relative_to(repo_root).as_posix()] = count
    return found


class TMPL002RatchetTests(TestCase):
    maxDiff = None

    def test_the_remaining_exemptions_are_exactly_the_decided_ones(self) -> None:
        self.assertEqual(scan_markers(), EXPECTED)

    def test_no_raw_button_hides_in_a_service_s_own_components_directory(self) -> None:
        self.assertEqual(scan_local_component_buttons(), LOCAL_COMPONENT_BUTTONS)
