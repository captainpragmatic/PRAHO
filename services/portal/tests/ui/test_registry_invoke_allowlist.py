"""Source guardrails for the delegated action registries.

No database access (portal test isolation).
"""

from __future__ import annotations

import re
from pathlib import Path

from django.test import SimpleTestCase

REPO_ROOT = Path(__file__).resolve().parents[4]
TEMPLATE_ROOTS = (
    REPO_ROOT / "services" / "platform" / "templates",
    REPO_ROOT / "services" / "portal" / "templates",
    REPO_ROOT / "shared" / "ui" / "templates",
)
UI_ACTIONS = REPO_ROOT / "shared" / "ui" / "static" / "js" / "ui-actions.js"
CSP_ACTIONS = REPO_ROOT / "services" / "portal" / "static" / "js" / "csp-actions.js"

EXPECTED_INVOKE_NAMES = 11
TEMPLATE_INVOKE_RE = re.compile(
    r"(?:data_invoke|data-invoke)\s*=\s*(?P<quote>['\"])(?P<name>[A-Za-z_$][\w$]*)(?P=quote)"
)
ALLOWLIST_RE = re.compile(
    r"var INVOKE_ALLOWLIST = Object\.freeze\(\{(?P<body>.*?)\}\);",
    re.DOTALL,
)
ALLOWLIST_NAME_RE = re.compile(r"^\s*([A-Za-z_$][\w$]*): true,?\s*$", re.MULTILINE)


def _template_invoke_names() -> set[str]:
    names: set[str] = set()
    for root in TEMPLATE_ROOTS:
        for path in root.rglob("*.html"):
            source = path.read_text(encoding="utf-8")
            names.update(match.group("name") for match in TEMPLATE_INVOKE_RE.finditer(source))
    return names


def _allowlist_names(source: str) -> list[str]:
    match = ALLOWLIST_RE.search(source)
    if match is None:
        return []
    return ALLOWLIST_NAME_RE.findall(match.group("body"))


class RegistryInvokeAllowlistGuardTests(SimpleTestCase):
    def test_invoke_allowlist_matches_literal_template_usage(self) -> None:
        template_names = _template_invoke_names()
        allowlist_names = _allowlist_names(UI_ACTIONS.read_text(encoding="utf-8"))

        self.assertEqual(
            len(template_names),
            EXPECTED_INVOKE_NAMES,
            "The template invoke-name count changed; update the templates and JavaScript allow-list deliberately.",
        )
        self.assertEqual(
            len(allowlist_names),
            EXPECTED_INVOKE_NAMES,
            "The JavaScript invoke allow-list count changed; update it and the template inventory deliberately.",
        )
        self.assertEqual(
            len(set(allowlist_names)),
            EXPECTED_INVOKE_NAMES,
            "The JavaScript invoke allow-list contains duplicate names; keep all 11 entries unique.",
        )
        self.assertEqual(template_names, set(allowlist_names))

    def test_confirm_submit_unknown_gate_fails_closed(self) -> None:
        source = UI_ACTIONS.read_text(encoding="utf-8")
        start = source.index('case "confirm-submit":')
        end = source.index('case "close-modal":', start)
        confirm_submit_source = source[start:end]

        self.assertIn("var gateName = el.dataset.invoke;", confirm_submit_source)
        self.assertIn("if (gateName !== undefined) {", confirm_submit_source)
        self.assertIn(
            "!Object.prototype.hasOwnProperty.call(INVOKE_ALLOWLIST, gateName)",
            confirm_submit_source,
        )
        self.assertIn('typeof window[gateName] !== "function"', confirm_submit_source)
        # Whitespace-tolerant but order-preserving: the blocked branch must
        # preventDefault, warn, and break adjacently, in that order.
        self.assertRegex(
            confirm_submit_source,
            r'event\.preventDefault\(\);\s*'
            r'console\.warn\("Blocked confirm-submit gate:", gateName\);\s*'
            r'break;',
        )

    def test_submit_form_uses_unclobberable_request_submit(self) -> None:
        source = CSP_ACTIONS.read_text(encoding="utf-8")

        self.assertIn("HTMLFormElement.prototype.requestSubmit.call(submitForm)", source)
        self.assertNotIn("submitForm.submit()", source)

    def test_navigate_requires_same_origin_url(self) -> None:
        source = CSP_ACTIONS.read_text(encoding="utf-8")
        start = source.index('case "navigate":')
        end = source.index('case "dismiss":', start)
        navigate_source = source[start:end]

        self.assertIn("new URL(href, window.location.origin)", navigate_source)
        self.assertIn("url.origin !== window.location.origin", navigate_source)
