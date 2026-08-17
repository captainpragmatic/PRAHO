"""Guard the portal's vendored Alpine CSP build and service-specific wiring.

The CSP build removes Alpine's new-Function evaluator so the portal can drop
``'unsafe-eval'``. The SHA pin is a supply-chain and tamper guard, while parser
and version markers provide a readable semantic layer beneath that byte-level
check. Runtime behavior is proved by the enforced-CSP E2E gate, not this test.

No database access (portal test isolation).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from django.test import SimpleTestCase

REPO_ROOT = Path(__file__).resolve().parents[4]
PORTAL_CSP_BUILD = REPO_ROOT / "services" / "portal" / "static" / "js" / "alpine-csp.min.js"
PORTAL_STANDARD_BUILD = REPO_ROOT / "services" / "portal" / "static" / "js" / "alpine.min.js"
PLATFORM_STANDARD_BUILD = REPO_ROOT / "services" / "platform" / "static" / "js" / "alpine.min.js"
PORTAL_BASE_TEMPLATE = REPO_ROOT / "services" / "portal" / "templates" / "base.html"
PLATFORM_BASE_TEMPLATE = REPO_ROOT / "services" / "platform" / "templates" / "base.html"

# Provenance: @alpinejs/csp@3.15.0, MIT license.
# Source: https://cdn.jsdelivr.net/npm/@alpinejs/csp@3.15.0/dist/cdn.min.js
# Fetched: 2026-08-02.
PINNED_CSP_SHA256 = "e7c863da5896692f5d478e10dae089e6164fed1c5c1b6a1f7cbbf7a9b093f055"
CSP_PARSER_MARKERS = ("tokenize", "parseExpression")

PORTAL_CSP_REFERENCE = "'js/alpine-csp.min.js'"
STANDARD_ALPINE_REFERENCE = "'js/alpine.min.js'"
SHARED_COMPONENTS_SCRIPT = (
    '<script defer src="{% static \'js/alpine-shared-components.js\' %}"></script>'
)
PORTAL_COMPONENTS_SCRIPT = '<script defer src="{% static \'js/alpine-components.js\' %}"></script>'
PORTAL_CSP_SCRIPT = '<script defer src="{% static \'js/alpine-csp.min.js\' %}"></script>'


class AlpineCSPBuildGuardTests(SimpleTestCase):
    def test_portal_csp_build_matches_pinned_sha256(self) -> None:
        digest = hashlib.sha256(PORTAL_CSP_BUILD.read_bytes()).hexdigest()

        self.assertEqual(digest, PINNED_CSP_SHA256)

    def test_portal_csp_build_has_parser_and_version_markers(self) -> None:
        source = PORTAL_CSP_BUILD.read_text(encoding="utf-8")

        for marker in CSP_PARSER_MARKERS:
            with self.subTest(marker=marker):
                self.assertIn(marker, source)
        self.assertIn('version:"3.15.0"', source)

    def test_platform_standard_build_lacks_csp_parser_markers(self) -> None:
        source = PLATFORM_STANDARD_BUILD.read_text(encoding="utf-8")

        for marker in CSP_PARSER_MARKERS:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, source)

    def test_portal_standard_build_is_absent(self) -> None:
        self.assertFalse(PORTAL_STANDARD_BUILD.exists())

    def test_each_service_references_its_intended_alpine_build(self) -> None:
        portal_template = PORTAL_BASE_TEMPLATE.read_text(encoding="utf-8")
        platform_template = PLATFORM_BASE_TEMPLATE.read_text(encoding="utf-8")

        self.assertIn(PORTAL_CSP_REFERENCE, portal_template)
        self.assertNotIn(STANDARD_ALPINE_REFERENCE, portal_template)
        self.assertIn(STANDARD_ALPINE_REFERENCE, platform_template)
        self.assertNotIn(PORTAL_CSP_REFERENCE, platform_template)

    def test_portal_registers_components_before_alpine_boots(self) -> None:
        portal_template = PORTAL_BASE_TEMPLATE.read_text(encoding="utf-8")
        alpine_csp_position = portal_template.index(PORTAL_CSP_SCRIPT)

        self.assertLess(portal_template.index(SHARED_COMPONENTS_SCRIPT), alpine_csp_position)
        self.assertLess(portal_template.index(PORTAL_COMPONENTS_SCRIPT), alpine_csp_position)
