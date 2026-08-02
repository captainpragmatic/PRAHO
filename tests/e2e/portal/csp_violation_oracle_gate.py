"""Hard-failing positive control for the browser CSP violation oracle.

This configuration-specific module is selected explicitly by
``make test-e2e-csp``. Its filename intentionally does not match the default
pytest discovery patterns used by the current-profile portal E2E suite.
"""

import os

from playwright.sync_api import Page

from tests.e2e.helpers import BASE_URL
from tests.e2e.helpers.csp import (
    install_csp_violation_capture,
    read_csp_violations,
)

CONTROL_URL = f"{BASE_URL}/__e2e__/csp-violation/"
STRICT_CSP_PROFILES = frozenset({"phase2-target", "phase3-target"})
VIOLATION_FIELDS = {
    "blockedURI",
    "violatedDirective",
    "disposition",
    "sourceFile",
    "lineNumber",
}


def _parse_csp(csp: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}

    for part in csp.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue

        name, *sources = tokens
        assert name not in directives, (
            f"Duplicate CSP directive {name!r} in {csp!r}"
        )
        directives[name] = sources

    return directives


def _assert_expected_strict_profile(
    csp: str,
    expected_profile: str,
) -> None:
    directives = _parse_csp(csp)

    assert directives.get("script-src-attr") == ["'none'"], (
        "Portal is not serving a target CSP: expected "
        '"script-src-attr \'none\'"; '
        f"received {csp!r}"
    )

    assert "script-src" in directives, (
        f"Portal CSP has no script-src directive: {csp!r}"
    )
    script_sources = directives["script-src"]

    nonce_sources = [
        source
        for source in script_sources
        if source.startswith("'nonce-") and source.endswith("'")
    ]
    assert len(nonce_sources) == 1, (
        "Expected exactly one request nonce in script-src; "
        f"received {script_sources!r}"
    )

    expected_sources = ["'self'", nonce_sources[0]]
    if expected_profile == "phase2-target":
        expected_sources.append("'unsafe-eval'")
    expected_sources.append("https://js.stripe.com")

    assert script_sources == expected_sources, (
        f"Portal is not serving expected profile {expected_profile!r}. "
        f"Expected script-src sources {expected_sources!r}; "
        f"received {script_sources!r}."
    )


def test_enforced_strict_csp_emits_real_browser_violation(
    page: Page,
) -> None:
    expected_profile = os.environ.get("EXPECTED_CSP_PROFILE")
    assert expected_profile in STRICT_CSP_PROFILES, (
        "EXPECTED_CSP_PROFILE must be phase2-target or phase3-target. "
        "Run this gate through `make test-e2e-csp CSP_PROFILE=<profile>`."
    )

    install_csp_violation_capture(page)

    response = page.goto(CONTROL_URL, wait_until="domcontentloaded")
    assert response is not None, (
        f"Navigation to {CONTROL_URL!r} produced no document response."
    )
    assert response.status == 200, (
        f"Positive-control endpoint returned HTTP {response.status}."
    )

    headers = response.headers
    assert "content-security-policy" in headers, (
        "Portal response has no enforced Content-Security-Policy header."
    )
    assert "content-security-policy-report-only" not in headers, (
        "Portal is serving CSP in Report-Only mode; the gate requires "
        "CSP_REPORT_ONLY=false."
    )
    _assert_expected_strict_profile(
        headers["content-security-policy"],
        expected_profile,
    )

    page.locator("#csp-positive-control").click()
    page.wait_for_function(
        "() => window.__prahoCspViolations.length === 1"
    )

    violations = read_csp_violations(page)
    assert len(violations) == 1, (
        f"Expected exactly one positive-control violation; got {violations!r}"
    )

    violation = violations[0]
    assert set(violation) == VIOLATION_FIELDS, (
        f"Violation payload has the wrong shape: {violation!r}"
    )
    assert violation["blockedURI"] == "inline"
    assert violation["violatedDirective"] == "script-src-attr"
    assert violation["disposition"] == "enforce"
    assert violation["sourceFile"] == page.url
    assert type(violation["lineNumber"]) is int
    assert violation["lineNumber"] > 0

    assert page.evaluate(
        "() => window.__cspPositiveControlExecuted === true"
    ) is False, "The deliberately forbidden inline handler executed."
