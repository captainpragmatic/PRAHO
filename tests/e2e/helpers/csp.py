"""Browser-level Content Security Policy violation capture."""

from typing import TypedDict, cast

from playwright.sync_api import Page


class CSPViolation(TypedDict):
    blockedURI: str
    violatedDirective: str
    disposition: str
    sourceFile: str
    lineNumber: int


_CSP_CAPTURE_INIT_SCRIPT = """
(() => {
  const violations = [];

  Object.defineProperty(window, "__prahoCspViolations", {
    value: violations,
    configurable: false,
    enumerable: false,
    writable: false,
  });

  document.addEventListener(
    "securitypolicyviolation",
    (event) => {
      violations.push({
        blockedURI: event.blockedURI,
        violatedDirective: event.violatedDirective,
        disposition: event.disposition,
        sourceFile: event.sourceFile,
        lineNumber: event.lineNumber,
      });
    },
    {capture: true},
  );
})();
"""


def install_csp_violation_capture(page: Page) -> None:
    """Install capture before navigation in the page and its future child frames."""
    if page.url != "about:blank":
        raise AssertionError(
            "CSP capture must be installed before the first navigation; "
            f"page is already at {page.url!r}."
        )

    # Playwright evaluates an init script for every navigation and whenever a
    # child frame is attached or navigated.
    page.add_init_script(script=_CSP_CAPTURE_INIT_SCRIPT)


def read_csp_violations(page: Page) -> list[CSPViolation]:
    """Read captured violations from the top document and every current frame."""
    violations: list[CSPViolation] = []

    for frame in page.frames:
        frame_violations = frame.evaluate(
            "() => window.__prahoCspViolations"
        )
        if not isinstance(frame_violations, list):
            raise AssertionError(
                "CSP capture state is absent from frame "
                f"{frame.url!r}; was capture installed before navigation?"
            )

        for violation in frame_violations:
            if not isinstance(violation, dict):
                raise AssertionError(
                    f"Malformed CSP violation from frame {frame.url!r}: "
                    f"{violation!r}"
                )
            violations.append(cast(CSPViolation, violation))

    return violations
