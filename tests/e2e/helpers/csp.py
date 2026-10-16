"""Browser-level Content Security Policy violation capture.

Each document pushes its violations onto ``window.__prahoCspViolations`` and also reports them to
Python through a page binding, so a violation outlives the document it happened in. The page's
registry is the source of truth for ``read_csp_violations``; the window array stays for callers that
wait on a violation from inside the page.
"""

from dataclasses import dataclass, field
from typing import TypedDict, cast
from weakref import WeakKeyDictionary

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Frame, Page


class CSPViolation(TypedDict):
    blockedURI: str
    violatedDirective: str
    disposition: str
    sourceFile: str
    lineNumber: int


_BINDING = "__prahoCspReport"

# Idempotent: Playwright runs it in every new document and frame, and ensure_csp_capture runs it
# again in the documents that already exist.
_CSP_CAPTURE_SCRIPT = """
(() => {
  if (window.__prahoCspHooked) {
    return;
  }
  const hidden = (value) => ({value, configurable: false, enumerable: false, writable: false});
  const violations = [];
  const pending = [];
  Object.defineProperty(window, "__prahoCspHooked", hidden(true));
  Object.defineProperty(window, "__prahoCspViolations", hidden(violations));
  Object.defineProperty(window, "__prahoCspPending", hidden(pending));

  document.addEventListener(
    "securitypolicyviolation",
    (event) => {
      const violation = {
        blockedURI: event.blockedURI,
        violatedDirective: event.violatedDirective,
        disposition: event.disposition,
        sourceFile: event.sourceFile,
        lineNumber: event.lineNumber,
      };
      violations.push(violation);
      if (typeof window.__prahoCspReport === "function") {
        pending.push(window.__prahoCspReport(violation));
      }
    },
    {capture: true},
  );
})();
"""

# Waits until Python has acknowledged every report this document has sent.
_DRAIN_SCRIPT = "() => Promise.allSettled((window.__prahoCspPending || []).splice(0))"

_FRAME_GONE = ("detached", "Execution context was destroyed", "Target page, context or browser has been closed")


@dataclass
class _CspState:
    violations: list[CSPViolation] = field(default_factory=list)


_STATES: "WeakKeyDictionary[Page, _CspState]" = WeakKeyDictionary()


def _in_frame(frame: Frame, script: str) -> None:
    """Run a script in a frame; a frame that detached or navigated meanwhile is skipped."""
    try:
        frame.evaluate(script)
    except PlaywrightError as exc:
        if not any(marker in str(exc) for marker in _FRAME_GONE):
            raise


def ensure_csp_capture(page: Page) -> _CspState:
    """Capture this page's violations from now on, in every frame and every later document."""
    state = _STATES.get(page)
    if state is None:
        state = _CspState()

        def report(_source: object, violation: CSPViolation) -> None:
            state.violations.append(cast(CSPViolation, dict(violation)))

        page.expose_binding(_BINDING, report)
        page.add_init_script(script=_CSP_CAPTURE_SCRIPT)
        _STATES[page] = state
    for frame in page.frames:
        _in_frame(frame, _CSP_CAPTURE_SCRIPT)
    return state


def install_csp_violation_capture(page: Page) -> None:
    """Install capture before navigation in the page and its future child frames."""
    if page.url != "about:blank":
        raise AssertionError(
            "CSP capture must be installed before the first navigation; "
            f"page is already at {page.url!r}."
        )

    ensure_csp_capture(page)


def read_csp_violations(page: Page) -> list[CSPViolation]:
    """Every violation the page's documents have reported since capture began, earlier pages included.

    A violation is included once its event has fired; waiting for an event that has not fired yet
    is the caller's job.
    """
    state = _STATES.get(page)
    if state is None:
        raise AssertionError("CSP capture was never installed on this page; call install_csp_violation_capture first.")

    for frame in page.frames:
        _in_frame(frame, _DRAIN_SCRIPT)
    return list(state.violations)
