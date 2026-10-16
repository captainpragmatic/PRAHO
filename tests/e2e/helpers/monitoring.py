"""
E2E Page Quality Monitoring — console, network, HTML, CSS, accessibility, performance.

Contains ComprehensivePageMonitor, ConsoleMonitor, and all quality check functions.
"""

import contextlib
import fnmatch
from collections.abc import Collection
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Page

from tests.e2e.helpers.constants import DJANGO_Q_LOG_FILE, PLATFORM_LOG_FILE, PORTAL_LOG_FILE
from tests.e2e.helpers.csp import ensure_csp_capture, read_csp_violations
from tests.e2e.helpers.server_logs import ServerLogScanner

# ===============================================================================
# CONSOLE ERROR MONITORING
# ===============================================================================

# An ignore pattern containing one of these would hide an access-control failure.
_AUTH_ERROR_TOKENS = ("401", "403", "404", "forbidden", "unauthorized")


def _sync_with_page(page: Page) -> None:
    """One round trip, so every event the browser has already emitted reaches the collectors."""
    # A closed or navigating page has nothing left to deliver; the checks that need the page
    # report their own failure.
    with contextlib.suppress(PlaywrightError):
        page.evaluate("() => null")


class _ConsoleCollector:
    """Console errors, warnings and uncaught page errors, with a listener that can be removed.

    An uncaught exception is not a console message in Playwright: it only fires ``pageerror``.
    """

    def __init__(self) -> None:
        self.messages: list[dict[str, Any]] = []
        self.page_errors: list[str] = []
        self._page: Page | None = None

        # One stable callable per event, so ``remove_listener`` finds what ``on`` registered. They
        # look the handler up on each call, so a test can observe delivery by patching the class.
        def on_console(msg: Any) -> None:
            self.handle_console(msg)

        def on_page_error(error: Any) -> None:
            self.handle_page_error(error)

        self._on_console = on_console
        self._on_page_error = on_page_error

    def handle_console(self, msg: Any) -> None:
        if msg.type in ("error", "warning"):
            self.messages.append({"type": msg.type, "text": msg.text, "location": msg.location})

    def handle_page_error(self, error: Any) -> None:
        self.page_errors.append(getattr(error, "message", None) or str(error))

    def attach(self, page: Page) -> None:
        # Each monitored block starts clean, so a reused monitor never fails on an earlier block.
        self.messages.clear()
        self.page_errors.clear()
        page.on("console", self._on_console)
        page.on("pageerror", self._on_page_error)
        self._page = page

    def detach(self) -> None:
        if self._page is not None:
            self._page.remove_listener("console", self._on_console)
            self._page.remove_listener("pageerror", self._on_page_error)
            self._page = None


def setup_console_monitoring_standalone(page: Page) -> list[dict[str, Any]]:
    """
    Set up console message monitoring for the page (standalone utility function).

    Args:
        page: Playwright page object

    Returns:
        list: Console messages list to collect messages

    Example:
        console_messages = setup_console_monitoring_standalone(page)
    """
    collector = _ConsoleCollector()
    collector.attach(page)
    return collector.messages


# ===============================================================================
# HTTP RESPONSE MONITORING
# ===============================================================================


@dataclass(frozen=True)
class HttpExpectation:
    """A response a test deliberately provokes: one of ``statuses`` at a path glob."""

    statuses: frozenset[int]
    path: str
    query: str | None = None

    def matches(self, status: int, url: str) -> bool:
        parts = urlsplit(url)
        return (
            status in self.statuses
            and fnmatch.fnmatchcase(parts.path, self.path)
            and (self.query is None or parts.query == self.query)
        )


@dataclass(frozen=True)
class HttpRecord:
    """A 4xx or 5xx response, judged against the expectations active when it arrived."""

    status: int
    method: str
    url: str
    resource_type: str
    excused: bool

    @property
    def requested_path(self) -> str:
        parts = urlsplit(self.url)
        return parts.path + (f"?{parts.query}" if parts.query else "")

    def describe(self) -> str:
        return f"HTTP {self.status} {self.method} {self.requested_path} ({self.resource_type})"


class _ResponseCollector:
    """Every response's request id, and every response of 400 or above."""

    def __init__(self, expectations: list[HttpExpectation]) -> None:
        self.records: list[HttpRecord] = []
        self.request_ids: set[str] = set()
        self._expectations = expectations
        self._page: Page | None = None

        def on_response(response: Any) -> None:
            self.handle_response(response)

        self._on_response = on_response

    def handle_response(self, response: Any) -> None:
        req_id = response.headers.get("x-request-id")
        if req_id:
            self.request_ids.add(req_id)
        if response.status >= 400:
            request = response.request
            self.records.append(
                HttpRecord(
                    status=response.status,
                    method=request.method,
                    url=response.url,
                    resource_type=request.resource_type,
                    excused=any(e.matches(response.status, response.url) for e in self._expectations),
                )
            )

    def attach(self, page: Page) -> None:
        # Each monitored block starts clean, as the console collector does.
        self.records.clear()
        self.request_ids.clear()
        page.on("response", self._on_response)
        self._page = page

    def detach(self) -> None:
        if self._page is not None:
            self._page.remove_listener("response", self._on_response)
            self._page = None


def _validate_ignore_patterns(patterns: list[str], *, allow_auth: bool) -> list[str]:
    """Refuse a pattern that would also hide an auth or not-found error, unless opted in."""
    if not allow_auth:
        for pattern in patterns:
            lowered = pattern.lower()
            if any(token in lowered for token in _AUTH_ERROR_TOKENS):
                raise ValueError(
                    f"Ignore pattern {pattern!r} would also hide auth or not-found errors; "
                    "pass allow_auth_error_ignores=True if that is the point of the test."
                )
    return list(patterns)


def assert_no_console_errors(console_messages: list[dict[str, Any]], ignore_patterns: list[str] | None = None,
                           context: str = "") -> None:
    """
    Assert that there are no JavaScript console errors.

    Args:
        console_messages: List of console messages from setup_console_monitoring_standalone
        ignore_patterns: List of error message patterns to ignore
        context: Context description for better error messages

    Raises:
        AssertionError: If console errors are found

    Example:
        console_messages = setup_console_monitoring_standalone(page)
        # ... perform actions ...
        assert_no_console_errors(console_messages, context="after login")
    """
    # Default patterns to ignore (common development noise)
    # NOTE: Browser-level "Failed to load resource" messages (e.g., favicon.ico 404)
    # are NOT application console.error() calls. The monitor's response collector reports the
    # failed response itself. Application JS errors use specific messages, not generic resource loads.
    default_ignore = [
        "favicon",           # Favicon not found errors
        "Failed to load resource",  # Browser resource loading (404s, CORS) — not app errors
        "debug_toolbar",     # Django debug toolbar warnings
        "net::ERR_INTERNET_DISCONNECTED",  # Network connectivity
        "chunks",           # Webpack chunk loading (if any)
        "sw.js",            # Service worker (if any)
        "ERR_NETWORK",      # Network errors during test cleanup
        "X-Frame-Options",   # X-Frame-Options meta tag warnings
    ]

    ignore_patterns = (ignore_patterns or []) + default_ignore

    # Filter out ignored patterns
    errors = []
    for msg in console_messages:
        if msg['type'] == 'error':
            message_text = msg['text']
            should_ignore = any(pattern.lower() in message_text.lower()
                              for pattern in ignore_patterns)
            if not should_ignore:
                errors.append(f"[{msg['type'].upper()}] {message_text}")

    if errors:
        context_msg = f" {context}" if context else ""
        error_list = "\n".join(f"  - {error}" for error in errors)
        raise AssertionError(f"Console errors found{context_msg}:\n{error_list}")

    if context:
        print(f"  ✅ No console errors {context}")
    else:
        print("  ✅ No console errors detected")


def check_html_validation(page: Page) -> list[str]:
    """
    Check for basic HTML validation issues and HTMX problems.

    Args:
        page: Playwright page object

    Returns:
        list[str]: List of HTML/HTMX validation issues
    """
    html_issues: list[str] = []

    try:
        # Check for duplicate IDs (major HTML validation issue)
        duplicate_ids = page.evaluate("""
            () => {
                const ids = {};
                const duplicates = [];
                document.querySelectorAll('[id]').forEach(el => {
                    const id = el.id;
                    if (ids[id]) {
                        duplicates.push(id);
                    } else {
                        ids[id] = true;
                    }
                });
                return [...new Set(duplicates)];
            }
        """)

        html_issues.extend(f"Duplicate ID found: '{duplicate_id}'" for duplicate_id in duplicate_ids)

        # Check for missing alt attributes on images
        missing_alt_images = page.locator('img:not([alt])').count()
        if missing_alt_images > 0:
            html_issues.append(f"{missing_alt_images} images missing alt attributes")

        # Check for HTMX-specific issues
        htmx_issues = page.evaluate("""
            () => {
                const issues = [];

                // Check for HTMX elements with invalid targets
                document.querySelectorAll('[hx-target]').forEach(el => {
                    const target = el.getAttribute('hx-target');
                    if (target &&
                        !target.startsWith('#') && !target.startsWith('.') &&
                        target !== 'this' && !target.includes(' ') &&
                        !document.querySelector(target)) {
                        issues.push('Invalid HTMX target: ' + target);
                    }
                });

                // Check for forms without proper CSRF tokens (Django-specific)
                document.querySelectorAll('form[method="post"]:not([hx-post]):not([hx-put]):not([hx-patch])').forEach(form => {
                    if (!form.querySelector('input[name="csrfmiddlewaretoken"]')) {
                        issues.push('Form missing CSRF token');
                    }
                });

                return issues;
            }
        """)

        html_issues.extend(htmx_issues)

    except Exception as e:
        html_issues.append(f"HTML validation check failed: {str(e)[:50]}")

    return html_issues


def check_css_issues(page: Page) -> list[str]:
    """
    Check for CSS-related issues and layout problems.

    Args:
        page: Playwright page object

    Returns:
        list[str]: List of CSS issues
    """
    css_issues = []

    try:
        # Check for CSS load failures
        css_errors = page.evaluate("""
            () => {
                const issues = [];

                // Check for failed CSS loads
                document.querySelectorAll('link[rel="stylesheet"]').forEach(link => {
                    if (link.sheet === null) {
                        issues.push('Failed to load CSS: ' + link.href);
                    }
                });

                // Check for elements with zero dimensions that shouldn't be hidden
                document.querySelectorAll('main, .content, [data-testid]').forEach(el => {
                    const rect = el.getBoundingClientRect();
                    if (rect.width === 0 && rect.height === 0 &&
                        getComputedStyle(el).display !== 'none' &&
                        getComputedStyle(el).visibility !== 'hidden') {
                        issues.push('Element has zero dimensions: ' + (el.id || el.className || el.tagName));
                    }
                });

                // Check for horizontal scrollbars (potential layout issue)
                if (document.documentElement.scrollWidth > window.innerWidth) {
                    issues.push('Horizontal scrollbar detected (potential layout issue)');
                }

                return issues;
            }
        """)

        css_issues.extend(css_errors)

    except Exception as e:
        css_issues.append(f"CSS validation check failed: {str(e)[:50]}")

    return css_issues


def check_accessibility_basics(page: Page) -> list[str]:
    """
    Check for basic accessibility issues.

    Automatically filters out Django Debug Toolbar elements since they are:
    - Development-only tools (disabled in production)
    - Third-party library code (not our application)
    - Not part of the user interface

    Args:
        page: Playwright page object

    Returns:
        list[str]: List of accessibility issues
    """
    a11y_issues = []

    try:
        accessibility_checks = page.evaluate("""
            () => {
                const issues = [];

                // Check for missing form labels (exclude Django Debug Toolbar elements)
                document.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="button"])').forEach(input => {
                    // Skip Django Debug Toolbar inputs (development only)
                    if (input.hasAttribute('data-cookie') && input.getAttribute('data-cookie').startsWith('djdt')) {
                        return;
                    }

                    // Skip inputs inside Django Debug Toolbar container
                    if (input.closest('#djDebug, .djDebugToolbar, [id*="djdt"], [class*="djdt"]')) {
                        return;
                    }

                    // Search inputs are exempt (acceptable UX pattern). A placeholder is not a label:
                    // it disappears on input and is not a reliable accessible name.
                    if (input.type === 'search' || input.name === 'search') {
                        return;
                    }

                    const id = input.id;
                    const hasLabelFor = id && document.querySelector('label[for="' + id + '"]');
                    const hasLabelParent = input.closest('label') !== null;
                    if (!hasLabelFor && !hasLabelParent) {
                        const ariaLabel = (input.getAttribute('aria-label') || '').trim();
                        const labelledBy = (input.getAttribute('aria-labelledby') || '').trim();
                        const labelElements = labelledBy.split(' ').filter(Boolean).map(ref => document.getElementById(ref));
                        const labelledByText = labelElements.length && labelElements.every(Boolean)
                            ? labelElements.map(el => el.textContent).join(' ').trim()
                            : '';
                        if (!ariaLabel && !labelledByText) {
                            issues.push('Input missing label: ' + (input.name || input.type || 'unknown'));
                        }
                    }
                });

                // Check for buttons without accessible names (exclude Django Debug Toolbar elements)
                document.querySelectorAll('button:not([aria-label]):not([title])').forEach(button => {
                    // Skip buttons inside Django Debug Toolbar container
                    if (button.closest('#djDebug, .djDebugToolbar, [id*="djdt"], [class*="djdt"]')) {
                        return;
                    }

                    if (!button.textContent.trim()) {
                        issues.push('Button without accessible name');
                    }
                });

                // Check for missing heading structure (warn-only: teardown page state
                // may differ from test page state after form saves and redirects)
                const headings = document.querySelectorAll('h1, h2, h3, h4, h5, h6');
                if (headings.length === 0) {
                    console.warn('[A11Y] Page has no heading elements');
                } else if (!document.querySelector('h1')) {
                    console.warn('[A11Y] Page missing h1 heading');
                }

                return issues;
            }
        """)

        a11y_issues.extend(accessibility_checks)

    except Exception as e:
        a11y_issues.append(f"Accessibility check failed: {str(e)[:50]}")

    return a11y_issues


def check_performance_issues(page: Page) -> list[str]:
    """
    Check for basic performance issues.

    Args:
        page: Playwright page object

    Returns:
        list[str]: List of performance issues
    """
    perf_issues = []

    try:
        # Check page load metrics
        performance_data = page.evaluate("""
            () => {
                const issues = [];
                const navigation = performance.getEntriesByType('navigation')[0];

                if (navigation) {
                    // Check for slow loading times (> 3 seconds)
                    const loadTime = navigation.loadEventEnd - navigation.fetchStart;
                    if (loadTime > 3000) {
                        issues.push(`Slow page load: ${Math.round(loadTime)}ms`);
                    }

                    // Check for slow server response (> 1 second)
                    const responseTime = navigation.responseEnd - navigation.requestStart;
                    if (responseTime > 1000) {
                        issues.push(`Slow server response: ${Math.round(responseTime)}ms`);
                    }
                }

                // Check for large images without optimization
                document.querySelectorAll('img').forEach(img => {
                    if (img.naturalWidth > 2000 && !img.src.includes('optimized')) {
                        issues.push('Large unoptimized image: ' + img.src.split('/').pop());
                    }
                });

                return issues;
            }
        """)

        perf_issues.extend(performance_data)

    except Exception as e:
        perf_issues.append(f"Performance check failed: {str(e)[:50]}")

    return perf_issues


# ===============================================================================
# PAGE MONITOR CONFIGURATION
# ===============================================================================

@dataclass
class PageQualityConfig:
    """Configuration object for page quality monitoring"""
    check_console: bool = True
    check_network: bool = True
    check_html: bool = True
    check_css: bool = True
    check_accessibility: bool = False  # Can be slow
    check_performance: bool = False    # Can be slow
    check_server_logs: bool = True     # Check platform/portal server logs for errors
    check_csp: bool = True             # Fail on CSP violations, enforced or report-only
    ignore_patterns: list[str] = field(default_factory=list)


class ComprehensivePageMonitor:
    """
    Comprehensive monitoring for all aspects of page quality during test execution.

    Events count when the browser delivered them before the monitor's final sync point in
    ``__exit__``; a test that starts background work it cares about must await it before
    leaving the block.

    Example:
        with ComprehensivePageMonitor(page, "login process") as monitor:
            login_user(page, email, password)
            # All quality checks are automatically performed when exiting context
    """

    def __init__(self, page: Page, context: str = "",
                 config: PageQualityConfig | None = None,
                 **kwargs: Any):
        # Explicit opt-outs for exceptional flows (e.g., known broken third-party pages)
        allow_accessibility_skip = bool(kwargs.pop("allow_accessibility_skip", False))
        allow_auth_error_ignores = bool(kwargs.pop("allow_auth_error_ignores", False))

        # Use default config if none provided
        if config is None:
            config = PageQualityConfig()

        # Override with any direct kwargs for backward compatibility
        for key, value in kwargs.items():
            if hasattr(config, key) and value is not None:
                setattr(config, key, value)

        self.page = page
        self.context = context
        self.config = config
        self.check_console = config.check_console
        self.check_network = config.check_network
        self.check_html = config.check_html
        self.check_css = config.check_css
        self.check_accessibility = config.check_accessibility
        self.check_performance = config.check_performance
        self.check_server_logs = config.check_server_logs
        self.check_csp = config.check_csp
        # Security hardening: never suppress auth/access-denied/not-found errors by default.
        self.ignore_patterns = _validate_ignore_patterns(
            list(config.ignore_patterns), allow_auth=allow_auth_error_ignores
        )
        self._log_scanner: ServerLogScanner | None = None
        self._expected_error_patterns: list[str] = []
        self._http_expectations: list[HttpExpectation] = []
        self._console = _ConsoleCollector()
        self._responses = _ResponseCollector(self._http_expectations)
        self._csp_seen = 0

        # Quality hardening: keep accessibility checks enabled unless explicitly opted out.
        if not self.check_accessibility and self.check_html and self.check_css and not allow_accessibility_skip:
            self.check_accessibility = True

    @property
    def console_messages(self) -> list[dict[str, Any]]:
        return self._console.messages

    def __enter__(self):
        try:
            if self.check_console:
                self._console.attach(self.page)

            if self.check_server_logs:
                self._log_scanner = ServerLogScanner([PLATFORM_LOG_FILE, PORTAL_LOG_FILE, DJANGO_Q_LOG_FILE])
                if self._log_scanner.available:
                    self._log_scanner.mark_position()
                else:
                    print("  ⚠️ Server log files not found — run `make dev-e2e-bg` to enable log checking")

            if self.check_network or self.check_server_logs:
                self._responses.attach(self.page)

            if self.check_csp:
                self._csp_seen = len(ensure_csp_capture(self.page).violations)
        except BaseException:
            self._detach()
            raise

        return self

    def expect_http(self, statuses: Collection[int], path: str, *, query: str | None = None) -> None:
        """Excuse responses with one of ``statuses`` whose URL path matches the ``path`` glob.

        Only responses that arrive after this call are excused. ``query``, when given, must equal
        the query string exactly; a ``?`` in ``path`` is refused because fnmatch reads it as a
        wildcard.
        """
        if "?" in path or "#" in path:
            raise ValueError(f"expect_http path {path!r} must not contain a query or fragment; pass query=")
        self._http_expectations.append(HttpExpectation(frozenset(statuses), path, query))

    def clear_http_expectations(self) -> None:
        """Stop excusing responses from now on; responses already judged keep their verdict."""
        self._http_expectations.clear()

    def _sync_point(self) -> None:
        _sync_with_page(self.page)

    def _detach(self) -> None:
        self._console.detach()
        self._responses.detach()

    def _check_console_issues(self) -> list[str]:
        """Console errors and uncaught page errors, minus the ones an excused response explains."""
        if not self.check_console:
            return []

        # A response a test provoked on purpose also makes HTMX log "Response Status Error Code
        # <status> from <path>", directly and inside the base templates' "HTMX Error:" detail. Only
        # that diagnostic is excused: another error that merely names the path still fails.
        excused_diagnostics = [
            f"Response Status Error Code {record.status} from {record.requested_path}"
            for record in self._responses.records
            if record.excused
        ]
        issues: list[str] = []
        try:
            assert_no_console_errors(
                self._console.messages,
                ignore_patterns=self.ignore_patterns + excused_diagnostics,
                context=self.context
            )
        except AssertionError as e:
            issues.append(f"Console: {e!s}")
        issues.extend(
            f"PageError: {error}"
            for error in self._console.page_errors
            if not any(pattern.lower() in error.lower() for pattern in self.ignore_patterns)
        )
        return issues

    def _check_network_issues(self) -> list[str]:
        """Every 4xx and 5xx response no expectation excused."""
        unexcused = [record for record in self._responses.records if not record.excused]
        if self.check_network:
            return [f"Network: {record.describe()}" for record in unexcused]
        if self.check_server_logs:
            # Without the network check, a server error still fails the test, as it always has.
            return [f"HTTP: {record.describe()}" for record in unexcused if record.status >= 500]
        return []

    def _check_csp_issues(self) -> list[str]:
        """Every violation since the monitor started, from this document and the earlier ones."""
        if not self.check_csp:
            return []

        return [
            f"CSP {v['disposition']}: {v['violatedDirective']} blocked {v['blockedURI']}"
            for v in read_csp_violations(self.page)[self._csp_seen:]
        ]

    def _check_html_issues(self) -> list[str]:
        """Check for HTML validation issues and return them."""
        if not self.check_html:
            return []

        html_issues = check_html_validation(self.page)
        return [f"HTML: {issue}" for issue in html_issues] if html_issues else []

    def _check_css_issues(self) -> list[str]:
        """Check for CSS issues and return them."""
        if not self.check_css:
            return []

        css_issues = check_css_issues(self.page)
        return [f"CSS: {issue}" for issue in css_issues] if css_issues else []

    def _check_accessibility_issues(self) -> list[str]:
        """Check for accessibility issues and return them."""
        if not self.check_accessibility:
            return []

        a11y_issues = check_accessibility_basics(self.page)
        return [f"A11Y: {issue}" for issue in a11y_issues] if a11y_issues else []

    def _check_performance_issues(self) -> list[str]:
        """Check for performance issues and return them."""
        if not self.check_performance:
            return []

        perf_issues = check_performance_issues(self.page)
        return [f"PERF: {issue}" for issue in perf_issues] if perf_issues else []

    def add_expected_error_patterns(self, patterns: list[str]) -> None:
        """Add patterns for expected server log errors, matched case-insensitively in the message.

        Accumulates across multiple calls so that multiple
        ``@pytest.mark.expect_server_errors`` markers on a single test
        all take effect.  Non-string arguments are coerced to ``str``
        to prevent ``AttributeError`` in the downstream ``.lower()`` filter.
        """
        self._expected_error_patterns.extend(str(p) for p in patterns)

    # Keep old name as alias so any external callers still work.
    set_expected_error_patterns = add_expected_error_patterns

    def _is_expected(self, entry: Any) -> bool:
        message = entry.message.lower()
        return any(pattern.lower() in message for pattern in self._expected_error_patterns)

    def _check_server_log_issues(self) -> list[str]:
        """Check for server-side errors in platform/portal logs."""
        if not self.check_server_logs or not (self._log_scanner and self._log_scanner.available):
            return []

        issues: list[str] = []
        request_ids = self._responses.request_ids
        entries = self._log_scanner.get_new_entries()

        # Errors correlated to this test's requests
        if request_ids:
            correlated = self._log_scanner.filter_by_request_ids(entries, request_ids)
            issues.extend(
                f"ServerLog[{entry.service}]: {entry.level} {entry.logger} "
                f'"{entry.message}" [req-id: {entry.request_id[:8]}...]'
                for entry in self._log_scanner.filter_errors(correlated)
                if not self._is_expected(entry)
            )

        # Uncorrelated errors from other requests during this test's window
        issues.extend(
            f"ServerLog[{entry.service}]: {entry.level} {entry.logger} "
            f'"{entry.message}" [uncorrelated]'
            for entry in self._log_scanner.filter_uncorrelated_errors(entries, request_ids)
            if not self._is_expected(entry)
        )
        return issues

    def _get_checks_performed(self) -> list[str]:
        """Get list of checks that were performed."""
        checks_performed = []
        if self.check_console:
            checks_performed.append("console")
        if self.check_network:
            checks_performed.append("network")
        if self.check_html:
            checks_performed.append("HTML")
        if self.check_css:
            checks_performed.append("CSS")
        if self.check_accessibility:
            checks_performed.append("accessibility")
        if self.check_performance:
            checks_performed.append("performance")
        if self.check_server_logs:
            checks_performed.append("server-logs")
        if self.check_csp:
            checks_performed.append("CSP")
        return checks_performed

    def _print_success_message(self) -> None:
        """Print success message with context and checks performed."""
        checks_performed = self._get_checks_performed()
        checks_str = ', '.join(checks_performed)

        if self.context:
            print(f"  ✅ Page quality verified {self.context} ({checks_str})")
        else:
            print(f"  ✅ Page quality verified ({checks_str})")

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Only check quality issues if the test didn't already fail
        if exc_type is not None:
            self._detach()
            return

        # The checks that drive the page run while the collectors still listen, so an error the
        # page raises meanwhile is caught; the listeners go before the verdict, never after it.
        try:
            page_issues = [
                *self._check_csp_issues(),
                *self._check_html_issues(),
                *self._check_css_issues(),
                *self._check_accessibility_issues(),
                *self._check_performance_issues(),
            ]
            self._sync_point()
        finally:
            self._detach()

        all_issues = [
            *self._check_console_issues(),
            *self._check_network_issues(),
            *page_issues,
            *self._check_server_log_issues(),
        ]

        if all_issues:
            context_msg = f" {self.context}" if self.context else ""
            issue_list = "\n".join(f"  - {issue}" for issue in all_issues)
            raise AssertionError(f"Page quality issues found{context_msg}:\n{issue_list}")

        self._print_success_message()


class ConsoleMonitor:
    """
    Lightweight console-only monitoring (for backwards compatibility).

    Example:
        with ConsoleMonitor(page, "login process") as monitor:
            login_user(page, email, password)
            # Console errors are automatically checked when exiting context
    """

    def __init__(self, page: Page, context: str = "", ignore_patterns: list[str] | None = None,
                 *, allow_auth_error_ignores: bool = False):
        self.page = page
        self.context = context
        self.ignore_patterns = _validate_ignore_patterns(ignore_patterns or [], allow_auth=allow_auth_error_ignores)
        self._console = _ConsoleCollector()

    @property
    def console_messages(self) -> list[dict[str, Any]]:
        return self._console.messages

    def __enter__(self):
        self._console.attach(self.page)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Deliver what the browser already emitted before the listeners go, as the full monitor does.
        try:
            if exc_type is None:
                _sync_with_page(self.page)
        finally:
            self._console.detach()
        # Only check console errors if the test didn't already fail
        if exc_type is None:
            assert_no_console_errors(
                self.console_messages,
                ignore_patterns=self.ignore_patterns,
                context=self.context
            )
            page_errors = [
                error for error in self._console.page_errors
                if not any(pattern.lower() in error.lower() for pattern in self.ignore_patterns)
            ]
            if page_errors:
                raise AssertionError("Uncaught page errors:\n" + "\n".join(f"  - {e}" for e in page_errors))


def apply_test_markers(monitor: ComprehensivePageMonitor, request: Any) -> None:
    """Apply a test's ``expect_server_errors`` and ``expect_http_errors`` markers to its monitor."""
    for marker in request.node.iter_markers("expect_server_errors"):
        monitor.add_expected_error_patterns(list(marker.args))
    for marker in request.node.iter_markers("expect_http_errors"):
        monitor.expect_http(marker.args, marker.kwargs["url"], query=marker.kwargs.get("query"))
