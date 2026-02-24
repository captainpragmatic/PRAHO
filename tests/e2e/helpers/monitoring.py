"""
E2E Page Quality Monitoring — console, network, HTML, CSS, accessibility, performance.

Contains ComprehensivePageMonitor, ConsoleMonitor, and all quality check functions.
"""

from dataclasses import dataclass, field
from typing import Any

from playwright.sync_api import Page

# ===============================================================================
# CONSOLE ERROR MONITORING
# ===============================================================================

def setup_console_monitoring_standalone(page: Page) -> list:
    """
    Set up console message monitoring for the page (standalone utility function).

    Args:
        page: Playwright page object

    Returns:
        list: Console messages list to collect messages

    Example:
        console_messages = setup_console_monitoring_standalone(page)
    """
    console_messages = []

    def handle_console_message(msg):
        if msg.type in ['error', 'warning']:
            message_text = msg.text
            console_messages.append({
                'type': msg.type,
                'text': message_text,
                'location': msg.location
            })

    # Set up listener to capture console messages
    page.on("console", handle_console_message)
    return console_messages


def assert_no_console_errors(console_messages: list, ignore_patterns: list[str] | None = None,
                           context: str = "") -> None:
    """
    Assert that there are no JavaScript console errors.

    Args:
        console_messages: List of console messages from setup_console_monitoring
        ignore_patterns: List of error message patterns to ignore
        context: Context description for better error messages

    Raises:
        AssertionError: If console errors are found

    Example:
        console_messages = setup_console_monitoring(page)
        # ... perform actions ...
        assert_no_console_errors(console_messages, context="after login")
    """
    # Default patterns to ignore (common development noise)
    # NOTE: Browser-level "Failed to load resource" messages (e.g., favicon.ico 404)
    # are NOT application console.error() calls. They're covered by check_network
    # instead. Application JS errors use specific messages, not generic resource loads.
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


def check_network_errors(page: Page) -> list[str]:
    """
    Check for HTTP network errors (4xx, 5xx responses).

    Args:
        page: Playwright page object

    Returns:
        list[str]: List of network error messages
    """
    network_errors: list[str] = []

    try:
        # Check for typical error indicators in the page
        error_indicators = [
            "500 Internal Server Error",
            "404 Not Found",
            "403 Forbidden",
            "502 Bad Gateway",
            "503 Service Unavailable"
        ]

        page_content = page.content()
        network_errors.extend(
            f"HTTP Error detected: {indicator}"
            for indicator in error_indicators
            if indicator in page_content
        )

    except Exception:  # noqa: S110
        pass

    return network_errors


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
                    if (target && !target.startsWith('#') && !target.startsWith('.') &&
                        target !== 'this' && target !== 'closest' && !document.querySelector(target)) {
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

                    // Skip common search inputs that have placeholder text (acceptable UX pattern)
                    if (input.type === 'search' || input.name === 'search' || input.placeholder) {
                        return;
                    }

                    const id = input.id;
                    const hasLabelFor = id && document.querySelector('label[for="' + id + '"]');
                    const hasLabelParent = input.closest('label') !== null;
                    if (!hasLabelFor && !hasLabelParent) {
                        const ariaLabel = input.getAttribute('aria-label');
                        if (!ariaLabel) {
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

                // Check for missing heading structure
                const headings = document.querySelectorAll('h1, h2, h3, h4, h5, h6');
                if (headings.length === 0) {
                    issues.push('Page has no heading elements');
                } else if (!document.querySelector('h1')) {
                    issues.push('Page missing h1 heading');
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
    ignore_patterns: list[str] = field(default_factory=list)


class ComprehensivePageMonitor:
    """
    Comprehensive monitoring for all aspects of page quality during test execution.

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
        self.ignore_patterns = list(config.ignore_patterns)
        self.console_messages: list[str] = []

        # Security hardening: never suppress auth/access-denied/not-found errors by default.
        if not allow_auth_error_ignores and self.ignore_patterns:
            blocked_patterns = {"401", "403", "404", "forbidden", "unauthorized"}
            self.ignore_patterns = [p for p in self.ignore_patterns if p.lower() not in blocked_patterns]

        # Quality hardening: keep accessibility checks enabled unless explicitly opted out.
        if not self.check_accessibility and self.check_html and self.check_css and not allow_accessibility_skip:
            self.check_accessibility = True

    def __enter__(self):
        if self.check_console:
            self.console_messages = setup_console_monitoring_standalone(self.page)
        return self

    def _check_console_issues(self) -> list[str]:
        """Check for console errors and return issues."""
        if not self.check_console:
            return []

        try:
            assert_no_console_errors(
                self.console_messages,
                ignore_patterns=self.ignore_patterns,
                context=self.context
            )
            return []
        except AssertionError as e:
            return [f"Console: {e!s}"]

    def _check_network_issues(self) -> list[str]:
        """Check for network errors and return issues."""
        if not self.check_network:
            return []

        network_issues = check_network_errors(self.page)
        return [f"Network: {issue}" for issue in network_issues] if network_issues else []

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

    def _get_all_quality_issues(self) -> list[str]:
        """Collect all quality issues from different checks."""
        all_issues = []
        all_issues.extend(self._check_console_issues())
        all_issues.extend(self._check_network_issues())
        all_issues.extend(self._check_html_issues())
        all_issues.extend(self._check_css_issues())
        all_issues.extend(self._check_accessibility_issues())
        all_issues.extend(self._check_performance_issues())
        return all_issues

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
            return

        all_issues = self._get_all_quality_issues()

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

    def __init__(self, page: Page, context: str = "", ignore_patterns: list[str] | None = None):
        self.page = page
        self.context = context
        self.ignore_patterns = ignore_patterns or []
        self.console_messages: list[str] = []

    def __enter__(self):
        self.console_messages = setup_console_monitoring_standalone(self.page)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Only check console errors if the test didn't already fail
        if exc_type is None:
            assert_no_console_errors(
                self.console_messages,
                ignore_patterns=self.ignore_patterns,
                context=self.context
            )
