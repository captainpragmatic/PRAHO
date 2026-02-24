"""
E2E Mobile Testing Utilities — viewport management, responsive breakpoints, touch testing.

MobileTestContext and run_responsive_breakpoints_test for mobile/tablet testing.
"""

from collections.abc import Callable
from typing import Any

from playwright.sync_api import Page, ViewportSize

from tests.e2e.helpers.interactions import count_elements, safe_click_element

# Common mobile viewport configurations based on 2024 Playwright best practices
MOBILE_VIEWPORTS: dict[str, ViewportSize] = {
    'mobile_small': {'width': 320, 'height': 568},      # iPhone SE, older smartphones
    'mobile_medium': {'width': 375, 'height': 667},     # iPhone 8, standard mobile
    'mobile_large': {'width': 414, 'height': 896},      # iPhone 11 Pro Max, large phones
    'tablet_portrait': {'width': 768, 'height': 1024},  # iPad portrait
    'tablet_landscape': {'width': 1024, 'height': 768}, # iPad landscape
}

# Desktop baseline for comparison
DESKTOP_VIEWPORT: ViewportSize = {'width': 1280, 'height': 720}


class MobileTestContext:
    """
    Context manager for mobile testing that handles viewport switching and cleanup.

    Automatically switches to mobile viewport, runs test content, then restores
    original viewport. Supports custom viewports and device-specific testing.

    Usage:
        with MobileTestContext(page, 'mobile_medium') as mobile:
            # Test mobile-specific functionality
            mobile.test_mobile_navigation()
            mobile.check_responsive_layout()
    """

    def __init__(self, page: Page, viewport_name: str = 'mobile_medium',
                 custom_viewport: ViewportSize | None = None):
        self.page = page
        self.viewport_name = viewport_name
        self.custom_viewport = custom_viewport
        self.original_viewport = None

    def __enter__(self):
        # Store original viewport
        self.original_viewport = self.page.viewport_size

        # Set mobile viewport
        viewport = self.custom_viewport or MOBILE_VIEWPORTS.get(self.viewport_name, MOBILE_VIEWPORTS['mobile_medium'])

        self.page.set_viewport_size(viewport)
        print(f"  📱 Switched to {self.viewport_name} viewport: {viewport['width']}x{viewport['height']}")

        # Wait for any responsive transitions
        self.page.wait_for_timeout(300)

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Restore original viewport
        if self.original_viewport:
            self.page.set_viewport_size(self.original_viewport)
            print(f"  🖥️  Restored to desktop viewport: {self.original_viewport['width']}x{self.original_viewport['height']}")
        else:
            # Fallback to standard desktop
            self.page.set_viewport_size(DESKTOP_VIEWPORT)
            print("  🖥️  Restored to default desktop viewport")

        # Wait for any responsive transitions
        self.page.wait_for_timeout(300)

    def test_mobile_navigation(self):
        """Test mobile-specific navigation elements."""
        mobile_nav_selectors = [
            ('.navbar-toggler', 'mobile menu toggle'),
            ('.navbar-toggle', 'navbar toggle'),
            ('[data-toggle="collapse"]', 'collapse toggle'),
            ('.hamburger', 'hamburger menu'),
            ('.mobile-menu-toggle', 'mobile menu toggle'),
        ]

        mobile_elements_found = 0

        for selector, description in mobile_nav_selectors:
            count = count_elements(self.page, selector, f"mobile {description}")
            mobile_elements_found += count

            if count > 0 and safe_click_element(self.page, selector, f"mobile {description}"):
                print(f"      ✅ Mobile menu toggle clicked: {description}")

                # Wait for mobile menu animation
                self.page.wait_for_timeout(500)

                # Look for expanded mobile menu
                expanded_menu_selectors = [
                    '.navbar-collapse.show',
                    '.mobile-menu.open',
                    '.nav-menu.active',
                    '[aria-expanded="true"]'
                ]

                for menu_selector in expanded_menu_selectors:
                    if count_elements(self.page, menu_selector, 'expanded mobile menu') > 0:
                        print("      ✅ Mobile menu expanded successfully")
                        break

                # Click somewhere else to close menu
                self.page.click('body')
                self.page.wait_for_timeout(200)

        print(f"    📱 Found {mobile_elements_found} mobile navigation elements")
        return mobile_elements_found

    def check_responsive_layout(self) -> list[str]:
        """Check for responsive layout issues on mobile viewport."""
        issues = []

        try:
            # Check for horizontal scrollbar (indicates non-responsive content)
            has_horizontal_scroll = self.page.evaluate("""
                () => document.documentElement.scrollWidth > document.documentElement.clientWidth
            """)

            if has_horizontal_scroll:
                issues.append("Horizontal scroll detected - content may not be responsive")

            # Check for elements that are too small for touch
            small_touch_targets = self.page.evaluate("""
                () => {
                    const minTouchSize = 44; // 44px minimum touch target size
                    const issues = [];

                    document.querySelectorAll('button, a, input[type="button"], input[type="submit"]').forEach(element => {
                        const rect = element.getBoundingClientRect();
                        if (rect.width > 0 && rect.height > 0 && (rect.width < minTouchSize || rect.height < minTouchSize)) {
                            const tagName = element.tagName.toLowerCase();
                            const className = element.className || '';
                            issues.push(`Small touch target: ${tagName} ${className}`.trim());
                        }
                    });

                    return issues.slice(0, 5); // Limit to first 5 issues
                }
            """)

            issues.extend(small_touch_targets)

            # Check for text that might be too small
            small_text = self.page.evaluate("""
                () => {
                    const minFontSize = 16; // 16px minimum readable font size on mobile
                    const issues = [];

                    document.querySelectorAll('p, span, div, a, button').forEach(element => {
                        const style = window.getComputedStyle(element);
                        const fontSize = parseInt(style.fontSize);

                        if (fontSize > 0 && fontSize < minFontSize && element.textContent.trim()) {
                            issues.push(`Small font size: ${fontSize}px`);
                        }
                    });

                    return [...new Set(issues)].slice(0, 3); // Unique issues, max 3
                }
            """)

            issues.extend(small_text)

        except Exception as e:
            issues.append(f"Mobile layout check failed: {str(e)[:50]}")

        return issues

    def test_touch_interactions(self) -> bool:
        """Test touch-specific interactions work correctly."""
        try:
            # Look for touch-interactive elements
            touch_elements = self.page.locator('[data-touch], [ontouchstart], button, a').first

            if touch_elements.count() > 0:
                # Test tap interaction
                touch_elements.tap(timeout=2000)
                print("      ✅ Touch interaction successful")
                return True
            else:
                print("      Info: No touch-interactive elements found")
                return False

        except Exception as e:
            print(f"      ⚠️ Touch interaction failed: {str(e)[:50]}")
            return False


_CRITICAL_LAYOUT_KEYWORDS = frozenset(['horizontal scroll', 'small touch'])


def run_standard_mobile_test(
    page: Page,
    mobile: MobileTestContext,
    *,
    context_label: str = "page",
    reload: bool = True,
) -> dict[str, Any]:
    """
    Run the standard mobile viewport checks that are duplicated across 13+ test files.

    Consolidates the common pattern: reload → test_mobile_navigation →
    check_responsive_layout → filter critical issues → test_touch_interactions.

    Args:
        page: Playwright page (already inside a MobileTestContext ``with`` block).
        mobile: The active MobileTestContext instance.
        context_label: Human-readable label for print output (e.g. "staff tickets").
        reload: Whether to reload the page to ensure mobile layout (default True).

    Returns:
        dict with keys: nav_count, layout_issues, critical_issues, touch_works

    Example::

        with MobileTestContext(page, 'mobile_medium') as mobile:
            result = run_standard_mobile_test(page, mobile, context_label="billing")
    """
    if reload:
        page.reload()
        page.wait_for_load_state("networkidle")

    nav_count = mobile.test_mobile_navigation()
    print(f"      Mobile navigation elements: {nav_count}")

    layout_issues = mobile.check_responsive_layout()
    critical_issues = [
        issue for issue in layout_issues
        if any(kw in issue.lower() for kw in _CRITICAL_LAYOUT_KEYWORDS)
    ]

    if critical_issues:
        print(f"      ⚠️ Critical mobile layout issues: {len(critical_issues)}")
        for issue in critical_issues[:3]:
            print(f"        - {issue}")
    else:
        print(f"      ✅ No critical mobile layout issues found for {context_label}")

    touch_works = mobile.test_touch_interactions()
    print(f"      Touch interactions: {'✅ Working' if touch_works else '⚠️ Limited'}")

    return {
        "nav_count": nav_count,
        "layout_issues": layout_issues,
        "critical_issues": critical_issues,
        "touch_works": touch_works,
    }


def assert_responsive_results(
    results: dict[str, Any],
    feature_name: str = "Feature",
) -> None:
    """
    Assert that all three responsive breakpoints passed in *results*.

    Replaces the 8-line boilerplate pattern duplicated 12+ times::

        desktop_pass = results.get('desktop', False)
        tablet_pass = results.get('tablet_landscape', False)
        mobile_pass = results.get('mobile', False)
        assert desktop_pass, "... should work on desktop viewport"
        assert tablet_pass, "... should work on tablet viewport"
        assert mobile_pass, "... should work on mobile viewport"

    Args:
        results: The dict returned by :func:`run_responsive_breakpoints_test`.
        feature_name: Human-readable feature name for assertion messages.
    """
    assert results.get("desktop", False), f"{feature_name} should work on desktop viewport"
    assert results.get("tablet_landscape", False), f"{feature_name} should work on tablet viewport"
    assert results.get("mobile", False), f"{feature_name} should work on mobile viewport"


def run_responsive_breakpoints_test(page: Page, test_function: Callable[..., Any], *args: Any, **kwargs: Any) -> dict[str, Any]:
    """
    Test a function across multiple responsive breakpoints.

    Runs the provided test function on desktop, tablet, and mobile viewports,
    collecting results for comparison.

    Args:
        page: Playwright page object
        test_function: Function to test across breakpoints
        *args, **kwargs: Arguments to pass to test function

    Returns:
        dict: Results from each breakpoint test

    Example:
        results = test_responsive_breakpoints(
            page,
            verify_dashboard_functionality,
            "superuser"
        )
    """
    results = {}

    # Test desktop (baseline)
    page.set_viewport_size(DESKTOP_VIEWPORT)
    page.wait_for_timeout(300)
    print(f"\n  🖥️  Testing desktop viewport: {DESKTOP_VIEWPORT['width']}x{DESKTOP_VIEWPORT['height']}")

    try:
        results['desktop'] = test_function(page, *args, **kwargs)
        print(f"    ✅ Desktop test: {'PASS' if results['desktop'] else 'FAIL'}")
    except Exception as e:
        results['desktop'] = False
        print(f"    ❌ Desktop test failed: {str(e)[:50]}")

    # Test tablet landscape
    with MobileTestContext(page, 'tablet_landscape'):
        print("\n  📱 Testing tablet landscape")
        try:
            results['tablet_landscape'] = test_function(page, *args, **kwargs)
            print(f"    ✅ Tablet landscape test: {'PASS' if results['tablet_landscape'] else 'FAIL'}")
        except Exception as e:
            results['tablet_landscape'] = False
            print(f"    ❌ Tablet landscape test failed: {str(e)[:50]}")

    # Test mobile medium
    with MobileTestContext(page, 'mobile_medium') as mobile:
        print("\n  📱 Testing mobile viewport")
        try:
            results['mobile'] = test_function(page, *args, **kwargs)
            print(f"    ✅ Mobile test: {'PASS' if results['mobile'] else 'FAIL'}")

            # Additional mobile-specific checks
            mobile_nav_count = mobile.test_mobile_navigation()
            layout_issues = mobile.check_responsive_layout()

            results['mobile_extras'] = {
                'navigation_elements': mobile_nav_count,
                'layout_issues': layout_issues,
                'touch_works': mobile.test_touch_interactions()
            }

        except Exception as e:
            results['mobile'] = False
            print(f"    ❌ Mobile test failed: {str(e)[:50]}")

    # Summary
    passed_count = sum(1 for result in [results.get('desktop'), results.get('tablet_landscape'), results.get('mobile')] if result)
    print(f"\n  📊 Responsive test summary: {passed_count}/3 breakpoints passed")

    return results
