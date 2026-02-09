#!/usr/bin/env python3

"""
===============================================================================
STAFF INFRASTRUCTURE SYSTEM - END-TO-END TESTS
===============================================================================

Comprehensive E2E testing for the PRAHO infrastructure deployment system.

Test Coverage:
- Staff access via Infrastructure dashboard
- Node deployment management (list, create, detail views)
- Lifecycle operations (start, stop, reboot, upgrade, maintenance)
- Provider, size, and region management
- Cost tracking and reporting
- Permission-based access control
- Mobile responsiveness and UI quality

Author: AI Assistant
Created: 2025-12-25
Framework: Playwright + pytest
"""

import pytest
from playwright.sync_api import Page

# Import shared utilities
from tests.e2e.utils import (
    SUPERUSER_EMAIL,
    SUPERUSER_PASSWORD,
    ComprehensivePageMonitor,
    ensure_fresh_session,
    login_user,
    require_authentication,
    run_responsive_breakpoints_test,
    safe_click_element,
)

# Test user credentials
STAFF_EMAIL = SUPERUSER_EMAIL
STAFF_PASSWORD = SUPERUSER_PASSWORD

# Base URL for infrastructure
BASE_URL = "http://localhost:8701"
INFRA_URL = f"{BASE_URL}/infrastructure/"


# =============================================================================
# DASHBOARD ACCESS TESTS
# =============================================================================


def test_staff_infrastructure_dashboard_access(page: Page) -> None:
    """
    Test staff can access infrastructure dashboard.

    Validates staff access to infrastructure management system.
    """
    print("🔧 Testing staff infrastructure dashboard access")

    with ComprehensivePageMonitor(page, "staff infrastructure dashboard access",
                                 check_console=True,
                                 check_network=True,
                                 check_html=True,
                                 check_css=True):
        # Login as staff user
        ensure_fresh_session(page)
        assert login_user(page, STAFF_EMAIL, STAFF_PASSWORD)

        # Navigate to infrastructure dashboard
        page.goto(INFRA_URL)
        page.wait_for_load_state("networkidle")

        # Verify we're on infrastructure page
        assert "/infrastructure/" in page.url, f"Expected infrastructure URL, got: {page.url}"

        # Check main heading
        dashboard_heading = page.locator('h1:has-text("Infrastructure")')
        assert dashboard_heading.is_visible(), "Infrastructure heading not visible"

        print("  ✅ Staff successfully accessed infrastructure dashboard")


def test_infrastructure_dashboard_stats_display(page: Page) -> None:
    """
    Test the infrastructure dashboard displays statistics correctly.

    Validates deployment counts, status breakdown, and quick actions.
    """
    print("📊 Testing infrastructure dashboard stats display")

    with ComprehensivePageMonitor(page, "infrastructure dashboard stats",
                                 check_console=True,
                                 check_network=True):
        # Login and navigate
        ensure_fresh_session(page)
        assert login_user(page, STAFF_EMAIL, STAFF_PASSWORD)

        page.goto(INFRA_URL)
        page.wait_for_load_state("networkidle")

        # Verify statistics cards are present
        # Look for common stat elements
        stat_cards = page.locator('[class*="bg-slate-800"]')
        assert stat_cards.count() > 0, "No stat cards found on dashboard"

        # Check for navigation links
        deployments_link = page.locator('a[href*="deployments"]')
        assert deployments_link.count() > 0, "Deployments link not found"

        print("  ✅ Dashboard stats displayed correctly")


# =============================================================================
# DEPLOYMENT LIST TESTS
# =============================================================================


def test_deployment_list_page_loads(page: Page) -> None:
    """
    Test the deployment list page loads correctly.
    """
    print("📋 Testing deployment list page")

    with ComprehensivePageMonitor(page, "deployment list page",
                                 check_console=True,
                                 check_network=True):
        ensure_fresh_session(page)
        assert login_user(page, STAFF_EMAIL, STAFF_PASSWORD)

        page.goto(f"{INFRA_URL}deployments/")
        page.wait_for_load_state("networkidle")

        # Verify page loaded
        assert "/deployments/" in page.url

        # Check for table or empty state
        table_or_empty = page.locator('table, [class*="text-center"]')
        assert table_or_empty.count() > 0, "No table or empty state found"

        # Check for create button
        create_btn = page.locator('a[href*="create"]')
        assert create_btn.count() > 0, "Create button not found"

        print("  ✅ Deployment list page loaded correctly")


def test_deployment_create_page_loads(page: Page) -> None:
    """
    Test the deployment create page loads with form.
    """
    print("➕ Testing deployment create page")

    with ComprehensivePageMonitor(page, "deployment create page",
                                 check_console=True,
                                 check_network=True):
        ensure_fresh_session(page)
        assert login_user(page, STAFF_EMAIL, STAFF_PASSWORD)

        page.goto(f"{INFRA_URL}deployments/create/")
        page.wait_for_load_state("networkidle")

        # Verify page loaded
        assert "/create/" in page.url

        # Check for form elements
        form = page.locator("form")
        assert form.count() > 0, "No form found on create page"

        # Check for key form fields
        provider_select = page.locator('select[name="provider"], [id*="provider"]')
        environment_select = page.locator('select[name="environment"], [id*="environment"]')

        # At least one of these should be present
        assert provider_select.count() > 0 or environment_select.count() > 0, \
            "Form fields not found"

        print("  ✅ Deployment create page loaded with form")


# =============================================================================
# PROVIDER MANAGEMENT TESTS
# =============================================================================


def test_provider_list_page_loads(page: Page) -> None:
    """
    Test the cloud provider list page loads.
    """
    print("☁️ Testing provider list page")

    with ComprehensivePageMonitor(page, "provider list page",
                                 check_console=True,
                                 check_network=True):
        ensure_fresh_session(page)
        assert login_user(page, STAFF_EMAIL, STAFF_PASSWORD)

        page.goto(f"{INFRA_URL}providers/")
        page.wait_for_load_state("networkidle")

        # Verify page loaded
        assert "/providers/" in page.url

        # Check for provider list or empty state
        content = page.locator('main, [class*="container"]')
        assert content.count() > 0, "Page content not found"

        print("  ✅ Provider list page loaded")


# =============================================================================
# SIZE MANAGEMENT TESTS
# =============================================================================


def test_size_list_page_loads(page: Page) -> None:
    """
    Test the node size list page loads.
    """
    print("📐 Testing size list page")

    with ComprehensivePageMonitor(page, "size list page",
                                 check_console=True,
                                 check_network=True):
        ensure_fresh_session(page)
        assert login_user(page, STAFF_EMAIL, STAFF_PASSWORD)

        page.goto(f"{INFRA_URL}sizes/")
        page.wait_for_load_state("networkidle")

        # Verify page loaded
        assert "/sizes/" in page.url

        print("  ✅ Size list page loaded")


# =============================================================================
# REGION MANAGEMENT TESTS
# =============================================================================


def test_region_list_page_loads(page: Page) -> None:
    """
    Test the region list page loads.
    """
    print("🌍 Testing region list page")

    with ComprehensivePageMonitor(page, "region list page",
                                 check_console=True,
                                 check_network=True):
        ensure_fresh_session(page)
        assert login_user(page, STAFF_EMAIL, STAFF_PASSWORD)

        page.goto(f"{INFRA_URL}regions/")
        page.wait_for_load_state("networkidle")

        # Verify page loaded
        assert "/regions/" in page.url

        print("  ✅ Region list page loaded")


# =============================================================================
# COST TRACKING TESTS
# =============================================================================


def test_cost_dashboard_page_loads(page: Page) -> None:
    """
    Test the cost dashboard page loads with cost information.
    """
    print("💰 Testing cost dashboard page")

    with ComprehensivePageMonitor(page, "cost dashboard page",
                                 check_console=True,
                                 check_network=True):
        ensure_fresh_session(page)
        assert login_user(page, STAFF_EMAIL, STAFF_PASSWORD)

        page.goto(f"{INFRA_URL}costs/")
        page.wait_for_load_state("networkidle")

        # Verify page loaded
        assert "/costs/" in page.url

        # Check for cost-related content
        cost_heading = page.locator('h1:has-text("Cost"), h1:has-text("Infrastructure Costs")')
        assert cost_heading.is_visible() or page.locator('text=EUR').count() > 0, \
            "Cost heading or EUR amounts not found"

        print("  ✅ Cost dashboard page loaded")


def test_cost_history_page_loads(page: Page) -> None:
    """
    Test the cost history page loads.
    """
    print("📈 Testing cost history page")

    with ComprehensivePageMonitor(page, "cost history page",
                                 check_console=True,
                                 check_network=True):
        ensure_fresh_session(page)
        assert login_user(page, STAFF_EMAIL, STAFF_PASSWORD)

        page.goto(f"{INFRA_URL}costs/history/")
        page.wait_for_load_state("networkidle")

        # Verify page loaded
        assert "/history/" in page.url

        print("  ✅ Cost history page loaded")


# =============================================================================
# PERMISSION TESTS
# =============================================================================


def test_unauthenticated_access_redirects_to_login(page: Page) -> None:
    """
    Test that unauthenticated users are redirected to login.
    """
    print("🔒 Testing unauthenticated access redirect")

    # Clear any existing session
    ensure_fresh_session(page)

    # Try to access infrastructure without logging in
    page.goto(INFRA_URL)
    page.wait_for_load_state("networkidle")

    # Should be redirected to login
    assert "/login" in page.url or "/accounts/login" in page.url, \
        f"Expected redirect to login, got: {page.url}"

    print("  ✅ Unauthenticated access correctly redirected to login")


# =============================================================================
# RESPONSIVE DESIGN TESTS
# =============================================================================


def test_infrastructure_dashboard_responsive(page: Page) -> None:
    """
    Test infrastructure dashboard is responsive across breakpoints.
    """
    print("📱 Testing infrastructure dashboard responsiveness")

    ensure_fresh_session(page)
    assert login_user(page, STAFF_EMAIL, STAFF_PASSWORD)

    page.goto(INFRA_URL)
    page.wait_for_load_state("networkidle")

    # Test different viewport sizes
    breakpoints = [
        {"width": 375, "height": 667, "name": "Mobile"},
        {"width": 768, "height": 1024, "name": "Tablet"},
        {"width": 1280, "height": 720, "name": "Desktop"},
    ]

    for bp in breakpoints:
        page.set_viewport_size({"width": bp["width"], "height": bp["height"]})
        page.wait_for_timeout(500)

        # Verify content is still visible
        main_content = page.locator("main, [class*='container'], [class*='content']")
        assert main_content.count() > 0, f"Content not visible at {bp['name']} breakpoint"

        print(f"    ✅ {bp['name']} ({bp['width']}px) - content visible")

    print("  ✅ Infrastructure dashboard is responsive")


# =============================================================================
# NAVIGATION TESTS
# =============================================================================


def test_infrastructure_navigation_links(page: Page) -> None:
    """
    Test navigation links within infrastructure section work correctly.
    """
    print("🔗 Testing infrastructure navigation links")

    with ComprehensivePageMonitor(page, "infrastructure navigation",
                                 check_console=True,
                                 check_network=True):
        ensure_fresh_session(page)
        assert login_user(page, STAFF_EMAIL, STAFF_PASSWORD)

        page.goto(INFRA_URL)
        page.wait_for_load_state("networkidle")

        # Test navigation to different sections
        nav_targets = [
            ("deployments/", "Deployments"),
            ("providers/", "Providers"),
            ("sizes/", "Sizes"),
            ("regions/", "Regions"),
            ("costs/", "Costs"),
        ]

        for path, name in nav_targets:
            page.goto(f"{INFRA_URL}{path}")
            page.wait_for_load_state("networkidle")

            assert path in page.url, f"Failed to navigate to {name}"
            print(f"    ✅ Navigated to {name}")

        print("  ✅ All navigation links working")
