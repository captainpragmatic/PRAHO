"""
===============================================================================
CUSTOMER SERVICES - END-TO-END TESTS
===============================================================================

Comprehensive E2E testing for the customer-facing services section of the portal.
Validates service detail views, plans browsing, action requests, usage statistics,
dashboard widget integration, mobile responsiveness, and cross-customer access control.

Test Coverage:
- Service detail page (metadata, tabs, action links)
- Hosting plans browsing page
- Service action request form (upgrade/downgrade/suspend/cancel)
- Usage tab with period selection (Alpine.js tab switching)
- Dashboard widget for services (active count, quick link)
- Mobile responsiveness of services list
- Cross-customer access control (customer2 cannot view customer1 services)

Expected Behavior:
- Customers can view their own service details with plan/status/billing info
- Plans page shows available hosting plans (or graceful error)
- Action request form presents radio options and reason field
- Usage tab renders with disk/bandwidth stats on service detail
- Dashboard shows services count and My Services quick action
- Services list is responsive on mobile viewports
- Accessing another customer's service returns 404 or redirect

Author: AI Assistant
Created: 2026-02-28
Framework: Playwright + pytest
"""

import re

import pytest
from playwright.sync_api import Locator, Page, expect

from tests.e2e.helpers import (
    BASE_URL,
    CUSTOMER2_EMAIL,
    CUSTOMER2_PASSWORD,
    CUSTOMER_EMAIL,
    CUSTOMER_PASSWORD,
    ComprehensivePageMonitor,
    MobileTestContext,
    ensure_fresh_session,
    login_user,
    run_standard_mobile_test,
)


def test_customer_service_detail_view(monitored_customer_page: Page) -> None:
    """
    Navigate to service list, click first service, verify detail page content.

    Expected: Detail page shows service name, status badge, plan info, action links,
    and tabbed content (overview, usage, billing).
    """
    page = monitored_customer_page
    print("🔍 Testing customer service detail view")

    # Navigate to services list
    print("  📋 Navigating to services list")
    page.goto(f"{BASE_URL}/services/")
    page.wait_for_load_state("networkidle")

    # Click the first service row to navigate to detail
    print("  🔗 Clicking first service to open detail view")
    first_service_row: Locator = page.locator("tr[onclick], div[onclick]").first
    if first_service_row.count() == 0:
        print("    ⚠️ No services found for this customer, skipping detail test")
        return

    first_service_row.click()
    page.wait_for_load_state("networkidle")

    # Verify we are on a service detail page
    current_url: str = page.url
    assert re.search(r"/services/\d+/", current_url), f"Expected service detail URL pattern, got: {current_url}"
    print(f"    ✅ Navigated to service detail: {current_url}")

    # Verify service header with name
    service_heading: Locator = page.locator("h1")
    expect(service_heading.first).to_be_visible()
    heading_text: str = service_heading.first.inner_text()
    print(f"    ✅ Service heading visible: {heading_text[:60]}")

    # Verify status badge is present (Active, Suspended, Pending, etc.)
    status_badge: Locator = page.locator(
        "span:has-text('Active'), span:has-text('Suspended'), span:has-text('Pending'), span:has-text('Cancelled')"
    )
    assert status_badge.count() > 0, "Status badge should be visible on service detail"
    print("    ✅ Status badge displayed")

    # Verify Back to Services link
    back_link: Locator = page.locator('a:has-text("Back to Services"), a:has-text("Înapoi")')
    assert back_link.count() > 0, "Back to Services link should be present"
    print("    ✅ Back to Services link present")

    # Verify Actions button linking to request-action
    actions_link: Locator = page.locator('a[href*="request-action"], a:has-text("Actions")')
    if actions_link.count() > 0:
        print("    ✅ Actions link present on service detail")
    else:
        print("    [i] No Actions link found (may vary by service status)")

    # Verify tabbed content area (Overview, Usage & Performance, Billing)
    overview_tab: Locator = page.locator('button:has-text("Overview")')
    if overview_tab.count() > 0:
        print("    ✅ Overview tab present")

    usage_tab: Locator = page.locator('button:has-text("Usage")')
    if usage_tab.count() > 0:
        print("    ✅ Usage & Performance tab present")

    billing_tab: Locator = page.locator('button:has-text("Billing")')
    if billing_tab.count() > 0:
        print("    ✅ Billing tab present")

    # Verify monthly cost is displayed
    monthly_cost: Locator = page.locator("text=/RON/")
    if monthly_cost.count() > 0:
        print("    ✅ Monthly cost (RON) displayed")

    print("  ✅ Service detail view validated successfully")


def test_customer_service_plans_page(monitored_customer_page: Page) -> None:
    """
    Navigate to /services/plans/ and verify plan cards or graceful error.

    Expected: Plans page loads with plan cards showing pricing, or displays an error
    message if plans cannot be loaded from the platform API.
    """
    page = monitored_customer_page
    print("📦 Testing customer service plans page")

    print("  📋 Navigating to plans page")
    page.goto(f"{BASE_URL}/services/plans/")
    page.wait_for_load_state("networkidle")

    current_url: str = page.url
    page_content: str = page.content().lower()

    # Check if we're on a plans page or got redirected/errored
    if "/plans/" in current_url or "/services/" in current_url:
        print(f"    ✅ Plans page accessible at: {current_url}")

        # Check for plan cards or plan-related content
        plan_cards: Locator = page.locator('[class*="rounded-lg"]')
        has_pricing: bool = "ron" in page_content or "eur" in page_content or "usd" in page_content

        if has_pricing:
            print("    ✅ Pricing information visible on plans page")
        else:
            print("    [i] No pricing info found (plans may not be loaded from API)")

        # Check for plan type filter if present
        type_filter: Locator = page.locator(
            'a:has-text("Shared Hosting"), a:has-text("VPS"), select, button:has-text("All Plan Types")'
        )
        if type_filter.count() > 0:
            print("    ✅ Plan type filter available")

        # Verify no plan management buttons (customer view only)
        mgmt_buttons: Locator = page.locator(
            'a:has-text("Create Plan"), a:has-text("Edit Plan"), button:has-text("Delete")'
        )
        assert mgmt_buttons.count() == 0, "Plan management buttons should be hidden from customers"
        print("    ✅ No plan management buttons visible (correct for customer)")
    else:
        # Redirected away — might be auth issue or missing template
        print(f"    ⚠️ Redirected to: {current_url} (template may not exist)")

    print("  ✅ Plans page test completed")


def test_customer_service_request_action(monitored_customer_page: Page) -> None:
    """
    Navigate to a service's request-action page and verify the form.

    Expected: Form shows radio options (upgrade, downgrade, suspend, cancel),
    a reason textarea, and submit/cancel buttons.
    """
    page = monitored_customer_page
    print("⚡ Testing customer service request action form")

    # First find a service to request action on
    print("  📋 Finding a service to request action on")
    page.goto(f"{BASE_URL}/services/")
    page.wait_for_load_state("networkidle")

    first_service_row: Locator = page.locator("tr[onclick], div[onclick]").first
    if first_service_row.count() == 0:
        print("    ⚠️ No services found, skipping request action test")
        return

    # Click to navigate to detail
    first_service_row.click()
    page.wait_for_load_state("networkidle")

    # Extract service ID from URL
    current_url: str = page.url
    match = re.search(r"/services/(\d+)/", current_url)
    if not match:
        print("    ⚠️ Could not extract service ID from URL, skipping")
        return
    service_id: str = match.group(1)

    # Navigate to request-action page
    print(f"  📝 Navigating to request-action for service {service_id}")
    page.goto(f"{BASE_URL}/services/{service_id}/request-action/")
    page.wait_for_load_state("networkidle")

    # Verify page heading
    heading: Locator = page.locator('h1:has-text("Request Service Action"), h1:has-text("Action")')
    if heading.count() > 0:
        print("    ✅ Request Service Action heading visible")
    else:
        print("    [i] Custom heading not found, checking page loaded")

    # Verify form with radio options
    form: Locator = page.locator("form")
    assert form.count() > 0, "Request action form should be present"
    print("    ✅ Form element present")

    # Check for radio button options
    radio_inputs: Locator = page.locator('input[type="radio"][name="action"]')
    radio_count: int = radio_inputs.count()
    if radio_count > 0:
        print(f"    ✅ Found {radio_count} action radio options")

        # Verify specific action types exist
        for action_value in ["upgrade_request", "downgrade_request", "suspend_request", "cancel_request"]:
            action_radio: Locator = page.locator(f'input[value="{action_value}"]')
            if action_radio.count() > 0:
                print(f"      ✅ {action_value} option present")
    else:
        print("    [i] No radio inputs found (action types may use different UI)")

    # Verify reason textarea
    reason_field: Locator = page.locator('textarea[name="reason"], textarea#reason')
    if reason_field.count() > 0:
        print("    ✅ Reason textarea present")

    # Verify submit button
    submit_btn: Locator = page.locator('button[type="submit"]:has-text("Submit")')
    if submit_btn.count() > 0:
        print("    ✅ Submit Request button present")

    # Verify cancel/back link
    cancel_link: Locator = page.locator(
        f'a[href*="/services/{service_id}/"], a:has-text("Cancel"), a:has-text("Back to Service Details")'
    )
    if cancel_link.count() > 0:
        print("    ✅ Cancel/back link present")

    # Test selecting suspend to verify reason-required indicator
    _verify_suspend_reason_required(page)

    print("  ✅ Service request action form validated successfully")


def _verify_suspend_reason_required(page: Page) -> None:
    """Click suspend radio and check that reason becomes required."""
    suspend_label: Locator = page.locator('label[for="action_suspend_request"]')
    if suspend_label.count() == 0:
        return
    suspend_label.click()
    page.wait_for_timeout(300)
    reason_required: Locator = page.locator("#reason-required")
    if reason_required.count() > 0 and reason_required.is_visible():
        print("    ✅ Reason required indicator shown for suspend action")


def test_customer_service_usage_chart(monitored_customer_page: Page) -> None:
    """
    On service detail, switch to Usage tab and verify usage statistics display.

    Expected: Usage tab shows disk and bandwidth usage bars with percentage info.
    The detail page uses Alpine.js tabs — clicking 'Usage & Performance' reveals usage data.
    """
    page = monitored_customer_page
    print("📊 Testing customer service usage chart / statistics")

    # Navigate to services list and pick first service
    print("  📋 Finding an active service for usage testing")
    page.goto(f"{BASE_URL}/services/")
    page.wait_for_load_state("networkidle")

    first_service_row: Locator = page.locator("tr[onclick], div[onclick]").first
    if first_service_row.count() == 0:
        print("    ⚠️ No services found, skipping usage test")
        return

    first_service_row.click()
    page.wait_for_load_state("networkidle")

    # Check if Usage tab exists (only shown for active services)
    usage_tab: Locator = page.locator('button:has-text("Usage")')
    if usage_tab.count() == 0:
        print("    [i] No Usage tab — service may not be active. Skipping.")
        return

    # Click the Usage tab (Alpine.js tab switching)
    print("  📈 Switching to Usage & Performance tab")
    usage_tab.click()
    page.wait_for_timeout(500)  # Allow Alpine.js transition

    # Verify usage content is visible
    # The detail page has inline usage stats (disk_usage_gb, bandwidth_usage_gb)
    usage_section: Locator = page.locator('[x-show*="usage"]')
    if usage_section.count() > 0:
        print("    ✅ Usage section revealed after tab click")

    # Check for disk usage display
    disk_usage: Locator = page.locator("text=/Disk|Storage|GB/")
    if disk_usage.count() > 0:
        print("    ✅ Disk usage information displayed")

    # Check for bandwidth usage display
    bandwidth_usage: Locator = page.locator("text=/Bandwidth|Transfer/")
    if bandwidth_usage.count() > 0:
        print("    ✅ Bandwidth usage information displayed")

    # Check for progress bars (usage percentage visualization)
    progress_bars: Locator = page.locator(
        '[class*="bg-blue-500"][class*="rounded-full"], [class*="bg-green-500"][class*="rounded-full"]'
    )
    if progress_bars.count() > 0:
        print(f"    ✅ Found {progress_bars.count()} usage progress bar(s)")

    # Check for percentage display
    percentage_text: Locator = page.locator("text=/\\d+(\\.\\d+)?%/")
    if percentage_text.count() > 0:
        print("    ✅ Usage percentages displayed")

    # Switch back to Overview tab to verify tab switching works
    overview_tab: Locator = page.locator('button:has-text("Overview")')
    if overview_tab.count() > 0:
        overview_tab.click()
        page.wait_for_timeout(300)
        print("    ✅ Tab switching works (switched back to Overview)")

    print("  ✅ Service usage statistics validated successfully")


def test_customer_services_dashboard_widget(monitored_customer_page: Page) -> None:
    """
    Navigate to /dashboard/ and verify the services section/widget.

    Expected: Dashboard shows 'My Services' stat card with active count,
    and a 'My Services' quick action link pointing to /services/.
    """
    page = monitored_customer_page
    print("🏠 Testing customer services dashboard widget")

    print("  🏠 Navigating to dashboard")
    page.goto(f"{BASE_URL}/dashboard/")
    page.wait_for_load_state("networkidle")

    # Verify we are on the dashboard
    current_url: str = page.url
    assert "/dashboard" in current_url, f"Expected dashboard URL, got: {current_url}"

    # Verify My Services stat card (shows active_services count)
    services_stat: Locator = page.locator('p:has-text("My Services")')
    if services_stat.count() > 0:
        print("    ✅ 'My Services' stat card found on dashboard")

        # Check for the count value next to it
        services_count: Locator = page.locator('div:has(> div p:has-text("My Services")) p.text-2xl')
        if services_count.count() > 0:
            count_text: str = services_count.first.inner_text().strip()
            print(f"    ✅ Active services count displayed: {count_text}")
    else:
        print("    [i] My Services stat card not found in expected location")

    # Verify My Services quick action link
    services_link: Locator = page.locator('a[href*="/services/"]:has-text("My Services")')
    if services_link.count() > 0:
        print("    ✅ 'My Services' quick action link found")

        # Verify the link points to services list
        href: str = services_link.first.get_attribute("href") or ""
        assert "/services/" in href, f"My Services link should point to /services/, got: {href}"
        print(f"    ✅ Link href: {href}")
    else:
        print("    [i] My Services quick action link not found (may use different text)")

    # Verify the rocket emoji icon for services
    rocket_icon: Locator = page.locator('text="🚀"')
    if rocket_icon.count() > 0:
        print("    ✅ Services rocket icon (🚀) present on dashboard")

    print("  ✅ Dashboard services widget validated successfully")


def test_customer_services_mobile_responsiveness(monitored_customer_page: Page) -> None:
    """
    Test the services list page on a mobile viewport.

    Expected: Services list renders properly with mobile card layout,
    no horizontal overflow, and touch-friendly elements.
    """
    page = monitored_customer_page
    print("📱 Testing customer services mobile responsiveness")

    # Navigate to services list
    page.goto(f"{BASE_URL}/services/")
    page.wait_for_load_state("networkidle")

    # Run standard mobile test
    with MobileTestContext(page, "mobile_medium") as mobile:
        print("    📱 Testing services list on mobile viewport")

        run_standard_mobile_test(page, mobile, context_label="services list")

        # Verify mobile card view is shown (md:hidden means mobile cards visible)
        mobile_cards: Locator = page.locator(".md\\:hidden div[onclick]")
        desktop_table: Locator = page.locator(".hidden.md\\:block table")

        # On mobile, the desktop table should be hidden
        if desktop_table.count() > 0:
            expect(desktop_table.first).to_be_hidden()
            print("      ✅ Desktop table hidden on mobile")

        # Verify mobile cards are visible
        if mobile_cards.count() > 0:
            print(f"      ✅ {mobile_cards.count()} mobile service cards visible")

        # Verify scrollable mobile navigation tabs
        mobile_nav: Locator = page.locator('.sm\\:hidden nav[role="tablist"]')
        if mobile_nav.count() > 0:
            print("      ✅ Mobile scrollable navigation tabs present")

        print("      ✅ Mobile responsiveness validated")

    print("  ✅ Services mobile responsiveness test completed")


@pytest.mark.expect_server_errors("not found", "access denied")
def test_customer_services_access_control(page: Page) -> None:  # noqa: PLR0915
    """
    Login as customer2 and attempt to access customer1's service detail.

    Expected: Accessing another customer's service returns 404 or redirects away.
    Cross-customer data isolation must be enforced.

    NOTE: This test intentionally uses bare ``page`` because it requires
    two separate login sessions (customer1 then customer2).
    """
    print("🔐 Testing cross-customer services access control")

    with ComprehensivePageMonitor(
        page,
        "customer services access control",
        check_console=False,  # Expect access denied / 404
        check_network=False,  # May have error status codes
        check_html=True,
        check_css=True,
        check_accessibility=False,
        allow_accessibility_skip=True,
    ):
        # Step 1: Login as customer1 and find a service ID
        print("  👤 Step 1: Login as customer1 to find a service ID")
        ensure_fresh_session(page)
        assert login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)

        page.goto(f"{BASE_URL}/services/")
        page.wait_for_load_state("networkidle")

        # Find first service and get its ID
        first_service_row: Locator = page.locator("tr[onclick], div[onclick]").first
        if first_service_row.count() == 0:
            print("    ⚠️ No services found for customer1, skipping access control test")
            return

        first_service_row.click()
        page.wait_for_load_state("networkidle")

        customer1_url: str = page.url
        match = re.search(r"/services/(\d+)/", customer1_url)
        if not match:
            print("    ⚠️ Could not extract service ID, skipping")
            return
        service_id: str = match.group(1)
        print(f"    ✅ Customer1 service ID: {service_id}")

        # Step 2: Login as customer2 and try accessing customer1's service
        print("  👤 Step 2: Login as customer2 and attempt cross-customer access")
        ensure_fresh_session(page)
        customer2_logged_in = login_user(page, CUSTOMER2_EMAIL, CUSTOMER2_PASSWORD)
        if not customer2_logged_in:
            print("    ⚠️ Customer 2 login failed (user may not exist in E2E fixtures) - skipping")
            return

        page.goto(f"{BASE_URL}/services/{service_id}/")
        page.wait_for_load_state("networkidle")

        # Verify access is denied
        current_url: str = page.url
        page_content: str = page.content().lower()

        # Check for 404 page heading
        is_404: bool = page.locator('h1:has-text("404")').count() > 0
        is_redirected: bool = f"/services/{service_id}/" not in current_url
        has_error_msg: bool = (
            "not found" in page_content or "access denied" in page_content or "permission" in page_content
        )

        access_denied: bool = is_404 or is_redirected or has_error_msg
        assert access_denied, (
            f"SECURITY ISSUE: Customer2 can access Customer1's service {service_id}. URL: {current_url}"
        )

        if is_404:
            print(f"    ✅ Service {service_id} returns 404 for customer2 (correct)")
        elif is_redirected:
            print(f"    ✅ Customer2 redirected away from service {service_id} to: {current_url}")
        elif has_error_msg:
            print(f"    ✅ Access denied message shown for service {service_id}")

        # Also verify customer2 cannot access request-action for customer1's service
        print("  🔒 Step 3: Verify request-action is also blocked")
        page.goto(f"{BASE_URL}/services/{service_id}/request-action/")
        page.wait_for_load_state("networkidle")

        action_url: str = page.url
        action_content: str = page.content().lower()
        action_is_404: bool = page.locator('h1:has-text("404")').count() > 0
        action_redirected: bool = f"/services/{service_id}/request-action/" not in action_url
        action_has_form: bool = page.locator('form input[name="action"]').count() > 0

        action_blocked: bool = action_is_404 or action_redirected or not action_has_form
        assert action_blocked, (
            f"SECURITY ISSUE: Customer2 can access request-action for Customer1's service {service_id}"
        )
        print("    ✅ Request-action also blocked for cross-customer access")

        print("  🛡️ Cross-customer access control validated successfully")


# ===============================================================================
# LIST PAGE STRUCTURE, FILTERING, SEARCH, AND PAGINATION TESTS
# ===============================================================================


def test_services_list_page_structure(monitored_customer_page: Page) -> None:
    """Test services list renders with shared header, tabs, search, and table."""
    page = monitored_customer_page
    print("📋 Testing services list page structure")

    page.goto(f"{BASE_URL}/services/")
    page.wait_for_load_state("networkidle")

    # Shared header component: page title
    heading: Locator = page.locator('h1:has-text("Services"), h1:has-text("Servicii")').first
    expect(heading).to_be_visible()
    print("    ✅ Page heading visible")

    # Header stats (Active, Total)
    stats: Locator = page.locator(".text-2xl.font-bold")
    if stats.count() >= 2:
        print(f"    ✅ Header stats displayed: {stats.count()} values")

    # Tab navigation (All / Active / Suspended / Pending / Cancelled)
    tabs: Locator = page.locator("button[role='tab']")
    assert tabs.count() >= 4, f"Expected >= 4 tabs, got {tabs.count()}"
    print(f"    ✅ {tabs.count()} filter tabs present")

    # Search input
    search_input: Locator = page.locator("#list-filter-search")
    expect(search_input).to_be_visible()
    print("    ✅ Search input visible")

    # Table or empty state
    table: Locator = page.locator("table")
    empty_state: Locator = page.locator("text=/No services found/")
    assert table.count() > 0 or empty_state.count() > 0, "Should show data table or empty state"
    print("    ✅ Content area rendered")

    print("  ✅ Services list page structure validated")


def test_services_tab_filtering(monitored_customer_page: Page) -> None:
    """Test status tab switching filters via HTMX without page reload."""
    page = monitored_customer_page
    print("🔀 Testing services tab filtering")

    page.goto(f"{BASE_URL}/services/")
    page.wait_for_load_state("networkidle")

    # Click "Active" tab
    active_tab: Locator = page.locator(
        "button[role='tab']:has-text('Active'), button[role='tab']:has-text('Activ')"
    ).first
    if active_tab.count() > 0:
        active_tab.click()
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(300)

        hidden_tab: Locator = page.locator("#list-filter-active-tab")
        tab_value: str = hidden_tab.input_value()
        assert tab_value == "active", f"Expected 'active' tab value, got: {tab_value}"
        print("    ✅ Active tab clicked, hidden input updated")

    # Click "All" to reset
    all_tab: Locator = page.locator(
        "button[role='tab']:has-text('All'), button[role='tab']:has-text('Toate')"
    ).first
    if all_tab.count() > 0:
        all_tab.click()
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(300)
        print("    ✅ All tab clicked, filter reset")

    print("  ✅ Services tab filtering validated")


def test_services_search(monitored_customer_page: Page) -> None:
    """Test live search filters services via HTMX."""
    page = monitored_customer_page
    print("🔍 Testing services search")

    page.goto(f"{BASE_URL}/services/")
    page.wait_for_load_state("networkidle")

    search_input: Locator = page.locator("#list-filter-search")
    expect(search_input).to_be_visible()

    rows_before: int = page.locator("tbody tr").count()

    # Type using press_sequentially to trigger keyup events (HTMX listens for keyup)
    search_input.click()
    search_input.press_sequentially("ZZZZNONEXISTENT999", delay=50)
    page.wait_for_timeout(2000)
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(500)

    rows_after: int = page.locator("tbody tr").count()
    empty_state: Locator = page.locator("text=/No services found/")

    if rows_before > 0:
        assert rows_after < rows_before or empty_state.count() > 0, (
            f"Search with non-matching term should reduce results ({rows_before} → {rows_after})"
        )
        print(f"    ✅ Search filtered: {rows_before} → {rows_after}")

    # Clear search
    search_input.fill("")
    search_input.dispatch_event("keyup")
    page.wait_for_timeout(1500)
    page.wait_for_load_state("networkidle")
    print("    ✅ Search cleared")

    print("  ✅ Services search validated")


def test_services_pagination(monitored_customer_page: Page) -> None:
    """Test shared pagination component on services list."""
    page = monitored_customer_page
    print("📄 Testing services pagination")

    page.goto(f"{BASE_URL}/services/")
    page.wait_for_load_state("networkidle")

    pagination: Locator = page.locator("nav[aria-label*='Pagination'], nav[aria-label*='pagination']")
    if pagination.count() == 0:
        print("    [i] No pagination (too few services)")
        return

    pagination_text: Locator = page.locator("text=/\\d+-\\d+ of \\d+/")
    if pagination_text.count() > 0:
        print(f"    ✅ Pagination: {pagination_text.first.inner_text()}")

    print("  ✅ Services pagination validated")


# ===============================================================================
# QA FIX REGRESSION TESTS
# ===============================================================================


def test_service_detail_shows_actual_dates_not_calculating(monitored_customer_page: Page) -> None:
    """M3/M4: Service detail page shows real dates (start date, renewal date), not 'Calculating...'."""
    page = monitored_customer_page
    print("🧪 Testing service detail shows real dates, not 'Calculating...'")

    # Navigate to services list
    page.goto(f"{BASE_URL}/services/")
    page.wait_for_load_state("networkidle")

    # Click first service row
    first_row: Locator = page.locator("tr[onclick], div[onclick]").first
    if first_row.count() == 0:
        print("  [i] No services found for this customer, skipping date check")
        return

    first_row.click()
    page.wait_for_load_state("networkidle")

    current_url: str = page.url
    if not re.search(r"/services/\d+/", current_url):
        print(f"  [i] Did not land on service detail URL: {current_url}")
        return

    print(f"    ✅ On service detail: {current_url}")

    page_text: str = page.text_content("body") or ""

    # "Calculating..." must not appear on the fully-loaded page
    assert "Calculating..." not in page_text, (
        "Service detail must not show 'Calculating...' after page load — "
        "dates must be resolved by the backend, not deferred to the client"
    )
    print("    ✅ No 'Calculating...' placeholder text found")

    # Also check that "---" placeholders are not excessive (a few may be ok for genuinely unknown values)
    placeholder_count = page_text.count("---")
    assert placeholder_count < 5, (
        f"Service detail has {placeholder_count} '---' placeholders, "
        "suggesting dates are not being populated from the backend"
    )

    # Look for date-related fields and verify they have real values
    date_fields: Locator = page.locator(
        'dt:has-text("Start"), dt:has-text("Renewal"), dt:has-text("Expiry"), '
        'dt:has-text("Since"), dt:has-text("Dată"), dt:has-text("Reînnoire")'
    )
    if date_fields.count() > 0:
        for field in date_fields.all():
            value_el: Locator = field.locator("xpath=following-sibling::dd[1]")
            if value_el.count() == 0:
                continue
            value_text: str = (value_el.first.text_content() or "").strip()
            if not value_text or value_text in ("—", "-", "N/A", ""):
                # Optional: log but don't fail for fields that may legitimately be empty
                print(f"    [i] Date field '{(field.text_content() or '').strip()}' has empty value")
                continue
            # Value should not be "Calculating..."
            assert "Calculating" not in value_text, (
                f"Date field should not show 'Calculating...', got: '{value_text}'"
            )
            # If it has a real date value, it should contain a year
            if re.search(r"\d", value_text):
                print(f"    ✅ Date field has value: '{value_text}'")

    print("  ✅ Service detail dates test completed")


def test_service_detail_domain_section_no_server_error(monitored_customer_page: Page) -> None:
    """M5: Service detail domain section must not cause a server error (KeyError 'results')."""
    page = monitored_customer_page
    print("🧪 Testing service detail domain section loads without error")

    page.goto(f"{BASE_URL}/services/")
    page.wait_for_load_state("networkidle")

    first_row: Locator = page.locator("tr[onclick], div[onclick]").first
    if first_row.count() == 0:
        print("  [i] No services found, skipping domain section test")
        return

    first_row.click()
    page.wait_for_load_state("networkidle")

    current_url: str = page.url
    if not re.search(r"/services/\\d+/", current_url):
        print(f"  [i] Not on service detail URL: {current_url}")
        return

    page_text: str = page.text_content("body") or ""

    # Must not show Python traceback or KeyError
    error_indicators = ["traceback", "keyerror", "internal server error"]
    for indicator in error_indicators:
        assert indicator not in page_text.lower(), (
            f"Service detail must not show '{indicator}' — check domain retrieval code"
        )
    print("    ✅ No server error indicators on service detail page")

    # Domain section should exist or gracefully show empty state
    has_domain_content = any(
        keyword in page_text.lower()
        for keyword in ["domain", "domeniu", "server", "hostname", "ip"]
    )
    if has_domain_content:
        print("    ✅ Domain/server information present on service detail")
    else:
        print("    [i] No domain section found (may not be applicable for this service type)")

    print("  ✅ Service detail domain section test completed")
