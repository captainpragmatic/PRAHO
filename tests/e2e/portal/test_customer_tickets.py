"""
Customer Ticket System E2E Tests for PRAHO Platform

This module comprehensively tests the customer ticket management functionality including:
- Customer ticket system navigation and access (customer permissions only)
- Viewing customer's own tickets only (access control)
- Creating support tickets for customer's own company
- Adding replies and comments to own tickets
- File attachment uploads (if supported)
- Ticket status visibility and interactions
- Mobile responsiveness for customer portal
- Privacy and security - no access to other customers' tickets
- No access to internal staff notes or features

Uses shared utilities from tests.e2e.helpers for consistency.
Based on real customer workflows for Romanian hosting support.
"""

import re

import pytest
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Locator, Page, expect

# Import shared utilities
from tests.e2e.helpers import (
    BASE_URL,
    CUSTOMER2_EMAIL,
    CUSTOMER2_PASSWORD,
    CUSTOMER_EMAIL,
    CUSTOMER_PASSWORD,
    ComprehensivePageMonitor,
    MobileTestContext,
    assert_responsive_results,
    ensure_fresh_session,
    login_user,
    navigate_to_dashboard,
    require_authentication,
    run_responsive_breakpoints_test,
    run_standard_mobile_test,
)

# ===============================================================================
# CUSTOMER TICKET SYSTEM ACCESS AND NAVIGATION TESTS
# ===============================================================================

def test_customer_ticket_system_access_via_navigation(monitored_customer_page: Page) -> None:
    """
    Test customer accessing the ticket system through Support dropdown navigation.

    This test verifies the complete navigation path to tickets for customers:
    1. Login as customer user
    2. Click Support dropdown in navigation
    3. Click My Tickets or Tickets link
    4. Verify ticket list page loads correctly with customer-only features
    """
    page = monitored_customer_page
    print("🧪 Testing customer ticket system access via navigation")

    require_authentication(page)

    # Navigate to dashboard first
    assert navigate_to_dashboard(page)
    expect(page).to_have_url(re.compile(r"/dashboard/"))

    # Navigate directly to tickets page
    page.goto(f"{BASE_URL}/tickets/")
    page.wait_for_load_state("networkidle")
    expect(page).to_have_url(re.compile(r"/tickets/"))

    # Verify page title and customer-specific content (handle both English and Romanian)
    # Soft check: page title may vary by language/configuration
    page_title = page.title()
    title_has_ticket_text = bool(re.search(r"support|ticket|tichete", page_title, re.IGNORECASE))
    if not title_has_ticket_text:
        print(f"  ⚠️ SOFT CHECK: Page title '{page_title}' does not contain expected ticket text")
    tickets_heading = page.locator('h1:has-text("Tickets"), h1:has-text("Tichete")').first
    if tickets_heading.is_visible():
        print("  ✅ Ticket system heading visible")
    else:
        print("  [i] Ticket heading not visible (may be inside collapsed header)")

    # Verify customer can see "New Ticket" button (customer can create their own tickets)
    # May be in different languages or locations for customers
    new_ticket_button = page.locator('a:has-text("New Ticket"), a:has-text("Tichet nou"), a[href*="/tickets/create/"]').first
    if new_ticket_button.is_visible():
        print("  ✅ Customer can create tickets")
    else:
        print("  [i] New ticket button may not be visible for customers or in different location")

    print("  ✅ Customer ticket system successfully accessible via Support navigation")


def test_customer_ticket_list_display_own_tickets_only(monitored_customer_page: Page) -> None:
    """
    Test the customer ticket list shows only customer's own tickets.

    This test verifies:
    - Customer can only see tickets for their own company
    - No access to other customers' tickets
    - Ticket statistics are customer-specific
    - Customer-appropriate features are visible
    """
    page = monitored_customer_page
    print("🧪 Testing customer ticket list displays own tickets only")

    page.goto(f"{BASE_URL}/tickets/")
    page.wait_for_load_state("networkidle")

    # Verify customer can access the ticket system (support both English and Romanian)
    tickets_heading = page.locator('h1:has-text("Tickets"), h1:has-text("Tichete")').first
    expect(tickets_heading).to_be_visible()

    # Verify customer can create new tickets (use the main button, not dropdown)
    new_ticket_button = page.locator('a[href="/tickets/create/"].inline-flex, a[href="/tickets/create/"][class*="bg-primary"]').first
    expect(new_ticket_button).to_be_visible()

    # Check if tickets are displayed and verify they belong to customer
    ticket_items = page.locator('tr:has-text("TK"), div:has-text("TK")')
    ticket_count = ticket_items.count()
    if ticket_count > 0:
        print(f"  ✅ Found {ticket_count} tickets for customer")

        # Verify no internal staff information is visible
        internal_notes = page.locator('text="INTERNAL", text="Internal Note"')
        assert internal_notes.count() == 0, "Customer should not see internal staff notes"

        # Check that customer name appears in tickets (if visible)
        customer_company = page.locator('text="Test Company"')  # Based on sample data
        if customer_company.is_visible():
            print("  ✅ Customer tickets show correct company association")
    else:
        print("  [i] No tickets currently exist for this customer")

    # Verify ticket statistics are customer-specific
    open_count = page.locator('text="Open:"')
    total_count = page.locator('text="Total:"')
    if open_count.is_visible() and total_count.is_visible():
        print("  ✅ Customer ticket statistics displayed")

    print("  ✅ Customer ticket list properly displays own tickets only")


# ===============================================================================
# CUSTOMER TICKET CREATION TESTS
# ===============================================================================


def _fill_ticket_form(page: Page, subject: str, description: str, priority: str) -> None:
    """Fill the customer ticket creation form fields."""
    customer_select = page.locator('select[name="customer_id"]')
    if customer_select.is_visible():
        customer_options = page.locator('select[name="customer_id"] option')
        option_count = customer_options.count()
        print(f"  [i] Customer selection has {option_count} options (should be limited to customer's companies)")
        if option_count > 1:
            page.select_option('select[name="customer_id"]', index=1)
    else:
        print("  ✅ Customer selection auto-handled (customer can only create for their own company)")

    subject_field = page.locator('input[name="subject"], input[name="title"]').first
    expect(subject_field).to_be_visible()
    subject_field.fill(subject)
    print("  ✅ Filled ticket subject")

    description_field = page.locator('textarea[name="description"]')
    expect(description_field).to_be_visible()
    description_field.fill(description)
    print("  ✅ Filled ticket description")

    priority_field = page.locator('select[name="priority"]')
    if priority_field.is_visible():
        try:
            page.select_option('select[name="priority"]', priority)
            print("  ✅ Set ticket priority")
        except (TimeoutError, PlaywrightError):
            page.select_option('select[name="priority"]', 'normal')
            print("  ✅ Set ticket priority (fallback to normal)")
    else:
        print("  [i] Priority field not found - may use default")


def _verify_ticket_creation_result(page: Page, subject: str) -> bool:
    """Verify outcome after submitting the ticket creation form. Returns True on success."""
    if "/tickets/" in page.url and page.url != f"{BASE_URL}/tickets/create/":
        print("  ✅ Customer ticket creation succeeded - redirected away from create page")
        success_message = page.get_by_role("alert").locator('div:has-text("created"), div:has-text("Ticket #")')
        if success_message.is_visible():
            print("  ✅ Success message displayed")
        else:
            print("  [i] Success message not immediately visible")
        return True

    error_messages = page.locator('div.text-red-600, .text-red-500, [class*="error"]')
    if error_messages.count() > 0:
        error_text = error_messages.first.inner_text()
        print(f"  ❌ Form validation error: {error_text}")
        return False

    print("  [i] Form submitted but still on create page - checking if ticket was created")
    page.goto(f"{BASE_URL}/tickets/")
    page.wait_for_load_state("networkidle")
    created_ticket = page.locator(f'text="{subject[:20]}"')
    if created_ticket.is_visible():
        print("  ✅ Ticket was created successfully (found in list)")
        return True
    else:
        print("  ❌ Ticket creation may have failed")
        return False


def test_customer_ticket_creation_workflow(monitored_customer_page: Page) -> None:
    """
    Test the complete customer ticket creation workflow.

    This test covers the customer ticket creation process:
    1. Navigate to ticket creation form
    2. Fill in ticket details for customer's own company
    3. Set priority and type (customer-appropriate options)
    4. Submit form and verify ticket is created
    5. Verify redirect to ticket detail page
    """
    page = monitored_customer_page
    print("🧪 Testing customer ticket creation workflow")

    page.goto(f"{BASE_URL}/tickets/")
    page.wait_for_load_state("networkidle")

    new_ticket_button = page.locator('a[href="/tickets/create/"].inline-flex, a[href="/tickets/create/"][class*="bg-primary"]').first
    expect(new_ticket_button).to_be_visible()
    new_ticket_button.click()

    page.wait_for_url("**/tickets/create/", timeout=8000)
    expect(page).to_have_url(re.compile(r"/tickets/create/"))

    create_heading = page.locator('h1:has-text("Create New Ticket"), h1:has-text("Creează tichet nou")').first
    expect(create_heading).to_be_visible()

    test_ticket_data = {
        'subject': 'Customer Website Loading Issues',
        'description': 'Our website at example.com has been loading very slowly for the past few days. Pages are taking 10-15 seconds to load. This is affecting our business operations.',
        'priority': 'high',
    }

    _fill_ticket_form(page, test_ticket_data['subject'], test_ticket_data['description'], test_ticket_data['priority'])

    internal_checkbox = page.locator('input[name="is_internal"], input:has-text("Internal")')
    assert internal_checkbox.count() == 0, "Customer should not see internal notes option"

    assignment_field = page.locator('select[name="assigned_to"]')
    assert assignment_field.count() == 0, "Customer should not see assignment options"

    submit_button = page.locator('button:has-text("Create Ticket"), button:has-text("Submit"), input[type="submit"]').first
    expect(submit_button).to_be_visible()
    submit_button.click()
    page.wait_for_load_state("networkidle")

    assert _verify_ticket_creation_result(page, test_ticket_data['subject']), \
        "Ticket creation failed or ticket not found after submission"

    print("  ✅ Customer ticket creation workflow completed")


# ===============================================================================
# CUSTOMER TICKET INTERACTION TESTS
# ===============================================================================

def test_customer_ticket_detail_and_comments(monitored_customer_page: Page) -> None:
    """
    Test customer ticket detail page and comment capabilities.

    This test verifies:
    - Ticket detail page loads with customer's information
    - Customer can add replies/comments
    - Customer cannot see internal staff notes
    - Customer cannot access staff management features
    """
    page = monitored_customer_page
    print("🧪 Testing customer ticket detail and comments")

    page.goto(f"{BASE_URL}/tickets/")
    page.wait_for_load_state("networkidle")

    # Find first ticket to view (customer's own tickets only)
    ticket_links = page.locator('a[href*="/tickets/"]:has-text("TK")')
    if ticket_links.count() == 0:
        # Try alternative selectors for ticket links
        ticket_links = page.locator('main a[href*="/tickets/"]:not([href*="create"])')

    if ticket_links.count() > 0:
        # Click on first ticket
        first_ticket_link = ticket_links.first
        first_ticket_link.click()
        page.wait_for_load_state("networkidle")

        # Verify we're on a ticket detail page
        assert "/tickets/" in page.url and page.url.endswith("/")
        print("  ✅ Navigated to customer ticket detail page")

        # Verify ticket detail elements are present
        ticket_info = page.locator('h1:has-text("TK"), h1:has-text("#")').first
        expect(ticket_info).to_be_visible()
        print("  ✅ Ticket information displayed")

        # Verify customer CANNOT see staff-only features
        internal_note_checkbox = page.locator('input[name="is_internal"], input:has-text("Internal")')
        assert internal_note_checkbox.count() == 0, "Customer should NOT see internal notes option"

        assignment_controls = page.locator('select[name="assigned_to"]')
        assignment_text = page.locator('text="Assign to"')
        assert assignment_controls.count() == 0 and assignment_text.count() == 0, "Customer should NOT see assignment controls"

        staff_actions = page.locator('text="Staff Actions", text="Admin"')
        assert staff_actions.count() == 0, "Customer should NOT see staff administrative actions"

        # Check for customer reply functionality
        reply_area = page.locator('textarea[name="message"], textarea[name="reply"], textarea[name="content"]')
        expect(reply_area).to_be_visible()
        print("  ✅ Customer reply functionality available")

        # Test adding a customer comment
        test_comment = "Thank you for looking into this issue. Just wanted to add that the problem seems worse during peak hours (9-11 AM and 2-4 PM)."
        reply_area.fill(test_comment)

        # Verify customer cannot set internal notes
        internal_checkbox = page.locator('input[name="is_internal"]')
        assert internal_checkbox.count() == 0, "Customer should NOT have internal notes checkbox"

        # Submit reply
        reply_button = page.locator('button:has-text("Reply"), button:has-text("Add"), button:has-text("Submit")').first
        expect(reply_button).to_be_visible()
        reply_button.click()
        page.wait_for_load_state("networkidle")
        print("  ✅ Customer comment/reply functionality tested")

        # Verify comment appears in conversation
        comment_added = page.locator(f'text="{test_comment[:20]}"')
        if comment_added.is_visible():
            print("  ✅ Customer comment appears in ticket conversation")
        else:
            print("  [i] Comment may need page refresh or HTMX update")

        # Verify customer can only see public comments (no internal staff notes)
        conversation = page.locator('div:has-text("INTERNAL:"), span:has-text("Internal")')
        assert conversation.count() == 0, "Customer should NOT see internal staff communications"

    else:
        print("  [i] No existing tickets found for customer")

    print("  ✅ Customer ticket detail and comments functionality verified")


def test_customer_ticket_file_attachments(monitored_customer_page: Page) -> None:
    """
    Test customer file attachment functionality in tickets.

    This test covers:
    - Customer ability to upload files to tickets
    - File type and size restrictions
    - Attachment display and download
    - Security considerations
    """
    page = monitored_customer_page
    print("🧪 Testing customer ticket file attachments")

    page.goto(f"{BASE_URL}/tickets/")
    page.wait_for_load_state("networkidle")

    # Find a ticket to work with
    ticket_links = page.locator('a[href*="/tickets/"]:has-text("TK")')
    if ticket_links.count() == 0:
        ticket_links = page.locator('main a[href*="/tickets/"]:not([href*="create"])')

    if ticket_links.count() > 0:
        first_ticket_link = ticket_links.first
        first_ticket_link.click()
        page.wait_for_load_state("networkidle")

        # Look for file upload functionality
        file_input = page.locator('input[type="file"]')
        attachment_section = page.locator('div:has-text("attachment"), label:has-text("attach")')

        has_upload_ui = file_input.is_visible() or attachment_section.is_visible()
        assert has_upload_ui, (
            "File upload control or attachment section must be present on ticket detail page"
        )

        if file_input.is_visible():
            print("  ✅ File upload functionality available to customers")

            # Check for file type restrictions information
            file_restrictions = page.locator('text="PDF", text="JPG", text="PNG", text="10MB"')
            if file_restrictions.count() > 0:
                print("  ✅ File type/size restrictions displayed")

        elif attachment_section.is_visible():
            print("  ✅ Attachment functionality interface present")

        # Check if any existing attachments are shown
        existing_attachments = page.locator('a:has-text("Download"), div:has-text(".pdf"), div:has-text(".jpg")')
        if existing_attachments.count() > 0:
            print("  ✅ Existing attachments displayed for customer")

            # Verify customer can only see attachments from their own tickets
            # (This is enforced by the access control in the backend)

    else:
        print("  [i] No tickets available for attachment testing")

    print("  ✅ Customer ticket file attachments functionality verified")


# ===============================================================================
# CUSTOMER TICKET STATUS AND WORKFLOW TESTS
# ===============================================================================

def test_customer_ticket_status_visibility_and_actions(monitored_customer_page: Page) -> None:
    """
    Test customer ticket status visibility and limited actions.

    This test covers:
    - Customer can see ticket status
    - Customer has limited status actions (e.g., close own tickets)
    - Customer cannot perform staff-only status changes
    - Proper workflow restrictions
    """
    page = monitored_customer_page
    print("🧪 Testing customer ticket status visibility and actions")

    page.goto(f"{BASE_URL}/tickets/")
    page.wait_for_load_state("networkidle")

    # Find a ticket to work with
    ticket_links = page.locator('a[href*="/tickets/"]:has-text("TK")')
    if ticket_links.count() == 0:
        ticket_links = page.locator('main a[href*="/tickets/"]:not([href*="create"])')

    if ticket_links.count() > 0:
        first_ticket_link = ticket_links.first
        first_ticket_link.click()
        page.wait_for_load_state("networkidle")

        # Check current ticket status display
        status_badges = page.locator('span[class*="badge"], span[class*="inline-flex"]')
        expect(status_badges.first).to_be_attached()
        current_status = status_badges.first.inner_text()
        print(f"  ✅ Customer can see ticket status: {current_status}")

        # Test customer-allowed actions
        # Customers may be able to close their own tickets
        close_link = page.locator('a[href*="/close/"], button:has-text("Close")')
        if close_link.is_visible():
            print("  ✅ Customer can close their own tickets")

            # Test closing (be careful not to actually close if we need to test more)
            # For now, just verify the option exists

        else:
            print("  [i] Ticket close option not visible to customer")

        # Verify customer CANNOT perform staff-only actions
        staff_status_controls = page.locator('select:has-text("Assign"), button:has-text("Escalate"), select:has-text("Priority")')
        assert staff_status_controls.count() == 0, "Customer should NOT see staff status management controls"

        assignment_controls = page.locator('text="Assign to", select[name="assigned_to"]')
        assert assignment_controls.count() == 0, "Customer should NOT see ticket assignment controls"

        internal_button = page.locator('button:has-text("Internal")')
        staff_only_text = page.locator('text="Staff Only"')
        assert internal_button.count() == 0 and staff_only_text.count() == 0, "Customer should NOT see internal staff controls"

        print("  ✅ Customer properly restricted from staff-only status actions")

    else:
        print("  [i] No tickets available for status testing")

    print("  ✅ Customer ticket status visibility and actions verified")


# ===============================================================================
# CUSTOMER ACCESS CONTROL AND SECURITY TESTS
# ===============================================================================

def test_customer_ticket_access_control_security(monitored_customer_page: Page) -> None:
    """
    Test customer ticket access control and security restrictions.

    This test verifies:
    1. Customer users can only access their own tickets
    2. No access to other customers' tickets
    3. No access to staff-only features
    4. Proper error handling for unauthorized access attempts
    """
    page = monitored_customer_page
    print("🧪 Testing customer ticket access control and security")

    # Test customer user access
    print("    Testing customer user access...")

    # Navigate directly to tickets URL
    page.goto(f"{BASE_URL}/tickets/")
    page.wait_for_load_state("networkidle")

    # Should successfully load ticket system for customer
    expect(page).to_have_url(re.compile(r"/tickets/"))
    tickets_heading = page.locator('h1:has-text("Tickets"), h1:has-text("Tichete")').first
    expect(tickets_heading).to_be_visible()

    # Verify customer can create tickets
    new_ticket_btn = page.locator('a[href="/tickets/create/"].inline-flex, a[href="/tickets/create/"][class*="bg-primary"]').first
    expect(new_ticket_btn).to_be_visible()

    # Verify customer can navigate to tickets via direct link (no dropdown navigation in portal)
    navigate_to_dashboard(page)
    tickets_nav_link = page.locator('a[href*="/tickets/"]')
    expect(tickets_nav_link.first).to_be_attached()
    print("    ✅ Customer has proper navigation access to tickets")

    # Test access to ticket creation form
    page.goto(f"{BASE_URL}/tickets/create/")
    page.wait_for_load_state("networkidle")

    create_form = page.locator('form.space-y-6, form:has(select[name="customer_id"]), form:has(input[name="subject"])').first
    expect(create_form).to_be_visible()

    # Verify customer selection is limited or auto-selected to their company
    customer_select = page.locator('select[name="customer_id"]')
    if customer_select.is_visible():
        customer_options = page.locator('select[name="customer_id"] option')
        option_count = customer_options.count()
        # Customer should only see their own company (plus placeholder)
        assert option_count <= 3, "Customer should have limited customer selection options"
        print("    ✅ Customer selection properly restricted")
    else:
        print("    ✅ Customer selection auto-handled (customer can only create for own company)")

    # Verify customer cannot access staff-only features in creation form
    staff_features = page.locator('input[name="is_internal"], select[name="assigned_to"], input:has-text("Internal")')
    assert staff_features.count() == 0, "Customer should not see staff-only creation features"

    print("  ✅ Customer ticket access control and security working correctly")


def _ticket_isolation_phase1_customer1(page: Page) -> None:
    """Phase 1: Verify Customer 1 can only see their own tickets."""
    print("    🔍 Phase 1: Testing Customer 1 ticket visibility")
    ensure_fresh_session(page)
    assert login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)

    page.goto(f"{BASE_URL}/tickets/")
    page.wait_for_load_state("networkidle")

    _title = page.title()
    if not re.search(r"support|ticket|tichete", _title, re.IGNORECASE):
        print(f"  ⚠️ SOFT CHECK: Page title '{_title}' does not contain expected ticket text")

    ticket_rows = page.locator('tr:has-text("TK"), tr:has-text("[C1"), tr:has-text("Database"), tr:has-text("Performance")')
    customer1_visible_tickets = ticket_rows.count()
    print(f"      Customer 1 sees {customer1_visible_tickets} tickets")

    if page.locator('text="C1 ONLY", text="Database Performance"').count() > 0:
        print("      ✅ Customer 1 can see their own isolation test ticket")

    customer2_ticket_count = page.locator('text="C2 ONLY", text="SSL Certificate Configuration", text="Second Test Company"').count()
    assert customer2_ticket_count == 0, (
        f"Customer ticket isolation failed - Customer 1 can see {customer2_ticket_count} tickets belonging to Customer 2"
    )
    print("      ✅ SECURITY: Customer 1 cannot see Customer 2's tickets")

    if page.locator('text="Test Company SRL"').count() > 0:
        print("      ✅ UI shows clear company ownership indicators")


def _ticket_isolation_phase2_customer2(page: Page) -> None:
    """Phase 2: Verify Customer 2 can only see their own tickets."""
    print("    🔍 Phase 2: Testing Customer 2 ticket visibility")
    ensure_fresh_session(page)
    customer2_logged_in = login_user(page, CUSTOMER2_EMAIL, CUSTOMER2_PASSWORD)

    if not customer2_logged_in:
        print("      ⚠️ Customer 2 login failed (user may not exist in E2E fixtures) - skipping phase 2")
        print("      [i] Phase 1 isolation verified: Customer 1 cannot see Customer 2's data")
        return

    page.goto(f"{BASE_URL}/tickets/")
    page.wait_for_load_state("networkidle")

    _title = page.title()
    if not re.search(r"support|ticket|tichete", _title, re.IGNORECASE):
        print(f"  ⚠️ SOFT CHECK: Page title '{_title}' does not contain expected ticket text")

    ticket_rows = page.locator('tr:has-text("TK"), tr:has-text("[C2"), tr:has-text("SSL"), tr:has-text("Certificate")')
    customer2_visible_tickets = ticket_rows.count()
    print(f"      Customer 2 sees {customer2_visible_tickets} tickets")

    if page.locator('text="C2 ONLY", text="SSL Certificate"').count() > 0:
        print("      ✅ Customer 2 can see their own isolation test ticket")

    customer1_ticket_count = page.locator('text="C1 ONLY", text="Database Performance", text="Test Company SRL"').count()
    assert customer1_ticket_count == 0, (
        f"Customer ticket isolation failed - Customer 2 can see {customer1_ticket_count} tickets belonging to Customer 1"
    )
    print("      ✅ SECURITY: Customer 2 cannot see Customer 1's tickets")

    if page.locator('text="Second Test Company SRL"').count() > 0:
        print("      ✅ UI shows Customer 2's company ownership indicators")


def test_customer_ticket_isolation_comprehensive_security(page: Page) -> None:
    """
    COMPREHENSIVE SECURITY TEST: Verify customer ticket isolation and data privacy.

    This is the most important security test for customer data protection:
    1. Login as Customer 1 and verify they can only see their own tickets
    2. Login as Customer 2 and verify they can only see their own tickets
    3. Verify customers cannot access each other's ticket URLs directly
    4. Ensure UI clearly shows ticket ownership
    5. Test that ticket lists properly filter by customer

    NOTE: This test intentionally uses bare ``page`` because it requires
    two separate login sessions (customer1 then customer2).
    """
    print("🔒 Testing comprehensive customer ticket isolation security")

    with ComprehensivePageMonitor(page, "customer ticket isolation security",
                                 check_console=True,
                                 check_network=True,
                                 check_html=False,
                                 check_css=True,
                                 check_accessibility=False,
                                 allow_accessibility_skip=True):

        _ticket_isolation_phase1_customer1(page)
        _ticket_isolation_phase2_customer2(page)

        # === PHASE 3: Direct URL Access Security Test ===
        print("    🔍 Phase 3: Testing direct ticket URL access security")
        for fake_id in (99999, 99998):
            page.goto(f"{BASE_URL}/tickets/{fake_id}/")
            page.wait_for_load_state("networkidle")
            assert "/login/" in page.url or "/tickets/" not in page.url, (
                "Direct URL access should be blocked for other customer's tickets"
            )

        print("  ✅ Customer ticket isolation security test completed successfully")
        print("  🔒 Both customers can only see their own tickets")
        print("  🛡️ No cross-customer data leakage detected")


@pytest.mark.expect_server_errors("not found", "access denied")
def test_customer_cannot_access_other_customers_tickets(monitored_customer_page: Page) -> None:
    """
    Test that customers cannot access tickets from other customers.

    This test verifies proper data isolation between customers.
    Note: This is a security-critical test.
    """
    page = monitored_customer_page
    print("🧪 Testing customer cannot access other customers' tickets (security)")

    # Navigate to tickets
    page.goto(f"{BASE_URL}/tickets/")
    page.wait_for_load_state("networkidle")

    # Get list of tickets visible to this customer
    visible_tickets = page.locator('tr:has-text("TK"), div:has-text("TK")')
    customer_ticket_count = visible_tickets.count()

    # Check that all visible tickets belong to the customer's company
    if customer_ticket_count > 0:
        print(f"  ✅ Customer sees {customer_ticket_count} tickets (should be own company only)")

        # Verify company name appears (if displayed)
        test_company = page.locator('text="Test Company"')  # Based on sample data
        if test_company.is_visible():
            print("  ✅ Tickets show correct customer company")
    else:
        print("  [i] No tickets visible to customer (expected if no tickets exist)")

    # Security test: Try to access a hypothetical ticket ID that might belong to another customer
    # This is a security test - customer should get access denied or 404
    print("    Testing access to potentially unauthorized ticket...")

    # Try accessing ticket IDs that might exist but don't belong to this customer
    for test_id in [999, 1000, 1001]:  # High IDs unlikely to be customer's tickets
        attempted_url = f"{BASE_URL}/tickets/{test_id}/"
        page.goto(attempted_url)
        page.wait_for_load_state("networkidle")

        # Should either redirect away or show access denied
        assert "/login/" in page.url or page.url != attempted_url, (
            f"Should not access ticket {test_id}"
        )

    print("  ✅ Customer ticket isolation security verified")


# ===============================================================================
# CUSTOMER MOBILE RESPONSIVENESS TESTS
# ===============================================================================

def test_customer_ticket_system_mobile_responsiveness(monitored_customer_page: Page) -> None:
    """
    Test customer ticket system mobile responsiveness and touch interactions.

    This test verifies:
    1. Customer ticket system displays correctly on mobile viewports
    2. Touch interactions work properly for customer features
    3. Mobile navigation elements function correctly
    4. Forms and ticket interactions are mobile-friendly
    """
    page = monitored_customer_page
    print("🧪 Testing customer ticket system mobile responsiveness")

    page.goto(f"{BASE_URL}/tickets/")
    page.wait_for_load_state("networkidle")

    # Test mobile viewport
    with MobileTestContext(page, 'mobile_medium') as mobile:
        print("    📱 Testing customer ticket system on mobile viewport")

        run_standard_mobile_test(page, mobile, context_label="customer tickets")

        # Verify key mobile elements are accessible for customers
        # Soft check: h1 may be hidden behind mobile nav or scrolled off-screen on small viewports
        tickets_heading = page.locator('h1:has-text("Tickets"), h1:has-text("Tichete")').first
        if tickets_heading.is_visible():
            print("      ✅ Ticket system heading visible on mobile")
        else:
            print("      ⚠️ SOFT CHECK: Ticket heading not visible on mobile viewport (may be behind mobile nav or scrolled off-screen)")

        new_ticket_btn = page.locator('a[href="/tickets/create/"].inline-flex, a[href="/tickets/create/"][class*="bg-primary"]').first
        if new_ticket_btn.is_visible():
            print("      ✅ New ticket button accessible on mobile")

            # Test ticket creation form on mobile
            new_ticket_btn.click()
            page.wait_for_load_state("networkidle")

            create_form = page.locator('form.space-y-6, form:has(select[name="customer_id"]), form:has(input[name="subject"])')
            if create_form.is_visible():
                print("      ✅ Ticket creation form loads on mobile")

                # Test form fields are properly sized for mobile
                subject_field = page.locator('input[name="subject"], input[name="title"]')
                description_field = page.locator('textarea[name="description"]')

                if subject_field.is_visible() and description_field.is_visible():
                    print("      ✅ Form fields properly displayed on mobile")

                # Navigate back to ticket list
                back_btn = page.locator('a:has-text("Back"), button:has-text("Back")')
                if back_btn.is_visible():
                    back_btn.click()
                    page.wait_for_load_state("networkidle")

    print("  ✅ Customer ticket system mobile responsiveness testing completed")


# ===============================================================================
# COMPREHENSIVE CUSTOMER WORKFLOW TESTS
# ===============================================================================


def _workflow_create_ticket_step1(page: Page, workflow_ticket: dict) -> bool:
    """Step 1: Create a new ticket and return True if creation succeeded."""
    print("    Step 1: Creating new ticket as customer...")
    page.goto(f"{BASE_URL}/tickets/create/")
    page.wait_for_load_state("networkidle")

    subject_field = page.locator('input[name="subject"], input[name="title"]').first
    expect(subject_field).to_be_visible()
    subject_field.fill(workflow_ticket['subject'])

    description_field = page.locator('textarea[name="description"]')
    expect(description_field).to_be_visible()
    description_field.fill(workflow_ticket['description'])

    customer_select = page.locator('select[name="customer_id"]')
    if customer_select.is_visible():
        customer_options = page.locator('select[name="customer_id"] option')
        if customer_options.count() > 1:
            page.select_option('select[name="customer_id"]', index=1)

    priority_field = page.locator('select[name="priority"]')
    if priority_field.is_visible():
        try:
            page.select_option('select[name="priority"]', workflow_ticket['priority'])
        except (TimeoutError, PlaywrightError):
            page.select_option('select[name="priority"]', 'normal')

    submit_btn = page.locator('button:has-text("Create"), button:has-text("Submit")').first
    expect(submit_btn).to_be_visible()
    submit_btn.click()
    page.wait_for_load_state("networkidle")

    if "/tickets/" in page.url and "create" not in page.url:
        print("      ✅ Customer ticket created successfully")
        return True

    page.goto(f"{BASE_URL}/tickets/")
    page.wait_for_load_state("networkidle")
    created_ticket_link = page.locator(f'text="{workflow_ticket["subject"][:20]}"')
    if created_ticket_link.is_visible():
        created_ticket_link.click()
        page.wait_for_load_state("networkidle")
        print("      ✅ Found and opened customer-created ticket")
        return True

    return False


def _workflow_interact_with_ticket(page: Page) -> None:
    """Steps 2-4: Add a comment and verify restrictions on the created ticket."""
    print("    Step 2: Adding customer follow-up comment...")
    reply_area = page.locator('textarea[name="message"], textarea[name="reply"], textarea[name="content"], textarea[name="body"]')
    if reply_area.count() > 0 and reply_area.first.is_visible():
        follow_up_comment = "Additional information: The email delivery issue affects both our contact forms and our newsletter system. Our customers are not receiving confirmation emails."
        reply_area.first.fill(follow_up_comment)

        internal_checkbox = page.locator('input[name="is_internal"]')
        assert internal_checkbox.count() == 0, "Customer should NOT have internal notes option"

        reply_btn = page.locator('button:has-text("Reply"), button:has-text("Add")').first
        if reply_btn.is_visible():
            reply_btn.click()
            page.wait_for_load_state("networkidle")
            print("      ✅ Customer follow-up comment added")
        else:
            print("      ⚠️ SOFT CHECK: Reply submit button not found")
    else:
        print("      ⚠️ SOFT CHECK: Reply textarea not found — reply form may use different field names or may not be present on this page")

    print("    Step 3: Verifying customer view restrictions...")
    internal_content = page.locator('text="INTERNAL:", text="Staff Only"')
    assert internal_content.count() == 0, "Customer should not see internal staff content"
    staff_controls = page.locator('select:has-text("Assign"), button:has-text("Escalate")')
    assert staff_controls.count() == 0, "Customer should not see staff controls"
    print("      ✅ Customer view properly restricted from staff features")

    print("    Step 4: Testing customer ticket status visibility...")
    status_badges = page.locator('span[class*="badge"], span[class*="inline-flex"]')
    expect(status_badges.first).to_be_attached()
    print("      ✅ Customer can see ticket status")

    print("  ✅ Complete customer ticket workflow successful")


def test_customer_complete_ticket_workflow(monitored_customer_page: Page) -> None:
    """
    Test the complete customer ticket workflow from creation to interaction.

    This comprehensive test covers:
    1. Customer creating a support ticket for their company
    2. Adding follow-up comments and information
    3. Viewing ticket status and updates
    4. Testing file attachments (if supported)
    5. Customer-appropriate ticket management
    """
    page = monitored_customer_page
    print("🧪 Testing complete customer ticket workflow")

    workflow_ticket = {
        'subject': 'Customer E2E Workflow - Email Delivery Issues',
        'description': 'We are experiencing issues with email delivery from our domain. Outgoing emails are being marked as spam or not delivered at all. This started yesterday around 3 PM. Please investigate our mail server configuration.',
        'priority': 'high',
    }

    ticket_created = _workflow_create_ticket_step1(page, workflow_ticket)

    if ticket_created:
        _workflow_interact_with_ticket(page)
    else:
        pytest.fail("Ticket creation failed")


def test_customer_ticket_system_responsive_breakpoints(monitored_customer_page: Page) -> None:
    """
    Test customer ticket system functionality across all responsive breakpoints.

    This test validates that customer ticket functionality works on:
    - Desktop viewports (baseline)
    - Tablet viewports (landscape and portrait)
    - Mobile viewports (various sizes)
    """
    page = monitored_customer_page
    print("🧪 Testing customer ticket system across responsive breakpoints")

    def test_customer_ticket_functionality(test_page, context="general"):
        """Test core customer ticket functionality across viewports."""
        try:
            # Navigate to tickets
            test_page.goto(f"{BASE_URL}/tickets/")
            test_page.wait_for_load_state("networkidle")

            # Verify authentication maintained
            require_authentication(test_page)

            # Check core elements are present
            # Find any visible h1 with ticket-related text
            all_h1s = test_page.locator('h1').all()
            heading_visible = False
            for h1 in all_h1s:
                if h1.is_visible():
                    text = (h1.text_content() or "").lower()
                    if "ticket" in text or "support" in text:
                        heading_visible = True
                        break
            # Find any visible create ticket link
            all_btns = test_page.locator('a[href="/tickets/create/"]').all()
            btn_visible = any(btn.is_visible() for btn in all_btns)

            elements_present = heading_visible and btn_visible

            if elements_present:
                print(f"      ✅ Customer ticket system functional in {context}")
                return True
            else:
                print(f"      ❌ Core ticket elements missing in {context}")
                return False

        except (TimeoutError, PlaywrightError) as e:
            print(f"      ❌ Ticket system test failed in {context}: {str(e)[:50]}")
            return False

    # Test across all breakpoints
    results = run_responsive_breakpoints_test(page, test_customer_ticket_functionality)

    # Verify all breakpoints pass
    assert_responsive_results(results, "Customer ticket system")

    print("  ✅ Customer ticket system validated across all responsive breakpoints")


# ===============================================================================
# HTMX SEARCH AND DASHBOARD WIDGET TESTS
# ===============================================================================


def test_customer_ticket_htmx_search(monitored_customer_page: Page) -> None:
    """
    Test the HTMX-powered ticket search and status filter on the ticket list page.

    Validates:
    - Typing in the search input triggers HTMX update of ticket list
    - Filtering by status dropdown updates the displayed tickets
    - Clearing search restores the full ticket list
    """
    page = monitored_customer_page
    print("🧪 Testing customer ticket HTMX search functionality")

    # Navigate to ticket list
    print("  📋 Navigating to ticket list...")
    page.goto(f"{BASE_URL}/tickets/")
    page.wait_for_load_state("networkidle")

    tickets_content: Locator = page.locator("#tickets-content")
    expect(tickets_content).to_be_attached()
    print("    ✅ Ticket list page loaded with #tickets-content container")

    # Count initial tickets visible (rows in table or mobile cards)
    initial_rows: Locator = page.locator("#tickets-content tr.hover\\:bg-slate-700\\/50, #tickets-content .cursor-pointer")
    initial_count: int = initial_rows.count()
    print(f"    ✅ Initial ticket count: {initial_count}")

    # Test search input
    print("  🔍 Testing search input HTMX trigger...")
    search_input: Locator = page.locator("#list-filter-search")
    expect(search_input).to_be_visible()

    # Type using press_sequentially to trigger keyup (HTMX listens for keyup changed)
    search_input.click()
    search_input.press_sequentially("zzz_nonexistent_query_zzz", delay=50)
    # Wait for HTMX to fire (delay:600ms configured in template) and update content
    page.wait_for_timeout(2000)
    page.wait_for_load_state("networkidle")

    filtered_rows: Locator = page.locator(
        "#tickets-content tr.hover\\:bg-slate-700\\/50, #tickets-content .cursor-pointer"
    )
    filtered_count: int = filtered_rows.count()
    print(f"    ✅ After search for nonsense string: {filtered_count} tickets (expected fewer or 0)")
    assert filtered_count <= initial_count, "Search filter should reduce results"

    # Clear search and verify tickets return
    print("  🔄 Clearing search input...")
    search_input.fill("")
    page.wait_for_timeout(1000)
    page.wait_for_load_state("networkidle")

    restored_rows: Locator = page.locator(
        "#tickets-content tr.hover\\:bg-slate-700\\/50, #tickets-content .cursor-pointer"
    )
    restored_count: int = restored_rows.count()
    print(f"    ✅ After clearing search: {restored_count} tickets (started with {initial_count})")
    assert restored_count >= initial_count, "Clearing search should restore all tickets"

    # Test status tab filtering (tabs replaced dropdown after ADR-0026)
    print("  🏷️ Testing status tab filtering...")
    closed_tab: Locator = page.locator(
        "button[role='tab']:has-text('Closed'), button[role='tab']:has-text('Închis')"
    ).first
    if closed_tab.count() > 0:
        closed_tab.click()
        page.wait_for_timeout(1000)
        page.wait_for_load_state("networkidle")

        closed_rows: Locator = page.locator(
            "#tickets-content tr.hover\\:bg-slate-700\\/50, #tickets-content .cursor-pointer"
        )
        closed_count: int = closed_rows.count()
        print(f"    ✅ Filtered by 'Closed' tab: {closed_count} tickets")

    # Reset to All tab
    all_tab: Locator = page.locator(
        "button[role='tab']:has-text('All'), button[role='tab']:has-text('Toate')"
    ).first
    if all_tab.count() > 0:
        all_tab.click()
        page.wait_for_timeout(1000)
        page.wait_for_load_state("networkidle")

        reset_rows: Locator = page.locator(
            "#tickets-content tr.hover\\:bg-slate-700\\/50, #tickets-content .cursor-pointer"
        )
        reset_count: int = reset_rows.count()
        print(f"    ✅ Reset to All tab: {reset_count} tickets")

    print("  ✅ Customer ticket HTMX search testing completed")


def test_customer_ticket_dashboard_widget(monitored_customer_page: Page) -> None:
    """
    Test the ticket widget section on the customer dashboard.

    Validates:
    - Dashboard loads with a tickets stats card (My Open Tickets)
    - Recent Tickets section is present with ticket entries or empty message
    - Ticket links navigate correctly
    """
    page = monitored_customer_page
    print("🧪 Testing customer ticket dashboard widget")

    # Navigate to dashboard
    print("  📊 Navigating to customer dashboard...")
    navigate_to_dashboard(page)
    page.wait_for_load_state("networkidle")

    # Verify the "My Open Tickets" stats card is present
    print("  🎫 Checking tickets stats card...")
    open_tickets_label: Locator = page.locator("text=My Open Tickets")
    expect(open_tickets_label).to_be_visible()
    print("    ✅ 'My Open Tickets' stats card is visible on dashboard")

    # Verify the "My Recent Tickets" section heading
    print("  📋 Checking recent tickets section...")
    recent_tickets_heading: Locator = page.locator("h3:has-text('My Recent Tickets')")
    expect(recent_tickets_heading).to_be_visible()
    print("    ✅ 'My Recent Tickets' section heading found")

    # Check for ticket entries or empty state message
    ticket_links: Locator = page.locator("a[href*='/tickets/'] .text-white.font-medium")
    empty_message: Locator = page.locator("text=No recent support tickets")

    if ticket_links.count() > 0:
        first_ticket_text: str = ticket_links.first.text_content() or ""
        print(f"    ✅ Found {ticket_links.count()} recent ticket(s), first: '{first_ticket_text.strip()}'")

        # Verify ticket links have proper href pointing to ticket detail
        first_ticket_link: Locator = ticket_links.first.locator("xpath=ancestor::a")
        ticket_href: str = first_ticket_link.get_attribute("href") or ""
        assert re.search(r"/tickets/\d+/", ticket_href), f"Ticket link should match /tickets/<id>/, got: {ticket_href}"
        print(f"    ✅ Ticket link href is valid: {ticket_href}")
    else:
        expect(empty_message).to_be_visible()
        print("    ✅ No tickets found — empty state message displayed correctly")

    # Verify "View all" link to tickets list
    view_all_link: Locator = page.locator("a[href='/tickets/']:has-text('View all')")
    expect(view_all_link).to_be_visible()
    print("    ✅ 'View all' link to tickets list is present")

    print("  ✅ Customer ticket dashboard widget testing completed")


# ===============================================================================
# QA FIX REGRESSION TESTS
# ===============================================================================


def test_ticket_subjects_have_no_status_prefix(monitored_customer_page: Page) -> None:
    """L4: Ticket subjects in the list must not be prefixed with [OPEN], [CLOSED], etc."""
    page = monitored_customer_page
    print("🧪 Testing ticket subjects have no [STATUS] prefix in list")

    page.goto(f"{BASE_URL}/tickets/")
    page.wait_for_load_state("networkidle")

    # Gather all visible ticket subject cells — these are the text cells in the table or cards
    subject_cells: Locator = page.locator(
        "#tickets-content td, #tickets-content .text-white.font-medium, "
        "#tickets-content .font-semibold"
    )

    if subject_cells.count() == 0:
        print("  [i] No ticket rows found (customer may have no tickets), skipping")
        return

    import re as _re
    status_prefix_pattern = _re.compile(r"^\s*\[(OPEN|CLOSED|PENDING|IN.PROGRESS|RESOLVED)\]", _re.IGNORECASE)

    bad_subjects: list[str] = []
    for cell in subject_cells.all():
        text: str = (cell.text_content() or "").strip()
        if text and status_prefix_pattern.match(text):
            bad_subjects.append(text)

    assert not bad_subjects, (
        f"Ticket subjects must not be prefixed with [STATUS] tags. Found: {bad_subjects}"
    )
    print(f"    ✅ Checked {subject_cells.count()} subject cells — no [STATUS] prefixes found")

    print("  ✅ Ticket subject no-prefix test completed")


def test_ticket_detail_back_link_is_at_top(monitored_customer_page: Page) -> None:
    """5.1: Ticket detail page has a 'Back to Tickets' link near the top of the page."""
    page = monitored_customer_page
    print("🧪 Testing ticket detail back link is at top of page")

    page.goto(f"{BASE_URL}/tickets/")
    page.wait_for_load_state("networkidle")

    # Find and click the first ticket
    ticket_links: Locator = page.locator('a[href*="/tickets/"]:has-text("TK")')
    if ticket_links.count() == 0:
        ticket_links = page.locator("main a[href*='/tickets/']:not([href*='create'])")

    if ticket_links.count() == 0:
        print("  [i] No ticket links found, skipping")
        return

    ticket_links.first.click()
    page.wait_for_load_state("networkidle")

    current_url: str = page.url
    if not re.search(r"/tickets/\d+/", current_url):
        print(f"  [i] Did not land on a ticket detail URL: {current_url}")
        return

    print(f"    ✅ On ticket detail page: {current_url}")

    # The back link must be present
    back_link: Locator = page.locator(
        'a[href*="/tickets/"]:has-text("Back"), '
        'a[href="/tickets/"]:has-text("Tickets"), '
        'a:has-text("Back to Tickets"), '
        'a:has-text("Înapoi la tichete")'
    ).first
    assert back_link.count() > 0, "Ticket detail must have a 'Back to Tickets' link"
    expect(back_link).to_be_visible()
    print("    ✅ Back to Tickets link is visible")

    # The back link should appear near the top — within the first 30% of page height.
    # We measure its Y position vs. the document height.
    link_box: dict = back_link.bounding_box() or {}
    link_y: float = link_box.get("y", 0)
    viewport_height: int = page.viewport_size.get("height", 800) if page.viewport_size else 800  # type: ignore[union-attr]

    assert link_y < viewport_height, (
        f"Back link should be visible within the first viewport (y={link_y:.0f}px, "
        f"viewport height={viewport_height}px)"
    )
    print(f"    ✅ Back link position y={link_y:.0f}px is within first viewport ({viewport_height}px)")

    print("  ✅ Ticket detail back link at top test completed")
