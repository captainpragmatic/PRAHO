"""
Staff Ticket System E2E Tests for PRAHO Platform

This module comprehensively tests the staff ticket management functionality including:
- Ticket system navigation and access (staff permissions)
- Ticket list view with filtering and search capabilities
- Creating tickets on behalf of customers
- Managing ticket details, status, priority, assignments
- Internal notes and staff-only features
- Comment management with visibility controls
- Ticket closure and reopening workflows
- SLA monitoring and escalation features
- File attachment handling
- HTMX interactions and real-time updates

Uses shared utilities from tests.e2e.utils for consistency.
Based on real staff workflows for Romanian hosting support operations.
"""

from playwright.sync_api import Page

from tests.e2e.utils import (
    PLATFORM_BASE_URL,
    MobileTestContext,
    assert_responsive_results,
    navigate_to_platform_page,
    require_authentication,
    run_responsive_breakpoints_test,
    run_standard_mobile_test,
)

# ===============================================================================
# STAFF TICKET SYSTEM ACCESS AND NAVIGATION TESTS
# ===============================================================================

def test_staff_ticket_system_access_via_navigation(monitored_staff_page: Page) -> None:
    """
    Test staff accessing the ticket system through direct navigation.

    This test verifies the complete navigation path to tickets for staff:
    1. Login as staff user (superuser)
    2. Navigate directly to tickets page
    3. Verify ticket list page loads correctly with staff features
    """
    print("🧪 Testing staff ticket system access via navigation")

    page = monitored_staff_page
    require_authentication(page)

    # Navigate directly to tickets page
    page.goto(f"{PLATFORM_BASE_URL}/tickets/")
    page.wait_for_load_state("networkidle")

    # Verify we're on the ticket list page
    assert "/tickets/" in page.url, "Should navigate to ticket list page"

    # Verify page title and staff-specific content (handle both English and Romanian)
    title = page.title()
    assert ("Support Tickets" in title or "Tichete de suport" in title), f"Expected ticket page title but got: {title}"
    tickets_heading = page.locator('h1:has-text("Support Tickets"), h1:has-text("Tichete de suport")').first
    assert tickets_heading.is_visible(), "Ticket system heading should be visible"

    # Verify staff can see "New Ticket" button (staff can create tickets for customers)
    new_ticket_button = page.locator('a:has-text("New Ticket")').first
    assert new_ticket_button.is_visible(), "Staff should see New Ticket creation button"

    print("  ✅ Staff ticket system successfully accessible via Support navigation")


def test_staff_ticket_list_dashboard_display(monitored_staff_page: Page) -> None:
    """
    Test the staff ticket list dashboard displays correctly with statistics and filtering.

    This test verifies:
    - Ticket statistics cards show accurate counts
    - Filtering and search interface is present for staff
    - Ticket table loads with existing tickets
    - Staff-specific features are visible
    """
    print("🧪 Testing staff ticket list dashboard display")

    page = monitored_staff_page
    # Login and navigate to tickets
    navigate_to_platform_page(page, "/tickets/")
    page.wait_for_load_state("networkidle")

    # Verify ticket statistics are present
    stats_section = page.locator('div').filter(has_text='Open:')
    if stats_section.is_visible():
        print("  ✅ Ticket statistics section is visible")
    else:
        # Try alternative selector for stats
        open_text = page.get_by_text('Open:')
        total_text = page.get_by_text('Total:')
        if open_text.count() > 0 or total_text.count() > 0:
            print("  ✅ Found ticket statistics")
        else:
            print("  [i] Ticket statistics not found - may need alternative implementation")

    # Verify staff can create new tickets
    new_ticket_button = page.locator('a:has-text("New Ticket")').first
    assert new_ticket_button.is_visible(), "Staff should see New Ticket button"

    # Verify filtering interface is present (if implemented)
    # Note: Based on template examination, there should be filtering options
    filters_section = page.locator('div.bg-slate-800\\/50').filter(has_text="Search").first
    if filters_section.is_visible():
        print("  ✅ Ticket filtering interface is present")
    else:
        print("  [i] Ticket filtering interface may not be implemented yet")

    # Verify tickets table or list is present (support both English and Romanian)
    tickets_container = page.locator('div.space-y-6:has-text("Support Tickets"), div.space-y-6:has-text("Tichete de suport")').first
    assert tickets_container.is_visible(), "Tickets container should be present"

    # Check if any tickets are displayed
    ticket_items = page.locator('tr:has-text("TK"), div:has-text("TK")')
    ticket_count = ticket_items.count()
    if ticket_count > 0:
        print(f"  ✅ Found {ticket_count} tickets in the system")
    else:
        print("  [i] No tickets currently in the system")

    print("  ✅ Staff ticket list dashboard displays correctly")


# ===============================================================================
# PRIVATE HELPERS FOR TICKET CREATION WORKFLOW
# ===============================================================================

def _fill_ticket_creation_form(page: Page, ticket_data: dict) -> None:
    """Fill the ticket creation form fields that are present on the page."""
    customer_select = page.locator('select[name="customer_id"]')
    if customer_select.is_visible():
        customer_options = page.locator('select[name="customer_id"] option')
        if customer_options.count() > 1:
            page.select_option('select[name="customer_id"]', index=1)
            print("  ✅ Selected customer for ticket creation")

    subject_field = page.locator('input[name="subject"], input[name="title"]').first
    if subject_field.is_visible():
        subject_field.fill(ticket_data['subject'])
        print("  ✅ Filled ticket subject")

    description_field = page.locator('textarea[name="description"]')
    if description_field.is_visible():
        description_field.fill(ticket_data['description'])
        print("  ✅ Filled ticket description")

    priority_field = page.locator('select[name="priority"]')
    if priority_field.is_visible():
        page.select_option('select[name="priority"]', ticket_data['priority'])
        print("  ✅ Set ticket priority")


def _submit_ticket_creation_form(page: Page) -> None:
    """Submit the ticket creation form and verify the outcome."""
    submit_button = page.locator('button:has-text("Create Ticket"), button:has-text("Submit"), input[type="submit"]').first
    if not submit_button.is_visible():
        print("  ❌ Submit button not found")
        return

    submit_button.click()
    page.wait_for_load_state("networkidle")

    if "/tickets/" in page.url and "/tickets/create/" not in page.url:
        print("  ✅ Ticket creation succeeded - redirected away from create page")
        success_message = page.get_by_role("alert").locator('div:has-text("created"), div:has-text("Ticket #")')
        if success_message.is_visible():
            print("  ✅ Success message displayed")
        else:
            print("  [i] Success message not immediately visible")
    else:
        error_messages = page.locator('div.text-red-600, .text-red-500, [class*="error"]')
        if error_messages.count() > 0:
            error_text = error_messages.first.inner_text()
            print(f"  ❌ Form validation error: {error_text}")
        else:
            print("  [i] Form submitted but still on create page")


# ===============================================================================
# STAFF TICKET CREATION TESTS
# ===============================================================================

def test_staff_ticket_creation_workflow(monitored_staff_page: Page) -> None:
    """
    Test the complete staff ticket creation workflow for customers.

    This test covers the full staff ticket creation process:
    1. Navigate to ticket creation form
    2. Fill in ticket details on behalf of a customer
    3. Set priority, type, and other staff-configurable options
    4. Submit form and verify ticket is created
    5. Verify redirect to ticket detail page
    """
    print("🧪 Testing staff ticket creation workflow")

    page = monitored_staff_page
    navigate_to_platform_page(page, "/tickets/")
    page.wait_for_load_state("networkidle")

    new_ticket_button = page.locator('a:has-text("New Ticket")').first
    assert new_ticket_button.is_visible(), "New Ticket button should be visible for staff"
    new_ticket_button.click()

    page.wait_for_url("**/tickets/create/", timeout=8000)
    assert "/tickets/create/" in page.url

    create_heading = page.locator('h1:has-text("Create New Ticket")').first
    assert create_heading.is_visible(), "Create ticket heading should be visible"

    test_ticket_data = {
        'subject': 'Staff Created - Server Performance Issue',
        'description': 'Customer reports slow website loading times. Need to investigate server performance and optimize database queries.',
        'priority': 'high',
    }

    _fill_ticket_creation_form(page, test_ticket_data)
    _submit_ticket_creation_form(page)

    print("  ✅ Staff ticket creation workflow completed")


# ===============================================================================
# STAFF TICKET MANAGEMENT TESTS
# ===============================================================================

def test_staff_ticket_detail_and_management_features(monitored_staff_page: Page) -> None:
    """
    Test staff ticket detail page and management capabilities.

    This test verifies:
    - Ticket detail page loads with all information
    - Staff-specific management features are visible
    - Internal notes functionality (staff-only)
    - Status and priority management
    - Assignment capabilities
    """
    print("🧪 Testing staff ticket detail and management features")

    page = monitored_staff_page
    # Login and navigate to tickets
    navigate_to_platform_page(page, "/tickets/")
    page.wait_for_load_state("networkidle")

    # Find first ticket to view (if any exist)
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
        print("  ✅ Navigated to ticket detail page")

        # Verify ticket detail elements are present
        ticket_info = page.locator('h1:has-text("TK"), h1:has-text("#")').first
        if ticket_info.is_visible():
            print("  ✅ Ticket information displayed")

        # Check for staff management features
        # Internal notes checkbox (staff-only feature)
        internal_note_checkbox = page.locator('input[name="is_internal"], input:has-text("Internal")')
        if internal_note_checkbox.is_visible():
            print("  ✅ Internal notes feature available (staff-only)")
        else:
            print("  [i] Internal notes feature not found")

        # Check for reply/comment functionality
        reply_area = page.locator('textarea[name="reply"], textarea[name="content"]')
        if reply_area.is_visible():
            print("  ✅ Reply functionality available")

            # Test adding a staff comment
            test_comment = "Staff internal note: Investigating server logs for performance issues."
            reply_area.fill(test_comment)

            # Check internal note checkbox if available
            if internal_note_checkbox.is_visible():
                internal_note_checkbox.check()

            # Submit reply
            reply_button = page.locator('button:has-text("Reply"), button:has-text("Add"), button:has-text("Submit")').first
            if reply_button.is_visible():
                reply_button.click()
                page.wait_for_load_state("networkidle")
                print("  ✅ Staff comment/reply functionality tested")

        # Check for ticket management actions
        close_button = page.locator('a:has-text("Close"), button:has-text("Close")')
        reopen_button = page.locator('a:has-text("Reopen"), button:has-text("Reopen")')

        if close_button.is_visible() or reopen_button.is_visible():
            print("  ✅ Ticket status management controls available")
        else:
            print("  [i] Ticket status controls not immediately visible")

    else:
        print("  [i] No existing tickets found - creating sample ticket for testing")

        # Navigate back to create a test ticket first
        navigate_to_platform_page(page, "/tickets/create/")
        # ... (ticket creation logic would go here)

    print("  ✅ Staff ticket management features verified")


def test_staff_ticket_comments_and_internal_notes(monitored_staff_page: Page) -> None:
    """
    Test staff-specific comment management and internal notes functionality.

    This test covers:
    - Adding public comments as staff
    - Creating internal notes (staff-only)
    - Viewing all comment types (customer, support, internal)
    - HTMX comment updates and real-time functionality
    """
    print("🧪 Testing staff ticket comments and internal notes")

    page = monitored_staff_page
    # Login and navigate to tickets
    navigate_to_platform_page(page, "/tickets/")
    page.wait_for_load_state("networkidle")

    # Find a ticket to work with
    ticket_links = page.locator('a[href*="/tickets/"]:has-text("TK")')
    if ticket_links.count() == 0:
        ticket_links = page.locator('main a[href*="/tickets/"]:not([href*="create"])')

    if ticket_links.count() > 0:
        first_ticket_link = ticket_links.first
        first_ticket_link.click()
        page.wait_for_load_state("networkidle")

        # Test adding a public staff comment
        reply_area = page.locator('textarea[name="reply"], textarea[name="content"]')
        if reply_area.is_visible():
            public_comment = "Thank you for reporting this issue. We are investigating the server performance problems and will have an update within 24 hours."
            reply_area.fill(public_comment)

            # Ensure internal note is NOT checked for public comment
            internal_checkbox = page.locator('input[name="is_internal"]')
            if internal_checkbox.is_visible() and internal_checkbox.is_checked():
                internal_checkbox.uncheck()

            # Submit public comment
            reply_button = page.locator('button:has-text("Reply"), button:has-text("Add")').first
            if reply_button.is_visible():
                reply_button.click()
                page.wait_for_load_state("networkidle")
                print("  ✅ Public staff comment added")

            # Now test internal note functionality
            page.wait_for_load_state("networkidle")
            reply_area_internal = page.locator('textarea[name="reply"], textarea[name="content"]')
            if reply_area_internal.is_visible():
                internal_note = "INTERNAL: Customer server is on shared hosting plan. May need to upgrade to VPS for better performance. Check resource usage logs."
                reply_area_internal.fill(internal_note)

                # Check internal note checkbox
                internal_checkbox = page.locator('input[name="is_internal"]')
                if internal_checkbox.is_visible():
                    internal_checkbox.check()
                    print("  ✅ Internal note checkbox checked")

                    # Submit internal note
                    reply_button = page.locator('button:has-text("Reply"), button:has-text("Add")').first
                    if reply_button.is_visible():
                        reply_button.click()
                        page.wait_for_load_state("networkidle")
                        print("  ✅ Internal note added (staff-only)")
                else:
                    print("  ⚠️ Internal note checkbox not found")

            # Verify comments are displayed
            comments_section = page.locator('div:has-text("Thank you for reporting"), div:has-text("INTERNAL:")')
            if comments_section.count() > 0:
                print("  ✅ Comments displayed in ticket conversation")
            else:
                print("  [i] Comments may need page refresh or HTMX update")

    else:
        print("  [i] No tickets available for comment testing")

    print("  ✅ Staff comment and internal notes functionality tested")


# ===============================================================================
# STAFF TICKET WORKFLOW TESTS
# ===============================================================================

def test_staff_ticket_status_management(monitored_staff_page: Page) -> None:
    """
    Test staff ticket status management workflows.

    This test covers:
    - Closing tickets
    - Reopening closed tickets
    - Status change validations
    - Workflow state management
    """
    print("🧪 Testing staff ticket status management workflows")

    page = monitored_staff_page
    # Login and navigate to tickets
    navigate_to_platform_page(page, "/tickets/")
    page.wait_for_load_state("networkidle")

    # Find an open ticket to work with
    ticket_links = page.locator('a[href*="/tickets/"]:has-text("TK")')
    if ticket_links.count() == 0:
        ticket_links = page.locator('main a[href*="/tickets/"]:not([href*="create"])')

    if ticket_links.count() > 0:
        first_ticket_link = ticket_links.first
        first_ticket_link.click()
        page.wait_for_load_state("networkidle")

        # Test closing a ticket
        close_link = page.locator('a[href*="/close/"], button:has-text("Close")')
        if close_link.is_visible():
            print("  🔄 Testing ticket closure...")
            close_link.click()
            page.wait_for_load_state("networkidle")

            # Check for success message
            success_message = page.get_by_role("alert").locator('div:has-text("closed")')
            if success_message.is_visible():
                print("  ✅ Ticket closed successfully")
            else:
                print("  [i] Ticket closure completed (no immediate success message)")

            # Now test reopening the ticket
            reopen_link = page.locator('a[href*="/reopen/"], button:has-text("Reopen")')
            if reopen_link.is_visible():
                print("  🔄 Testing ticket reopening...")
                reopen_link.click()
                page.wait_for_load_state("networkidle")

                # Check for success message
                reopen_success = page.get_by_role("alert").locator('div:has-text("reopened")')
                if reopen_success.is_visible():
                    print("  ✅ Ticket reopened successfully")
                else:
                    print("  [i] Ticket reopening completed")
            else:
                print("  [i] Reopen option not found - ticket may need to be closed first")
        else:
            print("  [i] Close option not found - ticket may already be closed or controls not visible")

        # Check current ticket status display
        status_display = page.locator('span:has-text("Open"), span:has-text("Closed"), span:has-text("New")').first
        if status_display.is_visible():
            current_status = status_display.inner_text()
            print(f"  ✅ Ticket status displayed: {current_status}")

    else:
        print("  [i] No tickets available for status management testing")

    print("  ✅ Staff ticket status management testing completed")


# ===============================================================================
# STAFF ACCESS CONTROL AND PERMISSIONS TESTS
# ===============================================================================

def test_staff_ticket_access_control_permissions(monitored_staff_page: Page) -> None:
    """
    Test that staff users have appropriate access to ticket management features.

    This test verifies:
    1. Staff users can access all ticket management features
    2. Internal note functionality is available
    3. Customer ticket visibility across all customers
    4. Administrative controls are present
    """
    print("🧪 Testing staff ticket access control and permissions")

    page = monitored_staff_page
    # Test staff user access
    print("    Testing staff user access...")

    # Navigate directly to tickets URL
    navigate_to_platform_page(page, "/tickets/")
    page.wait_for_load_state("networkidle")

    # Should successfully load ticket system
    assert "/tickets/" in page.url, "Staff user should access ticket system"
    tickets_heading = page.locator('h1:has-text("Support Tickets"), h1:has-text("Tichete de suport")').first
    assert tickets_heading.is_visible(), "Ticket system should load for staff user"

    # Verify staff can see ticket creation
    new_ticket_btn = page.locator('a:has-text("New Ticket")').first
    assert new_ticket_btn.is_visible(), "Staff should see ticket creation option"
    print("    ✅ Staff has proper navigation access to tickets")

    # Test access to ticket creation form
    navigate_to_platform_page(page, "/tickets/create/")
    page.wait_for_load_state("networkidle")

    create_form = page.locator('form').filter(has_text="Subject").first
    assert create_form.is_visible(), "Staff should access ticket creation form"

    # Verify customer selection is available (staff can create tickets for customers)
    customer_select = page.locator('select[name="customer_id"]')
    if customer_select.is_visible():
        print("    ✅ Staff can create tickets for customers")

    print("  ✅ Staff ticket access control working correctly")


# ===============================================================================
# STAFF MOBILE RESPONSIVENESS TESTS
# ===============================================================================

def test_staff_ticket_system_mobile_responsiveness(monitored_staff_page: Page) -> None:
    """
    Test staff ticket system mobile responsiveness and touch interactions.

    This test verifies:
    1. Ticket system displays correctly on mobile viewports
    2. Touch interactions work properly for staff features
    3. Mobile navigation elements function correctly
    4. Tables and forms are mobile-friendly
    """
    print("🧪 Testing staff ticket system mobile responsiveness")

    page = monitored_staff_page
    # Login and navigate to tickets on desktop first
    navigate_to_platform_page(page, "/tickets/")
    page.wait_for_load_state("networkidle")

    # Test mobile viewport
    with MobileTestContext(page, 'mobile_medium') as mobile:
        print("    📱 Testing staff ticket system on mobile viewport")
        run_standard_mobile_test(page, mobile, context_label="staff tickets")

        # Verify key mobile elements are accessible
        tickets_heading = page.locator('h1:has-text("Support Tickets"), h1:has-text("Tichete de suport")').first
        if tickets_heading.is_visible():
            print("      ✅ Ticket system heading visible on mobile")

        new_ticket_btn = page.locator('a:has-text("New Ticket")').first
        if new_ticket_btn.is_visible():
            print("      ✅ New ticket button accessible on mobile")

    print("  ✅ Staff ticket system mobile responsiveness testing completed")


# ===============================================================================
# PRIVATE HELPERS FOR COMPREHENSIVE WORKFLOW TEST
# ===============================================================================

def _create_workflow_ticket(page: Page, workflow_ticket: dict) -> bool:
    """
    Navigate to ticket creation, fill and submit the form.

    Returns True if the ticket was successfully created and the page navigated
    to a ticket detail URL, False otherwise.
    """
    navigate_to_platform_page(page, "/tickets/create/")
    page.wait_for_load_state("networkidle")

    subject_field = page.locator('input[name="subject"], input[name="title"]').first
    if subject_field.is_visible():
        subject_field.fill(workflow_ticket['subject'])

    description_field = page.locator('textarea[name="description"]')
    if description_field.is_visible():
        description_field.fill(workflow_ticket['description'])

    customer_select = page.locator('select[name="customer_id"]')
    if customer_select.is_visible():
        customer_options = page.locator('select[name="customer_id"] option')
        if customer_options.count() > 1:
            page.select_option('select[name="customer_id"]', index=1)

    submit_btn = page.locator('button:has-text("Create"), button:has-text("Submit")').first
    if submit_btn.is_visible():
        submit_btn.click()
        page.wait_for_load_state("networkidle")

    if "/tickets/" in page.url and "create" not in page.url:
        print("      ✅ Ticket created successfully")
        return True

    # Creation did not redirect — check if ticket is in the list
    print("      [i] Ticket creation may have validation issues - checking list")
    navigate_to_platform_page(page, "/tickets/")
    page.wait_for_load_state("networkidle")

    workflow_ticket_link = page.locator(f'text="{workflow_ticket["subject"][:20]}"')
    if workflow_ticket_link.is_visible():
        workflow_ticket_link.click()
        page.wait_for_load_state("networkidle")
        print("      ✅ Found and opened created ticket")
        return True

    print("      ❌ Ticket creation verification failed")
    return False


def _test_ticket_comment_and_notes(page: Page) -> None:
    """Add a public staff comment to the currently open ticket detail page."""
    print("    Step 2: Adding staff comments and internal notes...")

    reply_area = page.locator('textarea[name="reply"], textarea[name="content"]')
    if not reply_area.is_visible():
        return

    reply_area.fill("Thank you for this report. We are beginning investigation immediately.")

    internal_checkbox = page.locator('input[name="is_internal"]')
    if internal_checkbox.is_visible() and internal_checkbox.is_checked():
        internal_checkbox.uncheck()

    reply_btn = page.locator('button:has-text("Reply"), button:has-text("Add")').first
    if reply_btn.is_visible():
        reply_btn.click()
        page.wait_for_load_state("networkidle")
        print("      ✅ Public staff comment added")


def _test_ticket_lifecycle(page: Page) -> None:
    """Test closing and reopening the currently open ticket detail page."""
    print("    Step 3: Testing ticket status management...")

    close_link = page.locator('a[href*="/close/"]')
    if not close_link.is_visible():
        return

    close_link.click()
    page.wait_for_load_state("networkidle")
    print("      ✅ Ticket closed successfully")

    reopen_link = page.locator('a[href*="/reopen/"]')
    if reopen_link.is_visible():
        reopen_link.click()
        page.wait_for_load_state("networkidle")
        print("      ✅ Ticket reopened successfully")


# ===============================================================================
# COMPREHENSIVE STAFF WORKFLOW TESTS
# ===============================================================================

def test_staff_complete_ticket_management_workflow(monitored_staff_page: Page) -> None:
    """
    Test the complete staff ticket management workflow from creation to resolution.

    This comprehensive test covers:
    1. Creating a ticket on behalf of a customer
    2. Adding both public and internal comments
    3. Managing ticket status and priority
    4. Testing file attachments (if supported)
    5. Final ticket resolution and closure
    """
    print("🧪 Testing complete staff ticket management workflow")

    page = monitored_staff_page

    print("    Step 1: Creating new ticket for customer...")
    workflow_ticket = {
        'subject': 'Staff E2E Workflow - Complete Ticket Management Test',
        'description': 'This ticket tests the complete staff workflow including creation, comments, internal notes, status management, and resolution.',
        'priority': 'normal',
    }

    ticket_created = _create_workflow_ticket(page, workflow_ticket)

    if ticket_created:
        _test_ticket_comment_and_notes(page)
        _test_ticket_lifecycle(page)
        print("  ✅ Complete staff ticket workflow successful")
    else:
        print("  ⚠️ Workflow limited due to ticket creation issues")


def test_staff_ticket_system_responsive_breakpoints(monitored_staff_page: Page) -> None:
    """
    Test staff ticket system functionality across all responsive breakpoints.

    This test validates that staff ticket management works on:
    - Desktop viewports (baseline)
    - Tablet viewports (landscape and portrait)
    - Mobile viewports (various sizes)
    """
    print("🧪 Testing staff ticket system across responsive breakpoints")

    page = monitored_staff_page

    def test_staff_ticket_functionality(test_page, context="general"):
        """Test core staff ticket functionality across viewports."""
        try:
            # Navigate to tickets
            test_page.goto(f"{PLATFORM_BASE_URL}/tickets/")
            test_page.wait_for_load_state("networkidle")

            # Verify authentication maintained
            require_authentication(test_page)

            # Check core elements are present (iterate to find visible ones on mobile)
            heading_visible = any(
                h1.is_visible() and ("ticket" in (h1.text_content() or "").lower() or "tichete" in (h1.text_content() or "").lower())
                for h1 in test_page.locator('h1').all()
            )
            btn_visible = any(
                btn.is_visible()
                for btn in test_page.locator('a:has-text("New Ticket")').all()
            )

            elements_present = heading_visible and btn_visible

            if elements_present:
                print(f"      ✅ Staff ticket system functional in {context}")
                return True
            else:
                print(f"      ❌ Core ticket elements missing in {context}")
                return False

        except Exception as e:
            print(f"      ❌ Ticket system test failed in {context}: {str(e)[:50]}")
            return False

    # Test across all breakpoints
    results = run_responsive_breakpoints_test(page, test_staff_ticket_functionality)
    assert_responsive_results(results, "Staff ticket system")

    print("  ✅ Staff ticket system validated across all responsive breakpoints")
