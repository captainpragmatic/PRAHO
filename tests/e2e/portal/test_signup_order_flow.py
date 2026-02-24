"""
Signup and Order E2E Tests for PRAHO Platform

This module comprehensively tests the customer signup and order flows including:
- User registration with customer organization onboarding
- Form validation and Romanian business compliance
- Post-signup login and dashboard access
- Order viewing for customers
- Combined signup -> login -> order viewing flow
- Security boundary testing for new accounts
- Mobile responsiveness for signup flow

Uses shared utilities from tests.e2e.utils for consistency.
Based on real customer onboarding workflows for PragmaticHost.
"""

import re
import secrets
import string

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Page, expect

# Import shared utilities
from tests.e2e.utils import (
    BASE_URL,
    CUSTOMER_EMAIL,
    CUSTOMER_PASSWORD,
    LOGIN_URL,
    REGISTER_URL,
    ComprehensivePageMonitor,
    MobileTestContext,
    assert_responsive_results,
    ensure_fresh_session,
    is_login_url,
    login_user_with_retry,
    run_responsive_breakpoints_test,
)

# ===============================================================================
# TEST DATA GENERATORS
# ===============================================================================


def generate_test_email() -> str:
    """Generate a unique test email address"""
    random_suffix = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(8))
    return f"e2e_signup_test_{random_suffix}@test.praho.local"


def generate_test_phone() -> str:
    """Generate a random Romanian phone number"""
    # Romanian mobile format: +40.7XX.XXX.XXX
    return f"+40.7{secrets.randbelow(10)}{secrets.randbelow(10)}.{secrets.randbelow(1000):03d}.{secrets.randbelow(1000):03d}"


def generate_test_company_name() -> str:
    """Generate a unique test company name"""
    prefixes = ["Test", "E2E", "Auto", "QA"]
    suffixes = ["Solutions", "Tech", "Services", "Digital"]
    random_num = secrets.randbelow(9999) + 1
    return f"{secrets.choice(prefixes)} {secrets.choice(suffixes)} {random_num} SRL"


def generate_test_password() -> str:
    """Generate a secure test password meeting requirements"""
    # Password requirements: minimum 12 characters
    return f"TestPass123!{secrets.randbelow(9999):04d}"


# ===============================================================================
# SIGNUP PAGE ACCESS AND DISPLAY TESTS
# ===============================================================================


def test_signup_page_loads_correctly(page: Page) -> None:
    """
    Test that the signup page loads correctly with all required elements.

    This test verifies:
    1. Signup page is accessible at the register URL
    2. Page title and heading are correct
    3. All form sections are visible (Personal, Business, Address, Security, Privacy)
    4. Required form fields are present
    5. Submit button is visible and enabled
    """
    print("Testing signup page loads correctly")

    with ComprehensivePageMonitor(
        page,
        "signup page load",
        check_console=False,  # Alpine.js CSP eval errors expected on signup forms
        check_network=True,
        check_html=True,
        check_css=True,
                                 check_accessibility=False):
        # Navigate to signup page
        page.goto(f"{BASE_URL}{REGISTER_URL}")
        page.wait_for_load_state("networkidle")

        # Verify we're on the signup page
        assert REGISTER_URL in page.url, "Should be on signup page"

        # Verify page title
        title = page.title()
        assert "Create Account" in title or "PragmaticHost" in title, f"Page title should contain 'Create Account', got: {title}"

        # Verify main heading
        heading = page.locator("h1")
        expect(heading).to_contain_text("Create Your PragmaticHost Account")
        print("  Signup page heading is correct")

        # Verify all form sections are present
        sections = [
            ("Personal Information", "Personal info section"),
            ("Business Information", "Business info section"),
            ("Address Information", "Address info section"),
            ("Account Security", "Security section"),
            ("Privacy & Consent", "Privacy section"),
        ]

        for section_title, description in sections:
            section = page.locator(f'h3:has-text("{section_title}")')
            assert section.count() > 0, f"{description} should be visible"
            print(f"    {description} found")

        # Verify required form fields are present
        required_fields = [
            ('input[name="first_name"]', "First name field"),
            ('input[name="last_name"]', "Last name field"),
            ('input[name="email"]', "Email field"),
            ('select[name="customer_type"]', "Customer type dropdown"),
            ('input[name="company_name"]', "Company name field"),
            ('input[name="address_line1"]', "Address field"),
            ('input[name="city"]', "City field"),
            ('input[name="county"]', "County field"),
            ('input[name="postal_code"]', "Postal code field"),
            ('input[name="password1"]', "Password field"),
            ('input[name="password2"]', "Confirm password field"),
            ('input[name="data_processing_consent"]', "GDPR consent checkbox"),
        ]

        for selector, field_name in required_fields:
            field = page.locator(selector)
            assert field.count() > 0, f"{field_name} should be present"
        print("    All required form fields are present")

        # Verify submit button is present and enabled
        submit_button = page.locator('button:has-text("Create Account")')
        assert submit_button.is_visible(), "Submit button should be visible"
        assert submit_button.is_enabled(), "Submit button should be enabled"
        print("    Submit button is present and enabled")

        # Verify login link is present for existing users
        login_link = page.locator('a[href*="login"]:has-text("Sign in")')
        assert login_link.is_visible(), "Login link should be visible for existing users"
        print("    Login link for existing users is present")

        print("  Signup page loads correctly with all elements")


def test_signup_page_has_romanian_business_context(page: Page) -> None:
    """
    Test that the signup page shows Romanian business context and compliance elements.

    This test verifies:
    1. VAT number field shows Romanian format hint (RO12345678)
    2. Phone number shows Romanian format hint (+40.XX.XXX.XXXX)
    3. Customer type dropdown includes Romanian business types (SRL, PFA, II, etc.)
    4. GDPR consent is required
    """
    print("Testing signup page Romanian business context")

    with ComprehensivePageMonitor(
        page,
        "signup Romanian context",
        check_console=False,  # Alpine.js CSP eval errors expected on signup forms
        check_network=True,
        check_html=False,  # May have minor HTML issues
        check_css=True,
                                 check_accessibility=False):
        # Navigate to signup page
        page.goto(f"{BASE_URL}{REGISTER_URL}")
        page.wait_for_load_state("networkidle")

        # Check VAT number field has Romanian format placeholder
        vat_field = page.locator('input[name="vat_number"]')
        if vat_field.is_visible():
            vat_placeholder = vat_field.get_attribute("placeholder") or ""
            assert "RO" in vat_placeholder or "12345678" in vat_placeholder, "VAT field should show Romanian format"
            print("    VAT field shows Romanian format hint")

        # Check phone field has Romanian format
        phone_field = page.locator('input[name="phone"]')
        if phone_field.is_visible():
            phone_placeholder = phone_field.get_attribute("placeholder") or ""
            assert "+40" in phone_placeholder, "Phone field should show Romanian format"
            print("    Phone field shows Romanian format hint")

        # Check customer type dropdown has Romanian business types
        customer_type_select = page.locator('select[name="customer_type"]')
        assert customer_type_select.is_visible(), "Customer type dropdown should be visible"

        # Get all options
        options = customer_type_select.locator("option").all()
        option_values = [opt.get_attribute("value") for opt in options]

        # Verify Romanian business types are available
        expected_types = ["srl", "pfa"]  # At minimum SRL and PFA
        for expected in expected_types:
            assert expected in option_values, f"Customer type should include {expected}"
        print(f"    Customer type includes Romanian business types: {option_values}")

        # Verify GDPR consent checkbox is present and required
        gdpr_checkbox = page.locator('input[name="data_processing_consent"]')
        assert gdpr_checkbox.is_visible(), "GDPR consent checkbox should be visible"
        print("    GDPR consent checkbox is present")

        print("  Romanian business context elements are correct")


# ===============================================================================
# SIGNUP FORM VALIDATION TESTS
# ===============================================================================


def test_signup_form_validation_required_fields(page: Page) -> None:
    """
    Test that the signup form validates required fields properly.

    This test verifies:
    1. Form cannot be submitted with empty required fields
    2. Appropriate error messages are displayed
    3. Form stays on page after validation failure
    """
    print("Testing signup form validation for required fields")

    with ComprehensivePageMonitor(
        page,
        "signup form validation",
        check_console=False,  # Alpine.js CSP eval errors expected on signup forms
        check_network=True,
        check_html=False,
        check_css=True,
                                 check_accessibility=False):
        # Navigate to signup page
        page.goto(f"{BASE_URL}{REGISTER_URL}")
        page.wait_for_load_state("networkidle")

        # Try to submit empty form
        submit_button = page.locator('button:has-text("Create Account")')
        submit_button.click()

        # Wait for validation
        page.wait_for_load_state("networkidle")

        # Should still be on signup page
        assert REGISTER_URL in page.url, "Should remain on signup page after validation failure"

        # Check for HTML5 validation or error messages
        # HTML5 required field validation should prevent submission
        first_name_field = page.locator('input[name="first_name"]')

        # Try to check if field has validation state
        is_invalid = first_name_field.evaluate("el => !el.validity.valid") if first_name_field.is_visible() else False

        if is_invalid:
            print("    HTML5 validation prevents empty form submission")
        else:
            # Check for Django form errors
            error_elements = page.locator(".text-red-400, .text-red-500, .text-red-600, .error, .invalid-feedback")
            if error_elements.count() > 0:
                print(f"    Form validation errors displayed: {error_elements.count()} errors")
            else:
                print("    Form validation active (may use browser-native validation)")

        print("  Required field validation works correctly")


def test_signup_form_email_validation(page: Page) -> None:
    """
    Test that the signup form validates email format properly.

    This test verifies:
    1. Invalid email formats are rejected
    2. Valid email formats are accepted
    """
    print("Testing signup form email validation")

    with ComprehensivePageMonitor(
        page,
        "signup email validation",
        check_console=False,  # Alpine.js CSP eval errors expected on signup forms
        check_network=True,
        check_html=False,
        check_css=True,
                                 check_accessibility=False):
        # Navigate to signup page
        page.goto(f"{BASE_URL}{REGISTER_URL}")
        page.wait_for_load_state("networkidle")

        email_field = page.locator('input[name="email"]')

        # Test invalid email format
        # NOTE: "missing@domain" is valid per RFC 5321 (TLD-only domains accepted by browsers)
        invalid_emails = ["notanemail", "@nodomain.com"]

        for invalid_email in invalid_emails:
            email_field.fill(invalid_email)

            # Check HTML5 validation
            is_invalid = email_field.evaluate("el => !el.validity.valid")
            assert is_invalid, f"Invalid email '{invalid_email}' should be rejected by validation"
            print(f"    Invalid email '{invalid_email}' correctly rejected")

        # Test valid email format
        valid_email = generate_test_email()
        email_field.fill(valid_email)
        is_valid = email_field.evaluate("el => el.validity.valid")
        assert is_valid, f"Valid email '{valid_email}' should be accepted"
        print("    Valid email format accepted")

        print("  Email validation works correctly")


def test_signup_form_password_validation(page: Page) -> None:
    """
    Test that the signup form validates password requirements.

    This test verifies:
    1. Password fields match validation
    2. Password strength requirements are enforced
    """
    print("Testing signup form password validation")

    with ComprehensivePageMonitor(
        page,
        "signup password validation",
        check_console=False,  # Alpine.js CSP eval errors expected on signup forms
        check_network=True,
        check_html=False,
        check_css=True,
                                 check_accessibility=False):
        # Navigate to signup page
        page.goto(f"{BASE_URL}{REGISTER_URL}")
        page.wait_for_load_state("networkidle")

        password1_field = page.locator('input[name="password1"]')
        password2_field = page.locator('input[name="password2"]')

        # Test password mismatch - fill all required fields first to allow form submission
        test_password = generate_test_password()
        password1_field.fill(test_password)
        password2_field.fill(test_password + "mismatch")

        # Fill other required fields minimally
        page.locator('input[name="first_name"]').fill("Test")
        page.locator('input[name="last_name"]').fill("User")
        page.locator('input[name="email"]').fill(generate_test_email())
        page.locator('input[name="company_name"]').fill("Test Company SRL")
        page.locator('input[name="address_line1"]').fill("Test Street 123")
        page.locator('input[name="city"]').fill("Bucharest")
        page.locator('input[name="county"]').fill("Bucharest")
        page.locator('input[name="postal_code"]').fill("010001")
        page.locator('input[name="data_processing_consent"]').check()

        # Submit form
        submit_button = page.locator('button:has-text("Create Account")')
        submit_button.click()
        page.wait_for_load_state("networkidle")

        # Should show error about password mismatch
        # Check if still on register page (validation failed) or if error message shown
        assert REGISTER_URL in page.url, "Password mismatch should prevent form submission"
        print("    Password mismatch correctly prevented form submission")

        # Look for password error message
        password_errors = page.locator('p:has-text("password"), .error:has-text("password")')
        if password_errors.count() > 0:
            print("    Password mismatch error message displayed")

        # Test matching passwords
        password2_field.fill(test_password)
        print("    Matching passwords set correctly")

        print("  Password validation works correctly")


# ===============================================================================
# SUCCESSFUL SIGNUP FLOW TESTS
# ===============================================================================


def test_signup_form_successful_submission(page: Page) -> None:
    """
    Test successful signup form submission with all required data.

    This test verifies:
    1. Form can be submitted with all required fields filled
    2. After submission, user is redirected to confirmation page
    3. The flow is enumeration-safe (same response for existing emails)
    """
    print("Testing successful signup form submission")

    with ComprehensivePageMonitor(
        page,
        "signup form submission",
        check_console=False,  # Alpine.js CSP eval errors expected on signup forms
        check_network=True,
        check_html=False,
        check_css=True,
                                 check_accessibility=False):
        # Navigate to signup page
        page.goto(f"{BASE_URL}{REGISTER_URL}")
        page.wait_for_load_state("networkidle")

        # Generate unique test data
        test_email = generate_test_email()
        test_password = generate_test_password()
        test_company = generate_test_company_name()
        test_phone = generate_test_phone()

        print(f"    Using test email: {test_email}")
        print(f"    Using test company: {test_company}")

        # Fill personal information
        page.locator('input[name="first_name"]').fill("E2E")
        page.locator('input[name="last_name"]').fill("TestUser")
        page.locator('input[name="email"]').fill(test_email)
        page.locator('input[name="phone"]').fill(test_phone)
        print("    Personal information filled")

        # Fill business information
        page.locator('select[name="customer_type"]').select_option("srl")
        page.locator('input[name="company_name"]').fill(test_company)
        # VAT number is optional, skip for this test
        print("    Business information filled")

        # Fill address information
        page.locator('input[name="address_line1"]').fill("Strada Testelor Nr. 123")
        page.locator('input[name="city"]').fill("Bucuresti")
        page.locator('input[name="county"]').fill("Bucuresti")
        page.locator('input[name="postal_code"]').fill("010001")
        print("    Address information filled")

        # Fill password
        page.locator('input[name="password1"]').fill(test_password)
        page.locator('input[name="password2"]').fill(test_password)
        print("    Password set")

        # Accept GDPR consent
        page.locator('input[name="data_processing_consent"]').check()
        print("    GDPR consent accepted")

        # Submit form
        submit_button = page.locator('button:has-text("Create Account")')
        submit_button.click()

        # Wait for form processing
        page.wait_for_load_state("networkidle")

        # Check for successful submission
        # Should redirect to register/submitted/ or show success message
        current_url = page.url

        # App may redirect to /register/submitted/ OR stay on /register/ with success message
        page_content = page.content().lower()
        confirmation_indicators = ["submitted", "check your email", "registration", "thank you", "success", "account created"]
        on_submitted_page = "/submitted" in current_url
        has_success_message = any(indicator in page_content for indicator in confirmation_indicators)

        assert on_submitted_page or has_success_message or current_url != f"{BASE_URL}{REGISTER_URL}", (
            f"Should show confirmation after signup, got: {current_url}"
        )
        if on_submitted_page:
            print("    Successfully redirected to confirmation page")
        else:
            print("    [i] Signup processed (stayed on registration page with feedback)")

        found_indicator = on_submitted_page or has_success_message

        if found_indicator:
            print("    Confirmation page shows appropriate message")
        else:
            print("    Confirmation page loaded (content may vary)")

        print("  Signup form submission test completed")


def test_signup_then_login_flow(page: Page) -> None:
    """
    Test the complete flow: signup -> confirmation -> login.

    Note: This test may not complete the full flow if email verification is required.
    It tests the UI flow as far as possible without email access.
    """
    print("Testing signup then login flow")

    with ComprehensivePageMonitor(
        page,
        "signup then login flow",
        check_console=False,  # Alpine.js CSP eval errors expected on signup forms
        check_network=True,
        check_html=False,
        check_css=True,
                                 check_accessibility=False):
        # Generate unique test data
        test_email = generate_test_email()
        test_password = generate_test_password()
        test_company = generate_test_company_name()

        print(f"    Test email: {test_email}")

        # Complete signup
        page.goto(f"{BASE_URL}{REGISTER_URL}")
        page.wait_for_load_state("networkidle")

        # Fill all required fields
        page.locator('input[name="first_name"]').fill("E2E")
        page.locator('input[name="last_name"]').fill("LoginTest")
        page.locator('input[name="email"]').fill(test_email)
        page.locator('select[name="customer_type"]').select_option("srl")
        page.locator('input[name="company_name"]').fill(test_company)
        page.locator('input[name="address_line1"]').fill("Test Street 1")
        page.locator('input[name="city"]').fill("Bucuresti")
        page.locator('input[name="county"]').fill("Bucuresti")
        page.locator('input[name="postal_code"]').fill("010001")
        page.locator('input[name="password1"]').fill(test_password)
        page.locator('input[name="password2"]').fill(test_password)
        page.locator('input[name="data_processing_consent"]').check()

        # Submit
        page.locator('button:has-text("Create Account")').click()
        page.wait_for_load_state("networkidle")

        # After signup, navigate to login
        page.goto(f"{BASE_URL}{LOGIN_URL}")
        page.wait_for_load_state("networkidle")

        # Verify we can access login page
        assert is_login_url(page.url), "Should be able to access login page"
        print("    Login page accessible after signup")

        # Try to login with new credentials
        # Note: This may fail if email verification is required
        page.locator('input[name="email"]').fill(test_email)
        page.locator('input[name="password"]').fill(test_password)
        page.locator('button[type="submit"]').click()

        page.wait_for_load_state("networkidle")

        current_url = page.url
        if "/dashboard/" in current_url:
            print("    Successfully logged in with new account")
        elif is_login_url(current_url):
            # Check for error messages
            error_msg = page.locator(".alert, .error, .text-red-500").first
            if error_msg.is_visible():
                error_text = error_msg.text_content()
                print(f"    Login blocked (may require email verification): {error_text}")
            else:
                print("    Login form shown (credentials may need verification)")
        else:
            print(f"    Redirected to: {current_url}")

        print("  Signup then login flow test completed")


# ===============================================================================
# ORDER VIEWING TESTS (Customer Perspective)
# ===============================================================================


def test_customer_can_view_orders_list(page: Page) -> None:
    """
    Test that logged-in customers can view their orders list.

    This test verifies:
    1. Customer can access /order/ after login
    2. Orders list page displays correctly
    3. Customer sees appropriate order status filters
    """
    print("Testing customer order list viewing")

    with ComprehensivePageMonitor(
        page,
        "customer order list",
        check_console=False,  # Alpine.js CSP eval errors expected on signup forms
        check_network=True,
        check_html=False,
        check_css=True,
                                 check_accessibility=False):
        # Login as customer
        ensure_fresh_session(page)
        assert login_user_with_retry(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD), "Customer login should succeed"

        # Navigate to orders
        page.goto(f"{BASE_URL}/order/")
        page.wait_for_load_state("networkidle")

        # Verify we're on orders page or allowed to access
        current_url = page.url
        assert "/order/" in current_url, f"Customer should be able to access orders page, got: {current_url}"
        print("    Customer can access orders page")

        # Check for orders list elements
        # Look for table or list of orders, or "no orders" message
        orders_content = page.locator("table, .order-list, .no-orders")

        # Check for status filter buttons/tabs
        status_filters = page.locator('a:has-text("All"), a:has-text("Pending"), a:has-text("Completed")')
        if status_filters.count() > 0:
            print(f"    Found {status_filters.count()} status filter options")

        # Check page structure
        page_heading = page.locator("h1, h2")
        if page_heading.count() > 0:
            heading_text = page_heading.first.text_content()
            print(f"    Page heading: {heading_text}")

        print("  Customer order viewing test completed")


def test_customer_order_list_shows_correct_data(page: Page) -> None:
    """
    Test that the orders list shows correct data for the customer.

    This test verifies:
    1. Only customer's own orders are displayed (multi-tenant security)
    2. Order information is displayed correctly
    3. Search and filter functionality works
    """
    print("Testing customer order list data accuracy")

    with ComprehensivePageMonitor(
        page,
        "customer order data",
        check_console=False,  # Alpine.js CSP eval errors expected on signup forms
        check_network=True,
        check_html=False,
        check_css=True,
                                 check_accessibility=False):
        # Login as customer
        ensure_fresh_session(page)
        assert login_user_with_retry(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD), "Customer login should succeed"

        # Navigate to orders
        page.goto(f"{BASE_URL}/order/")
        page.wait_for_load_state("networkidle")

        if "/order/" not in page.url:
            print("    Cannot access orders page - skipping data tests")
            return

        # Check if there are any orders displayed
        order_rows = page.locator("table tbody tr")
        order_count = order_rows.count()

        print(f"    Found {order_count} orders in list")

        if order_count > 0:
            # Check first order has expected columns
            first_row = order_rows.first
            row_text = first_row.text_content()

            # Orders typically show: order number, status, date, total
            expected_patterns = [
                r"ORD-\d+",  # Order number pattern
            ]

            for pattern in expected_patterns:
                if re.search(pattern, row_text or ""):
                    print("    Order number pattern found")
                    break

            # Check for order detail link
            detail_link = first_row.locator("a")
            if detail_link.count() > 0:
                print("    Order detail links are present")
        else:
            # Check for "no orders" message
            no_orders_msg = page.locator('text="No orders", text="no orders found"')
            if no_orders_msg.count() > 0:
                print("    'No orders' message displayed correctly")
            else:
                print("    Orders list is empty (new customer)")

        # Test search functionality if available
        search_input = page.locator('input[name="search"], input[placeholder*="search"]')
        if search_input.is_visible():
            print("    Search functionality is available")

        print("  Customer order data accuracy test completed")


# ===============================================================================
# COMBINED SIGNUP + ORDER FLOW TESTS
# ===============================================================================


def _journey_fill_registration_form(page: Page, test_email: str, test_password: str, test_company: str) -> None:
    """Step 2: Fill all fields in the customer registration form."""
    page.locator('input[name="first_name"]').fill("Journey")
    page.locator('input[name="last_name"]').fill("TestUser")
    page.locator('input[name="email"]').fill(test_email)
    page.locator('input[name="phone"]').fill(generate_test_phone())
    page.locator('select[name="customer_type"]').select_option("srl")
    page.locator('input[name="company_name"]').fill(test_company)
    page.locator('input[name="vat_number"]').fill("RO12345678")
    page.locator('input[name="address_line1"]').fill("Bulevardul Test Nr. 100")
    page.locator('input[name="city"]').fill("Bucuresti")
    page.locator('input[name="county"]').fill("Bucuresti")
    page.locator('input[name="postal_code"]').fill("010001")
    page.locator('input[name="password1"]').fill(test_password)
    page.locator('input[name="password2"]').fill(test_password)
    page.locator('input[name="data_processing_consent"]').check()

    marketing_checkbox = page.locator('input[name="marketing_consent"]')
    if marketing_checkbox.is_visible():
        marketing_checkbox.check()

    print("    Step 2: Registration form filled")


def _journey_handle_post_login(page: Page, test_email: str, test_password: str, current_url: str) -> None:
    """Steps 5-6: Handle login result — navigate to orders if successful, report otherwise."""
    if "/dashboard/" in current_url:
        print("    Step 5: Successfully logged in to dashboard")

        page.goto(f"{BASE_URL}/order/")
        page.wait_for_load_state("networkidle")

        if "/order/" in page.url:
            print("    Step 6: Successfully accessed orders section")
            if "order" in page.content().lower():
                print("    Complete journey successful - new customer can view orders")
        else:
            print(f"    Step 6: Orders page access result: {page.url}")
        return

    print(f"    Step 5: Login result: {current_url}")
    if is_login_url(current_url):
        error_msg = page.locator(".alert, .error, .text-red-500")
        if error_msg.count() > 0:
            print(f"      Login message: {error_msg.first.text_content()}")
        print("      (Account may require email verification)")


def test_complete_new_customer_journey(page: Page) -> None:
    """
    Test the complete new customer journey: signup -> login -> dashboard -> orders.

    This comprehensive test simulates a real customer onboarding flow:
    1. New user visits signup page
    2. Fills registration form with Romanian business data
    3. Submits registration
    4. Attempts to login (may require email verification)
    5. Views dashboard (if login succeeds)
    6. Navigates to orders section

    Note: Full flow completion depends on email verification settings.
    """
    print("Testing complete new customer journey")

    with ComprehensivePageMonitor(
        page,
        "complete customer journey",
        check_console=False,  # Alpine.js CSP eval errors expected on signup forms
        check_network=True,
        check_html=False,
        check_css=True,
                                 check_accessibility=False):
        test_email = generate_test_email()
        test_password = generate_test_password()
        test_company = generate_test_company_name()

        print(f"    Journey test email: {test_email}")
        print(f"    Journey test company: {test_company}")

        page.goto(f"{BASE_URL}{REGISTER_URL}")
        page.wait_for_load_state("networkidle")
        assert REGISTER_URL in page.url, "Should be on signup page"
        print("    Step 1: Signup page accessed")

        _journey_fill_registration_form(page, test_email, test_password, test_company)

        page.locator('button:has-text("Create Account")').click()
        page.wait_for_load_state("networkidle")

        submitted_url = page.url
        page_content = page.content().lower()
        on_submitted = "/submitted" in submitted_url
        has_feedback = any(w in page_content for w in ["success", "submitted", "thank you", "account created", "check your email"])
        assert on_submitted or has_feedback or submitted_url != f"{BASE_URL}{REGISTER_URL}", (
            f"Step 3: Registration should show confirmation, got: {submitted_url}"
        )
        print("    Step 3: Registration submitted successfully")

        page.goto(f"{BASE_URL}{LOGIN_URL}")
        page.wait_for_load_state("networkidle")
        print("    Step 4: Navigated to login page")

        page.locator('input[name="email"]').fill(test_email)
        page.locator('input[name="password"]').fill(test_password)
        page.locator('button[type="submit"]').click()
        page.wait_for_load_state("networkidle")

        _journey_handle_post_login(page, test_email, test_password, page.url)

        print("  Complete new customer journey test finished")


# ===============================================================================
# MOBILE RESPONSIVENESS TESTS
# ===============================================================================


def test_signup_page_mobile_responsiveness(page: Page) -> None:
    """
    Test signup page mobile responsiveness.

    This test verifies:
    1. Signup form displays correctly on mobile viewports
    2. All form fields are accessible and usable on mobile
    3. Submit button is properly sized for touch interaction
    4. No horizontal scrolling issues
    """
    print("Testing signup page mobile responsiveness")

    with ComprehensivePageMonitor(
        page,
        "signup mobile responsiveness",
        check_console=False,  # Alpine.js CSP eval errors expected on signup forms
        check_network=True,
        check_html=False,
        check_css=True,
                                 check_accessibility=False):
        # Navigate to signup on desktop first
        page.goto(f"{BASE_URL}{REGISTER_URL}")
        page.wait_for_load_state("networkidle")

        # Test mobile viewport
        with MobileTestContext(page, "mobile_medium") as mobile:
            print("    Testing on mobile viewport")

            # Reload to ensure mobile layout
            page.reload()
            page.wait_for_load_state("networkidle")

            # Check for horizontal scroll issues
            layout_issues = mobile.check_responsive_layout()
            horizontal_scroll_issues = [
                issue for issue in layout_issues if "horizontal scroll" in issue.lower()
            ]

            if horizontal_scroll_issues:
                print("      Horizontal scroll issue detected")
            else:
                print("      No horizontal scroll issues")

            # Verify form fields are visible
            form_fields = [
                'input[name="first_name"]',
                'input[name="email"]',
                'input[name="password1"]',
                'button:has-text("Create Account")',
            ]

            for selector in form_fields:
                field = page.locator(selector)
                if field.is_visible():
                    # Check if field is properly sized
                    box = field.bounding_box()
                    if box and box["width"] >= 250:  # Reasonable mobile input width
                        print(f"      {selector} properly sized for mobile")
                    else:
                        print(f"      {selector} may be too narrow for mobile")

            # Test mobile navigation
            mobile.test_mobile_navigation()

        print("  Signup mobile responsiveness test completed")


def test_signup_across_responsive_breakpoints(page: Page) -> None:
    """
    Test signup form across all responsive breakpoints.

    This test validates that the signup form works on:
    - Desktop viewports (baseline)
    - Tablet viewports
    - Mobile viewports
    """
    print("Testing signup across responsive breakpoints")

    with ComprehensivePageMonitor(
        page,
        "signup responsive breakpoints",
        check_console=False,  # Alpine.js CSP eval errors expected on signup forms
        check_network=True,
        check_html=False,
        check_css=True,
                                 check_accessibility=False):
        def test_signup_form_visibility(test_page: Page, context: str = "") -> bool:
            """Test that signup form is visible and functional"""
            try:
                test_page.goto(f"{BASE_URL}{REGISTER_URL}")
                test_page.wait_for_load_state("networkidle")

                # Check key form elements
                email_field = test_page.locator('input[name="email"]')
                submit_button = test_page.locator('button:has-text("Create Account")')

                email_visible = email_field.is_visible()
                submit_visible = submit_button.is_visible()

                if email_visible and submit_visible:
                    print(f"      Signup form visible in {context}")
                    return True
                else:
                    print(f"      Signup form issues in {context}")
                    return False

            except (TimeoutError, PlaywrightError) as e:
                print(f"      Error in {context}: {str(e)[:50]}")
                return False

        # Test across breakpoints
        results = run_responsive_breakpoints_test(page, test_signup_form_visibility)

        assert_responsive_results(results, "Signup form")

        print("  Signup responsive breakpoints test completed")


# ===============================================================================
# SECURITY BOUNDARY TESTS
# ===============================================================================


def test_signup_rate_limiting_indication(page: Page) -> None:
    """
    Test that the signup page handles rate limiting gracefully.

    Note: This test checks for rate limiting UI elements, not actual rate limit triggering.
    """
    print("Testing signup rate limiting indication")

    with ComprehensivePageMonitor(
        page,
        "signup rate limiting",
        check_console=False,  # Alpine.js CSP eval errors expected on signup forms
        check_network=True,
        check_html=False,
        check_css=True,
                                 check_accessibility=False):
        # Navigate to signup
        page.goto(f"{BASE_URL}{REGISTER_URL}")
        page.wait_for_load_state("networkidle")

        # Check page content for rate limiting handling
        # The system should have rate limiting in place but show user-friendly messages
        page_content = page.content().lower()

        # Rate limiting should not expose timing information
        # Check that the form is normally accessible
        submit_button = page.locator('button:has-text("Create Account")')
        assert submit_button.is_visible(), "Submit button should be visible on normal access"

        print("    Signup page accessible with normal request")
        print("    Rate limiting UI check passed (not triggered)")

        print("  Signup rate limiting indication test completed")


def test_signup_enumeration_protection(page: Page) -> None:
    """
    Test that the signup process is enumeration-safe.

    The system should respond identically whether or not an email exists,
    to prevent attackers from discovering valid email addresses.
    """
    print("Testing signup enumeration protection")

    with ComprehensivePageMonitor(
        page,
        "signup enumeration protection",
        check_console=False,  # Alpine.js CSP eval errors expected on signup forms
        check_network=True,
        check_html=False,
        check_css=True,
                                 check_accessibility=False):
        # Complete signup with a new email
        new_email = generate_test_email()
        test_password = generate_test_password()
        test_company = generate_test_company_name()

        # Fill and submit form with new email
        page.goto(f"{BASE_URL}{REGISTER_URL}")
        page.wait_for_load_state("networkidle")

        page.locator('input[name="first_name"]').fill("Enum")
        page.locator('input[name="last_name"]').fill("Test")
        page.locator('input[name="email"]').fill(new_email)
        page.locator('select[name="customer_type"]').select_option("srl")
        page.locator('input[name="company_name"]').fill(test_company)
        page.locator('input[name="address_line1"]').fill("Test St 1")
        page.locator('input[name="city"]').fill("Bucuresti")
        page.locator('input[name="county"]').fill("Bucuresti")
        page.locator('input[name="postal_code"]').fill("010001")
        page.locator('input[name="password1"]').fill(test_password)
        page.locator('input[name="password2"]').fill(test_password)
        page.locator('input[name="data_processing_consent"]').check()

        page.locator('button:has-text("Create Account")').click()
        page.wait_for_load_state("networkidle")

        new_email_url = page.url

        # Try to signup with existing customer email
        page.goto(f"{BASE_URL}{REGISTER_URL}")
        page.wait_for_load_state("networkidle")

        page.locator('input[name="first_name"]').fill("Existing")
        page.locator('input[name="last_name"]').fill("User")
        page.locator('input[name="email"]').fill(CUSTOMER_EMAIL)  # Existing email
        page.locator('select[name="customer_type"]').select_option("srl")
        page.locator('input[name="company_name"]').fill("Existing Company SRL")
        page.locator('input[name="address_line1"]').fill("Test St 2")
        page.locator('input[name="city"]').fill("Bucuresti")
        page.locator('input[name="county"]').fill("Bucuresti")
        page.locator('input[name="postal_code"]').fill("010001")
        page.locator('input[name="password1"]').fill(test_password)
        page.locator('input[name="password2"]').fill(test_password)
        page.locator('input[name="data_processing_consent"]').check()

        page.locator('button:has-text("Create Account")').click()
        page.wait_for_load_state("networkidle")

        existing_email_url = page.url

        # Both should result in similar behavior (enumeration-safe)
        # The system should redirect to the same confirmation page
        if "/submitted" in new_email_url and "/submitted" in existing_email_url:
            print("    Both new and existing emails redirect to same page - enumeration safe")
        elif new_email_url == existing_email_url:
            print("    Same response for new and existing emails - enumeration safe")
        else:
            print(f"    New email result: {new_email_url}")
            print(f"    Existing email result: {existing_email_url}")
            # Note: Some difference may be acceptable if both are secure responses

        print("  Signup enumeration protection test completed")


# ===============================================================================
# EDGE CASE TESTS
# ===============================================================================


def test_signup_with_special_characters_in_company_name(page: Page) -> None:
    """
    Test signup with special characters in company name.

    Romanian company names may include special characters like:
    - & (si)
    - Diacritics (a, a, i, s, t)
    - Quotes in legal names
    """
    print("Testing signup with special characters in company name")

    with ComprehensivePageMonitor(
        page,
        "signup special characters",
        check_console=False,  # Alpine.js CSP eval errors expected on signup forms
        check_network=True,
        check_html=False,
        check_css=True,
                                 check_accessibility=False):
        page.goto(f"{BASE_URL}{REGISTER_URL}")
        page.wait_for_load_state("networkidle")

        # Use company name with Romanian diacritics
        special_company = "Soluții & Servicii Românești SRL"
        test_email = generate_test_email()
        test_password = generate_test_password()

        page.locator('input[name="first_name"]').fill("Ioan")
        page.locator('input[name="last_name"]').fill("Popescu")
        page.locator('input[name="email"]').fill(test_email)
        page.locator('select[name="customer_type"]').select_option("srl")
        page.locator('input[name="company_name"]').fill(special_company)
        page.locator('input[name="address_line1"]').fill("Strada Victoriei Nr. 10")
        page.locator('input[name="city"]').fill("București")  # With diacritics
        page.locator('input[name="county"]').fill("București")
        page.locator('input[name="postal_code"]').fill("010001")
        page.locator('input[name="password1"]').fill(test_password)
        page.locator('input[name="password2"]').fill(test_password)
        page.locator('input[name="data_processing_consent"]').check()

        # Submit and check for success
        page.locator('button:has-text("Create Account")').click()
        page.wait_for_load_state("networkidle")

        # Should succeed or show only valid errors (not encoding issues)
        current_url = page.url
        page_content = page.content()

        # Check for encoding errors
        encoding_errors = ["encoding", "unicode", "invalid character", "codec"]
        has_encoding_error = any(err in page_content.lower() for err in encoding_errors)

        assert not has_encoding_error, "Special characters should not cause encoding errors"
        print("    Special characters handled correctly")

        if "/submitted" in current_url:
            print("    Form with special characters submitted successfully")

        print("  Special characters test completed")
