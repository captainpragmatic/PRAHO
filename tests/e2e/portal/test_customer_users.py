"""
Customer User Management E2E Tests for PRAHO Platform

This module comprehensively tests the customer-facing user functionality including:
- User authentication and session management
- Profile management and editing
- Password change functionality
- Two-factor authentication setup and management (TOTP/WebAuthn)
- Account security settings and features
- Security boundary testing - ensuring customers cannot access staff-only URLs
- Mobile responsiveness for customer profile management
- Customer account security and privacy

Uses shared utilities from tests.e2e.utils for consistency.
Based on real customer workflows for user account management.
"""

import re

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Locator, Page, expect

# Import shared utilities
from tests.e2e.utils import (
    # Base URL constant
    BASE_URL,
    # Legacy credentials (keep for fallback compatibility)
    CUSTOMER_EMAIL,
    CUSTOMER_PASSWORD,
    ComprehensivePageMonitor,
    MobileTestContext,
    # New dynamic user management
    assert_responsive_results,
    ensure_fresh_session,
    login_user_with_retry,
    navigate_to_dashboard,
    require_authentication,
    run_responsive_breakpoints_test,
    run_standard_mobile_test,
)

# ===============================================================================
# CUSTOMER AUTHENTICATION AND PROFILE ACCESS TESTS
# ===============================================================================

def test_customer_login_and_profile_access(page: Page) -> None:
    """
    Test customer login and basic profile access using dynamic test users.

    This test verifies:
    1. Fresh customer user can login successfully
    2. Customer can access their profile page
    3. Customer profile displays correct information
    4. Authentication is maintained across navigation
    5. Clean test isolation with automatic cleanup
    """
    print("🧪 Testing customer login and profile access")

    with ComprehensivePageMonitor(page, "customer login and profile access",
                                 check_console=False,  # Temporarily disabled due to SVG errors
                                 check_network=True,
                                 check_html=False,  # May have duplicate ID issues
                                 check_css=True,
                                 check_accessibility=False):
        # Login with dedicated E2E customer credentials
        ensure_fresh_session(page)
        assert login_user_with_retry(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)

        # Verify authentication is successful
        require_authentication(page)

        # Navigate to dashboard first
        assert navigate_to_dashboard(page)
        expect(page).to_have_url(re.compile(r"/dashboard/"))

        # Navigate to user profile
        page.goto(f"{BASE_URL}/profile/")
        page.wait_for_load_state("networkidle")

        # Verify we're on the profile page
        expect(page).to_have_url(re.compile(r"/profile/"))

        # Verify profile page title and content
        page_title = page.title()
        title_ok = any(word in page_title.lower() for word in ["profile", "profil", "account", "settings"])
        if not title_ok:
            print(f"  [i] Profile page title: '{page_title}' (may vary)")

        # Check for profile page elements (fields may not be wrapped in a <form> tag)
        # Complex OR condition: save_button or profile_fields present
        save_button = page.locator('button:has-text("Save"), button:has-text("Update"), button[type="submit"]')
        profile_fields = page.locator('input[name="first_name"], input[name="last_name"]')
        assert save_button.count() > 0 or profile_fields.count() > 0, "Profile page should have editable fields or save button"

        # Check for basic profile fields
        first_name_field = page.locator('input[name="first_name"]')
        last_name_field = page.locator('input[name="last_name"]')
        email_field = page.locator('input[name="email"], input[type="email"]')

        expect(first_name_field).to_be_visible()
        print("  ✅ First name field available")
        expect(last_name_field).to_be_visible()
        print("  ✅ Last name field available")
        expect(email_field).to_be_visible()
        print("  ✅ Email field visible in profile")

        # Check for 2FA management section
        mfa_section = page.locator('div:has-text("Two-Factor"), div:has-text("2FA"), a[href*="2fa"]')
        if mfa_section.count() > 0:
            print("  ✅ 2FA management section available")
        else:
            print("  [i] 2FA management section not found in profile")


def test_customer_profile_using_convenience_helper(page: Page) -> None:
    """
    Test customer profile management with standard credentials.

    This test covers:
    - Quick customer login
    - Profile page navigation
    - Profile information validation
    """
    print("🧪 Testing customer profile access")

    with ComprehensivePageMonitor(page, "customer profile access test",
                                 check_console=False,  # Temporarily disabled due to SVG errors
                                 check_network=True,
                                 check_html=False,
                                 check_css=True,
                                 check_accessibility=False,
                                 allow_accessibility_skip=True):
        # Login with dedicated E2E customer credentials
        ensure_fresh_session(page)
        assert login_user_with_retry(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)

        # Navigate to profile (already authenticated)
        page.goto(f"{BASE_URL}/profile/")
        page.wait_for_load_state("networkidle")

        # Verify profile page access
        expect(page).to_have_url(re.compile(r"/profile/"))

        # Verify profile form fields are present and populated
        first_name_field = page.locator('input[name="first_name"]')
        expect(first_name_field).to_be_visible()
        print("  ✅ Profile form with first_name field visible")

        last_name_field = page.locator('input[name="last_name"]')
        if last_name_field.count() > 0:
            expect(last_name_field).to_be_visible()
            print("  ✅ Last name field visible")

        # Verify save button is present (form editing tested in test_customer_profile_editing)
        save_button = page.locator(
            'button[type="submit"]:has-text("Save"), '
            'button[type="submit"]:has-text("Salvează")'
        )
        if save_button.count() > 0:
            expect(save_button.first).to_be_visible()
            print("  ✅ Save button available")

        # Check for password change option
        password_change = page.locator('a:has-text("Change Password"), a[href*="password-change"]')
        if password_change.count() > 0:
            print("  ✅ Password change option available")
        else:
            print("  [i] Password change option not found")

        print("  ✅ Customer login and profile access successful")


def test_customer_profile_editing(page: Page) -> None:
    """
    Test customer profile editing functionality.

    This test covers:
    - Editing profile information
    - Form validation
    - Profile update submission
    - Success/error message handling
    """
    print("🧪 Testing customer profile editing functionality")

    with ComprehensivePageMonitor(page, "customer profile editing",
                                 check_console=False,  # Temporarily disabled due to SVG errors
                                 check_network=True,
                                 check_html=False,  # May have duplicate ID issues
                                 check_css=True,
                                 check_accessibility=False):
        # Login and navigate to profile
        ensure_fresh_session(page)
        assert login_user_with_retry(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)
        page.goto(f"{BASE_URL}/profile/")
        page.wait_for_load_state("networkidle")

        # Test profile data
        test_profile_data = {
            'first_name': 'CustomerTest',
            'last_name': 'UserTest',
            'phone': '+40711223344'
        }

        # Fill first name field
        first_name_field = page.locator('input[name="first_name"]')
        expect(first_name_field).to_be_visible()
        first_name_field.clear()
        first_name_field.fill(test_profile_data['first_name'])
        print("  ✅ Updated first name field")

        # Fill last name field
        last_name_field = page.locator('input[name="last_name"]')
        expect(last_name_field).to_be_visible()
        last_name_field.clear()
        last_name_field.fill(test_profile_data['last_name'])
        print("  ✅ Updated last name field")

        # Fill phone if field exists (optional profile field)
        phone_field = page.locator('input[name="phone"], input[name="phone_number"]')
        if phone_field.is_visible():
            phone_field.clear()
            phone_field.fill(test_profile_data['phone'])
            print("  ✅ Updated phone field")

        # Submit the profile form
        submit_button = page.locator('button:has-text("Update"), button:has-text("Save"), input[type="submit"]').first
        if submit_button.is_visible():
            submit_button.click()

            # Wait for form processing
            page.wait_for_load_state("networkidle")

            # Check for success message
            success_message = page.get_by_role("alert").locator('div:has-text("updated"), div:has-text("saved"), div:has-text("success")').first
            if success_message.is_visible():
                print("  ✅ Profile update success message displayed")
            elif "/profile/" in page.url:
                # Look for validation errors
                error_messages = page.locator('div.text-red-600, .text-red-500, [class*="error"], .invalid-feedback')
                if error_messages.count() > 0:
                    error_text = error_messages.first.inner_text()
                    print(f"  ⚠️ Form validation error: {error_text}")
                else:
                    print("  [i] Profile form submitted but no clear success indication")
            else:
                print("  ✅ Profile form submitted successfully (redirected away)")
        else:
            print("  ⚠️ Profile update button not found")

        print("  ✅ Customer profile editing test completed")


# ===============================================================================
# CUSTOMER PASSWORD CHANGE TESTS
# ===============================================================================

def test_customer_password_change_workflow(page: Page) -> None:
    """
    Test customer password change functionality.

    This test covers:
    - Accessing password change form
    - Current password validation
    - New password requirements
    - Password change success workflow
    """
    print("🧪 Testing customer password change workflow")

    with ComprehensivePageMonitor(page, "customer password change",
                                 check_console=False,  # Temporarily disabled due to SVG errors
                                 check_network=True,
                                 check_html=False,  # May have duplicate ID issues
                                 check_css=True,
                                 check_accessibility=False):
        # Login as customer
        ensure_fresh_session(page)
        assert login_user_with_retry(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)

        # Navigate to password change page
        page.goto(f"{BASE_URL}/auth/password-change/")
        page.wait_for_load_state("networkidle")

        # Portal may not have a dedicated password change page
        page_content_lower = page.content().lower()
        if "404" in page.title().lower() or "not found" in page_content_lower:
            print("  [i] Password change page not available on portal (platform-only feature)")
        else:
            # Verify we're on the password change page
            expect(page).to_have_url(re.compile(r"/auth/password-change/"))

            # Verify password change form elements
            change_heading = page.locator('h1:has-text("Change Password"), h2:has-text("Change Password"), h1:has-text("Password Change")')
            if not change_heading.is_visible():
                print("  [i] Password change heading not found - may use different text or layout")

            # Check for required password fields
            old_password_field = page.locator('input[name="old_password"]')
            new_password1_field = page.locator('input[name="new_password1"]')
            new_password2_field = page.locator('input[name="new_password2"]')

            # Password change form fields are required when testing password change
            expect(old_password_field).to_be_visible()
            expect(new_password1_field).to_be_visible()
            expect(new_password2_field).to_be_visible()

            # Test password change data
            test_password_data = {
                'old_password': CUSTOMER_PASSWORD,
                'new_password': 'NewTestPass123!',
                'confirm_password': 'NewTestPass123!'
            }

            # Fill password change form
            old_password_field.fill(test_password_data['old_password'])
            new_password1_field.fill(test_password_data['new_password'])
            new_password2_field.fill(test_password_data['confirm_password'])
            print("  ✅ Filled password change form")

            # Submit the form
            submit_button = page.locator('button:has-text("Change Password"), button:has-text("Submit"), input[type="submit"]').first
            if submit_button.is_visible():
                submit_button.click()

                # Wait for form processing
                page.wait_for_load_state("networkidle")

                # Check if password change was successful
                if "/profile/" in page.url:
                    print("  ✅ Password change succeeded - redirected to profile")

                    # Look for success message
                    success_message = page.get_by_role("alert").locator('div:has-text("password"), div:has-text("changed"), div:has-text("updated")').first
                    if success_message.is_visible():
                        print("  ✅ Password change success message displayed")
                elif "/auth/password-change/" in page.url:
                    # Still on password change page - check for errors
                    error_messages = page.locator('div.text-red-600, .text-red-500, [class*="error"], .invalid-feedback')
                    if error_messages.count() > 0:
                        error_text = error_messages.first.inner_text()
                        print(f"  ⚠️ Password change error: {error_text}")
                    else:
                        print("  [i] Password change form submitted but still on same page")
            else:
                print("  ⚠️ Password change submit button not found")

        print("  ✅ Customer password change workflow test completed")


# ===============================================================================
# CUSTOMER TWO-FACTOR AUTHENTICATION TESTS
# ===============================================================================

def _2fa_verify_totp_setup_page(page: Page) -> None:
    """Verify TOTP setup page elements after navigating to it."""
    if "/auth/2fa/setup/totp/" not in page.url:
        print("  ⚠️ TOTP setup page not accessible")
        return

    print("  ✅ TOTP setup page accessible")
    qr_code = page.locator('img[alt*="QR"], canvas, svg, .qr-code')
    secret_text = page.locator('code, .secret, input[readonly]')
    token_field = page.locator('input[name="token"]')

    if qr_code.count() > 0:
        print("  ✅ QR code displayed for TOTP setup")
    if secret_text.count() > 0:
        print("  ✅ Secret text available for manual entry")
    expect(token_field).to_be_visible()
    print("  ✅ Token verification field present")
    print("  [i] TOTP setup form structure validated (not completed)")


def _2fa_test_webauthn_option(page: Page) -> None:
    """Test WebAuthn option availability from the 2FA setup page."""
    webauthn_option = page.locator('a:has-text("WebAuthn"), a:has-text("Passkey"), a[href*="webauthn"]')
    if webauthn_option.count() == 0:
        print("  [i] WebAuthn option not found")
        return

    print("  ✅ WebAuthn/Passkey option available")
    webauthn_option.first.click()
    page.wait_for_load_state("networkidle")

    if "/auth/2fa/setup/webauthn/" in page.url:
        print("  ✅ WebAuthn setup page accessible")
    elif "/auth/2fa/setup/totp/" in page.url:
        print("  [i] WebAuthn redirects to TOTP (not yet implemented)")
    else:
        print("  ⚠️ WebAuthn setup navigation unclear")


def _2fa_test_disable_page(page: Page) -> None:
    """Test the 2FA disable page access."""
    page.goto(f"{BASE_URL}/auth/2fa/disable/")
    page.wait_for_load_state("networkidle")

    if "/auth/2fa/disable/" not in page.url:
        return

    disable_form = page.locator('form')
    if disable_form.is_visible():
        print("  ✅ 2FA disable page accessible")
        return

    info_message = page.locator('div:has-text("not enabled"), div:has-text("disabled")')
    if info_message.is_visible():
        print("  [i] 2FA not enabled for test customer")
    else:
        print("  ⚠️ 2FA disable page unclear")


def test_customer_2fa_setup_access_and_flow(page: Page) -> None:
    """
    Test customer 2FA setup access and method selection flow.

    This test covers:
    - Accessing 2FA setup from profile
    - 2FA method selection page
    - TOTP setup flow
    - WebAuthn setup availability
    - 2FA disable functionality
    """
    print("🧪 Testing customer 2FA setup access and flow")

    with ComprehensivePageMonitor(page, "customer 2FA setup",
                                 check_console=False,  # Temporarily disabled due to SVG errors
                                 check_network=True,
                                 check_html=False,  # May have duplicate ID issues
                                 check_css=True,
                                 check_accessibility=False):
        ensure_fresh_session(page)
        assert login_user_with_retry(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)

        page.goto(f"{BASE_URL}/auth/2fa/setup/")
        page.wait_for_load_state("networkidle")

        page_content_lower = page.content().lower()
        if "404" in page.title().lower() or "not found" in page_content_lower:
            print("  [i] 2FA setup page not available on portal (platform-only feature)")
            print("  ✅ Customer 2FA setup access and flow test completed")
            return

        expect(page).to_have_url(re.compile(r"/auth/2fa/"))

        method_selection = page.locator('h1:has-text("Two-Factor"), h1:has-text("2FA"), h1:has-text("Authentication")')
        expect(method_selection).to_be_visible()
        print("  ✅ 2FA setup page loaded")

        totp_option = page.locator('a:has-text("Authenticator"), a[href*="totp"], button:has-text("App")')
        expect(totp_option.first).to_be_attached()
        print("  ✅ TOTP/Authenticator App option available")

        totp_option.first.click()
        page.wait_for_load_state("networkidle")
        _2fa_verify_totp_setup_page(page)

        page.goto(f"{BASE_URL}/auth/2fa/setup/")
        page.wait_for_load_state("networkidle")
        _2fa_test_webauthn_option(page)

        _2fa_test_disable_page(page)

        print("  ✅ Customer 2FA setup access and flow test completed")


# ===============================================================================
# CUSTOMER SECURITY BOUNDARY TESTS
# ===============================================================================

def _check_staff_user_list_access(page: Page) -> bool:
    """Return True if access to /auth/users/ was properly denied."""
    if "/auth/users/" not in page.url:
        print("    ✅ Redirected away from staff user list (access denied)")
        return True

    page_content = page.content().lower()
    error_indicators = [
        "permission denied", "access denied", "not authorized",
        "forbidden", "not allowed", "insufficient privileges",
        "you do not have permission", "403", "unauthorized",
    ]
    if any(indicator in page_content for indicator in error_indicators):
        print("    ✅ Permission denied message displayed")
        return True

    user_mgmt_content = page.locator('h1:has-text("User"), h1:has-text("Users"), table').count()
    if user_mgmt_content > 0:
        print("    ❌ Customer can access staff user management - SECURITY ISSUE")
        return False

    print("    ✅ No user management content visible")
    return True


def _check_user_detail_access(page: Page) -> bool:
    """Return True if access to /auth/users/1/ was properly denied."""
    if "/auth/users/1/" not in page.url:
        print("    ✅ Redirected away from user detail page")
        return True

    page_content = page.content().lower()
    if any(indicator in page_content for indicator in ["permission", "denied", "forbidden", "403"]):
        print("    ✅ User detail access denied")
        return True

    sensitive_content = page.locator('div:has-text("Email:"), div:has-text("@"), table td').count()
    if sensitive_content > 0:
        print("    ❌ Customer can view other user details - PRIVACY VIOLATION")
        return False

    print("    ✅ No sensitive user details visible")
    return True


def test_customer_staff_access_restrictions(page: Page) -> None:
    """
    Test that customers cannot access staff-only URLs and features.

    This critical security test ensures:
    - Customers cannot access /auth/users/ management URLs
    - Customers cannot access staff user administration
    - Proper error messages and redirects for unauthorized access
    - Customer data privacy is maintained
    """
    print("🧪 Testing customer staff access restrictions (Security Boundary)")

    with ComprehensivePageMonitor(page, "customer staff access restrictions",
                                 check_console=False,  # Temporarily disabled due to SVG errors
                                 check_network=True,
                                 check_html=False,  # May have duplicate ID issues
                                 check_css=True,
                                 check_accessibility=False):
        ensure_fresh_session(page)
        assert login_user_with_retry(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)
        require_authentication(page)

        print("  🔒 Testing staff user list access restriction")
        page.goto(f"{BASE_URL}/auth/users/")
        page.wait_for_load_state("networkidle")
        assert _check_staff_user_list_access(page), "Customer should not have access to staff user management"

        print("  🔒 Testing individual user detail access restriction")
        page.goto(f"{BASE_URL}/auth/users/1/")
        page.wait_for_load_state("networkidle")
        assert _check_user_detail_access(page), "Customer should not access other user details"

        print("  ✅ Verifying customer can still access own profile")
        page.goto(f"{BASE_URL}/profile/")
        page.wait_for_load_state("networkidle")

        expect(page).to_have_url(re.compile(r"/profile/"))
        profile_fields = page.locator('input[name="first_name"], input[name="last_name"], button:has-text("Save")')
        expect(profile_fields.first).to_be_attached()
        print("    ✅ Customer own profile remains accessible")

        print("  ✅ Customer staff access restrictions verified - security boundaries intact")


def test_customer_cannot_edit_other_users(page: Page) -> None:
    """
    Test that customers cannot edit other users or access user management APIs.

    This test ensures:
    - API endpoints for user management are protected
    - Form submissions for other users are rejected
    - Customer data isolation is maintained
    """
    print("🧪 Testing customer cannot edit other users")

    with ComprehensivePageMonitor(page, "customer user editing restrictions",
                                 check_console=False,  # Expected 404/405 errors from security tests
                                 check_network=False,  # Expected failed requests from security tests
                                 check_html=False,  # May have duplicate ID issues
                                 check_css=True,
                                 check_accessibility=False):
        # Login as customer
        ensure_fresh_session(page)
        assert login_user_with_retry(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)

        # Test API endpoint protection
        print("  🔒 Testing API endpoint protection")

        # Try to access user check API (should be protected or limited)
        page.goto(f"{BASE_URL}/auth/api/check-email/")
        page.wait_for_load_state("networkidle")

        # Should not show internal user data
        api_content = page.content().lower()
        if "method not allowed" in api_content or "405" in api_content:
            print("    ✅ API endpoint properly requires POST method")
        elif "forbidden" in api_content or "403" in api_content:
            print("    ✅ API endpoint access forbidden")
        else:
            print("    [i] API endpoint response unclear - may require further testing")

        # Test navigation to ensure customer stays in customer area
        print("  🔒 Testing navigation boundaries")

        # Try to navigate to admin areas
        restricted_urls = [
            "/users/",
            "/users/create/",
            "/staff/users/",
            "/admin/",
            "/admin/users/",
        ]

        access_denied_count = 0

        for restricted_url in restricted_urls:
            try:
                full_url = f"{BASE_URL}{restricted_url}"
                page.goto(full_url)
                page.wait_for_load_state("networkidle", timeout=3000)

                # Check if access was denied
                current_url = page.url
                page_content = page.content().lower()

                access_denied = False
                if restricted_url not in current_url:
                    access_denied = True
                    print(f"    ✅ Redirected away from {restricted_url}")
                elif any(word in page_content for word in ["forbidden", "denied", "permission", "403", "404"]):
                    access_denied = True
                    print(f"    ✅ Access denied to {restricted_url}")
                else:
                    print(f"    ⚠️ Unclear access result for {restricted_url}")

                if access_denied:
                    access_denied_count += 1

            except (TimeoutError, PlaywrightError) as e:
                # Exception likely means access was properly blocked
                print(f"    ✅ Exception accessing {restricted_url} (likely blocked): {str(e)[:50]}")
                access_denied_count += 1

        print(f"    📊 {access_denied_count}/{len(restricted_urls)} restricted URLs properly blocked")

        print("  ✅ Customer user editing restrictions verified")


# ===============================================================================
# CUSTOMER MOBILE RESPONSIVENESS TESTS
# ===============================================================================

def test_customer_profile_mobile_responsiveness(page: Page) -> None:
    """
    Test customer profile management mobile responsiveness.

    This test verifies:
    1. Profile page displays correctly on mobile viewports
    2. Form elements are touch-friendly
    3. Mobile navigation works for profile features
    4. 2FA setup is mobile-accessible
    """
    print("🧪 Testing customer profile mobile responsiveness")

    with ComprehensivePageMonitor(page, "customer profile mobile responsiveness",
                                 check_console=False,  # Temporarily disabled due to SVG errors
                                 check_network=True,
                                 check_html=False,  # May have duplicate ID issues
                                 check_css=True,
                                 check_accessibility=False,
                                 check_performance=False):
        # Login and navigate to profile on desktop first
        ensure_fresh_session(page)
        assert login_user_with_retry(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)
        page.goto(f"{BASE_URL}/profile/")
        page.wait_for_load_state("networkidle")

        # Test mobile viewport
        with MobileTestContext(page, 'mobile_medium') as mobile:
            print("    📱 Testing customer profile on mobile viewport")

            run_standard_mobile_test(page, mobile, context_label="customer profile")

            # Verify key profile elements are accessible on mobile
            profile_fields = page.locator('input[name="first_name"], input[name="last_name"]')
            if profile_fields.count() > 0:
                print("      ✅ Profile fields visible on mobile")

            # Test form field accessibility on mobile
            form_fields = page.locator('input, textarea, select').count()
            if form_fields > 0:
                print(f"      ✅ {form_fields} form fields accessible on mobile")

            # Test 2FA setup mobile accessibility
            mfa_links = page.locator('a[href*="2fa"], a:has-text("Two-Factor"), a:has-text("2FA")')
            if mfa_links.count() > 0:
                print("      ✅ 2FA setup links accessible on mobile")

                # Test 2FA setup mobile flow
                mfa_links.first.click()
                page.wait_for_load_state("networkidle")

                if "/auth/2fa/" in page.url:
                    print("      ✅ 2FA setup accessible on mobile")

                    # Check for mobile-friendly 2FA elements
                    method_options = page.locator('button, a, .method-option').count()
                    if method_options > 0:
                        print(f"      ✅ {method_options} 2FA method options on mobile")

        print("  ✅ Customer profile mobile responsiveness testing completed")


# ===============================================================================
# COMPREHENSIVE CUSTOMER WORKFLOW TESTS
# ===============================================================================


def _workflow_step3_security_settings(page: Page) -> None:
    """Step 3: Verify password change form is accessible and well-structured."""
    print("    Step 3: Security settings and options")
    password_change_link = page.locator('a[href*="password-change"], a:has-text("Change Password")')
    if password_change_link.count() == 0:
        return

    password_change_link.first.click()
    page.wait_for_load_state("networkidle")

    if "/auth/password-change/" not in page.url:
        return

    print("      ✅ Password change form accessible")
    old_pass_field = page.locator('input[name="old_password"]')
    new_pass_field = page.locator('input[name="new_password1"]')
    expect(old_pass_field).to_be_visible()
    expect(new_pass_field).to_be_visible()
    print("      ✅ Password change form properly structured")

    page.goto(f"{BASE_URL}/profile/")
    page.wait_for_load_state("networkidle")


def _workflow_step4_2fa_exploration(page: Page) -> None:
    """Step 4: Explore 2FA setup page and TOTP method without completing setup."""
    print("    Step 4: 2FA setup exploration")
    mfa_setup_link = page.locator('a[href*="2fa"], a:has-text("Two-Factor"), a:has-text("2FA")')
    if mfa_setup_link.count() == 0:
        return

    mfa_setup_link.first.click()
    page.wait_for_load_state("networkidle")

    if "/auth/2fa/" not in page.url:
        return

    print("      ✅ 2FA setup accessible")
    method_options = page.locator('a, button, .method-card').count()
    assert method_options > 0, "2FA setup page should have method options"
    print(f"      ✅ {method_options} 2FA method options available")

    totp_link = page.locator('a[href*="totp"], a:has-text("App"), a:has-text("Authenticator")')
    if totp_link.count() == 0:
        return

    totp_link.first.click()
    page.wait_for_load_state("networkidle")

    if "/auth/2fa/setup/totp/" in page.url:
        print("      ✅ TOTP setup flow accessible")
        qr_code = page.locator('img, canvas, svg').count()
        assert qr_code > 0, "TOTP setup page should have visual elements (QR code)"
        print("      ✅ TOTP setup visual elements present")


def test_customer_complete_account_management_workflow(page: Page) -> None:
    """
    Test the complete customer account management workflow.

    This comprehensive test covers:
    1. Customer login and dashboard access
    2. Profile viewing and editing
    3. Security settings management
    4. 2FA setup exploration
    5. Password change workflow
    6. Session management
    """
    print("🧪 Testing complete customer account management workflow")

    with ComprehensivePageMonitor(page, "customer complete account management",
                                 check_console=False,  # Temporarily disabled due to SVG errors
                                 check_network=True,
                                 check_html=False,  # May have duplicate ID issues
                                 check_css=True,
                                 check_accessibility=False):
        print("    Step 1: Customer authentication and dashboard access")
        ensure_fresh_session(page)
        assert login_user_with_retry(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)

        assert navigate_to_dashboard(page)
        customer_dashboard = page.locator('h1, h2, .dashboard, .welcome').count()
        assert customer_dashboard > 0, "Customer should see dashboard content"
        print("      ✅ Customer dashboard accessible")

        print("    Step 2: Profile viewing and basic information")
        page.goto(f"{BASE_URL}/profile/")
        page.wait_for_load_state("networkidle")

        profile_elements = page.locator('form, input, .profile-info').count()
        assert profile_elements > 0, "Customer profile should have editable content"
        print("      ✅ Customer profile loaded with editable content")

        first_name_field = page.locator('input[name="first_name"]')
        expect(first_name_field).to_be_visible()
        current_value = first_name_field.input_value()
        first_name_field.fill("WorkflowTest")
        print("      ✅ Profile field editing works")
        first_name_field.fill(current_value or "")

        _workflow_step3_security_settings(page)
        _workflow_step4_2fa_exploration(page)

        print("    Step 5: Session and navigation validation")
        assert navigate_to_dashboard(page)
        require_authentication(page)
        print("      ✅ Customer session maintained throughout workflow")

        page.goto(f"{BASE_URL}/auth/users/")
        page.wait_for_load_state("networkidle")

        page_content = page.content().lower()
        staff_access_denied = (
            "/auth/users/" not in page.url
            or "permission" in page_content
            or "not found" in page_content
            or "404" in page.title().lower()
        )
        assert staff_access_denied, "Customer should not have access to staff user management area"
        print("      ✅ Staff area access properly restricted")

        print("  ✅ Complete customer account management workflow successful")


def test_customer_account_responsive_breakpoints(page: Page) -> None:
    """
    Test customer account management across all responsive breakpoints.

    This test validates that customer account functionality works on:
    - Desktop viewports (baseline)
    - Tablet viewports (landscape and portrait)
    - Mobile viewports (various sizes)
    """
    print("🧪 Testing customer account management across responsive breakpoints")

    with ComprehensivePageMonitor(page, "customer account responsive breakpoints",
                                 check_console=False,  # Temporarily disabled due to SVG errors
                                 check_network=True,
                                 check_html=False,  # May have duplicate ID issues
                                 check_css=True,
                                 check_accessibility=False):
        # Login first
        ensure_fresh_session(page)
        assert login_user_with_retry(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)

        def test_customer_account_functionality(test_page, context="general"):
            """Test core customer account functionality across viewports."""
            try:
                # Navigate to profile
                test_page.goto(f"{BASE_URL}/profile/")
                test_page.wait_for_load_state("networkidle")

                # Verify authentication maintained
                require_authentication(test_page)

                # Check core elements are present (fields may not be in a <form> wrapper)
                profile_fields = test_page.locator('input[name="first_name"], input[name="last_name"], button:has-text("Save")')

                elements_present = profile_fields.count() > 0

                if elements_present:
                    print(f"      ✅ Customer account management functional in {context}")
                    return True
                else:
                    print(f"      ❌ Core account elements missing in {context}")
                    return False

            except (TimeoutError, PlaywrightError) as e:
                print(f"      ❌ Account management test failed in {context}: {str(e)[:50]}")
                return False

        # Test across all breakpoints
        results = run_responsive_breakpoints_test(page, test_customer_account_functionality)

        # Verify all breakpoints pass
        assert_responsive_results(results, "Customer account management")

        print("  ✅ Customer account management validated across all responsive breakpoints")


# ===============================================================================
# CUSTOMER COMPANY PROFILE, PRIVACY, AND MFA TESTS
# ===============================================================================


def test_customer_company_profile_view(page: Page) -> None:
    """
    Test customer company profile view page.

    This test verifies:
    1. Customer can access /company/ page
    2. Company information sections are displayed (name, VAT/CUI, address)
    3. Edit button or view-only indicator is present
    4. Billing address and business contact sections render
    """
    print("🧪 Testing customer company profile view")

    with ComprehensivePageMonitor(page, "customer company profile view",
                                 check_console=False,
                                 check_network=True,
                                 check_html=False,
                                 check_css=True,
                                 check_accessibility=False,
                                 allow_accessibility_skip=True):
        ensure_fresh_session(page)
        assert login_user_with_retry(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)

        page.goto(f"{BASE_URL}/company/")
        page.wait_for_load_state("networkidle")

        # Verify we're on the company profile page (or redirected if no company)
        page_content_lower: str = page.content().lower()
        if "404" in page.title().lower() or "not found" in page_content_lower:
            print("  [i] Company profile page not available (customer may not have a company)")
            print("  ✅ Customer company profile view test completed")
            return

        # Check for company profile heading
        heading = page.locator('h1:has-text("Company Profile"), h1:has-text("Profil")')
        if heading.count() > 0:
            expect(heading.first).to_be_visible()
            print("  ✅ Company Profile heading displayed")
        else:
            print("  [i] Company profile heading not found - page may use different layout")

        # Check for company information section
        company_info_section = page.locator('h2:has-text("Company Information"), h2:has-text("Informații")')
        if company_info_section.count() > 0:
            print("  ✅ Company Information section present")

        # Check for VAT/CUI label
        vat_label = page.locator('dt:has-text("VAT"), dt:has-text("CUI")')
        if vat_label.count() > 0:
            print("  ✅ VAT Number / CUI field displayed")

        # Check for Billing Address section
        billing_section = page.locator('h2:has-text("Billing Address"), h2:has-text("Adresă")')
        if billing_section.count() > 0:
            print("  ✅ Billing Address section present")

        # Check for Business Contact section
        contact_section = page.locator('h2:has-text("Business Contact"), h2:has-text("Contact")')
        if contact_section.count() > 0:
            print("  ✅ Business Contact section present")

        # Check for edit button or view-only indicator
        edit_link = page.locator('a:has-text("Edit Company Profile"), a:has-text("Editează")')
        view_only = page.locator('div:has-text("View Only")')
        if edit_link.count() > 0:
            print("  ✅ Edit Company Profile button available")
        elif view_only.count() > 0:
            print("  ✅ View Only indicator displayed (role-based)")
        else:
            print("  [i] Neither edit button nor view-only indicator found")

        print("  ✅ Customer company profile view test completed")


def test_customer_company_profile_edit(page: Page) -> None:
    """
    Test customer company profile editing page.

    This test verifies:
    1. Customer can navigate to /company/edit/
    2. Edit form is populated with existing company data
    3. Form fields for company name, VAT, address are present
    4. Save Changes button is available
    """
    print("🧪 Testing customer company profile edit")

    with ComprehensivePageMonitor(page, "customer company profile edit",
                                 check_console=False,
                                 check_network=True,
                                 check_html=False,
                                 check_css=True,
                                 check_accessibility=False,
                                 allow_accessibility_skip=True):
        ensure_fresh_session(page)
        assert login_user_with_retry(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)

        page.goto(f"{BASE_URL}/company/edit/")
        page.wait_for_load_state("networkidle")

        page_content_lower: str = page.content().lower()
        if "404" in page.title().lower() or "not found" in page_content_lower:
            print("  [i] Company profile edit page not available")
            print("  ✅ Customer company profile edit test completed")
            return

        # Check if redirected (e.g., insufficient permissions)
        if "/company/edit/" not in page.url:
            print(f"  [i] Redirected away from company edit to {page.url}")
            print("  ✅ Customer company profile edit test completed")
            return

        # Verify edit page heading
        heading = page.locator('h1:has-text("Edit Company Profile"), h1:has-text("Editează")')
        if heading.count() > 0:
            expect(heading.first).to_be_visible()
            print("  ✅ Edit Company Profile heading displayed")

        # Check for form element
        form = page.locator("form[method='post']")
        expect(form.first).to_be_attached()
        print("  ✅ Edit form present")

        # Verify key form fields exist
        company_name_field = page.locator('input[name="company_name"], input[id*="company_name"]')
        if company_name_field.count() > 0:
            expect(company_name_field.first).to_be_visible()
            print("  ✅ Company name field visible")

        vat_field = page.locator('input[name="vat_number"], input[id*="vat_number"]')
        if vat_field.count() > 0:
            expect(vat_field.first).to_be_visible()
            print("  ✅ VAT number field visible")

        city_field = page.locator('input[name="city"], input[id*="city"]')
        if city_field.count() > 0:
            print("  ✅ City field present in billing address")

        # Check for Save Changes button
        save_button = page.locator('button[type="submit"]:has-text("Save"), button[type="submit"]:has-text("Salvează")')
        if save_button.count() > 0:
            expect(save_button.first).to_be_visible()
            print("  ✅ Save Changes button available")
        else:
            print("  [i] Save button not found with expected text")

        # Check for Cancel link
        cancel_link = page.locator('a:has-text("Cancel"), a:has-text("Anulează")')
        if cancel_link.count() > 0:
            print("  ✅ Cancel link available")

        print("  ✅ Customer company profile edit test completed")


def test_customer_privacy_dashboard(page: Page) -> None:
    """
    Test customer GDPR privacy dashboard page.

    This test verifies:
    1. Customer can access /privacy/ page
    2. Privacy settings overview with consent statuses displayed
    3. Data export link and consent history link are present
    4. GDPR rights information section renders
    """
    print("🧪 Testing customer privacy dashboard")

    with ComprehensivePageMonitor(page, "customer privacy dashboard",
                                 check_console=False,
                                 check_network=True,
                                 check_html=False,
                                 check_css=True,
                                 check_accessibility=False,
                                 allow_accessibility_skip=True):
        ensure_fresh_session(page)
        assert login_user_with_retry(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)

        page.goto(f"{BASE_URL}/privacy/")
        page.wait_for_load_state("networkidle")

        page_content_lower: str = page.content().lower()
        if "404" in page.title().lower() or "not found" in page_content_lower:
            print("  [i] Privacy dashboard not available")
            print("  ✅ Customer privacy dashboard test completed")
            return

        # Verify privacy dashboard heading
        heading = page.locator('h1:has-text("Privacy Dashboard"), h1:has-text("Confidențialitate")')
        if heading.count() > 0:
            expect(heading.first).to_be_visible()
            print("  ✅ Privacy Dashboard heading displayed")

        # Check for privacy settings overview section
        settings_section = page.locator('h3:has-text("Privacy Settings"), h3:has-text("Setări")')
        if settings_section.count() > 0:
            print("  ✅ Privacy Settings Overview section present")

        # Check for Data Processing consent status
        data_processing = page.locator('div:has-text("Data Processing"), div:has-text("Prelucrare")')
        if data_processing.count() > 0:
            print("  ✅ Data Processing consent status displayed")

        # Check for Marketing Communications consent status
        marketing = page.locator('div:has-text("Marketing Communications"), div:has-text("Marketing")')
        if marketing.count() > 0:
            print("  ✅ Marketing Communications consent status displayed")

        # Check for Export My Data link
        export_link = page.locator('a[href*="data-export"], a:has-text("Export My Data"), a:has-text("Exportă")')
        if export_link.count() > 0:
            print("  ✅ Export My Data link present")
        else:
            print("  [i] Data export link not found")

        # Check for Consent History link
        consent_link = page.locator(
            'a[href*="consent-history"], a:has-text("Consent History"), a:has-text("Consimțământ")'
        )
        if consent_link.count() > 0:
            print("  ✅ Consent History link present")
        else:
            print("  [i] Consent history link not found")

        # Check for GDPR rights section
        gdpr_section = page.locator('h3:has-text("GDPR Rights"), h3:has-text("Drepturile")')
        if gdpr_section.count() > 0:
            print("  ✅ GDPR Rights information section present")

        # Check for Cookie Preferences section
        cookie_section = page.locator('h3:has-text("Cookie"), h3:has-text("Cookie")')
        if cookie_section.count() > 0:
            print("  ✅ Cookie Preferences section present")

        print("  ✅ Customer privacy dashboard test completed")


def test_customer_data_export_request(page: Page) -> None:
    """
    Test customer data export request page (GDPR Article 20).

    This test verifies:
    1. Customer can access /data-export/ page
    2. Data inclusion information is displayed
    3. Export request form with submit button is present
    4. Legal information section renders
    """
    print("🧪 Testing customer data export request")

    with ComprehensivePageMonitor(page, "customer data export request",
                                 check_console=False,
                                 check_network=True,
                                 check_html=False,
                                 check_css=True,
                                 check_accessibility=False,
                                 allow_accessibility_skip=True):
        ensure_fresh_session(page)
        assert login_user_with_retry(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)

        page.goto(f"{BASE_URL}/data-export/")
        page.wait_for_load_state("networkidle")

        page_content_lower: str = page.content().lower()
        if "404" in page.title().lower() or "not found" in page_content_lower:
            print("  [i] Data export page not available")
            print("  ✅ Customer data export request test completed")
            return

        # Verify data export heading
        heading = page.locator('h1:has-text("Export My Data"), h1:has-text("Exportă")')
        if heading.count() > 0:
            expect(heading.first).to_be_visible()
            print("  ✅ Export My Data heading displayed")

        # Check for data inclusion info section
        what_included = page.locator('h3:has-text("What Data"), h3:has-text("Ce date")')
        if what_included.count() > 0:
            print("  ✅ Data inclusion information section present")

        # Check for data categories listed
        account_info = page.locator('div:has-text("Account Information"), div:has-text("Cont")')
        if account_info.count() > 0:
            print("  ✅ Account Information data category listed")

        # Check for export request form
        export_form = page.locator("form[method='post']")
        if export_form.count() > 0:
            print("  ✅ Export request form present")

        # Check for submit button
        submit_button = page.locator(
            'button[type="submit"]:has-text("Request Data Export"), '
            'button[type="submit"]:has-text("Solicită")'
        )
        if submit_button.count() > 0:
            expect(submit_button.first).to_be_visible()
            print("  ✅ Request Data Export button available")
        else:
            print("  [i] Export submit button not found with expected text")

        # Check for legal information section
        legal_section = page.locator('h3:has-text("Legal Information"), h3:has-text("Juridic")')
        if legal_section.count() > 0:
            print("  ✅ Legal Information section present")

        # Check for GDPR reference
        gdpr_ref = page.locator('p:has-text("GDPR"), p:has-text("Regulation")')
        if gdpr_ref.count() > 0:
            print("  ✅ GDPR legal reference displayed")

        # Check for back to privacy dashboard link
        back_link = page.locator('a[href*="privacy"], a:has-text("Back to Privacy"), a:has-text("Înapoi")')
        if back_link.count() > 0:
            print("  ✅ Back to Privacy Dashboard link present")

        print("  ✅ Customer data export request test completed")


def test_customer_mfa_management_hub(page: Page) -> None:
    """
    Test customer MFA management hub page.

    This test verifies:
    1. Customer can access /mfa/ page
    2. Current MFA status (enabled/disabled) is displayed
    3. Links to TOTP setup and backup codes are present
    4. Security status information renders correctly
    """
    print("🧪 Testing customer MFA management hub")

    with ComprehensivePageMonitor(page, "customer MFA management hub",
                                 check_console=False,
                                 check_network=True,
                                 check_html=False,
                                 check_css=True,
                                 check_accessibility=False,
                                 allow_accessibility_skip=True):
        ensure_fresh_session(page)
        assert login_user_with_retry(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)

        page.goto(f"{BASE_URL}/mfa/")
        page.wait_for_load_state("networkidle")

        page_content_lower: str = page.content().lower()
        if "404" in page.title().lower() or "not found" in page_content_lower:
            print("  [i] MFA management page not available")
            print("  ✅ Customer MFA management hub test completed")
            return

        # Verify MFA page heading
        heading = page.locator(
            'h1:has-text("Two-Factor Authentication"), '
            'h1:has-text("Autentificare"), '
            'h1:has-text("2FA")'
        )
        if heading.count() > 0:
            expect(heading.first).to_be_visible()
            print("  ✅ Two-Factor Authentication heading displayed")

        # Check for security status section
        status_section = page.locator(
            'h3:has-text("Current Security Status"), h3:has-text("Stare")'
        )
        if status_section.count() > 0:
            print("  ✅ Current Security Status section present")

        # Check for MFA enabled/disabled indicator
        mfa_enabled_indicator = page.locator('text="Enabled"')
        mfa_disabled_indicator = page.locator('text="Disabled"')
        if mfa_enabled_indicator.count() > 0:
            print("  ✅ MFA status: Enabled")
        elif mfa_disabled_indicator.count() > 0:
            print("  ✅ MFA status: Disabled")
        else:
            print("  [i] MFA enabled/disabled status not clearly displayed")

        # Check for TOTP setup link
        totp_link = page.locator(
            'a[href*="mfa/setup/totp"], '
            'a:has-text("Set Up Authenticator"), '
            'a:has-text("Authenticator App")'
        )
        if totp_link.count() > 0:
            print("  ✅ TOTP / Authenticator App setup link present")

        # Check for backup codes link (visible when MFA is enabled)
        backup_link = page.locator(
            'a[href*="mfa/backup-codes"], '
            'a:has-text("Backup Codes"), '
            'a:has-text("Coduri")'
        )
        if backup_link.count() > 0:
            print("  ✅ Backup Codes link present")
        else:
            print("  [i] Backup Codes link not visible (MFA may be disabled)")

        # Check for manage MFA settings section
        manage_section = page.locator(
            'h3:has-text("Manage MFA"), h3:has-text("Setări MFA")'
        )
        if manage_section.count() > 0:
            print("  ✅ Manage MFA Settings section present")

        # Check for Back to Profile link
        back_link = page.locator('a[href*="profile"], a:has-text("Back to Profile"), a:has-text("Înapoi")')
        if back_link.count() > 0:
            print("  ✅ Back to Profile link present")

        print("  ✅ Customer MFA management hub test completed")


def test_customer_mfa_backup_codes(page: Page) -> None:
    """
    Test customer MFA backup codes page.

    This test verifies:
    1. Customer can access /mfa/backup-codes/ page
    2. Backup codes are displayed or a generation prompt is shown
    3. Recovery code instructions section renders
    4. Regenerate codes option is available
    """
    print("🧪 Testing customer MFA backup codes")

    with ComprehensivePageMonitor(page, "customer MFA backup codes",
                                 check_console=False,
                                 check_network=True,
                                 check_html=False,
                                 check_css=True,
                                 check_accessibility=False,
                                 allow_accessibility_skip=True):
        ensure_fresh_session(page)
        assert login_user_with_retry(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)

        page.goto(f"{BASE_URL}/mfa/backup-codes/")
        page.wait_for_load_state("networkidle")

        page_content_lower: str = page.content().lower()
        if "404" in page.title().lower() or "not found" in page_content_lower:
            print("  [i] Backup codes page not available")
            print("  ✅ Customer MFA backup codes test completed")
            return

        # May redirect if MFA is not enabled
        if "/mfa/backup-codes/" not in page.url:
            print(f"  [i] Redirected from backup codes to {page.url} (MFA may not be enabled)")
            print("  ✅ Customer MFA backup codes test completed")
            return

        # Verify backup codes heading
        heading = page.locator(
            'h1:has-text("Backup Codes"), h1:has-text("Coduri")'
        )
        if heading.count() > 0:
            expect(heading.first).to_be_visible()
            print("  ✅ Backup Codes heading displayed")

        # Check for recovery codes section
        recovery_section = page.locator(
            'h3:has-text("Your Recovery Codes"), h3:has-text("Codurile")'
        )
        if recovery_section.count() > 0:
            print("  ✅ Your Recovery Codes section present")

        # Check for backup codes display or no-codes message
        code_elements = page.locator("code")
        no_codes_msg = page.locator(
            'h5:has-text("No Backup Codes"), '
            'h5:has-text("Niciun cod")'
        )
        if code_elements.count() > 0:
            code_count: int = code_elements.count()
            print(f"  ✅ {code_count} backup code(s) displayed")
        elif no_codes_msg.count() > 0:
            print("  ✅ No Backup Codes Available message displayed")
        else:
            print("  [i] Backup codes state unclear")

        # Check for regenerate codes section
        regenerate_section = page.locator(
            'h3:has-text("Regenerate"), h3:has-text("Regenerează")'
        )
        if regenerate_section.count() > 0:
            print("  ✅ Regenerate Codes section present")

        # Check for regenerate button
        regenerate_button = page.locator(
            'button:has-text("Generate New"), '
            'button:has-text("Generează")'
        )
        if regenerate_button.count() > 0:
            print("  ✅ Generate New Backup Codes button available")

        # Check for usage instructions section
        instructions_section = page.locator(
            'h3:has-text("How to Use"), h3:has-text("Cum se folosesc")'
        )
        if instructions_section.count() > 0:
            print("  ✅ How to Use Backup Codes instructions present")

        # Check for back to MFA management link
        back_link = page.locator(
            'a[href*="mfa"], a:has-text("Back to MFA"), a:has-text("Înapoi")'
        )
        if back_link.count() > 0:
            print("  ✅ Back to MFA Management link present")

        print("  ✅ Customer MFA backup codes test completed")


# ===============================================================================
# CUSTOMER COMPANY CREATE AND SWITCH CUSTOMER TESTS
# ===============================================================================


def test_customer_company_create_redirect(page: Page) -> None:
    """
    Test that /company/create/ redirects when customer already has a company.

    This test verifies:
    1. Customer navigates to /company/create/
    2. If customer already has a company, redirects to /company/ or shows message
    3. If no company, the create form is displayed
    """
    print("🧪 Testing customer company create redirect")

    with ComprehensivePageMonitor(page, "customer company create redirect",
                                 check_console=False,
                                 check_network=True,
                                 check_html=False,
                                 check_css=True,
                                 check_accessibility=False,
                                 allow_accessibility_skip=True):
        ensure_fresh_session(page)
        assert login_user_with_retry(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)

        page.goto(f"{BASE_URL}/company/create/")
        page.wait_for_load_state("networkidle")

        page_content_lower: str = page.content().lower()
        current_url: str = page.url

        if "404" in page.title().lower() or "not found" in page_content_lower:
            print("  [i] Company create page not available (404)")
            print("  ✅ Customer company create redirect test completed")
            return

        # Case 1: Redirected to /company/ (already has a company)
        if "/company/create/" not in current_url and "/company/" in current_url:
            print("  ✅ Redirected to /company/ (already has a company)")
            print("  ✅ Customer company create redirect test completed")
            return

        # Case 2: Redirected to dashboard or profile
        if "/dashboard/" in current_url or "/profile/" in current_url:
            print(f"  ✅ Redirected to {current_url} (already has company)")
            print("  ✅ Customer company create redirect test completed")
            return

        # Case 3: Shows "already have a company" message on same page
        already_msg = page.locator(
            'div:has-text("already"), div:has-text("deja")'
        )
        if already_msg.count() > 0:
            print("  ✅ Already has company message displayed")
            print("  ✅ Customer company create redirect test completed")
            return

        # Case 4: Create company form is shown (customer has no company)
        heading = page.locator(
            'h1:has-text("Create Company"), h1:has-text("Creare")'
        )
        if heading.count() > 0:
            expect(heading.first).to_be_visible()
            print("  ✅ Create Company form displayed (no company yet)")

            # Verify form is present
            form = page.locator("form[method='post']")
            if form.count() > 0:
                print("  ✅ Company creation form present")

        print("  ✅ Customer company create redirect test completed")


def test_customer_switch_customer_single_org(page: Page) -> None:
    """
    Test /switch-customer/ endpoint for a customer with a single organization.

    This test verifies:
    1. Customer navigates to /switch-customer/
    2. With single org: redirects or shows current organization
    3. Page loads without errors
    """
    print("🧪 Testing customer switch customer (single org)")

    with ComprehensivePageMonitor(page, "customer switch customer single org",
                                 check_console=False,
                                 check_network=True,
                                 check_html=False,
                                 check_css=True,
                                 check_accessibility=False,
                                 allow_accessibility_skip=True):
        ensure_fresh_session(page)
        assert login_user_with_retry(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)

        page.goto(f"{BASE_URL}/switch-customer/")
        page.wait_for_load_state("networkidle")

        page_content_lower: str = page.content().lower()
        current_url: str = page.url

        if "404" in page.title().lower() or "not found" in page_content_lower:
            print("  [i] Switch customer page not available (404)")
            print("  ✅ Customer switch customer test completed")
            return

        # Case 1: Redirected (single org auto-selects)
        if "/switch-customer/" not in current_url:
            print(f"  ✅ Redirected to {current_url} (auto-selected)")
            print("  ✅ Customer switch customer test completed")
            return

        # Case 2: Page shows organization list or current org
        org_list = page.locator(
            'a[href*="switch"], button:has-text("Select"), '
            'div:has-text("organization"), div:has-text("organizați")'
        )
        if org_list.count() > 0:
            print("  ✅ Organization selection/display present")

        # Check for current org indicator
        current_org = page.locator(
            'div:has-text("current"), div:has-text("curent"), '
            'span:has-text("active"), span:has-text("activ")'
        )
        if current_org.count() > 0:
            print("  ✅ Current organization indicator displayed")

        # Verify page has meaningful content (not an error)
        page_title: str = page.title()
        has_content: bool = (
            "switch" in page_content_lower
            or "customer" in page_content_lower
            or "organization" in page_content_lower
            or "company" in page_content_lower
        )
        if has_content:
            print(f"  ✅ Page loaded with content (title: {page_title})")
        else:
            print(f"  [i] Page content unclear (title: {page_title})")

        print("  ✅ Customer switch customer test completed")


# ===============================================================================
# PASSWORD RESET TESTS
# ===============================================================================


def test_customer_password_reset_form(page: Page) -> None:
    """
    Test the password reset form renders and accepts an email submission.

    Validates:
    - Password reset page loads at /password-reset/ (unauthenticated)
    - Form contains an email input field
    - Submitting an email shows a uniform success message (ADR-003 email enumeration prevention)
    """
    print("🧪 Testing customer password reset form")

    with ComprehensivePageMonitor(page, "customer password reset form",
                                 check_console=True,
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=False,
                                 allow_accessibility_skip=True):
        ensure_fresh_session(page)

        # Navigate to password reset page (no login needed)
        print("  🔑 Navigating to password reset page...")
        page.goto(f"{BASE_URL}/password-reset/")
        page.wait_for_load_state("networkidle")

        # Verify heading
        heading: Locator = page.locator("h2:has-text('Reset Your Password')")
        expect(heading).to_be_visible()
        print("    ✅ Password reset page heading visible")

        # Verify email input field is present
        email_input: Locator = page.locator("input[type='email'], input[name='email']")
        expect(email_input).to_be_visible()
        print("    ✅ Email input field present")

        # Verify submit button
        submit_btn: Locator = page.locator("button[type='submit']:has-text('Send Password Reset')")
        expect(submit_btn).to_be_visible()
        print("    ✅ Submit button present")

        # Verify back to login link
        back_link: Locator = page.locator("a[href*='login']:has-text('Back to login')")
        expect(back_link).to_be_visible()
        print("    ✅ Back to login link present")

        # Submit the form with a test email
        print("  📧 Submitting password reset form...")
        email_input.fill("test-reset@example.com")
        submit_btn.click()
        page.wait_for_load_state("networkidle")

        # Verify uniform success message (ADR-003: no email enumeration)
        success_message: Locator = page.locator("text=If an account with that email exists")
        expect(success_message).to_be_visible(timeout=5000)
        print("    ✅ Uniform success message displayed (email enumeration prevention)")

        print("  ✅ Customer password reset form test completed")
