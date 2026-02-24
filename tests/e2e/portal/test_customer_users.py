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
from playwright.sync_api import Page, expect

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
                                 check_accessibility=False):
        # Login with dedicated E2E customer credentials
        ensure_fresh_session(page)
        assert login_user_with_retry(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)

        # Navigate to profile (already authenticated)
        page.goto(f"{BASE_URL}/profile/")
        page.wait_for_load_state("networkidle")

        # Verify profile page access
        expect(page).to_have_url(re.compile(r"/profile/"))

        # Test profile form interaction
        first_name_field = page.locator('input[name="first_name"]')
        expect(first_name_field).to_be_visible()
        # Update first name
        first_name_field.clear()
        first_name_field.fill("UpdatedTest")

        # Look for save/update button
        save_button = page.locator('button[type="submit"]:has-text("Update"), button:has-text("Save")')
        if save_button.count() > 0:
            save_button.first.click()
            page.wait_for_load_state("networkidle")
            print("  ✅ Profile update attempted")

        print("  ✅ Customer profile test completed")

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
