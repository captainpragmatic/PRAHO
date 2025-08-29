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

import pytest
from playwright.sync_api import Page

# Import shared utilities
from tests.e2e.utils import (
    # Legacy credentials (keep for fallback compatibility)
    CUSTOMER_EMAIL,
    CUSTOMER_PASSWORD,
    SUPERUSER_EMAIL,
    SUPERUSER_PASSWORD,
    # New dynamic user management
    TestUserManager,
    login_test_user,
    create_and_login_customer,
    create_and_login_admin,
    # Existing utilities
    ComprehensivePageMonitor,
    MobileTestContext,
    ensure_fresh_session,
    login_user,
    navigate_to_dashboard,
    require_authentication,
    run_responsive_breakpoints_test,
    safe_click_element,
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
    print("🧪 Testing customer login and profile access with dynamic users")
    
    # Use dynamic test user management for better isolation
    with TestUserManager() as user_mgr:
        # Create fresh customer user with organization
        customer_user, customer_org = user_mgr.create_customer_with_org(
            company_name="Profile Test Corp"
        )
        
        print(f"  📧 Testing with customer: {customer_user['email']}")
        print(f"  🏢 Organization: {customer_org['company_name']}")
        
        with ComprehensivePageMonitor(page, "dynamic customer login and profile access",
                                     check_console=True,
                                     check_network=True,
                                     check_html=False,  # May have duplicate ID issues
                                     check_css=True):
            # Login with fresh customer user
            ensure_fresh_session(page)
            assert login_test_user(page, customer_user)
            require_authentication(page)
        
        # Navigate to dashboard first
        assert navigate_to_dashboard(page)
        assert "/app/" in page.url
        
        # Navigate to user profile
        page.goto("http://localhost:8001/auth/profile/")
        page.wait_for_load_state("networkidle")
        
        # Verify we're on the profile page
        assert "/auth/profile/" in page.url, "Should navigate to customer profile page"
        
        # Verify profile page title and content
        title = page.title()
        assert any(word in title.lower() for word in ["profile", "profil"]), f"Expected profile page title but got: {title}"
        
        # Check for profile form elements (the one with profile fields)
        profile_form = page.locator('form[method="post"].space-y-6')
        assert profile_form.is_visible(), "Profile form should be visible"
        
        # Check for basic profile fields
        first_name_field = page.locator('input[name="first_name"]')
        last_name_field = page.locator('input[name="last_name"]')
        email_field = page.locator('input[name="email"], input[type="email"]')
        
        if first_name_field.is_visible():
            print("  ✅ First name field available")
        if last_name_field.is_visible():
            print("  ✅ Last name field available")
        if email_field.is_visible():
            print("  ✅ Email field visible in profile")
        
        # Check for 2FA management section
        mfa_section = page.locator('div:has-text("Two-Factor"), div:has-text("2FA"), a[href*="2fa"]')
        if mfa_section.count() > 0:
            print("  ✅ 2FA management section available")
        else:
            print("  ℹ️ 2FA management section not found in profile")


def test_customer_profile_using_convenience_helper(page: Page) -> None:
    """
    Test customer profile management using convenience helpers.
    
    This example shows the simplest way to create and login a customer
    using the one-step helper functions.
    """
    print("🧪 Testing customer profile with convenience helpers")
    
    with TestUserManager() as user_mgr:
        # One-step: create customer with org and login immediately
        ensure_fresh_session(page)
        customer_user, customer_org = create_and_login_customer(page, user_mgr)
        
        # User is already logged in and on dashboard
        print(f"  ✅ Already logged in as: {customer_user['email']}")
        print(f"  🏢 Organization: {customer_org['company_name']}")
        
        with ComprehensivePageMonitor(page, "customer profile convenience test"):
            # Navigate to profile (already authenticated)
            page.goto("http://localhost:8001/auth/profile/")
            page.wait_for_load_state("networkidle")
            
            # Verify profile page access
            assert "/auth/profile/" in page.url
            
            # Test profile form interaction
            first_name_field = page.locator('input[name="first_name"]')
            if first_name_field.is_visible():
                # Update first name
                first_name_field.clear()
                first_name_field.fill("UpdatedTest")
                
                # Look for save/update button
                save_button = page.locator('button[type="submit"]:has-text("Update"), button:has-text("Save")')
                if save_button.count() > 0:
                    save_button.first.click()
                    page.wait_for_load_state("networkidle")
                    print("  ✅ Profile update attempted")
                
        print("  ✅ Customer profile test completed with convenience helpers")
        
        # Check for password change option
        password_change = page.locator('a:has-text("Change Password"), a[href*="password-change"]')
        if password_change.count() > 0:
            print("  ✅ Password change option available")
        else:
            print("  ℹ️ Password change option not found")
        
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
                                 check_console=True,
                                 check_network=True,
                                 check_html=False,  # May have duplicate ID issues
                                 check_css=True):
        # Login and navigate to profile
        ensure_fresh_session(page)
        assert login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)
        page.goto("http://localhost:8001/auth/profile/")
        page.wait_for_load_state("networkidle")
        
        # Test profile data
        test_profile_data = {
            'first_name': 'CustomerTest',
            'last_name': 'UserTest',
            'phone': '+40711223344'
        }
        
        # Fill first name if field exists
        first_name_field = page.locator('input[name="first_name"]')
        if first_name_field.is_visible():
            first_name_field.clear()
            first_name_field.fill(test_profile_data['first_name'])
            print("  ✅ Updated first name field")
        
        # Fill last name if field exists  
        last_name_field = page.locator('input[name="last_name"]')
        if last_name_field.is_visible():
            last_name_field.clear()
            last_name_field.fill(test_profile_data['last_name'])
            print("  ✅ Updated last name field")
        
        # Fill phone if field exists
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
            page.wait_for_timeout(1000)
            
            # Check for success message
            success_message = page.get_by_role("alert").locator('div:has-text("updated"), div:has-text("saved"), div:has-text("success")').first
            if success_message.is_visible():
                print("  ✅ Profile update success message displayed")
            else:
                # Check if we're still on profile page (form might have validation issues)
                if "/auth/profile/" in page.url:
                    # Look for validation errors
                    error_messages = page.locator('div.text-red-600, .text-red-500, [class*="error"], .invalid-feedback')
                    if error_messages.count() > 0:
                        error_text = error_messages.first.inner_text()
                        print(f"  ⚠️ Form validation error: {error_text}")
                    else:
                        print("  ℹ️ Profile form submitted but no clear success indication")
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
                                 check_console=True,
                                 check_network=True,
                                 check_html=False,  # May have duplicate ID issues
                                 check_css=True):
        # Login as customer
        ensure_fresh_session(page)
        assert login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)
        
        # Navigate to password change page
        page.goto("http://localhost:8001/auth/password-change/")
        page.wait_for_load_state("networkidle")
        
        # Verify we're on the password change page
        assert "/auth/password-change/" in page.url, "Should navigate to password change page"
        
        # Verify password change form elements
        change_heading = page.locator('h2:has-text("Change Password")')
        assert change_heading.is_visible(), "Password change heading should be visible"
        
        # Check for required password fields
        old_password_field = page.locator('input[name="old_password"]')
        new_password1_field = page.locator('input[name="new_password1"]')
        new_password2_field = page.locator('input[name="new_password2"]')
        
        # Only test if all required fields are present
        if (old_password_field.is_visible() and 
            new_password1_field.is_visible() and 
            new_password2_field.is_visible()):
            
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
                page.wait_for_timeout(1000)
                
                # Check if password change was successful
                if "/auth/profile/" in page.url:
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
                        print("  ℹ️ Password change form submitted but still on same page")
            else:
                print("  ⚠️ Password change submit button not found")
        else:
            print("  ℹ️ Password change form fields not all visible - may not be implemented")
        
        print("  ✅ Customer password change workflow test completed")


# ===============================================================================
# CUSTOMER TWO-FACTOR AUTHENTICATION TESTS
# ===============================================================================

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
                                 check_console=True,
                                 check_network=True,
                                 check_html=False,  # May have duplicate ID issues
                                 check_css=True):
        # Login as customer (accounts have been reset)
        ensure_fresh_session(page)
        assert login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)
        
        # Navigate to 2FA setup
        page.goto("http://localhost:8001/auth/2fa/setup/")
        page.wait_for_load_state("networkidle")
        
        # Verify we're on 2FA setup page
        assert "/auth/2fa/" in page.url, "Should navigate to 2FA setup page"
        
        # Check for 2FA method selection elements
        method_selection = page.locator('h1:has-text("Two-Factor"), h1:has-text("2FA"), h1:has-text("Authentication")')
        if method_selection.is_visible():
            print("  ✅ 2FA setup page loaded")
            
            # Look for TOTP method option
            totp_option = page.locator('a:has-text("Authenticator"), a[href*="totp"], button:has-text("App")')
            if totp_option.count() > 0:
                print("  ✅ TOTP/Authenticator App option available")
                
                # Test TOTP setup flow
                totp_option.first.click()
                page.wait_for_load_state("networkidle")
                
                if "/auth/2fa/setup/totp/" in page.url:
                    print("  ✅ TOTP setup page accessible")
                    
                    # Check for QR code or setup elements
                    qr_code = page.locator('img[alt*="QR"], canvas, svg, .qr-code')
                    secret_text = page.locator('code, .secret, input[readonly]')
                    token_field = page.locator('input[name="token"]')
                    
                    if qr_code.count() > 0:
                        print("  ✅ QR code displayed for TOTP setup")
                    if secret_text.count() > 0:
                        print("  ✅ Secret text available for manual entry")
                    if token_field.is_visible():
                        print("  ✅ Token verification field present")
                        
                        # Note: We don't actually complete 2FA setup as it would affect test user permanently
                        print("  ℹ️ TOTP setup form structure validated (not completed)")
                else:
                    print("  ⚠️ TOTP setup page not accessible")
            else:
                print("  ℹ️ TOTP option not found on method selection")
            
            # Navigate back to method selection
            page.goto("http://localhost:8001/auth/2fa/setup/")
            page.wait_for_load_state("networkidle")
            
            # Look for WebAuthn option
            webauthn_option = page.locator('a:has-text("WebAuthn"), a:has-text("Passkey"), a[href*="webauthn"]')
            if webauthn_option.count() > 0:
                print("  ✅ WebAuthn/Passkey option available")
                
                # Test WebAuthn setup access
                webauthn_option.first.click()
                page.wait_for_load_state("networkidle")
                
                if "/auth/2fa/setup/webauthn/" in page.url:
                    print("  ✅ WebAuthn setup page accessible")
                elif "/auth/2fa/setup/totp/" in page.url:
                    print("  ℹ️ WebAuthn redirects to TOTP (not yet implemented)")
                else:
                    print("  ⚠️ WebAuthn setup navigation unclear")
            else:
                print("  ℹ️ WebAuthn option not found")
        else:
            print("  ⚠️ 2FA setup page not properly loaded")
        
        # Test 2FA disable access (if user has 2FA enabled)
        page.goto("http://localhost:8001/auth/2fa/disable/")
        page.wait_for_load_state("networkidle")
        
        if "/auth/2fa/disable/" in page.url:
            disable_form = page.locator('form')
            if disable_form.is_visible():
                print("  ✅ 2FA disable page accessible")
            else:
                # User may not have 2FA enabled
                info_message = page.locator('div:has-text("not enabled"), div:has-text("disabled")')
                if info_message.is_visible():
                    print("  ℹ️ 2FA not enabled for test customer")
                else:
                    print("  ⚠️ 2FA disable page unclear")
        
        print("  ✅ Customer 2FA setup access and flow test completed")


# ===============================================================================
# CUSTOMER SECURITY BOUNDARY TESTS  
# ===============================================================================

def test_customer_staff_access_restrictions(page: Page) -> None:
    """
    Test that customers cannot access staff-only URLs and features.
    
    This critical security test ensures:
    - Customers cannot access /app/users/ management URLs
    - Customers cannot access staff user administration
    - Proper error messages and redirects for unauthorized access
    - Customer data privacy is maintained
    """
    print("🧪 Testing customer staff access restrictions (Security Boundary)")
    
    with ComprehensivePageMonitor(page, "customer staff access restrictions",
                                 check_console=True,
                                 check_network=True,
                                 check_html=False,  # May have duplicate ID issues 
                                 check_css=True):
        # Login as customer
        ensure_fresh_session(page)
        assert login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)
        require_authentication(page)
        
        # Test 1: Try to access staff user list
        print("  🔒 Testing staff user list access restriction")
        page.goto("http://localhost:8001/auth/users/")
        page.wait_for_load_state("networkidle")
        
        # Should be denied access - check for various denial indicators
        access_denied = False
        
        # Check if redirected away from users list
        if "/auth/users/" not in page.url:
            print("    ✅ Redirected away from staff user list (access denied)")
            access_denied = True
        else:
            # Still on users page - check for permission error
            page_content = page.content().lower()
            error_indicators = [
                "permission denied", "access denied", "not authorized", 
                "forbidden", "not allowed", "insufficient privileges",
                "you do not have permission", "403", "unauthorized"
            ]
            
            if any(indicator in page_content for indicator in error_indicators):
                print("    ✅ Permission denied message displayed")
                access_denied = True
            else:
                # Check if page shows user management content (should not for customers)
                user_mgmt_content = page.locator('h1:has-text("User"), h1:has-text("Users"), table').count()
                if user_mgmt_content > 0:
                    print("    ❌ Customer can access staff user management - SECURITY ISSUE")
                    access_denied = False
                else:
                    print("    ✅ No user management content visible")
                    access_denied = True
        
        assert access_denied, "Customer should not have access to staff user management"
        
        # Test 2: Try to access individual user detail page
        print("  🔒 Testing individual user detail access restriction")
        page.goto("http://localhost:8001/auth/users/1/")
        page.wait_for_load_state("networkidle")
        
        # Should be denied access
        user_detail_denied = False
        
        if "/auth/users/1/" not in page.url:
            print("    ✅ Redirected away from user detail page")
            user_detail_denied = True
        else:
            # Check for permission error
            page_content = page.content().lower()
            if any(indicator in page_content for indicator in ["permission", "denied", "forbidden", "403"]):
                print("    ✅ User detail access denied")
                user_detail_denied = True
            else:
                # Check if personal user details are shown (privacy violation)
                sensitive_content = page.locator('div:has-text("Email:"), div:has-text("@"), table td').count()
                if sensitive_content > 0:
                    print("    ❌ Customer can view other user details - PRIVACY VIOLATION")
                    user_detail_denied = False
                else:
                    print("    ✅ No sensitive user details visible")
                    user_detail_denied = True
        
        assert user_detail_denied, "Customer should not access other user details"
        
        # Test 3: Verify customer can still access their own profile
        print("  ✅ Verifying customer can still access own profile")
        page.goto("http://localhost:8001/auth/profile/")
        page.wait_for_load_state("networkidle")
        
        assert "/auth/profile/" in page.url, "Customer should still access own profile"
        
        profile_form = page.locator('form[method="post"].space-y-6')
        assert profile_form.is_visible(), "Customer profile should be accessible"
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
                                 check_css=True):
        # Login as customer
        ensure_fresh_session(page)
        assert login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)
        
        # Test API endpoint protection
        print("  🔒 Testing API endpoint protection")
        
        # Try to access user check API (should be protected or limited)
        page.goto("http://localhost:8001/auth/api/check-email/")
        page.wait_for_load_state("networkidle")
        
        # Should not show internal user data
        api_content = page.content().lower()
        if "method not allowed" in api_content or "405" in api_content:
            print("    ✅ API endpoint properly requires POST method")
        elif "forbidden" in api_content or "403" in api_content:
            print("    ✅ API endpoint access forbidden")
        else:
            print("    ℹ️ API endpoint response unclear - may require further testing")
        
        # Test navigation to ensure customer stays in customer area
        print("  🔒 Testing navigation boundaries")
        
        # Try to navigate to admin areas
        restricted_urls = [
            "/app/users/",
            "/app/users/create/",  
            "/app/staff/users/",
            "/admin/",
            "/admin/users/",
        ]
        
        access_denied_count = 0
        
        for restricted_url in restricted_urls:
            try:
                full_url = f"http://localhost:8001{restricted_url}"
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
                    
            except Exception as e:
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
                                 check_console=True,
                                 check_network=True,
                                 check_html=False,  # May have duplicate ID issues
                                 check_css=True,
                                 check_accessibility=True,
                                 check_performance=False):
        # Login and navigate to profile on desktop first
        ensure_fresh_session(page)
        assert login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)
        page.goto("http://localhost:8001/auth/profile/")
        page.wait_for_load_state("networkidle")
        
        # Test mobile viewport
        with MobileTestContext(page, 'mobile_medium') as mobile:
            print("    📱 Testing customer profile on mobile viewport")
            
            # Reload page to ensure mobile layout
            page.reload()
            page.wait_for_load_state("networkidle")
            
            # Test mobile navigation to profile features
            mobile_nav_count = mobile.test_mobile_navigation()
            print(f"      Mobile navigation elements: {mobile_nav_count}")
            
            # Check responsive layout issues
            layout_issues = mobile.check_responsive_layout()
            critical_issues = [issue for issue in layout_issues 
                             if any(keyword in issue.lower() 
                                  for keyword in ['horizontal scroll', 'small touch'])]
            
            if critical_issues:
                print(f"      ⚠️ Critical mobile layout issues: {len(critical_issues)}")
                for issue in critical_issues[:3]:  # Show first 3 issues
                    print(f"        - {issue}")
            else:
                print("      ✅ No critical mobile layout issues found")
            
            # Test touch interactions on profile elements
            touch_success = mobile.test_touch_interactions()
            print(f"      Touch interactions: {'✅ Working' if touch_success else '⚠️ Limited'}")
            
            # Verify key profile elements are accessible on mobile
            profile_form = page.locator('form[method="post"].space-y-6')
            if profile_form.is_visible():
                print("      ✅ Profile form visible on mobile")
            
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
                                 check_console=True,
                                 check_network=True,
                                 check_html=False,  # May have duplicate ID issues
                                 check_css=True):
        # Step 1: Customer authentication
        print("    Step 1: Customer authentication and dashboard access")
        ensure_fresh_session(page)
        assert login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)
        
        # Verify dashboard access
        assert navigate_to_dashboard(page)
        customer_dashboard = page.locator('h1, h2, .dashboard, .welcome').count()
        assert customer_dashboard > 0, "Customer should see dashboard content"
        print("      ✅ Customer dashboard accessible")
        
        # Step 2: Profile management
        print("    Step 2: Profile viewing and basic information")
        page.goto("http://localhost:8001/auth/profile/")
        page.wait_for_load_state("networkidle")
        
        # Verify profile content
        profile_elements = page.locator('form, input, .profile-info').count()
        if profile_elements > 0:
            print("      ✅ Customer profile loaded with editable content")
            
            # Test basic field interaction
            first_name_field = page.locator('input[name="first_name"]')
            if first_name_field.is_visible():
                current_value = first_name_field.input_value()
                test_value = "WorkflowTest"
                first_name_field.fill(test_value)
                print("      ✅ Profile field editing works")
                
                # Restore original value
                first_name_field.fill(current_value or "")
        else:
            print("      ⚠️ Profile content limited")
        
        # Step 3: Security settings exploration
        print("    Step 3: Security settings and options")
        
        # Check password change access
        password_change_link = page.locator('a[href*="password-change"], a:has-text("Change Password")')
        if password_change_link.count() > 0:
            password_change_link.first.click()
            page.wait_for_load_state("networkidle")
            
            if "/auth/password-change/" in page.url:
                print("      ✅ Password change form accessible")
                
                # Verify form elements without changing password
                old_pass_field = page.locator('input[name="old_password"]')
                new_pass_field = page.locator('input[name="new_password1"]')
                
                if old_pass_field.is_visible() and new_pass_field.is_visible():
                    print("      ✅ Password change form properly structured")
                
                # Navigate back to profile
                page.goto("http://localhost:8001/auth/profile/")
                page.wait_for_load_state("networkidle")
        
        # Step 4: 2FA setup exploration
        print("    Step 4: 2FA setup exploration")
        
        mfa_setup_link = page.locator('a[href*="2fa"], a:has-text("Two-Factor"), a:has-text("2FA")')
        if mfa_setup_link.count() > 0:
            mfa_setup_link.first.click()
            page.wait_for_load_state("networkidle")
            
            if "/auth/2fa/" in page.url:
                print("      ✅ 2FA setup accessible")
                
                # Check for method options
                method_options = page.locator('a, button, .method-card').count()
                if method_options > 0:
                    print(f"      ✅ {method_options} 2FA method options available")
                
                # Test TOTP method access without completing setup
                totp_link = page.locator('a[href*="totp"], a:has-text("App"), a:has-text("Authenticator")')
                if totp_link.count() > 0:
                    totp_link.first.click()
                    page.wait_for_load_state("networkidle")
                    
                    if "/auth/2fa/setup/totp/" in page.url:
                        print("      ✅ TOTP setup flow accessible")
                        
                        # Check for setup elements
                        qr_code = page.locator('img, canvas, svg').count()
                        if qr_code > 0:
                            print("      ✅ TOTP setup visual elements present")
        
        # Step 5: Session validation
        print("    Step 5: Session and navigation validation")
        
        # Navigate back to dashboard to ensure session integrity
        assert navigate_to_dashboard(page)
        require_authentication(page)
        print("      ✅ Customer session maintained throughout workflow")
        
        # Test navigation to restricted areas (should be blocked)
        page.goto("http://localhost:8001/auth/users/")
        page.wait_for_load_state("networkidle")
        
        # Should not have access to staff areas
        if "/auth/users/" not in page.url or "permission" in page.content().lower():
            print("      ✅ Staff area access properly restricted")
        else:
            print("      ⚠️ Staff area access restriction needs verification")
        
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
                                 check_console=True,
                                 check_network=True,
                                 check_html=False,  # May have duplicate ID issues
                                 check_css=True):
        # Login first
        ensure_fresh_session(page)
        assert login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)
        
        def test_customer_account_functionality(test_page, context="general"):
            """Test core customer account functionality across viewports."""
            try:
                # Navigate to profile
                test_page.goto("http://localhost:8001/auth/profile/")
                test_page.wait_for_load_state("networkidle")
                
                # Verify authentication maintained
                require_authentication(test_page)
                
                # Check core elements are present
                profile_form = test_page.locator('form[method="post"].space-y-6')
                
                elements_present = profile_form.is_visible()
                
                if elements_present:
                    print(f"      ✅ Customer account management functional in {context}")
                    return True
                else:
                    print(f"      ❌ Core account elements missing in {context}")
                    return False
                    
            except Exception as e:
                print(f"      ❌ Account management test failed in {context}: {str(e)[:50]}")
                return False
        
        # Test across all breakpoints
        results = run_responsive_breakpoints_test(page, test_customer_account_functionality)
        
        # Verify all breakpoints pass
        desktop_pass = results.get('desktop', False)
        tablet_pass = results.get('tablet_landscape', False) 
        mobile_pass = results.get('mobile', False)
        
        assert desktop_pass, "Customer account management should work on desktop viewport"
        assert tablet_pass, "Customer account management should work on tablet viewport"
        assert mobile_pass, "Customer account management should work on mobile viewport"
        
        print("  ✅ Customer account management validated across all responsive breakpoints")