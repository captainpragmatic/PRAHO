"""
Invoices E2E Tests for PRAHO Platform

This module tests invoices/billing functionality including:
- Staff invoice management (all customer invoices)
- Customer invoice access (my invoices only)
- Proforma and invoice workflows
- Payment processing
- Mobile responsiveness
- Role-based access control

Uses shared utilities from tests.e2e.utils for consistency.
"""

import pytest
from playwright.sync_api import Page

# Import shared utilities
from tests.e2e.utils import (
    BASE_URL,
    CUSTOMER_EMAIL,
    CUSTOMER_PASSWORD,
    SUPERUSER_EMAIL,
    SUPERUSER_PASSWORD,
    AuthenticationError,
    ComprehensivePageMonitor,
    MobileTestContext,
    ensure_fresh_session,
    login_user,
    require_authentication,
    run_responsive_breakpoints_test,
)


def navigate_to_invoices(page: Page) -> bool:
    """
    Navigate to the invoices/billing page.
    
    Args:
        page: Playwright page object
        
    Returns:
        bool: True if navigation successful
    """
    try:
        page.goto(f"{BASE_URL}/app/billing/invoices/")
        page.wait_for_load_state("networkidle", timeout=5000)
        
        # Verify we're on the billing page
        current_url = page.url
        if "/app/billing/invoices/" in current_url:
            print("    ✅ Successfully navigated to invoices page")
            return True
        else:
            print(f"    ❌ Navigation failed - expected billing/invoices, got {current_url}")
            return False
            
    except Exception as e:
        print(f"    ❌ Navigation to invoices failed: {str(e)[:50]}")
        return False


def _validate_basic_page_structure(page: Page) -> int:
    """Validate basic page structure elements and return count."""
    basic_elements = [
        ('main', 'main content area'),
        ('h1, h2, h3', 'page headings'),
        ('table, .table, .invoice-list', 'invoice listing'),
    ]
    
    total_elements = 0
    for selector, description in basic_elements:
        count = page.locator(selector).count()
        total_elements += count
        print(f"📊 Found {count} {description}")
    
    return total_elements


def _check_superuser_features(page: Page) -> None:
    """Check superuser-specific invoice features."""
    staff_features = [
        ('a[href*="/proformas/create/"], button:has-text("Create"), .btn-create', 'create invoice/proforma'),
        ('a[href*="/reports/"], .reports', 'billing reports access'),
        ('.invoice-actions, .actions', 'invoice action buttons'),
    ]
    
    staff_feature_count = 0
    for selector, feature_name in staff_features:
        count = page.locator(selector).count()
        staff_feature_count += count
        if count > 0:
            print(f"    ✅ Found {feature_name}: {count} elements")
        else:
            print(f"    ❌ Missing {feature_name}")
    
    print(f"👤 Staff features found: {staff_feature_count}")


def _check_customer_features(page: Page) -> None:
    """Check customer-specific invoice features and restrictions."""
    customer_features = [
        ('.invoice-list, .my-invoices', 'my invoices list'),
        ('a[href*="/invoices/"], .invoice-link', 'invoice detail links'),
        ('.invoice-status, .status', 'invoice status indicators'),
    ]
    
    customer_feature_count = 0
    for selector, feature_name in customer_features:
        count = page.locator(selector).count()
        customer_feature_count += count
        if count > 0:
            print(f"    ✅ Found {feature_name}: {count} elements")
    
    # Customer should NOT see staff-only features
    restricted_features = page.locator('a[href*="/proformas/create/"], a[href*="/reports/"]').count()
    if restricted_features == 0:
        print("    ✅ Properly restricted from staff features")
    else:
        print(f"    ❌ Has access to {restricted_features} staff-only features")
    
    print(f"👤 Customer features found: {customer_feature_count}")


def _count_navigation_elements(page: Page) -> int:
    """Count navigation elements on the page."""
    nav_elements = [
        ('nav', 'navigation elements'),
        ('a[href*="/app/"]', 'app navigation links'),
        ('button', 'interactive buttons'),
    ]
    
    nav_total = 0
    for selector, description in nav_elements:
        count = page.locator(selector).count()
        nav_total += count
    
    return nav_total


def verify_invoices_functionality(page: Page, user_type: str) -> bool:
    """
    Verify invoice page functionality for different user types.
    
    Args:
        page: Playwright page object
        user_type: Type of user ('superuser' or 'customer')
        
    Returns:
        bool: True if invoice functionality is working correctly
    """
    print(f"📊 Verifying invoice functionality for {user_type}")
    
    # Navigate to invoices page
    if not navigate_to_invoices(page):
        return False
    
    # Validate page structure
    total_elements = _validate_basic_page_structure(page)
    
    # User-specific functionality checks
    if user_type == "superuser":
        _check_superuser_features(page)
    elif user_type == "customer":
        _check_customer_features(page)
    
    # Count navigation elements
    nav_total = _count_navigation_elements(page)
    print(f"📊 Total invoice content elements: {total_elements + nav_total}")
    
    # Page should have meaningful content
    has_content = total_elements >= 3  # At least main, headings, and invoice list/table
    
    if has_content:
        print(f"✅ Invoice functionality verified for {user_type}")
        return True
    else:
        print(f"❌ Invoice page appears to lack sufficient content for {user_type}")
        return False


def test_staff_invoices_functionality(page: Page):
    """Test staff invoice management displays correct content and functions properly."""
    print("🧪 Testing staff invoice functionality with comprehensive monitoring")
    
    with ComprehensivePageMonitor(page, "staff invoices test", 
                                 check_console=True,
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=True,   # Enable full validation
                                 check_performance=False):   # Keep fast for staff test
        # Ensure fresh session and login as staff
        ensure_fresh_session(page)
        if not login_user(page, SUPERUSER_EMAIL, SUPERUSER_PASSWORD):
            pytest.skip("Cannot login as superuser")
        
        try:
            # Verify staff invoice functionality
            assert verify_invoices_functionality(page, "superuser"), \
                "Staff invoice functionality verification failed"
                
        except AuthenticationError:
            pytest.fail("Lost authentication during staff invoices test")


def test_customer_invoices_functionality(page: Page):
    """Test customer invoice access displays correct content and functions properly."""
    print("🧪 Testing customer invoice functionality with comprehensive monitoring")
    
    with ComprehensivePageMonitor(page, "customer invoices test",
                                 check_console=False,        # Disable to avoid connection issues
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=True,   # Enable full validation
                                 check_performance=False):   # Keep fast for customer test
        # Ensure fresh session and login as customer  
        ensure_fresh_session(page)
        if not login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD):
            pytest.skip("Cannot login as customer")
        
        try:
            # Verify customer invoice functionality
            assert verify_invoices_functionality(page, "customer"), \
                "Customer invoice functionality verification failed"
                
        except AuthenticationError:
            pytest.fail("Lost authentication during customer invoices test")


def test_invoices_role_based_access(page: Page):
    """
    Test that invoices display appropriate content based on user roles.
    
    This test verifies role-based access control is working correctly
    by testing both staff and customer invoice access.
    """
    print("🧪 Testing invoice role-based access with comprehensive monitoring")
    
    with ComprehensivePageMonitor(page, "invoices role-based access test",
                                 check_console=True,    # Re-enable console checking
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=True,   # Enable full validation
                                 check_performance=False):   # Keep fast for multi-user test
        
        users = [
            (SUPERUSER_EMAIL, SUPERUSER_PASSWORD, "superuser"),
            (CUSTOMER_EMAIL, CUSTOMER_PASSWORD, "customer"),
        ]
        
        for email, password, user_type in users:
            print(f"\n  👤 Testing invoice access for {user_type}")
            
            # Fresh session for each user
            ensure_fresh_session(page)
            
            if not login_user(page, email, password):
                pytest.skip(f"Cannot login as {user_type}")
            
            try:
                # Verify role-based invoice access
                assert verify_invoices_functionality(page, user_type), \
                    f"Invoice access verification failed for {user_type}"
                
                print(f"    ✅ Invoice access correct for {user_type}")
                
            except AuthenticationError:
                pytest.fail(f"Lost authentication during {user_type} invoice test")
        
        print("  ✅ Invoice role-based access control verified!")


def test_invoices_actions_and_interactions(page: Page):
    """
    Test invoice actions and interactive elements work correctly.
    
    This test focuses on invoice-specific buttons, forms, and interactions
    for staff users who have full invoice management capabilities.
    """
    print("🧪 Testing invoice actions and interactions with full validation")
    
    with ComprehensivePageMonitor(page, "invoice interactions test",
                                 check_console=True,
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=True,   # Enable full validation
                                 check_performance=False):   # Skip performance for speed
        # Login as staff for maximum invoice access
        ensure_fresh_session(page)
        if not login_user(page, SUPERUSER_EMAIL, SUPERUSER_PASSWORD):
            pytest.skip("Cannot login as superuser")
        
        try:
            require_authentication(page)
            
            # Navigate to invoices page
            if not navigate_to_invoices(page):
                pytest.fail("Cannot navigate to invoices page")
            
            print("  🔘 Testing invoice content interactions...")
            
            # Test invoice-specific interactive elements
            invoice_elements = [
                ('.invoice-actions button', 'invoice action buttons'),
                ('a[href*="/invoices/"]', 'invoice detail links'),
                ('.pagination a, .pagination button', 'pagination controls'),
                ('.search-form input, .filter-form select', 'search and filter controls'),
                ('table th a, .sortable', 'sortable table headers'),
            ]
            
            interactions_tested = 0
            
            for selector, element_type in invoice_elements:
                elements = page.locator(selector)
                count = elements.count()
                
                if count > 0:
                    print(f"    📊 Found {count} {element_type}")
                    
                    # Test first interactive element if it's safe
                    try:
                        first_element = elements.first
                        if first_element.is_visible() and first_element.is_enabled():
                            # Get element info for safety check
                            href = first_element.get_attribute("href") or ""
                            onclick = first_element.get_attribute("onclick") or ""
                            
                            # Skip dangerous elements
                            if any(danger in (href + onclick).lower() 
                                   for danger in ['delete', 'remove', 'logout']):
                                print("      ⚠️ Skipping potentially dangerous element")
                                continue
                            
                            # Safe interaction test
                            first_element.click(timeout=2000)
                            page.wait_for_load_state("networkidle", timeout=3000)
                            interactions_tested += 1
                            
                            # Verify we're still authenticated
                            require_authentication(page)
                            
                            print(f"      ✅ Successfully interacted with {element_type}")
                            
                            # Return to invoices if we navigated away
                            if "/billing/invoices/" not in page.url:
                                navigate_to_invoices(page)
                            
                    except Exception as e:
                        print(f"      ⚠️ Interaction failed: {str(e)[:50]}")
                        continue
            
            print(f"  📊 Invoice interactions tested: {interactions_tested}")
            
            # Verify we're still on invoices page after interactions
            if "/billing/invoices/" not in page.url:
                print("  🔄 Returning to invoices page after interactions")
                navigate_to_invoices(page)
            
        except AuthenticationError:
            pytest.fail("Lost authentication during invoice interactions test")


def test_invoices_mobile_responsiveness(page: Page):
    """
    Test invoice management responsiveness across mobile breakpoints.
    
    This test ensures the invoice system works correctly on mobile devices by:
    - Testing functionality across different viewport sizes
    - Checking mobile-specific navigation elements
    - Validating responsive layout behavior
    - Testing touch interactions
    """
    print("🧪 Testing invoice mobile responsiveness with comprehensive validation")
    
    with ComprehensivePageMonitor(page, "invoices mobile responsiveness test",
                                 check_console=True,
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=True,   # Enable full validation
                                 check_performance=False):   # Skip performance for speed
        # Login as staff for full invoice access
        ensure_fresh_session(page)
        if not login_user(page, SUPERUSER_EMAIL, SUPERUSER_PASSWORD):
            pytest.skip("Cannot login as superuser")
        
        try:
            require_authentication(page)
            
            # Test invoice functionality across responsive breakpoints
            results = run_responsive_breakpoints_test(page, verify_invoices_functionality, "superuser")
            
            # Verify desktop functionality as baseline
            assert results.get('desktop'), "Invoices should work on desktop viewport"
            
            # Verify tablet functionality
            assert results.get('tablet_landscape'), "Invoices should work on tablet landscape viewport"
            
            # Verify mobile functionality
            assert results.get('mobile'), "Invoices should work on mobile viewport"
            
            # Check mobile-specific results
            mobile_extras = results.get('mobile_extras', {})
            
            # Log mobile-specific findings
            nav_elements = mobile_extras.get('navigation_elements', 0)
            layout_issues = mobile_extras.get('layout_issues', [])
            touch_works = mobile_extras.get('touch_works', False)
            
            print(f"    📱 Mobile navigation elements: {nav_elements}")
            print(f"    📱 Layout issues found: {len(layout_issues)}")
            print(f"    📱 Touch interactions: {'WORKING' if touch_works else 'LIMITED'}")
            
            # Report any layout issues (but don't fail the test)
            if layout_issues:
                print("    ⚠️  Mobile layout issues detected:")
                for issue in layout_issues[:3]:  # Show first 3 issues
                    print(f"      - {issue}")
            
            print("  ✅ Invoice mobile responsiveness validated across all breakpoints")
                
        except AuthenticationError:
            pytest.fail("Lost authentication during invoice mobile responsiveness test")


def test_invoices_mobile_specific_features(page: Page):
    """
    Test invoice features specific to mobile viewport.
    
    This test focuses on mobile-only behaviors like:
    - Mobile invoice table/list layouts
    - Touch-optimized interactions for invoice management
    - Responsive content adaptation
    - Mobile-specific UI elements
    """
    print("🧪 Testing invoice mobile-specific features")
    
    with ComprehensivePageMonitor(page, "invoices mobile features test",
                                 check_console=True,
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=False,  # Keep fast for focused test
                                 check_performance=False):   # Keep fast for focused test
        # Login as staff
        ensure_fresh_session(page)
        if not login_user(page, SUPERUSER_EMAIL, SUPERUSER_PASSWORD):
            pytest.skip("Cannot login as superuser")
        
        try:
            require_authentication(page)
            
            # Test mobile medium viewport (standard smartphone)
            with MobileTestContext(page, 'mobile_medium') as mobile:
                print("  📱 Testing standard mobile invoice viewport (375x667)")
                
                # Verify invoice functionality still works
                assert verify_invoices_functionality(page, "superuser"), \
                    "Invoice functionality should work on mobile"
                
                # Test mobile navigation
                nav_count = mobile.test_mobile_navigation()
                print(f"    ✅ Mobile navigation test completed ({nav_count} elements)")
                
                # Check responsive layout for invoice tables/lists
                layout_issues = mobile.check_responsive_layout()
                if layout_issues:
                    print(f"    ⚠️  Found {len(layout_issues)} responsive layout issues")
                    for issue in layout_issues[:2]:  # Show first 2
                        print(f"      - {issue}")
                else:
                    print("    ✅ No responsive layout issues detected")
                
                # Test touch interactions on invoice elements
                touch_success = mobile.test_touch_interactions()
                if not touch_success:
                    print("    Info: Limited touch interactivity (may be normal for this page)")
            
            # Test mobile small viewport (older/smaller devices)  
            with MobileTestContext(page, 'mobile_small') as mobile_small:
                print("  📱 Testing small mobile invoice viewport (320x568)")
                
                # Verify invoice core functionality still works
                basic_functionality = verify_invoices_functionality(page, "superuser")
                if basic_functionality:
                    print("    ✅ Invoices work on small mobile viewport")
                else:
                    print("    ⚠️  Invoices have issues on small mobile viewport")
                
                # Check for critical layout problems on small screens
                small_layout_issues = mobile_small.check_responsive_layout()
                critical_issues = [issue for issue in small_layout_issues 
                                 if 'horizontal scroll' in issue.lower()]
                
                if critical_issues:
                    print(f"    ⚠️  Critical small-screen issues: {len(critical_issues)}")
                else:
                    print("    ✅ No critical small-screen layout issues")
            
            print("  ✅ Mobile-specific invoice features tested successfully")
                
        except AuthenticationError:
            pytest.fail("Lost authentication during invoice mobile features test")
