"""
E2E Element Interaction Utilities — safe click, count elements.

Low-level page interaction helpers used by navigation and mobile modules.
"""

from playwright.sync_api import Page


def safe_click_element(page: Page, selector: str, description: str | None = None) -> bool:
    """
    Safely click an element with proper error handling.

    Args:
        page: Playwright page object
        selector: CSS selector for the element
        description: Optional description for logging

    Returns:
        bool: True if click successful, False otherwise

    Example:
        success = safe_click_element(page, 'button[type="submit"]', 'submit button')
    """
    desc = description or selector
    print(f"🔘 Attempting to click: {desc}")

    try:
        element = page.locator(selector)

        if element.count() == 0:
            print(f"⚠️  Element not found: {desc}")
            return False

        if not element.first.is_visible():
            print(f"⚠️  Element not visible: {desc}")
            return False

        if not element.first.is_enabled():
            print(f"⚠️  Element not enabled: {desc}")
            return False

        # Perform the click
        element.first.click(timeout=2000)
        page.wait_for_load_state("networkidle", timeout=3000)

        print(f"✅ Successfully clicked: {desc}")
        return True

    except Exception as e:
        print(f"❌ Click failed for {desc}: {str(e)[:100]}")
        return False


def count_elements(page: Page, selector: str, description: str | None = None) -> int:
    """
    Count elements matching a selector with logging.

    Args:
        page: Playwright page object
        selector: CSS selector for the elements
        description: Optional description for logging

    Returns:
        int: Number of elements found

    Example:
        button_count = count_elements(page, 'button', 'buttons')
    """
    desc = description or selector

    try:
        count = page.locator(selector).count()
        print(f"📊 Found {count} {desc}")
        return count

    except Exception as e:
        print(f"❌ Error counting {desc}: {str(e)[:100]}")
        return 0
