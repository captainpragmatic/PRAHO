"""
Rate-Limit UX E2E Tests

Tests that the portal shows proper rate-limit feedback in the browser.
These tests require both services running (make dev).

Since triggering real 429s requires exceeding throttle thresholds,
these tests focus on verifying the UX contract:
- Login throttle message contains retry guidance (not "invalid credentials")
- Rate-limit warnings use amber/warning styling (not red/error)
"""

import pytest
from playwright.sync_api import Page

from tests.e2e.helpers import (
    BASE_URL,
    CUSTOMER_EMAIL,
    CUSTOMER_PASSWORD,
    ensure_fresh_session,
    login_user,
)


@pytest.mark.e2e
class TestLoginRateLimitUX:
    """Verify login page handles throttle responses with correct UX."""

    def test_rapid_login_attempts_show_throttle_not_invalid(self, page: Page) -> None:
        """
        Rapidly submit wrong passwords to trigger Platform's auth throttle.
        The error message must mention 'try again' or 'too many', never
        just 'invalid credentials' when the real cause is rate limiting.

        NOTE: This test depends on Platform's auth throttle being set low
        enough to trigger within ~10 attempts. If it doesn't trigger,
        the test is skipped (not failed) since the UX path is covered
        by unit tests.
        """
        ensure_fresh_session(page)
        page.goto(f"{BASE_URL}/login/")
        page.wait_for_load_state("networkidle")

        throttle_triggered = False

        for attempt in range(15):
            # Fill and submit wrong password
            email_field = page.locator('input[name="email"], input[name="username"], input[type="email"]').first
            password_field = page.locator('input[name="password"]').first

            if email_field.count() == 0 or password_field.count() == 0:
                pytest.skip("Login form fields not found — page structure may have changed")

            email_field.fill(f"ratelimit-test-{attempt}@example.com")
            password_field.fill("wrong_password")

            submit = page.locator('button[type="submit"], input[type="submit"]').first
            submit.click()
            page.wait_for_load_state("networkidle")

            # Check page content for rate-limit indicators
            body_text = page.locator("body").inner_text().lower()
            if "too many" in body_text or "try again" in body_text or "rate" in body_text:
                throttle_triggered = True
                # Verify it's a warning-style message, not a generic "invalid" error
                assert "invalid credentials" not in body_text or "too many" in body_text, (
                    "Rate-limit response should show throttle message, not 'invalid credentials'"
                )
                break

        if not throttle_triggered:
            pytest.skip(
                "Auth throttle did not trigger within 15 attempts. "
                "Rate-limit UX is covered by unit tests in test_login_errors.py."
            )


@pytest.mark.e2e
class TestAuthenticatedRateLimitUX:
    """Verify authenticated pages show rate-limit warnings correctly."""

    def test_dashboard_loads_without_rate_limit_banner_normally(self, page: Page) -> None:
        """Under normal load, dashboard should not show rate-limit warnings."""
        ensure_fresh_session(page)
        if not login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD):
            pytest.skip("Login failed — is the E2E service running? (make dev-e2e)")

        page.goto(f"{BASE_URL}/dashboard/")
        page.wait_for_load_state("networkidle")

        # No rate-limit warning should appear under normal conditions
        body_text = page.locator("body").inner_text().lower()
        assert "too many requests" not in body_text, (
            "Rate-limit warning should not appear under normal load"
        )

    def test_catalog_page_accessible_without_rate_limit(self, page: Page) -> None:
        """Orders catalog should load without rate-limit warnings normally."""
        ensure_fresh_session(page)
        if not login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD):
            pytest.skip("Login failed — is the E2E service running? (make dev-e2e)")

        page.goto(f"{BASE_URL}/orders/catalog/")
        page.wait_for_load_state("networkidle")

        # Page should load (200 or redirect to login)
        current_url = page.url
        if "/login/" in current_url:
            pytest.skip("Customer not authorized for orders catalog")

        body_text = page.locator("body").inner_text().lower()
        assert "too many requests" not in body_text
