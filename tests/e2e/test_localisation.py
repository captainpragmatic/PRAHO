"""Profile localisation through both real services; restore preferences after each test."""

from datetime import date

import pytest
from playwright.sync_api import Page, expect

from tests.e2e.helpers.constants import (
    BASE_URL,
    CUSTOMER_EMAIL,
    CUSTOMER_PASSWORD,
    LOGIN_URL,
    PLATFORM_BASE_URL,
    PLATFORM_LOGIN_URL,
    STAFF_EMAIL,
    STAFF_PASSWORD,
)


@pytest.mark.e2e
@pytest.mark.parametrize(
    "service",
    [
        (PLATFORM_BASE_URL, PLATFORM_LOGIN_URL, "/auth/profile/", STAFF_EMAIL, STAFF_PASSWORD),
        (BASE_URL, LOGIN_URL, "/profile/", CUSTOMER_EMAIL, CUSTOMER_PASSWORD),
    ],
    ids=["staff", "customer"],
)
def test_profile_localisation_persists_and_can_inherit(page: Page, service: tuple[str, str, str, str, str]) -> None:
    base_url, login_path, profile_path, email, password = service
    page.goto(f"{base_url}{login_path}")
    page.locator('input[name="email"]').fill(email)
    page.locator('input[name="password"]').fill(password)
    page.locator('button[type="submit"]').first.click()
    page.wait_for_url(lambda url: login_path not in url)
    page.goto(f"{base_url}{profile_path}")
    consent = page.get_by_role("button", name="Accept essential cookies only")
    if consent.is_visible():
        consent.click()

    names = ("preferred_language", "timezone", "date_format")
    original = {name: page.locator(f'select[name="{name}"]').input_value() for name in names}
    original_first_name = page.locator('input[name="first_name"]').input_value()

    def save() -> None:
        form = page.locator("form").filter(has=page.locator('select[name="date_format"]'))
        with page.expect_navigation(wait_until="domcontentloaded"):
            form.locator('button[type="submit"]').click()
        expect(page).to_have_url(f"{base_url}{profile_path}")

    try:
        # Saving language must also persist the rest of the profile in the same POST.
        page.locator('input[name="first_name"]').fill("Localisation")
        for name, value in {"preferred_language": "en", "timezone": "UTC", "date_format": "%Y-%m-%d"}.items():
            page.locator(f'select[name="{name}"]').select_option(value)
        save()
        expect(page.locator("html")).to_have_attribute("lang", "en")
        expect(page.locator('input[name="first_name"]')).to_have_value("Localisation")
        member_since = page.locator("dt").filter(has_text="Member Since").locator("..").locator("dd")
        joined = date.fromisoformat(member_since.inner_text().strip())
        for pattern in ("%d.%m.%Y", "%m/%d/%Y", "%d/%m/%Y", "%Y-%m-%d"):
            page.locator('select[name="date_format"]').select_option(pattern)
            save()
            expect(member_since).to_have_text(joined.strftime(pattern))

        page.locator('select[name="preferred_language"]').select_option("ro")
        page.locator('select[name="timezone"]').select_option("Europe/Bucharest")
        save()
        expect(page.locator("html")).to_have_attribute("lang", "ro")
        expect(page.locator('select[name="timezone"]')).to_have_value("Europe/Bucharest")

        for name in names:
            page.locator(f'select[name="{name}"]').select_option("")
        save()
        page.reload()
        for name in names:
            expect(page.locator(f'select[name="{name}"]')).to_have_value("")
        assert all(cookie["name"] != "django_language" for cookie in page.context.cookies())
    finally:
        page.goto(f"{base_url}{profile_path}")
        page.locator('input[name="first_name"]').fill(original_first_name)
        for name, value in original.items():
            page.locator(f'select[name="{name}"]').select_option(value)
        save()
