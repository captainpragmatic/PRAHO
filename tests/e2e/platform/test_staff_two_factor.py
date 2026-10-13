"""Staff two-factor authentication, end to end, with the staff policy switched on.

An administrator switches `users.mfa_required_for_staff` on. A support member without a second factor
signs in and can only enrol; enrols despite a mistyped code; signs in again with an app code and with
a backup code; cannot disable 2FA; loses their device and is reset by the administrator, which ends
their session and sends them back to enrol; and can disable 2FA once the policy is off again.

The policy is global state on a stack the whole suite shares, and with it on, the unenrolled
e2e-admin could only enrol. So only the enrolled administrator of this test's own scenario switches it,
over Platform's own save endpoint, and the fixture switches it off in `finally` and then proves that
an unenrolled account reaches the dashboard again. If its session is gone, it signs in afresh with a
backup code kept in reserve. A stack killed mid-test is reset by the next seed, which starts with the
policy off.

Over HTTP rather than the ORM: the e2e server caches settings in its own process (LocMemCache), so a
write from this process would not reach it (the same reasoning as the maintenance-window test).
"""

import json
import re
import time
from collections.abc import Callable, Iterator
from typing import Any
from urllib.parse import urlsplit

import pyotp
import pytest
import requests
from playwright.sync_api import Browser, Page, expect

from tests.e2e.helpers import (
    PLATFORM_BASE_URL,
    PLATFORM_LOGIN_URL,
    SUPERUSER_EMAIL,
    SUPERUSER_PASSWORD,
    login_platform_user_with_code,
)

pytestmark = pytest.mark.e2e

KEY = "users.mfa_required_for_staff"
TIMEOUT = 15
SETUP_PATH = "/auth/mfa/setup/totp/"
BACKUP_CODES_PATH = "/auth/mfa/backup-codes/"
VERIFY_PATH = "/auth/mfa/verify/"
DASHBOARD_PATH = "/dashboard/"


def _csrf_from(session: requests.Session, path: str) -> str:
    html = session.get(f"{PLATFORM_BASE_URL}{path}", timeout=TIMEOUT).text
    match = re.search(r'csrfmiddlewaretoken" value="([^"]+)"', html)
    assert match, f"no CSRF token on {path}"
    return match.group(1)


def _sign_in(session: requests.Session, email: str, password: str, code: str | None = None) -> None:
    """Sign in over HTTP; with a code, through the second step too."""
    session.post(
        f"{PLATFORM_BASE_URL}{PLATFORM_LOGIN_URL}",
        data={"email": email, "password": password, "csrfmiddlewaretoken": _csrf_from(session, PLATFORM_LOGIN_URL)},
        headers={"Referer": f"{PLATFORM_BASE_URL}{PLATFORM_LOGIN_URL}"},
        timeout=TIMEOUT,
    )
    if code is not None:
        session.post(
            f"{PLATFORM_BASE_URL}{VERIFY_PATH}",
            data={"token": code, "csrfmiddlewaretoken": _csrf_from(session, VERIFY_PATH)},
            headers={"Referer": f"{PLATFORM_BASE_URL}{VERIFY_PATH}"},
            timeout=TIMEOUT,
        )


class StaffMFAPolicy:
    """Switches the staff 2FA policy through Platform's own save endpoint, as an enrolled administrator."""

    def __init__(self, accounts: dict[str, Any]) -> None:
        self.accounts = accounts
        self._session = requests.Session()
        _sign_in(
            self._session,
            accounts["admin_email"],
            accounts["password"],
            pyotp.TOTP(accounts["admin_totp_secret"]).now(),
        )
        landing = self._session.get(f"{PLATFORM_BASE_URL}/settings/", timeout=TIMEOUT)
        assert landing.status_code == 200, "the administrator could not sign in; this test cannot switch the policy"

    def set(self, on: bool) -> None:
        current = self._session.get(f"{PLATFORM_BASE_URL}/settings/api/{KEY}/", timeout=TIMEOUT)
        baseline = current.json()["setting"].get("updated_at") if current.status_code == 200 else None
        response = self._session.post(
            f"{PLATFORM_BASE_URL}/settings/save/",
            data=json.dumps({"changes": {KEY: on}, "baselines": {KEY: baseline}, "reason": "E2E staff 2FA policy"}),
            headers={
                "X-CSRFToken": self._session.cookies.get("csrftoken"),
                "Content-Type": "application/json",
                "Referer": PLATFORM_BASE_URL,
            },
            timeout=TIMEOUT,
        )
        assert response.status_code == 200, f"could not set {KEY}={on}: {response.status_code} {response.text[:200]}"

    def switch_off(self) -> None:
        try:
            self.set(False)
        except (AssertionError, requests.RequestException, ValueError):
            # The session may be gone; a fresh sign-in with the reserved backup code still works.
            self._session = requests.Session()
            _sign_in(
                self._session,
                self.accounts["admin_email"],
                self.accounts["password"],
                self.accounts["admin_backup_codes"][-1],
            )
            self.set(False)


def assert_unenrolled_staff_reach_the_dashboard() -> None:
    """The stack is usable again: an account without 2FA signs in with a password alone."""
    session = requests.Session()
    _sign_in(session, SUPERUSER_EMAIL, SUPERUSER_PASSWORD)
    response = session.get(f"{PLATFORM_BASE_URL}{DASHBOARD_PATH}", timeout=TIMEOUT, allow_redirects=False)
    assert response.status_code == 200, f"e2e-admin no longer reaches the dashboard: {response.status_code}"


@pytest.fixture
def accounts(e2e_scenario: Callable[[str], dict[str, Any]]) -> dict[str, Any]:
    return e2e_scenario("staff_mfa")


@pytest.fixture
def policy(accounts: dict[str, Any]) -> Iterator[StaffMFAPolicy]:
    switch = StaffMFAPolicy(accounts)  # registered before the policy is switched on
    try:
        yield switch
    finally:
        switch.switch_off()
        assert_unenrolled_staff_reach_the_dashboard()


def _path(page: Page) -> str:
    return urlsplit(page.url).path


def _sign_in_with_password(page: Page, email: str, password: str) -> None:
    page.goto(f"{PLATFORM_BASE_URL}{PLATFORM_LOGIN_URL}")
    page.locator('input[name="email"]').fill(email)
    page.locator('input[name="password"]').fill(password)
    page.locator('button[type="submit"]').click()


def _enrol(page: Page, password: str) -> tuple[str, list[str]]:
    """On the setup page: enrol with the shown secret; return it and the backup codes shown."""
    secret = (page.locator("#secret-key").text_content() or "").strip()
    page.locator('input[name="token"]').fill(pyotp.TOTP(secret).now())
    page.locator('input[name="password"]').fill(password)
    page.get_by_role("button", name="Verify & Enable MFA").click()
    page.wait_for_url(lambda url: urlsplit(url).path == BACKUP_CODES_PATH)
    codes = page.locator("#backup-codes-grid code").all_text_contents()
    return secret, codes


def _forced_enrolment(page: Page, email: str, password: str) -> tuple[str, list[str]]:
    """Without a second factor, signing in leads to setup only; a mistyped code keeps the secret."""
    _sign_in_with_password(page, email, password)
    page.wait_for_url(lambda url: urlsplit(url).path == SETUP_PATH)
    expect(page.get_by_text("It is required for staff accounts").first).to_be_visible()
    page.goto(f"{PLATFORM_BASE_URL}/customers/")
    assert _path(page) == SETUP_PATH

    secret = (page.locator("#secret-key").text_content() or "").strip()
    page.locator('input[name="token"]').fill("000000")
    page.locator('input[name="password"]').fill(password)
    page.get_by_role("button", name="Verify & Enable MFA").click()
    expect(page.get_by_text("The password or the code is incorrect.").first).to_be_visible()
    expect(page.locator("#secret-key")).to_have_text(secret)

    enrolled_secret, codes = _enrol(page, password)
    assert enrolled_secret == secret, "the app scanned before the mistyped code must still work"
    assert len(codes) == 8
    expect(page.get_by_text("Your 8 backup codes").first).to_be_visible()
    return secret, codes


def _signing_in_asks_for_the_code(page: Page, email: str, password: str, secret: str, backup_code: str) -> None:
    """A wrong code is refused, the app's next code is accepted, and a backup code works once."""
    page.goto(f"{PLATFORM_BASE_URL}/auth/logout/")
    _sign_in_with_password(page, email, password)
    page.wait_for_url(lambda url: urlsplit(url).path == VERIFY_PATH)
    page.locator('input[name="token"]').fill("000000")
    page.locator('button[type="submit"]').click()
    expect(page.get_by_text("The 2FA code or backup code is invalid.").first).to_be_visible()
    assert _path(page) == VERIFY_PATH
    page.locator('input[name="token"]').fill(pyotp.TOTP(secret).at(time.time() + 30))
    page.locator('button[type="submit"]').click()
    page.wait_for_url(lambda url: urlsplit(url).path == DASHBOARD_PATH)

    page.goto(f"{PLATFORM_BASE_URL}/auth/logout/")
    login_platform_user_with_code(page, email, password, backup_code)
    expect(page.get_by_text("You have 7 codes remaining").first).to_be_visible()


def _staff_keep_their_second_factor(page: Page) -> None:
    page.goto(f"{PLATFORM_BASE_URL}/auth/profile/")
    expect(page.get_by_role("link", name="Disable MFA")).to_have_count(0)
    page.goto(f"{PLATFORM_BASE_URL}/auth/mfa/disable/")
    assert _path(page) == "/auth/profile/"
    expect(page.get_by_text("required for staff accounts, so it cannot be disabled").first).to_be_visible()


def _administrator_resets(browser: Browser, accounts: dict[str, Any]) -> None:
    """The lost-device recovery path, confirmed before it runs."""
    admin_page = browser.new_context().new_page()
    login_platform_user_with_code(
        admin_page, accounts["admin_email"], accounts["password"], accounts["admin_backup_codes"][0]
    )
    admin_page.goto(f"{PLATFORM_BASE_URL}/auth/users/{accounts['staff_id']}/")
    dialogs: list[str] = []
    admin_page.once("dialog", lambda dialog: (dialogs.append(dialog.message), dialog.accept()))
    admin_page.get_by_role("button", name="Reset two-factor authentication").click()
    expect(
        admin_page.get_by_text(f"Two-factor authentication was reset for {accounts['staff_email']}").first
    ).to_be_visible()
    assert dialogs and "Their sessions end" in dialogs[0], "the reset must ask before it runs"
    admin_page.context.close()


def _disabling_with_the_policy_off(page: Page, password: str, backup_code: str) -> None:
    page.goto(f"{PLATFORM_BASE_URL}/auth/mfa/disable/")
    page.locator("#password").fill(password)
    page.locator("#token").fill(backup_code)
    page.locator("#checkbox-confirm_disable").check()
    page.once("dialog", lambda dialog: dialog.accept())
    page.get_by_role("button", name="Disable MFA", exact=True).click()
    page.wait_for_url(lambda url: urlsplit(url).path == "/auth/profile/")
    expect(page.get_by_text("Two-factor authentication has been disabled.").first).to_be_visible()


def test_staff_2fa_from_forced_enrolment_to_an_admin_reset(
    page: Page, browser: Browser, accounts: dict[str, Any], policy: StaffMFAPolicy
) -> None:
    email, password = accounts["staff_email"], accounts["password"]
    policy.set(True)

    secret, codes = _forced_enrolment(page, email, password)
    _signing_in_asks_for_the_code(page, email, password, secret, codes[0])
    _staff_keep_their_second_factor(page)
    _administrator_resets(browser, accounts)

    # The reset ended the session; the next sign-in has no code step and goes back to setup.
    page.goto(f"{PLATFORM_BASE_URL}{DASHBOARD_PATH}")
    assert _path(page) == PLATFORM_LOGIN_URL
    _sign_in_with_password(page, email, password)
    page.wait_for_url(lambda url: urlsplit(url).path == SETUP_PATH)
    new_secret, new_codes = _enrol(page, password)
    assert new_secret != secret

    policy.set(False)
    _disabling_with_the_policy_off(page, password, new_codes[0])
