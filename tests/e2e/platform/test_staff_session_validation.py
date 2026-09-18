"""A saved cookie must reach a real protected page before a test is authenticated."""

import json
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

from tests.e2e.helpers import PLATFORM_BASE_URL, apply_storage_state, login_platform_user


@pytest.mark.parametrize("path,authenticated", [("/dashboard/", True), ("/app/dashboard/", False)])
def test_saved_staff_session_requires_successful_protected_page(
    page: Page, _staff_storage_state: str, path: str, authenticated: bool
) -> None:
    assert apply_storage_state(page, _staff_storage_state, PLATFORM_BASE_URL + path, "/auth/login/") is authenticated
    if authenticated:
        expect(page).to_have_url(PLATFORM_BASE_URL + "/dashboard/")
        expect(page.get_by_role("link", name="Logout", exact=True)).to_be_visible()
    else:
        assert page.context.cookies() == []


def test_invalid_saved_staff_session_requires_real_login(page: Page, _staff_storage_state: str, tmp_path: Path) -> None:
    state = json.loads(Path(_staff_storage_state).read_text())
    sessions = [cookie for cookie in state["cookies"] if cookie["name"] == "pragmatichost_dev_sessionid"]
    assert len(sessions) == 1, "The saved state must include the staff session cookie"
    sessions[0]["value"] = "expired-e2e-session"
    invalid = tmp_path / "invalid-staff-session.json"
    invalid.write_text(json.dumps(state))
    dashboard = PLATFORM_BASE_URL + "/dashboard/"
    assert not apply_storage_state(page, str(invalid), dashboard, "/auth/login/")
    assert page.context.cookies() == []
    assert login_platform_user(page)
    response = page.goto(dashboard)
    assert response.status == 200
    expect(page).to_have_url(dashboard)
