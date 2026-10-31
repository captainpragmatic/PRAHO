"""In a real browser, htmx sends the page's CSRF token, and a stale token says to reload.

The Platform's CSRF cookie is HttpOnly, so the page carries the token on `<body hx-headers>`. These run with the CSRF
middleware on (e2e settings, as staging) and click real controls:
- the service page's Suspend button, which sends no token of its own;
- a control with an unrelated `hx-headers` of its own (htmx merges header names, so the token still goes);
- a product toggle after htmx swapped it in;
- a stale token (the secret rotated in another tab): one refused request, the reload message, no retry.
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import Dialog, Page, Request, expect

from tests.e2e.helpers import PLATFORM_BASE_URL
from tests.e2e.platform.test_staff_provisioning import _create, _transition

PLATFORM_CSRF_COOKIE = "platform_csrftoken"  # dev and e2e settings name it apart from the Portal's


def _accept_dialogs(page: Page) -> list[str]:
    seen: list[str] = []

    def accept(dialog: Dialog) -> None:
        seen.append(dialog.message)
        dialog.accept()

    page.on("dialog", accept)
    return seen


def _active_service(page: Page, e2e_scenario) -> str:
    url, _ = _create(page, e2e_scenario("account"))
    _transition(page, url, "activate", "Active")
    return url


def test_the_service_suspend_button_works_and_shows_the_new_status(monitored_staff_page: Page, e2e_scenario) -> None:
    page = monitored_staff_page
    url = _active_service(page, e2e_scenario)
    _accept_dialogs(page)
    page.goto(url)

    with page.expect_request(lambda r: r.method == "POST" and r.url.endswith("/suspend/")) as sent:
        page.locator("main").get_by_role("button", name="Suspend", exact=True).click()

    assert len(sent.value.headers.get("x-csrftoken", "")) == 64
    expect(page).to_have_url(url)
    expect(page.get_by_text("Suspended", exact=True)).to_be_visible()


def test_a_control_with_its_own_headers_still_sends_the_token(monitored_staff_page: Page, e2e_scenario) -> None:
    page = monitored_staff_page
    url = _active_service(page, e2e_scenario)
    page.goto(url)
    page.evaluate(
        """(target) => {
            const button = document.createElement("button");
            button.id = "own-headers";
            button.setAttribute("hx-post", target);
            button.setAttribute("hx-headers", '{"X-Own-Header": "1"}');
            button.textContent = "own headers";
            document.querySelector("main").appendChild(button);
            htmx.process(button);
        }""",
        url + "suspend/",
    )

    with page.expect_request(lambda r: r.method == "POST" and r.url.endswith("/suspend/")) as sent:
        page.locator("#own-headers").click()

    headers = sent.value.headers
    assert headers.get("x-own-header") == "1"
    assert len(headers.get("x-csrftoken", "")) == 64
    expect(page).to_have_url(url)
    expect(page.get_by_text("Suspended", exact=True)).to_be_visible()


def test_a_mobile_product_toggle_works_again_after_htmx_swapped_it(monitored_staff_page: Page, e2e_scenario) -> None:
    page = monitored_staff_page
    slug = e2e_scenario("pricing")["product_slug"]
    page.set_viewport_size({"width": 375, "height": 812})
    page.goto(f"{PLATFORM_BASE_URL}/products/?search={slug}")
    toggle = page.locator(f'button[hx-post*="/{slug}/toggle-active/"]:visible')
    expect(toggle).to_have_count(1)
    expect(toggle).to_contain_text("Active")

    for expected in ("Inactive", "Active"):  # the second click is on the control the first response swapped in
        with page.expect_response(lambda r: "/toggle-active/" in r.url) as answered:
            toggle.click()
        assert answered.value.status == 200
        expect(toggle).to_contain_text(re.compile(rf"^\s*{expected}\s*$"))


@pytest.mark.expect_http_errors(403, url="/provisioning/services/*/suspend/")
def test_a_stale_token_says_to_reload_and_is_not_retried(monitored_staff_page: Page, e2e_scenario) -> None:
    page = monitored_staff_page
    url = _active_service(page, e2e_scenario)
    dialogs = _accept_dialogs(page)
    page.goto(url)
    # Another tab signing in rotates the secret: this page's token no longer matches the cookie.
    cookie = next(c for c in page.context.cookies() if c["name"] == PLATFORM_CSRF_COOKIE)
    page.context.add_cookies([{**cookie, "value": "r" * 32}])
    posts: list[Request] = []
    page.on("request", lambda r: posts.append(r) if r.method == "POST" and r.url.endswith("/suspend/") else None)

    with page.expect_response(lambda r: r.url.endswith("/suspend/")) as answered:
        page.locator("main").get_by_role("button", name="Suspend", exact=True).click()

    assert answered.value.status == 403
    assert answered.value.headers.get("x-csrf-failure") == "reload"
    for _ in range(50):  # the alert follows the response; give it up to 5s
        if any("reload the page" in message for message in dialogs):
            break
        page.wait_for_timeout(100)
    assert any("reload the page" in message for message in dialogs), dialogs
    assert len(posts) == 1
    page.reload()
    expect(page.get_by_text("Active", exact=True).first).to_be_visible()
