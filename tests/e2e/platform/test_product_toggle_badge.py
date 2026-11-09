"""In a real browser, a product's flag toggles keep the stored flag and the badge in step (#821).

The toggle endpoints invert the flag, so a click that ran twice would undo itself while the page showed one change.
`hx-sync="this:drop"` drops a second click while the first is in flight and `hx-disabled-elt` disables the control
until the answer arrives. The test holds the first answer while two more clicks land: exactly one POST goes out, and
the flag is inverted once, on the page and after a reload. The swapped-in control keeps its id, so keyboard focus
comes back to it, and nothing on the page breaks the CSP.
"""

from __future__ import annotations

from playwright.sync_api import Page, Request, Route, expect

from tests.e2e.helpers import PLATFORM_BASE_URL
from tests.e2e.helpers.csp import ensure_csp_capture, read_csp_violations


def test_a_double_click_while_the_first_answer_is_pending_posts_once_and_flips_once(
    monitored_staff_page: Page, e2e_scenario
) -> None:
    """The first response is held until both clicks have happened, so the second click certainly lands mid-flight."""
    page = monitored_staff_page
    ensure_csp_capture(page)
    product = e2e_scenario("pricing")
    page.goto(f"{PLATFORM_BASE_URL}/products/{product['product_slug']}/")
    for field, initial in (("active", "true"), ("public", "true"), ("featured", "false")):
        flipped = "false" if initial == "true" else "true"
        control = page.locator(f"#detail-{field}-badge")
        expect(control).to_have_attribute("aria-pressed", initial)
        posts: list[str] = []
        held: list[Route] = []
        pattern = f"**/products/{product['product_slug']}/toggle-{field}/"

        def record(request: Request) -> None:
            if request.method == "POST":
                posts.append(request.url)  # noqa: B023 -- removed before the next iteration

        def hold(route: Route) -> None:
            held.append(route)  # noqa: B023 -- unrouted before the next iteration

        page.on("request", record)
        page.route(pattern, hold)
        control.click()
        expect(control).to_be_disabled()  # hx-disabled-elt while the first request is in flight
        control.dblclick(force=True)  # two more clicks on the in-flight control
        page.wait_for_timeout(300)
        assert len(held) == 1, f"expected one held POST for {field}, got {len(held)}"
        held[0].continue_()
        expect(control).to_have_attribute("aria-pressed", flipped)
        expect(control).to_be_enabled()
        page.unroute(pattern)
        page.remove_listener("request", record)
        assert len(posts) == 1, posts
        assert f"toggle-{field}/" in posts[0], posts
        page.reload()
        expect(page.locator(f"#detail-{field}-badge")).to_have_attribute("aria-pressed", flipped)
    assert read_csp_violations(page) == []


def test_focus_comes_back_to_the_swapped_control(monitored_staff_page: Page, e2e_scenario) -> None:
    page = monitored_staff_page
    ensure_csp_capture(page)
    product = e2e_scenario("pricing")
    page.goto(f"{PLATFORM_BASE_URL}/products/{product['product_slug']}/")
    control = page.locator("#detail-featured-badge")
    expect(control).to_have_attribute("aria-pressed", "false")
    control.focus()
    page.keyboard.press("Enter")
    expect(control).to_have_attribute("aria-pressed", "true")
    expect(control).to_be_focused()
    expect(control).to_have_text("Featured")
    assert read_csp_violations(page) == []
