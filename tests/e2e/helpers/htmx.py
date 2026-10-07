"""HTMX synchronization helpers for e2e tests."""

from playwright.sync_api import Page

# True once no element carries htmx's in-flight, swapping or settling class. All three are needed:
# with a swap delay (`htmx.config.defaultSwapDelay`, set on some pages) htmx drops the request
# class before the swap lands, and the settling class stays on the target until the settle ends.
_HTMX_IDLE = """() => {
    const config = window.htmx && window.htmx.config;
    if (!config) return true;
    const phases = [config.requestClass, config.swappingClass, config.settlingClass];
    return !document.querySelector(phases.map((name) => "." + name).join(","));
}"""


def wait_for_htmx_settle(page: Page, timeout: int = 8000) -> None:
    """Wait until every HTMX request on the page has finished, swapped and settled.

    Call it straight after the interaction that fires the request: a click or a key press on an
    element with a plain trigger starts the request before Playwright returns. It does not help
    with a delayed trigger (`delay:`, `changed`, `every`), whose request may not have started yet;
    after those, assert the swapped content with a retrying `expect`.

    `page.wait_for_load_state("networkidle")` is no substitute: once the page has loaded it returns
    at once, without waiting for a request the test fired afterwards. This helper used to be that
    call plus a fixed 300 ms, so on a slow run the test read the page before the swap, and a second
    interaction cancelled the first request (`hx-sync` replace) instead of following it.
    """
    page.wait_for_function(_HTMX_IDLE, timeout=timeout)
