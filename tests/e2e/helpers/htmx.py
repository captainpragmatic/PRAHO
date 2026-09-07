"""HTMX synchronization helpers for e2e tests."""

from playwright.sync_api import Page


def wait_for_htmx_settle(page: Page, timeout: int = 8000) -> None:
    """Wait for in-flight HTMX requests to finish and the DOM to settle.

    networkidle alone is not sufficient right after an interaction that fires
    a request: the swap happens after the response lands, so a short grace
    period follows. This also absorbs the ``hx-sync="...:replace"``
    cancellation storm — rapid interactions (e.g. arrow-key tab navigation)
    cancel each other's requests, and only the final one settles; callers
    should interact first, then call this once and assert final state.
    """
    page.wait_for_load_state("networkidle", timeout=timeout)
    page.wait_for_timeout(300)
