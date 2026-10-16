"""The browser suite's page monitor fails on what a user would see break.

Each test drives a real headless Chromium against a local site, so the monitor's verdict comes from
the browser's own events, not from a stand-in.
"""

from __future__ import annotations

from typing import Any, ClassVar

import pytest
from playwright.sync_api import Page

from tests.e2e.helpers import monitoring
from tests.e2e.helpers.monitoring import ComprehensivePageMonitor
from tests.e2e.helpers.server_logs import LogEntry, ServerLogScanner
from tests.integration.conftest import LocalSite


def _monitor(page: Page, **options: Any) -> ComprehensivePageMonitor:
    settings: dict[str, Any] = {
        "check_server_logs": False,
        "check_html": False,
        "check_css": False,
        "allow_accessibility_skip": True,
    }
    settings.update(options)
    return ComprehensivePageMonitor(page, "selftest", **settings)


class _StubScanner(ServerLogScanner):
    """A log scanner that is always available and returns the entries a test sets."""

    entries: ClassVar[list[LogEntry]] = []

    def __init__(self, log_paths: list[Any]) -> None:
        super().__init__([])
        self._available = True

    def mark_position(self) -> None:
        pass

    def get_new_entries(self) -> list[LogEntry]:
        return list(self.entries)


def test_an_uncaught_exception_fails_the_monitor(page: Page, local_site: LocalSite) -> None:
    local_site.route("/", "<script>undefinedFn()</script>")

    with pytest.raises(AssertionError, match="PageError: undefinedFn is not defined"), _monitor(page):
        page.goto(local_site.url("/"))


def test_monitoring_a_page_twice_leaves_no_listener_behind(page: Page, local_site: LocalSite) -> None:
    local_site.route("/", "<p>hi</p>")
    page.goto(local_site.url("/"))
    with _monitor(page) as first:
        pass

    with pytest.raises(AssertionError, match="once"), _monitor(page) as second:
        page.evaluate("() => console.error('once')")

    assert first.console_messages == []
    assert [m["text"] for m in second.console_messages] == ["once"]


def test_a_failing_enter_leaves_no_listener(page: Page, local_site: LocalSite, monkeypatch: pytest.MonkeyPatch) -> None:
    class _BrokenScanner(_StubScanner):
        def mark_position(self) -> None:
            raise RuntimeError("log scanner broke")

    monkeypatch.setattr(monitoring, "ServerLogScanner", _BrokenScanner)
    local_site.route("/", "<p>hi</p>")
    page.goto(local_site.url("/"))
    monitor = _monitor(page, check_server_logs=True)

    with pytest.raises(RuntimeError, match="log scanner broke"):
        monitor.__enter__()
    page.evaluate("() => console.error('after a failed enter')")
    page.evaluate("() => null")

    assert monitor.console_messages == []


def test_console_monitor_collects_a_page_error_that_arrives_as_it_exits(
    page: Page, local_site: LocalSite, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = monitoring._sync_with_page

    def late_page_error_then_sync(target: Page) -> None:
        target.evaluate(
            "async () => { setTimeout(() => { throw new Error('late page error'); }, 0);"
            " await new Promise((resolve) => setTimeout(resolve, 20)); }"
        )
        original(target)

    monkeypatch.setattr(monitoring, "_sync_with_page", late_page_error_then_sync)
    local_site.route("/", "<p>hi</p>")

    with pytest.raises(AssertionError, match="late page error"), monitoring.ConsoleMonitor(page, "selftest"):
        page.goto(local_site.url("/"))


def test_a_reused_console_monitor_starts_each_block_clean(page: Page, local_site: LocalSite) -> None:
    local_site.route("/boom", "<script>undefinedFn()</script>")
    local_site.route("/", "<p>hi</p>")
    monitor = monitoring.ConsoleMonitor(page, "selftest")

    with pytest.raises(AssertionError, match="undefinedFn"), monitor:
        page.goto(local_site.url("/boom"))
    with monitor:
        page.goto(local_site.url("/"))

    assert monitor.console_messages == []


def test_events_the_final_check_triggers_are_still_collected(
    page: Page, local_site: LocalSite, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = ComprehensivePageMonitor._sync_point

    def late_events_then_sync(self: ComprehensivePageMonitor) -> None:
        self.page.evaluate("async () => { console.error('late console'); await Promise.resolve(); }")
        original(self)

    monkeypatch.setattr(ComprehensivePageMonitor, "_sync_point", late_events_then_sync)
    local_site.route("/", "<p>hi</p>")

    with pytest.raises(AssertionError) as raised, _monitor(page):
        page.goto(local_site.url("/"))

    assert "late console" in str(raised.value)
