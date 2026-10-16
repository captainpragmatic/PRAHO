"""The browser suite's page monitor fails on what a user would see break.

Each test drives a real headless Chromium against a local site, so the monitor's verdict comes from
the browser's own events, not from a stand-in.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

import pytest
from playwright.sync_api import Page

from tests.e2e.helpers import monitoring
from tests.e2e.helpers.monitoring import ComprehensivePageMonitor
from tests.e2e.helpers.server_logs import LogEntry, ServerLogScanner
from tests.integration.conftest import LocalSite

HTMX = Path(__file__).resolve().parents[2] / "services/portal/static/js/htmx.min.js"


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


def _entry(logger: str, message: str, request_id: str) -> LogEntry:
    return LogEntry("2026-10-16 12:00:00", "ERROR", "PLAT", logger, message, request_id, "", "platform.log")


def test_a_404_stylesheet_fails_the_monitor(page: Page, local_site: LocalSite) -> None:
    local_site.route("/", '<link rel="stylesheet" href="/missing.css"><p>hi</p>')

    with pytest.raises(AssertionError, match=r"HTTP 404 GET /missing\.css \(stylesheet\)"), _monitor(page):
        page.goto(local_site.url("/"))


def test_page_text_saying_404_is_not_a_network_error(page: Page, local_site: LocalSite) -> None:
    local_site.route("/", "<p>Our guide to 404 Not Found pages</p>")

    with _monitor(page):
        page.goto(local_site.url("/"))


def test_an_uncaught_exception_fails_the_monitor(page: Page, local_site: LocalSite) -> None:
    local_site.route("/", "<script>undefinedFn()</script>")

    with pytest.raises(AssertionError, match="PageError: undefinedFn is not defined"), _monitor(page):
        page.goto(local_site.url("/"))


def test_expect_http_excuses_only_the_named_status_and_path(page: Page, local_site: LocalSite) -> None:
    local_site.route("/", '<link rel="stylesheet" href="/missing.css">')
    local_site.route("/other", '<link rel="stylesheet" href="/other.css">')

    with _monitor(page) as monitor:
        monitor.expect_http({404}, "/missing.css")
        page.goto(local_site.url("/"))

    with pytest.raises(AssertionError, match=r"/other\.css"), _monitor(page) as monitor:
        monitor.expect_http({404}, "/missing.css")
        page.goto(local_site.url("/other"))

    with pytest.raises(AssertionError, match=r"HTTP 404 GET /missing\.css"), _monitor(page) as monitor:
        monitor.expect_http({403}, "/missing.css")
        page.goto(local_site.url("/"))


def test_expect_http_matches_a_query_exactly_and_refuses_one_in_the_path(page: Page) -> None:
    monitor = _monitor(page)
    with pytest.raises(ValueError, match="query"):
        monitor.expect_http({404}, "/a?b")

    by_query = monitoring.HttpExpectation(frozenset({404}), "/a", "page=1")
    assert by_query.matches(404, "http://127.0.0.1/a?page=1")
    assert not by_query.matches(404, "http://127.0.0.1/a?page=2")
    assert not monitoring.HttpExpectation(frozenset({404}), "/a").matches(404, "http://127.0.0.1/aXb")


def test_expectations_do_not_leak_across_clear(page: Page, local_site: LocalSite) -> None:
    local_site.route("/x/", "gone", status=404)

    with pytest.raises(AssertionError) as raised, _monitor(page) as monitor:
        monitor.expect_http({404}, "/x/")
        page.goto(local_site.url("/x/"))
        monitor.clear_http_expectations()
        page.goto(local_site.url("/x/"))

    assert str(raised.value).count("HTTP 404 GET /x/ (document)") == 1


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
        self.page.evaluate("async () => { console.error('late console'); await fetch('/late-404'); }")
        original(self)

    monkeypatch.setattr(ComprehensivePageMonitor, "_sync_point", late_events_then_sync)
    local_site.route("/", "<p>hi</p>")

    with pytest.raises(AssertionError) as raised, _monitor(page):
        page.goto(local_site.url("/"))

    assert "late console" in str(raised.value)
    assert "HTTP 404 GET /late-404 (fetch)" in str(raised.value)


def test_expected_server_patterns_match_the_message_only(page: Page, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        _StubScanner,
        "entries",
        [
            _entry("apps.access.views", "boom", "a1b2c3d4-0000-0000-0000-000000000001"),
            _entry("apps.tickets.views", "access denied", "a1b2c3d4-0000-0000-0000-000000000002"),
        ],
    )
    monkeypatch.setattr(monitoring, "ServerLogScanner", _StubScanner)

    with pytest.raises(AssertionError) as raised, _monitor(page, check_server_logs=True) as monitor:
        monitor.add_expected_error_patterns(["access"])

    assert '"boom"' in str(raised.value)
    assert "access denied" not in str(raised.value)


def test_a_server_error_behind_an_http_200_is_still_correlated(
    page: Page, local_site: LocalSite, monkeypatch: pytest.MonkeyPatch
) -> None:
    request_id = "c0ffee00-0000-0000-0000-000000000001"
    monkeypatch.setattr(_StubScanner, "entries", [_entry("apps.orders.views", "half saved", request_id)])
    monkeypatch.setattr(monitoring, "ServerLogScanner", _StubScanner)
    local_site.route("/", "<p>saved</p>", headers={"X-Request-ID": request_id})

    with (
        pytest.raises(AssertionError, match=r'"half saved" \[req-id: c0ffee00'),
        _monitor(page, check_server_logs=True),
    ):
        page.goto(local_site.url("/"))


def test_a_server_error_still_fails_a_monitor_without_the_network_check(
    page: Page, local_site: LocalSite, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(monitoring, "ServerLogScanner", _StubScanner)
    local_site.route("/", "<p>broken</p>", status=500)

    with pytest.raises(AssertionError, match="500"), _monitor(page, check_network=False, check_server_logs=True):
        page.goto(local_site.url("/"))


def test_an_expected_htmx_4xx_does_not_fail_the_console_check(page: Page, local_site: LocalSite) -> None:
    local_site.route("/htmx.min.js", HTMX.read_bytes(), content_type="application/javascript")
    local_site.route("/validate/", "<p>fix the form</p>", status=422)
    # The portal base template's handler, verbatim, then a marker the test can wait on.
    local_site.route(
        "/",
        '<script src="/htmx.min.js"></script>'
        '<button id="go" hx-post="/validate/" hx-target="#out">go</button><div id="out"></div>'
        "<script>"
        "document.body.addEventListener('htmx:responseError', function(evt) {"
        " console.error('HTMX Error:', evt.detail); });"
        "document.body.addEventListener('htmx:responseError', function() { window.__answered = true; });"
        "</script>",
    )

    def submit_invalid_form(monitor: ComprehensivePageMonitor) -> None:
        monitor.expect_http({422}, "/validate/")
        page.goto(local_site.url("/"))
        page.click("#go")
        page.wait_for_function("() => window.__answered === true")

    with _monitor(page) as monitor:
        submit_invalid_form(monitor)

    with pytest.raises(AssertionError) as raised, _monitor(page) as monitor:
        submit_invalid_form(monitor)
        page.evaluate("() => console.error('boom')")

    assert "boom" in str(raised.value)
    assert "HTMX Error" not in str(raised.value)

    # An unrelated error is not excused just because it names the excused path.
    with pytest.raises(AssertionError, match="parser crashed for /validate/"), _monitor(page) as monitor:
        submit_invalid_form(monitor)
        page.evaluate("() => console.error('parser crashed for /validate/')")
    assert "Response Status Error Code" not in str(raised.value)
