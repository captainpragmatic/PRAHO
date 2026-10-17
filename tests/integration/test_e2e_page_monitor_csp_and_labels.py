"""The page monitor's CSP capture, label check and ignore-pattern guard, driven in a real Chromium."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from playwright.sync_api import Page

from tests.e2e.helpers.csp import ensure_csp_capture, install_csp_violation_capture, read_csp_violations
from tests.e2e.helpers.monitoring import ComprehensivePageMonitor, ConsoleMonitor, check_accessibility_basics
from tests.integration.conftest import LocalSite

ENFORCE_SELF = {"Content-Security-Policy": "script-src 'self'"}
VIOLATION_FIELDS = {"blockedURI", "violatedDirective", "disposition", "sourceFile", "lineNumber"}


def _monitor(page: Page, **options: Any) -> ComprehensivePageMonitor:
    settings: dict[str, Any] = {
        "check_server_logs": False,
        "check_html": False,
        "check_css": False,
        "allow_accessibility_skip": True,
    }
    settings.update(options)
    return ComprehensivePageMonitor(page, "selftest", **settings)


def _wait_for_violations(frame_or_page: Any, count: int) -> None:
    frame_or_page.wait_for_function(f"() => (window.__prahoCspViolations || []).length >= {count}")


@pytest.fixture
def other_site() -> Iterator[LocalSite]:
    site = LocalSite()
    yield site
    site.close()


@pytest.mark.parametrize("pattern", ["403 Forbidden", "Unauthorized access", "404"])
def test_an_ignore_pattern_naming_an_auth_error_is_refused(page: Page, pattern: str) -> None:
    with pytest.raises(ValueError, match="auth or not-found"):
        ComprehensivePageMonitor(page, "selftest", ignore_patterns=[pattern])
    with pytest.raises(ValueError, match="auth or not-found"):
        ConsoleMonitor(page, "selftest", ignore_patterns=[pattern])


def test_a_harmless_or_opted_in_ignore_pattern_is_accepted(page: Page) -> None:
    assert ComprehensivePageMonitor(page, "selftest", ignore_patterns=["chunk load"]).ignore_patterns == ["chunk load"]
    opted_in = ComprehensivePageMonitor(
        page, "selftest", ignore_patterns=["403 Forbidden"], allow_auth_error_ignores=True
    )
    assert opted_in.ignore_patterns == ["403 Forbidden"]


def test_a_placeholder_is_not_a_label(page: Page) -> None:
    page.set_content(
        '<label for="a">Name</label><input id="a" name="labelled">'
        '<span id="hint">Email</span><input name="labelled_by" aria-labelledby="hint">'
        '<input name="placeholder_only" placeholder="Your name">'
        '<input name="missing_ref" aria-labelledby="nope">'
        '<input name="partial_ref" aria-labelledby="hint nope">'
        '<span id="empty"> </span><input name="empty_ref" aria-labelledby="empty">'
        '<input name="blank_aria" aria-label="  ">'
        '<input type="search" name="q" placeholder="Search">'
    )

    missing = sorted(
        issue.removeprefix("Input missing label: ")
        for issue in check_accessibility_basics(page)
        if issue.startswith("Input missing label")
    )

    assert missing == ["blank_aria", "empty_ref", "missing_ref", "partial_ref", "placeholder_only"]


def test_a_report_only_violation_fails_the_monitor(page: Page, local_site: LocalSite) -> None:
    local_site.route(
        "/",
        "<script>window.ran = true</script>",
        headers={"Content-Security-Policy-Report-Only": "script-src 'self'"},
    )

    with pytest.raises(AssertionError, match="CSP report: script-src-elem blocked inline"), _monitor(page):
        page.goto(local_site.url("/"))
        _wait_for_violations(page, 1)


def test_violations_from_earlier_pages_are_kept(page: Page, local_site: LocalSite) -> None:
    local_site.route("/one", "<script>window.one = 1</script>", headers=ENFORCE_SELF)
    local_site.route("/two", '<img src="/x.png" alt="x">', headers={"Content-Security-Policy": "img-src 'none'"})
    install_csp_violation_capture(page)

    page.goto(local_site.url("/one"))
    _wait_for_violations(page, 1)
    page.goto(local_site.url("/two"))
    _wait_for_violations(page, 1)

    assert [v["violatedDirective"] for v in read_csp_violations(page)] == ["script-src-elem", "img-src"]


def test_a_monitor_entered_after_navigation_captures_later_violations(page: Page, local_site: LocalSite) -> None:
    local_site.route("/", "<p>no images yet</p>", headers={"Content-Security-Policy": "img-src 'none'"})
    page.goto(local_site.url("/"))

    with pytest.raises(AssertionError, match="CSP enforce: img-src blocked"), _monitor(page):
        page.evaluate(
            "() => { const img = new Image(); img.alt = 'x'; img.src = '/x.png'; document.body.append(img); }"
        )
        _wait_for_violations(page, 1)


def test_a_violation_delivered_during_the_final_sync_is_reported(
    page: Page, local_site: LocalSite, monkeypatch: pytest.MonkeyPatch
) -> None:
    local_site.route("/", "<p>no images yet</p>", headers={"Content-Security-Policy": "img-src 'none'"})
    original = ComprehensivePageMonitor._sync_point

    def violation_then_sync(self: ComprehensivePageMonitor) -> None:
        self.page.evaluate(
            "() => { const img = new Image(); img.alt = 'x'; img.src = '/late.png'; document.body.append(img); }"
        )
        _wait_for_violations(self.page, 1)
        original(self)

    monkeypatch.setattr(ComprehensivePageMonitor, "_sync_point", violation_then_sync)

    with pytest.raises(AssertionError, match="CSP enforce: img-src blocked"), _monitor(page):
        page.goto(local_site.url("/"))


def test_violation_payload_keeps_the_gate_contract(page: Page, local_site: LocalSite) -> None:
    local_site.route("/", "<script>window.ran = true</script>", headers=ENFORCE_SELF)
    install_csp_violation_capture(page)

    page.goto(local_site.url("/"))
    _wait_for_violations(page, 1)
    (violation,) = read_csp_violations(page)

    assert set(violation) == VIOLATION_FIELDS
    assert violation["disposition"] == "enforce"
    assert violation["sourceFile"] == page.url
    assert type(violation["lineNumber"]) is int


def test_a_violation_is_captured_once_its_event_has_fired(page: Page, local_site: LocalSite) -> None:
    local_site.route("/", "<p>ready</p>", headers=ENFORCE_SELF)
    install_csp_violation_capture(page)
    page.goto(local_site.url("/"))

    page.evaluate("() => { const s = document.createElement('script'); s.textContent = '1'; document.body.append(s); }")
    _wait_for_violations(page, 1)

    assert len(read_csp_violations(page)) == 1
    assert len(read_csp_violations(page)) == 1


def test_frames_are_captured_and_frame_races_do_not_abort_the_read(
    page: Page, local_site: LocalSite, other_site: LocalSite
) -> None:
    blocked = "<script>window.ran = true</script>"
    for path in ("/existing", "/attached", "/removed"):
        local_site.route(path, blocked, headers=ENFORCE_SELF)
    other_site.route("/cross", blocked, headers=ENFORCE_SELF)
    # A frame that removes itself while it is being read, so the read meets a detached frame.
    local_site.route(
        "/vanishing",
        "<script>Promise.allSettled = () => { window.frameElement.remove(); return new Promise(() => {}); };</script>",
    )
    local_site.route(
        "/",
        f'<iframe src="/existing"></iframe><iframe src="{other_site.url("/cross")}"></iframe>'
        '<iframe id="vanishing" src="/vanishing"></iframe>',
    )
    install_csp_violation_capture(page)
    ensure_csp_capture(page)

    page.goto(local_site.url("/"))
    for frame in page.frames[1:]:
        if not frame.url.endswith("/vanishing"):
            _wait_for_violations(frame, 1)

    page.evaluate(
        "() => { for (const [id, src] of [['attached', '/attached'], ['removed', '/removed']]) {"
        " const f = document.createElement('iframe'); f.id = id; f.src = src; document.body.append(f); } }"
    )
    for name in ("attached", "removed"):
        frame = page.wait_for_selector(f"#{name}").content_frame()
        assert frame is not None
        frame.wait_for_load_state()
        _wait_for_violations(frame, 1)
    page.evaluate("() => document.getElementById('removed').remove()")

    sources = sorted(v["sourceFile"].rsplit("/", 1)[-1] for v in read_csp_violations(page))
    assert sources == ["attached", "cross", "existing", "removed"]
    assert page.locator("#vanishing").count() == 0
