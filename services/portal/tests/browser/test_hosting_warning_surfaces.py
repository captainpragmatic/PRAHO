"""Opt-in Chromium acceptance of actual hosting warning/preference templates.

Only Platform response methods are doubled. Cache sessions seed an existing
billing identity; WSGI, Locale, CSRF, messages, views, forms and templates are real.
Platform tenant/privacy authorization and native quotas have separate test gates.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from copy import deepcopy
from pathlib import Path
from socketserver import ThreadingMixIn
from unittest.mock import patch
from urllib.parse import quote
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

import pytest
from django.conf import settings
from django.contrib.sessions.backends.cache import SessionStore
from django.contrib.staticfiles.handlers import StaticFilesHandler
from django.core.handlers.wsgi import WSGIHandler
from django.test import override_settings
from django.utils.translation import gettext, override
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.browser
ARTIFACTS = Path(__file__).resolve().parents[4] / "output/playwright/hosting-warning-boundary"
DETAIL = "/services/5/"
PREFERENCES = "/company/notifications/"


class _ThreadedServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


class _QuietHandler(WSGIRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 -- stdlib signature.
        pass


class WarningBoundary:
    """Mutable Platform DTO/response seam; no Portal business behavior is replaced."""

    def __init__(self) -> None:
        self.url = ""
        self.session_key = ""
        self.optional = True
        self.global_unsubscribe = False
        self.refuse_save = False
        self.preference_calls: list[tuple[int, int, bool | None]] = []
        self.limits: dict[str, object] = {
            "state": "verified",
            "enforcement_state": "managed",
            "operational": {"disk_mib": 5120, "disk_gib": 5, "bandwidth_mib": 102400, "bandwidth_gib": 100},
            "assigned": {"disk_mib": 5120, "disk_gib": 5, "bandwidth_mib": 102400, "bandwidth_gib": 100},
        }
        self.service = {
            "id": 5,
            "status": "active",
            "domain": "example.test",
            "service_name": "Hosting boundary acceptance",
            "currency_code": "RON",
            "service_plan": {"name": "Purchased hosting", "plan_type": "shared_hosting"},
            "plan_changes_enabled": True,
            "hosting_raise": None,
            "hosting_limits": self.limits,
            "hosting_warnings": {},
        }

    def warning(self, *, condition: int | None = 100, availability: str = "fresh") -> dict[str, object]:
        return {
            "condition": condition,
            "availability": availability,
            "used_bytes": 5 * 1024**3,
            "operational_allowance_mib": 5120,
            "observed_at": "2026-11-04T10:00:00+00:00",
        }

    def preferences(self, customer_id: int, user_id: int, *, quota_warnings: bool | None = None) -> dict[str, object]:
        self.preference_calls.append((customer_id, user_id, quota_warnings))
        if quota_warnings is not None:
            if self.refuse_save:
                return {"success": False}
            self.optional = quota_warnings
        return {
            "success": True,
            "data": {"quota_warnings": self.optional, "global_unsubscribe": self.global_unsubscribe},
        }


@pytest.fixture
def boundary() -> Iterator[WarningBoundary]:
    fixture = WarningBoundary()
    with (
        override_settings(
            ALLOWED_HOSTS=["127.0.0.1"],
            SESSION_ENGINE="django.contrib.sessions.backends.cache",
            CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
            SESSION_COOKIE_SECURE=False,
            CSRF_COOKIE_SECURE=False,
            LANGUAGE_CODE="en",
            MIDDLEWARE=[
                "django.contrib.sessions.middleware.SessionMiddleware",
                "django.middleware.locale.LocaleMiddleware",
                "django.middleware.csrf.CsrfViewMiddleware",
                "django.contrib.messages.middleware.MessageMiddleware",
            ],
        ),
        patch("apps.services.views.services_api") as api,
        patch(
            "apps.customers.notification_preferences.api_client.hosting_warning_preferences",
            side_effect=fixture.preferences,
        ),
    ):
        api.get_service_detail.side_effect = lambda *args: deepcopy(fixture.service)
        api.get_service_usage.return_value = {"current_usage": {}, "historical_usage": {}}
        api.get_service_domains.return_value = []
        api.get_service_maintenance.return_value = {"windows": [], "last_completed": None}
        session = SessionStore()
        session.update(
            {
                "customer_id": 42,
                "user_id": 7,
                "user_memberships": [{"customer_id": 42, "role": "billing"}],
                "user_memberships_fetched_at": time.time(),
            }
        )
        session.save()
        fixture.session_key = session.session_key or ""
        server = make_server(
            "127.0.0.1", 0, StaticFilesHandler(WSGIHandler()), server_class=_ThreadedServer, handler_class=_QuietHandler
        )
        fixture.url = f"http://127.0.0.1:{server.server_port}"
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield fixture
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            session.delete()


@pytest.fixture(params=("en", "ro"))
def language(request: pytest.FixtureRequest) -> str:
    return str(request.param)


@pytest.fixture(params=(390, 820, 1280))
def width(request: pytest.FixtureRequest) -> int:
    return int(request.param)


def _translated(language: str, message: str) -> str:
    with override(language):
        value = gettext(message)
    assert language != "ro" or value != message, f"Missing Romanian translation: {message}"
    return value


def _open(page: Page, boundary: WarningBoundary, language: str, width: int, path: str = DETAIL) -> None:
    page.set_viewport_size({"width": width, "height": 960})
    page.context.add_cookies(
        [
            {"name": settings.SESSION_COOKIE_NAME, "value": boundary.session_key, "url": boundary.url},
            {"name": settings.LANGUAGE_COOKIE_NAME, "value": language, "url": boundary.url},
            {"name": "cookie_consent", "value": quote('{"essential":true,"functional":true}'), "url": boundary.url},
        ]
    )
    response = page.goto(boundary.url + path)
    assert response is not None and response.status == 200
    expect(page.locator("html")).to_have_attribute("lang", language)


def _layout(page: Page, language: str, width: int, phase: str) -> None:
    expect(page.locator("#main-content")).to_be_visible()
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), "Horizontal page overflow"
    buttons = page.locator("#main-content button:visible").evaluate_all(
        "els => els.map(el => ({text: el.innerText, height: el.getBoundingClientRect().height}))"
    )
    assert all(button["height"] >= 44 for button in buttons), buttons
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(ARTIFACTS / f"{language}-{width}-{phase}.png"), full_page=True)


@pytest.mark.parametrize("threshold", (80, 95, 100))
def test_disk_and_partial_bandwidth_warning_levels(
    page: Page, boundary: WarningBoundary, language: str, width: int, threshold: int
) -> None:
    boundary.service["hosting_warnings"] = {
        "disk": boundary.warning(condition=threshold),
        "bandwidth": boundary.warning(condition=threshold, availability="partial"),
    }
    _open(page, boundary, language, width)
    disk = page.locator('[data-hosting-warning="disk"]')
    bandwidth = page.locator('[data-hosting-warning="bandwidth"]')
    for warning in (disk, bandwidth):
        expect(warning).to_have_attribute("data-level", str(threshold))
        expect(warning).to_contain_text(f"{threshold}%")
    disk_heading = {80: "Disk usage is high", 95: "Disk allowance almost used up", 100: "Disk allowance reached"}[
        threshold
    ]
    expect(disk).to_contain_text(_translated(language, disk_heading))
    expect(bandwidth).to_contain_text(_translated(language, "This incomplete reading is a confirmed lower bound."))
    expect(disk).to_contain_text(
        "Limita spațiului pe disc inclus a fost atinsă"
        if language == "ro" and threshold == 100
        else _translated(language, disk_heading)
    )
    write_copy = _translated(language, "Writes may fail when the enforced cap is reached.")
    if threshold == 100:
        expect(disk).to_contain_text(write_copy)
    else:
        expect(disk).not_to_contain_text(write_copy)
    _layout(page, language, width, f"warnings-{threshold}")


def test_stale_warning_and_unknown_unlimited_resources(
    page: Page, boundary: WarningBoundary, language: str, width: int
) -> None:
    boundary.limits["state"] = "unverified"
    boundary.service["hosting_warnings"] = {"disk": boundary.warning(availability="stale")}
    _open(page, boundary, language, width)
    warning = page.locator('[data-hosting-warning="disk"]')
    expect(warning).to_contain_text(_translated(language, "Last known warning"))
    expect(warning).to_contain_text(
        _translated(language, "A fresh reading has not yet confirmed the current condition.")
    )
    expect(warning).not_to_contain_text(_translated(language, "Writes may fail when the enforced cap is reached."))
    expect(warning).not_to_contain_text("100% of the current allowance")
    _layout(page, language, width, "stale-unverified")
    for availability in ("unknown", "unlimited"):
        boundary.service["hosting_warnings"] = {"disk": boundary.warning(condition=None, availability=availability)}
        page.reload()
        expect(page.locator("[data-hosting-warning]")).to_have_count(0)


@pytest.mark.parametrize("state", ("requested", "verified", "expired_attention", "expired"))
def test_temporary_capacity_states_keep_purchased_warning_denominator(
    page: Page, boundary: WarningBoundary, language: str, width: int, state: str
) -> None:
    boundary.service["hosting_warnings"] = {"disk": boundary.warning()}
    boundary.service["hosting_raise"] = {
        "state": state,
        "extra_mib": 1280,
        "revision": 1,
        "expires_at": "2026-11-07T10:00:00+00:00",
    }
    _open(page, boundary, language, width)
    relief = page.locator(f'[data-hosting-raise="{state}"]')
    headings = {
        "requested": "Temporary disk relief requested",
        "verified": "Temporary disk relief verified",
        "expired_attention": "Temporary disk relief has expired",
        "expired": "Temporary disk relief removed",
    }
    expect(relief).to_contain_text(_translated(language, headings[state]))
    expect(relief).to_contain_text(_translated(language, "Usage warnings continue to use your purchased allowance."))
    expect(page.locator('[data-hosting-warning="disk"]')).to_contain_text("100%")
    if state in {"requested", "verified"}:
        expect(relief).to_contain_text("1,25 GiB" if language == "ro" else "1.25 GiB")
    else:
        expect(relief).not_to_contain_text("1,25 GiB")
        expect(relief).not_to_contain_text("1.25 GiB")
    if state == "requested":
        expect(relief).to_contain_text(_translated(language, "Extra capacity is pending verification."))
    if state == "expired_attention":
        expect(relief).to_contain_text(
            _translated(language, "Current capacity needs review. Contact support if you need help.")
        )
    _layout(page, language, width, f"relief-{state}")


def test_pending_paid_change_retains_operational_allowance_and_review_action(
    page: Page, boundary: WarningBoundary, language: str, width: int
) -> None:
    boundary.limits["state"] = "pending"
    boundary.limits["assigned"] = {
        "disk_mib": 20480,
        "disk_gib": 20,
        "bandwidth_mib": 204800,
        "bandwidth_gib": 200,
    }
    boundary.service["plan_change"] = {"id": "d1a4adf1-6950-4c4f-9e91-1e0f84000001", "status": "applying_limits"}
    boundary.service["hosting_warnings"] = {"disk": boundary.warning()}
    _open(page, boundary, language, width)
    main = page.locator("#main-content")
    expect(main).to_contain_text("5 GiB")
    expect(main).to_contain_text("20 GiB")
    expect(main).to_contain_text(
        _translated(
            language,
            "The requested limits are not yet verified. Usage percentages still use the operational allowance.",
        )
    )
    warning = page.locator('[data-hosting-warning="disk"]')
    expect(warning).to_contain_text("100%")
    expect(warning.get_by_role("link", name=_translated(language, "Review plan change"))).to_be_visible()
    expect(warning.get_by_role("link", name=_translated(language, "Change plan"), exact=True)).to_have_count(0)
    _layout(page, language, width, "pending-paid")


def test_preferences_real_csrf_post_changes_only_optional_warnings(
    page: Page, boundary: WarningBoundary, language: str, width: int
) -> None:
    boundary.global_unsubscribe = True
    _open(page, boundary, language, width, PREFERENCES)
    main = page.locator("#main-content")
    expect(main.locator("h1")).to_have_text(
        "Preferințe pentru avertizările de găzduire" if language == "ro" else "Hosting warning preferences"
    )
    expect(main).to_contain_text("80%")
    expect(main).to_contain_text("95%")
    expect(main).to_contain_text(
        _translated(language, "Your global email opt-out also blocks optional hosting warnings.")
    )
    checkbox = page.locator("#quota_warnings")
    expect(checkbox).to_be_checked()
    page.get_by_text(_translated(language, "Receive optional hosting allowance warnings"), exact=True).click()
    expect(checkbox).not_to_be_checked()
    _layout(page, language, width, "preferences-before-save")
    page.get_by_role("button", name=_translated(language, "Save preferences")).click()
    expect(page).to_have_url(boundary.url + PREFERENCES)
    expect(checkbox).not_to_be_checked()
    assert boundary.preference_calls == [(42, 7, None), (42, 7, False), (42, 7, None)]
    expect(main).to_contain_text(
        _translated(
            language,
            "Critical allowance notices remain enabled. Delivery still requires current ownership, a valid recipient and no hard delivery block.",
        )
    )
    expect(page.get_by_text(_translated(language, "Hosting warning preferences saved."), exact=True)).to_be_visible()
    _layout(page, language, width, "preferences-saved")


def test_refused_preference_save_keeps_failure_visible(
    page: Page, boundary: WarningBoundary, language: str, width: int
) -> None:
    boundary.refuse_save = True
    _open(page, boundary, language, width, PREFERENCES)
    page.locator("#quota_warnings").uncheck()
    with page.expect_response(
        lambda response: response.url == boundary.url + PREFERENCES and response.request.method == "POST"
    ) as result:
        page.get_by_role("button", name=_translated(language, "Save preferences")).click()
    assert result.value.status == 503
    expect(page.locator('[role="alert"]')).to_contain_text(
        _translated(language, "The preference could not be saved. Please try again.")
    )
    assert boundary.optional is True
    assert boundary.preference_calls == [(42, 7, None), (42, 7, False)]
    _layout(page, language, width, "preferences-refused")
