"""Opt-in Chromium acceptance of real Portal checkout views and JavaScript.

Platform DTOs and Stripe's hosted-field SDK are explicit boundary doubles. Sessions
are seeded as in Portal view tests. This does not prove Platform authorization,
gateway settlement, or native quota qualification; those have separate gates.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from socketserver import ThreadingMixIn
from unittest.mock import Mock, patch
from urllib.parse import quote
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

import pytest
from django.conf import settings
from django.contrib.sessions.backends.cache import SessionStore
from django.contrib.staticfiles.handlers import StaticFilesHandler
from django.core.handlers.wsgi import WSGIHandler
from django.test import override_settings
from django.utils import timezone
from django.utils.translation import gettext, override
from playwright.sync_api import Page, expect

from tests.services.test_plan_change_checkout import BASE, DETAIL, TARGET, accepted_change

pytestmark = pytest.mark.browser
ARTIFACTS = Path(__file__).resolve().parents[4] / "output/playwright/hosting-plan-checkout-boundary"
VIEWPORTS = (390, 820, 1280)
LANGUAGES = ("en", "ro")

STRIPE_DOUBLE = """
window.__stripeConfirmations = [];
window.Stripe = (key) => ({
  elements: (options) => {
    window.__stripeOptions = {key, ...options};
    return {create: (type) => ({mount: (selector) => {
      window.__stripeElementType = type;
      const frame = document.createElement('iframe');
      frame.title = 'Synthetic hosted payment field';
      frame.style.width = '100%';
      frame.srcdoc = '<p>Stripe boundary double: no card data</p>';
      document.querySelector(selector).append(frame);
    }})};
  },
  confirmPayment: (request) => {
    window.__stripeConfirmations.push({
      redirect: request.redirect, return_url: request.confirmParams.return_url
    });
    return new Promise((resolve, reject) => {
      window.__resolveStripeResult = resolve;
      window.__rejectStripeResult = reject;
    });
  }
});
"""


class _ThreadedServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


class _QuietHandler(WSGIRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 -- stdlib signature.
        pass


class CheckoutBoundary:
    """Only Platform's response boundary is doubled; Portal owns each HTTP response."""

    def __init__(self) -> None:
        self.change = accepted_change(
            expires_at=(timezone.now() + timedelta(minutes=15)).isoformat(),
            authority_expires_at=(timezone.now() + timedelta(minutes=30)).isoformat(),
        )
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.url = ""
        self.session_key = ""

    def platform(self, endpoint: str, data: dict[str, object] | None = None, **kwargs: object) -> dict[str, object]:
        values = dict(data or {})
        self.calls.append((endpoint, values))
        if endpoint.endswith("options/"):
            result: object = [
                {
                    "product_id": TARGET,
                    "name": "Browser hosting target",
                    "available": True,
                    "direction": self.change["direction"],
                    "next_recurring_total_cents": self.change["next_recurring_total_cents"],
                    "currency": "RON",
                    "expected_limit_revision": 2,
                    "effective_at": self.change["effective_at"],
                }
            ]
        elif endpoint.endswith("confirm/"):
            if self.change["direction"] == "downgrade":
                self.change["status"] = "scheduled"
            elif self.change["total_cents"] == 0:
                assert values["accept_zero_due"] is True
                self.change["status"] = "applying_limits"
            else:
                self.change["status"] = "awaiting_payment"
            result = self.change.copy()
        elif endpoint.endswith("payment-intent/"):
            self.change.update(status="payment_in_flight", payment_state="ready")
            result = {
                "state": "ready",
                "attempt_id": TARGET,
                "client_secret": "pi_browser_boundary_secret",
                "publishable_key": "pk_test_browser_boundary",
            }
        elif endpoint.endswith("cancel/"):
            self.change["status"] = "cancelled"
            result = self.change.copy()
        else:
            result = self.change.copy()
        return {"success": True, "data": result}

    def actions(self, action: str) -> list[dict[str, object]]:
        return [data for path, data in self.calls if path.endswith(f"/{action}/")]


@pytest.fixture
def checkout() -> Iterator[CheckoutBoundary]:
    fixture = CheckoutBoundary()
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
        patch("apps.services.plan_changes.PlatformAPIClient", return_value=Mock(post=fixture.platform)),
    ):
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
            "127.0.0.1",
            0,
            StaticFilesHandler(WSGIHandler()),
            server_class=_ThreadedServer,
            handler_class=_QuietHandler,
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


@pytest.fixture(params=LANGUAGES)
def language(request: pytest.FixtureRequest) -> str:
    return str(request.param)


@pytest.fixture(params=VIEWPORTS)
def width(request: pytest.FixtureRequest) -> int:
    return int(request.param)


def _open(page: Page, checkout: CheckoutBoundary, language: str, width: int, path: str = DETAIL) -> None:
    page.set_viewport_size({"width": width, "height": 960})
    page.context.add_cookies(
        [
            {"name": settings.SESSION_COOKIE_NAME, "value": checkout.session_key, "url": checkout.url},
            {"name": settings.LANGUAGE_COOKIE_NAME, "value": language, "url": checkout.url},
            {"name": "cookie_consent", "value": quote('{"essential":true,"functional":true}'), "url": checkout.url},
        ]
    )
    page.route(
        "https://js.stripe.com/v3/",
        lambda route: route.fulfill(
            status=200,
            content_type="application/javascript",
            body=STRIPE_DOUBLE,
        ),
    )
    response = page.goto(checkout.url + path)
    assert response is not None and response.status == 200
    expect(page.locator("html")).to_have_attribute("lang", language)
    expect(page.locator("#main-content h1")).to_have_text(
        "Schimbați planul de găzduire" if language == "ro" else "Change hosting plan"
    )
    if language == "ro":
        expect(page.locator("#main-content")).to_contain_text("Totalul următoarei reînnoiri, inclusiv TVA")
        if path == DETAIL:
            expect(page.locator("#main-content")).to_contain_text("Total de plată acum")


def _layout(page: Page, language: str, width: int, phase: str) -> None:
    main = page.locator("#main-content")
    expect(main).to_be_visible()
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), "Horizontal page overflow"
    buttons = main.locator("button:visible").evaluate_all(
        "els => els.map(el => ({text: el.innerText, height: el.getBoundingClientRect().height}))"
    )
    assert buttons and all(button["height"] >= 44 for button in buttons), buttons
    # Stripe owns the editable payment fields; Portal must not collect card data.
    expect(main.locator('input:not([type="hidden"]):not([type="checkbox"])')).to_have_count(0)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(ARTIFACTS / f"{language}-{width}-{phase}.png"), full_page=True)


def _submit(page: Page, action: str) -> None:
    form = "#hosting-plan-refresh-form" if action == "refresh" else f'form[action$="/{action}/"]'
    page.locator(form + ' button[type="submit"]').click()


def _phase(page: Page, language: str, message: str) -> None:
    with override(language):
        translated = gettext(message)
        assert language != "ro" or translated != message, "Romanian phase copy must not fall back to English"
        expect(page.locator("#main-content h2")).to_have_text(translated)


def test_quote_explicit_card_resume_and_fresh_status(
    page: Page,
    checkout: CheckoutBoundary,
    language: str,
    width: int,
) -> None:
    _open(page, checkout, language, width, BASE)
    _layout(page, language, width, "options")
    page.locator(f"#plan-{TARGET} button").click()
    expect(page).to_have_url(checkout.url + DETAIL)
    expect(page.locator("#main-content")).to_contain_text("72,60")
    expect(page.locator("#main-content")).to_contain_text("12,60")
    expect(page.locator("#main-content")).to_contain_text("242,00")
    _layout(page, language, width, "quote")
    _submit(page, "confirm")
    expect(page.locator('form[action$="/payment-intent/"]')).to_be_visible()
    assert checkout.actions("payment-intent") == []
    _submit(page, "payment-intent")
    expect(page.locator("#hosting-plan-payment-element iframe")).to_be_visible()
    assert page.evaluate("window.__stripeElementType") == "payment"
    assert page.evaluate("window.__stripeOptions.clientSecret") == "pi_browser_boundary_secret"
    _layout(page, language, width, "hosted-payment")
    # A plain GET never replays payment creation or exposes its synthetic secret.
    page.goto(checkout.url + DETAIL)
    expect(page.locator("#hosting-plan-payment-config")).to_have_count(0)
    assert len(checkout.actions("payment-intent")) == 1
    _submit(page, "payment-intent")
    expect(page.locator("#hosting-plan-payment-element iframe")).to_be_visible()
    assert len(checkout.actions("payment-intent")) == 2
    assert checkout.actions("payment-intent")[0] == checkout.actions("payment-intent")[1]
    submit = page.locator("#hosting-plan-payment-form button[type=submit]")
    submit.click()
    expect(submit).to_be_disabled()
    assert page.evaluate("window.__stripeConfirmations") == [
        {
            "redirect": "if_required",
            "return_url": checkout.url + DETAIL,
        }
    ]
    assert checkout.change["payment_received"] is False
    # Only a new Platform status response can render paid/applying, not SDK success.
    checkout.change.update(status="applying_limits", payment_received=True)
    page.evaluate("window.__resolveStripeResult({})")
    expect(page.locator("#hosting-plan-payment-form")).to_have_count(0)
    _phase(page, language, "Payment received. Your new limits are being applied.")
    assert len(checkout.actions("payment-intent")) == 2
    assert checkout.actions("status")[-1]["user_id"] == 7
    _layout(page, language, width, "applying")


def test_sca_error_then_unknown_and_review_never_start_a_new_checkout(
    page: Page,
    checkout: CheckoutBoundary,
    language: str,
    width: int,
) -> None:
    checkout.change.update(status="awaiting_payment")
    _open(page, checkout, language, width)
    _submit(page, "payment-intent")
    submit = page.locator("#hosting-plan-payment-form button[type=submit]")
    submit.click()
    page.evaluate("window.__resolveStripeResult({error: {message: 'Synthetic SCA challenge declined'}})")
    expect(page.locator("#hosting-plan-payment-error")).to_have_text("Synthetic SCA challenge declined")
    expect(submit).to_be_enabled()
    assert len(checkout.actions("payment-intent")) == 1
    _layout(page, language, width, "sca-error")
    submit.click()
    page.evaluate("window.__rejectStripeResult(new Error('Synthetic lost response'))")
    expect(page.locator("#hosting-plan-payment-error")).to_be_visible()
    checkout.change.update(status="payment_in_flight", payment_state="unknown")
    _submit(page, "refresh")
    expect(page.locator('form[action$="/payment-intent/"]')).to_have_count(0)
    _phase(page, language, "Payment status is uncertain. Refresh its status before taking another action.")
    _layout(page, language, width, "unknown")
    for state in ("review", "refused"):
        checkout.change["payment_state"] = state
        page.reload()
        expect(page.locator('form[action$="/payment-intent/"]')).to_have_count(0)
        _phase(page, language, "This card payment needs staff review. Refresh its status or contact support.")
    checkout.change.update(status="paid_review", payment_received=True)
    page.reload()
    expect(page.locator('form[action$="/confirm/"]')).to_have_count(0)
    expect(page.locator('form[action$="/payment-intent/"]')).to_have_count(0)
    _phase(page, language, "Payment received. Staff must review this change before the plan can be applied.")
    assert len(checkout.actions("payment-intent")) == 1
    _layout(page, language, width, "paid-review")


@pytest.mark.parametrize("direction", ("upgrade", "downgrade"))
def test_zero_due_explicit_acceptance_or_scheduled_lower_terms(
    page: Page,
    checkout: CheckoutBoundary,
    language: str,
    width: int,
    direction: str,
) -> None:
    checkout.change.update(direction=direction, net_cents=0, tax_cents=0, total_cents=0)
    if direction == "downgrade":
        checkout.change.update(
            periods=[],
            effective_at="2026-12-01T00:00:00Z",
            next_recurring_net_cents=4000,
            next_recurring_total_cents=4840,
            proposed_limits={"disk_mib": 2048, "bandwidth_mib": 20480},
        )
    else:
        checkout.change["periods"] = [{**checkout.change["periods"][0], "net_cents": 0}]
    _open(page, checkout, language, width)
    checkbox = page.locator('input[name="accept_zero_due"]')
    if direction == "upgrade":
        expect(checkbox).to_have_attribute("required", "")
        label = page.locator(f'label[for="{checkbox.get_attribute("id")}"]')
        expect(label).to_be_visible()
        assert label.evaluate("el => el.getBoundingClientRect().height >= 44")
        _submit(page, "confirm")
        expect(checkbox).not_to_be_checked()
        assert checkout.actions("confirm") == []  # Real browser required consent stops POST.
        label.click()
        expect(checkbox).to_be_checked()
    else:
        expect(checkbox).to_have_count(0)
    _submit(page, "confirm")
    expected = "applying_limits" if direction == "upgrade" else "scheduled"
    assert checkout.change["status"] == expected
    assert checkout.change["payment_received"] is False
    assert checkout.actions("payment-intent") == []
    expect(page.locator('form[action$="/payment-intent/"]')).to_have_count(0)
    expect(page.locator("#hosting-plan-payment-config")).to_have_count(0)
    _phase(
        page,
        language,
        "Your accepted terms are recorded. Your new limits are being applied."
        if direction == "upgrade"
        else "Downgrade scheduled for the agreed renewal boundary",
    )
    if direction == "downgrade":
        expect(page.locator("#main-content")).to_contain_text("48,40")
        expect(page.locator("#main-content")).to_contain_text("01.12.2026")
    _layout(page, language, width, "zero-due" if direction == "upgrade" else "scheduled")


def test_cancellation_and_other_billing_viewer_keep_safe_actions(
    page: Page,
    checkout: CheckoutBoundary,
    language: str,
    width: int,
) -> None:
    checkout.change.update(viewer_can_accept=False, viewer_can_pay=False)
    _open(page, checkout, language, width)
    expect(page.locator('form[action$="/confirm/"]')).to_have_count(0)
    checkout.change["status"] = "awaiting_payment"
    page.reload()
    expect(page.locator('form[action$="/payment-intent/"]')).to_have_count(0)
    _submit(page, "cancel")
    assert checkout.actions("cancel") == [
        {
            "quote_fingerprint": "a" * 64,
            "accept_zero_due": False,
            "customer_id": 42,
            "user_id": 7,
        }
    ]
    expect(page.locator('form[action$="/cancel/"]')).to_have_count(0)
    expect(page.locator('form[action$="/payment-intent/"]')).to_have_count(0)
    _phase(page, language, "Plan change cancelled")
    _layout(page, language, width, "cancelled")


def test_missing_csrf_never_reaches_the_platform_boundary(page: Page, checkout: CheckoutBoundary) -> None:
    _open(page, checkout, "en", 390)
    calls_before = list(checkout.calls)
    response = page.request.post(
        checkout.url + DETAIL + "confirm/",
        form={"quote_fingerprint": "a" * 64},
    )
    assert response.status == 403
    assert checkout.calls == calls_before
