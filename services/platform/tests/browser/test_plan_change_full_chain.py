"""Real browser -> Portal password/session/signer -> Platform -> Stripe SDK seam.

Only Stripe SDK/provider calls and the initial native SSH qualification receipt
are doubled. All user authentication, HMAC/session/step-up checks, commercial
models, tax documents, webhook verification and settlement execute real code.
"""

from __future__ import annotations

import importlib.util
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta
from decimal import Decimal
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

import pytest
import requests
from django.core.cache import cache
from django.core.management import call_command
from django.db import connection
from django.test import TransactionTestCase
from playwright.sync_api import Page, expect, sync_playwright

from apps.billing.models import Invoice, Payment, ProformaInvoice
from apps.billing.plan_change_models import PlanChange
from apps.billing.plan_change_payment_models import PlanChangePaymentAttempt
from apps.integrations.models import WebhookEvent
from apps.products.models import ProductPrice
from apps.provisioning.hosting_limit_models import HostingLimitApplication, ServiceHostingLimits
from apps.settings.services import SettingsService
from apps.users.models import CustomerMembership, PortalSession
from tests.helpers.hmac import HMAC_TEST_SECRET
from tests.helpers.plan_change_checkout import VerifiedPlanChangeCheckoutFixture

pytestmark = pytest.mark.checkout_browser
ROOT = Path(__file__).resolve().parents[4]
ARTIFACTS = ROOT / "output/playwright/hosting-plan-checkout-full"
PASSWORD = "synthetic-hosting-browser-password"
KEY = "sk_test_hosting_browser_only"
WEBHOOK_KEY = "whsec_hosting_browser_only"


def load_tests(loader, tests, pattern):
    """This separately required browser gate never launches in ordinary test runs."""
    if os.environ.get("HOSTING_CHECKOUT_FULL") != "1":
        return loader.suiteClass()
    return tests


def _supervisor():
    """Reuse the existing process-group supervisor without importing Portal apps."""
    path = ROOT / "services/portal/tests/server/harness.py"
    spec = importlib.util.spec_from_file_location("hosting_browser_process_supervisor", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _read(path):
    return json.loads(path.read_text())


@contextmanager
def stack(fixture, name) -> Iterator[SimpleNamespace]:
    with TemporaryDirectory(prefix="hosting-checkout-full-") as directory:
        yield from _running_stack(fixture, Path(directory), name)


def _running_stack(fixture, tmp_path, name) -> Iterator[SimpleNamespace]:
    assert connection.vendor == "postgresql" and 160000 <= connection.pg_version < 170000
    assert connection.settings_dict["NAME"] == "test_hosting_browser"
    token = secrets.token_hex(16)
    safe = {name: os.environ[name] for name in ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR") if name in os.environ}
    safe.update(
        {
            "DJANGO_SETTINGS_MODULE": "tests.browser.full_checkout_settings",
            "PRAHO_SKIP_DOTENV": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUNBUFFERED": "1",
            "PYTHONNOUSERSITE": "1",
            "NO_PROXY": "*",
            "HOSTING_CHECKOUT_FULL": "1",
            "HOSTING_CHECKOUT_DIRECTORY": str(tmp_path),
            "HOSTING_CHECKOUT_TOKEN": token,
            "PYTHONPATH": str(ROOT / "services/platform") + os.pathsep + str(ROOT),
            "DB_NAME": "test_hosting_browser",
            "DB_HOST": str(connection.settings_dict["HOST"]),
            "DB_PORT": str(connection.settings_dict["PORT"]),
            "DB_USER": str(connection.settings_dict["USER"]),
            "DB_PASSWORD": str(connection.settings_dict["PASSWORD"]),
        }
    )
    supervisor = _supervisor()
    log = tmp_path / "platform.log"
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with log.open("wb") as output:
        process = subprocess.Popen(  # noqa: S603 -- Fixed guarded test server; clean allow-listed environment.
            [sys.executable, "tests/browser/full_checkout_server.py"],
            cwd=ROOT / "services/platform",
            env=safe,
            stdout=output,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    try:
        ready = tmp_path / "platform-ready.json"
        deadline = time.monotonic() + 45
        while not ready.exists():
            assert process.poll() is None, log.read_text()
            assert time.monotonic() < deadline, log.read_text()
            time.sleep(0.05)
        platform = _read(ready)["url"]
        with supervisor.running_portal(
            platform + "/api",
            DJANGO_SETTINGS_MODULE="tests.browser.full_checkout_settings",
            HOSTING_CHECKOUT_FULL="1",
            TESTING="1",
            HOSTING_CHECKOUT_PLATFORM_URL=platform,
            PLATFORM_API_SECRET=HMAC_TEST_SECRET,
            PORTAL_HMAC_SECRET=HMAC_TEST_SECRET,
            PORTAL_ID="hosting-browser",
            PLATFORM_TO_PORTAL_WEBHOOK_SECRET="test-webhook-secret-do-not-use-in-prod",
            PORTAL_GUNICORN_WORKER_CLASS="gthread",
            PORTAL_GUNICORN_WORKERS="1",
            PORTAL_GUNICORN_THREADS="4",
        ) as portal:
            (tmp_path / "portal-origin.json").write_text(json.dumps({"origin": portal.base_url}))
            try:
                yield SimpleNamespace(
                    fixture=fixture,
                    platform=platform,
                    portal=portal.base_url,
                    token=token,
                    journal=lambda: _read(tmp_path / "journal.json"),
                )
            finally:
                shutil.copy2(portal.log, ARTIFACTS / (name + "-portal.log"))
    finally:
        supervisor._stop(process)
        shutil.copy2(log, ARTIFACTS / (name + "-platform.log"))
        if (tmp_path / "journal.json").exists():
            shutil.copy2(tmp_path / "journal.json", ARTIFACTS / (name + "-journal.json"))


def _login(page: Page, stack):
    page.set_viewport_size({"width": 390, "height": 960})
    page.context.add_cookies(
        [
            {
                "name": "cookie_consent",
                "value": "%7B%22essential%22%3Atrue%2C%22functional%22%3Atrue%7D",
                "url": stack.portal,
            }
        ]
    )
    checkout = f"/services/{stack.fixture.service.pk}/change-plan/"
    response = page.goto(stack.portal + "/login/?next=" + checkout)
    assert response is not None and response.status == 200
    page.locator('input[name="email"]').fill(stack.fixture.actor.email)
    page.locator('input[name="password"]').fill(PASSWORD)
    page.locator('form button[type="submit"]').click()
    expect(page).to_have_url(stack.portal + checkout)
    # Real HMAC middleware must reject an unsigned request even with valid fixture IDs.
    refused = requests.post(
        stack.platform + f"/api/services/{stack.fixture.service.pk}/plan-changes/options/",
        json={"user_id": stack.fixture.actor.pk, "customer_id": stack.fixture.customer.pk},
        timeout=10,
    )
    assert refused.status_code == 401
    assert refused.json()["error"] == "HMAC authentication failed"


def _quote(page: Page, stack):
    page.locator(f"#plan-{stack.fixture.target.pk} button").click()
    expect(page.locator('form[action$="/confirm/"]')).to_be_visible()
    return page.url.rstrip("/").rsplit("/", 1)[1]


def _hosted_sdk(page: Page, stack):
    script = """
window.Stripe = () => ({
  elements: (config) => {
    window.__hostingClientSecret = config.clientSecret;
    return {create: () => ({mount: (selector) => {
      const frame = document.createElement('iframe'); frame.title = 'Synthetic hosted provider field';
      frame.setAttribute('width', '100%');
      frame.src = 'https://js.stripe.com/v3/hosting-browser-frame.html';
      document.querySelector(selector).append(frame);
    }})};
  },
  confirmPayment: () => fetch('https://api.stripe.com/v1/hosting-browser-confirm', {
    method: 'POST', headers: {'Content-Type': 'text/plain'},
    body: JSON.stringify({client_secret: window.__hostingClientSecret})
  }).then(response => response.json())
});
"""
    page.route(
        "https://js.stripe.com/v3/",
        lambda route: route.fulfill(
            status=200,
            content_type="application/javascript",
            body=script,
        ),
    )
    page.route(
        "https://js.stripe.com/v3/hosting-browser-frame.html",
        lambda route: route.fulfill(
            status=200,
            content_type="text/html",
            body="<!doctype html><html><body>Isolated provider fixture: no real card data</body></html>",
        ),
    )

    def provider(route):
        assert route.request.method == "POST"
        response = requests.post(
            stack.platform + "/__hosting_checkout__/confirm?token=" + stack.token,
            json=route.request.post_data_json,
            headers={"Origin": stack.portal},
            timeout=40,
        )
        route.fulfill(
            status=response.status_code,
            content_type="application/json",
            body=response.content,
            headers={"Access-Control-Allow-Origin": stack.portal},
        )

    page.route("https://api.stripe.com/v1/hosting-browser-confirm", provider)


class FullPlanCheckoutBrowserTests(VerifiedPlanChangeCheckoutFixture, TransactionTestCase):
    """DB setup/assertions run outside Playwright's loop; auth is never synthesized."""

    def setUp(self):
        if self._testMethodName.startswith("test_real_zero"):
            self.period_remaining = timedelta(days=1)
        cache.clear()
        super().setUp()
        self.actor.set_password(PASSWORD)
        self.actor.save(update_fields=["password"])
        CustomerMembership.objects.filter(user=self.actor, customer=self.customer).update(is_primary=True)
        if self._testMethodName.startswith("test_real_zero"):
            ProductPrice.objects.filter(product=self.target).update(monthly_price_cents=8001)
        call_command("setup_email_templates", verbosity=0, stdout=StringIO())
        for name, value in (
            ("integrations.stripe_enabled", True),
            ("integrations.stripe_secret_key", KEY),
            ("integrations.stripe_publishable_key", "pk_test_hosting_browser_only"),
            ("integrations.stripe_webhook_secret", WEBHOOK_KEY),
        ):
            result = SettingsService.update_setting(name, value)
            self.assertTrue(result.is_ok(), str(result))
        self.initial_document_counts = (
            Payment.objects.count(),
            Invoice.objects.count(),
            ProformaInvoice.objects.count(),
        )
        self.original_period_end = self.subscription.current_period_end

    def assert_real_authority(self, state):
        session = PortalSession.objects.get(user=self.actor)
        self.assertIsNotNone(session.reauth_at)
        self.assertIsNone(session.revoked_at)
        self.assertEqual(session.credential_snapshot, self.actor.get_session_auth_hash())
        signed = [
            item
            for item in state.journal()["requests"]
            if "/plan-changes/" in item["path"] and item["status"].startswith("20")
        ]
        self.assertTrue(signed)
        self.assertTrue(
            all(
                item["has_signature"] and item["session_id"] == str(session.pk) and item["step_up_at"]
                for item in signed
            )
        )

    def test_real_paid_checkout_replays_one_intent_then_signed_webhook_settles(self):  # noqa: PLR0915 -- One complete browser-to-model money trajectory.
        self.assertFalse(PortalSession.objects.filter(user=self.actor).exists())
        with stack(self, self._testMethodName) as state:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch()
                page = browser.new_page()
                errors: list[str] = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.on("console", lambda message: errors.append(message.text) if message.type == "error" else None)
                _login(page, state)
                _hosted_sdk(page, state)
                change_id = _quote(page, state)
                detail_url = page.url
                page.locator('form[action$="/confirm/"] button').click()
                expect(page.locator('form[action$="/payment-intent/"]')).to_be_visible()
                page.locator('form[action$="/payment-intent/"] button').click()
                expect(page.locator("#hosting-plan-payment-element iframe")).to_be_visible()
                secret = page.evaluate("window.__hostingClientSecret")
                page.goto(detail_url)
                expect(page.locator("#hosting-plan-payment-config")).to_have_count(0)
                page.locator('form[action$="/payment-intent/"] button').click()
                expect(page.locator("#hosting-plan-payment-element iframe")).to_be_visible()
                self.assertEqual(page.evaluate("window.__hostingClientSecret"), secret)
                page.locator("#hosting-plan-payment-form button").click()
                expect(page.locator("#main-content h2")).to_have_text(
                    "Payment received. Your new limits are being applied."
                )
                self.assertFalse(page.evaluate("document.documentElement.scrollWidth > window.innerWidth"))
                page.screenshot(path=str(ARTIFACTS / "real-paid-applying-390.png"), full_page=True)
                self.assertEqual(errors, [])
                browser.close()
            change = PlanChange.objects.get(pk=change_id)
            self.assertEqual(change.status, "applying_limits")
            self.assertEqual((change.requested_by_id, change.customer_id), (self.actor.pk, self.customer.pk))
            assert change.invoice_id is not None
            assert change.proforma_id is not None
            invoice = Invoice.objects.get(pk=change.invoice_id)
            document = ProformaInvoice.objects.get(pk=change.proforma_id)
            self.assertEqual((invoice.status, invoice.total_cents), ("paid", change.total_cents))
            self.assertEqual(document.total_cents, change.total_cents)
            self.assertEqual(document.lines.count(), 1)
            self.assertIsNone(document.lines.get().billing_cycle_id)
            self.assertEqual(Payment.objects.filter(meta__source="hosting_plan_change").count(), 1)
            self.assertEqual(PlanChangePaymentAttempt.objects.filter(change=change).count(), 1)
            self.assertEqual(
                (Payment.objects.count(), Invoice.objects.count(), ProformaInvoice.objects.count()),
                tuple(value + 1 for value in self.initial_document_counts),
            )
            assert change.limit_application_id is not None
            self.assertTrue(HostingLimitApplication.objects.filter(pk=change.limit_application_id).exists())
            limits = ServiceHostingLimits.objects.get(service=self.service)
            self.assertEqual((limits.revision, limits.applied_revision), (3, 2))
            self.assertEqual(limits.disk_allowance_mib, 20480)
            self.subscription.refresh_from_db()
            self.service.refresh_from_db()
            self.assertEqual(
                (self.subscription.product_id, self.subscription.unit_price_cents), (self.target.pk, 20000)
            )
            self.assertEqual(self.subscription.current_period_end, self.original_period_end)
            self.assertEqual(self.service.price, Decimal("200.00"))
            created = [item for item in state.journal()["sdk"] if item["action"] == "create"]
            self.assertEqual(len(created), 1)
            self.assertIs(created[0]["in_atomic"], False)
            self.assertEqual(created[0]["payload"]["amount"], change.total_cents)
            self.assertIs(created[0]["payload"]["confirm"], False)
            self.assertNotIn("off_session", created[0]["payload"])
            self.assert_real_authority(state)
            event = WebhookEvent.objects.get(source="stripe")
            self.assertEqual(event.status, "processed")
            self.assertNotIn("client_secret", json.dumps(event.payload))

    def test_real_zero_due_acceptance_has_no_payment_or_provider_call(self):
        with stack(self, self._testMethodName) as state:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch()
                page = browser.new_page()
                errors: list[str] = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.on("console", lambda message: errors.append(message.text) if message.type == "error" else None)
                _login(page, state)
                change_id = _quote(page, state)
                consent = page.locator('input[name="accept_zero_due"]')
                expect(consent).to_have_attribute("required", "")
                confirmations = []
                page.on(
                    "request",
                    lambda req: (
                        confirmations.append(req.url)
                        if req.method == "POST" and req.url.endswith("/confirm/")
                        else None
                    ),
                )
                page.locator('form[action$="/confirm/"] button').click()
                self.assertEqual(confirmations, [])
                consent.check()
                page.locator('form[action$="/confirm/"] button').click()
                expect(page.locator("#main-content h2")).to_have_text(
                    "Your accepted terms are recorded. Your new limits are being applied."
                )
                self.assertEqual(len(confirmations), 1)
                page.screenshot(path=str(ARTIFACTS / "real-zero-due-applying-390.png"), full_page=True)
                self.assertEqual(errors, [])
                browser.close()
            change = PlanChange.objects.get(pk=change_id)
            self.assertEqual((change.status, change.total_cents), ("applying_limits", 0))
            self.assertIsNotNone(change.confirmed_at)
            self.assertIsNone(change.proforma_id)
            self.assertIsNone(change.invoice_id)
            self.assertFalse(Payment.objects.filter(meta__source="hosting_plan_change").exists())
            self.assertFalse(PlanChangePaymentAttempt.objects.filter(change=change).exists())
            self.assertEqual(
                (Payment.objects.count(), Invoice.objects.count(), ProformaInvoice.objects.count()),
                self.initial_document_counts,
            )
            self.subscription.refresh_from_db()
            self.service.refresh_from_db()
            self.assertEqual(self.subscription.unit_price_cents, 8001)
            self.assertEqual(self.subscription.current_period_end, self.original_period_end)
            self.assertEqual(self.service.price, Decimal("80.01"))
            self.assertEqual(state.journal()["sdk"], [])
            assert change.limit_application_id is not None
            self.assertTrue(HostingLimitApplication.objects.filter(pk=change.limit_application_id).exists())
            self.assert_real_authority(state)
