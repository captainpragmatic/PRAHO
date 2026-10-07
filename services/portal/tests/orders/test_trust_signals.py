"""Regression coverage for responsive trust badges using the shipped CSS."""

from __future__ import annotations

from pathlib import Path

from django.template.loader import render_to_string
from django.test import SimpleTestCase
from django.utils import translation
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[4]


class TrustSignalsTests(SimpleTestCase):
    def test_data_center_badge_is_hidden_below_sm_and_visible_from_sm(self) -> None:
        with translation.override("en"):
            markup = render_to_string("orders/partials/trust_signals.html")

        playwright = self.enterContext(sync_playwright())
        browser = playwright.chromium.launch()
        self.addCleanup(browser.close)
        page = browser.new_page()
        page.set_content(markup)
        page.add_style_tag(path=str(ROOT / "services/portal/static/css/tailwind.min.css"))
        badge = page.locator("span.inline-flex").filter(has_text="Romanian Data Center")
        self.assertEqual(badge.count(), 1)
        for width, visible in ((375, False), (639, False), (640, True), (1024, True)):
            with self.subTest(width=width):
                page.set_viewport_size({"width": width, "height": 768})
                self.assertEqual(badge.is_visible(), visible)
        wrapper = badge.locator("..")
        self.assertEqual(wrapper.get_attribute("class"), "hidden sm:block")
        self.assertNotIn("hidden", (badge.get_attribute("class") or "").split())
