"""Open the translated shared modal with each service's real Alpine CSP build."""

from __future__ import annotations

from pathlib import Path

from django.template.loader import render_to_string
from django.test import SimpleTestCase
from django.utils import translation
from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[4]


class DangerousActionModalTests(SimpleTestCase):
    def test_romanian_defaults_and_caller_overrides_survive_opening(self) -> None:
        with translation.override("ro"):
            markup = render_to_string("components/dangerous_action_modal.html")

        playwright = self.enterContext(sync_playwright())
        browser = playwright.chromium.launch()
        self.addCleanup(browser.close)
        for service in ("platform", "portal"):
            with self.subTest(service=service):
                page = browser.new_page()
                errors: list[str] = []
                page.on("pageerror", lambda error, captured=errors: captured.append(str(error)))
                page.set_content("<style>[x-cloak] { display: none !important; }</style>" + markup)
                page.add_script_tag(path=str(ROOT / "shared/ui/static/js/alpine-shared-components.js"))
                page.add_script_tag(path=str(ROOT / f"services/{service}/static/js/alpine-csp.min.js"))
                modal = page.locator('[x-data="dangerousActionModal"]')
                expect(modal).not_to_have_attribute("x-cloak", "")
                expect(modal).to_be_hidden()
                page.evaluate(
                    """() => {
                        window.confirmed = '';
                        window.dispatchEvent(new CustomEvent('confirm-dangerous-action', {
                            detail: {action: () => { window.confirmed = 'default'; }}
                        }));
                    }"""
                )
                expect(modal).to_be_visible()
                expect(modal.locator('[x-text="title"]')).to_have_text("Acțiune periculoasă")
                expect(modal.locator('[x-html="message"]')).to_have_text("Această acțiune nu poate fi anulată.")
                phrase = "Sunt sigur că vreau să fac acest lucru!"
                expect(modal.locator('[x-text="confirmText"]')).to_have_text(phrase)
                confirmation = modal.locator("#dangerous-action-confirmation")
                confirm = modal.locator("button").filter(has_text="Confirmă")
                confirmation.fill("I understand")
                expect(confirm).to_be_disabled()
                self.assertEqual(page.evaluate("window.confirmed"), "")
                confirmation.fill(phrase)
                expect(confirm).to_be_enabled()
                confirm.click()
                expect(modal).to_be_hidden()
                self.assertEqual(page.evaluate("window.confirmed"), "default")

                page.evaluate(
                    """() => {
                        window.dispatchEvent(new CustomEvent('confirm-dangerous-action', {
                            detail: {
                                title: 'Titlu ales',
                                message: '<strong>Mesaj ales</strong>',
                                confirmText: 'CONFIRMĂ ALES',
                                action: () => { window.confirmed = 'override'; }
                            }
                        }));
                    }"""
                )
                expect(modal).to_be_visible()
                expect(modal.locator('[x-text="title"]')).to_have_text("Titlu ales")
                expect(modal.locator('[x-html="message"] strong')).to_have_text("Mesaj ales")
                expect(modal.locator('[x-text="confirmText"]')).to_have_text("CONFIRMĂ ALES")
                confirmation.fill("CONFIRMĂ ALES")
                confirm.click()
                expect(modal).to_be_hidden()
                self.assertEqual(page.evaluate("window.confirmed"), "override")
                page.evaluate(
                    """() => window.dispatchEvent(
                        new CustomEvent('confirm-dangerous-action', {detail: {}})
                    )"""
                )
                expect(modal).to_be_visible()
                expect(modal.locator('[x-text="title"]')).to_have_text("Acțiune periculoasă")
                expect(modal.locator('[x-text="confirmText"]')).to_have_text(phrase)
                expect(confirmation).to_have_value("")
                self.assertEqual(errors, [])
                page.close()
