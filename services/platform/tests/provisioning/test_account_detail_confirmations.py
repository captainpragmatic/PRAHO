"""Rendered account-detail confirmations retain their locale and HTTP actions."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from django.template import Context, Engine
from django.test import SimpleTestCase
from django.utils import translation
from playwright.sync_api import expect, sync_playwright

from apps.common.localisation import DisplayLocalisation

ROOT = Path(__file__).resolve().parents[4]


class AccountDetailConfirmationTests(SimpleTestCase):
    def render_account(self, *, protected: bool) -> str:
        engine = Engine(
            dirs=[str(ROOT / "services/platform/templates"), str(ROOT / "shared/ui/templates")],
            loaders=[
                (
                    "django.template.loaders.locmem.Loader",
                    {"base.html": ("{% block content %}{% endblock %}{% block extra_modals %}{% endblock %}")},
                ),
                "django.template.loaders.filesystem.Loader",
            ],
            libraries={
                "i18n": "django.templatetags.i18n",
                "ui_components": "apps.ui.templatetags.ui_components",
                "localisation_tags": "apps.ui.templatetags.localisation_tags",
            },
        )
        policy = DisplayLocalisation("ro", "RO", "Europe/Bucharest", "d.m.Y")
        with patch("apps.ui.templatetags.localisation_tags.get_request_localisation", return_value=policy):
            return engine.get_template("provisioning/virtualmin/account_detail.html").render(
                Context(
                    {
                        "account": {
                            "domain": "hosting.example.com",
                            "protected_from_deletion": protected,
                            "can_be_deleted": not protected,
                            "is_active": True,
                        },
                        "toggle_protection_url": "/protection/",
                        "delete_url": "/delete/",
                        "csrf_token": "test-token",
                    }
                )
            )

    def test_account_confirmations_use_romanian_and_preserve_the_requested_action(self) -> None:
        with translation.override("ro"):
            playwright = self.enterContext(sync_playwright())
            browser = playwright.chromium.launch()
            self.addCleanup(browser.close)
            cases = (
                ("confirmProtectionToggle", True, "Disable Protection", "POST", "/protection/"),
                ("confirmAccountDelete", False, "Delete Account", "DELETE", "/delete/"),
            )
            for function, protected, title, method, url in cases:
                with self.subTest(function=function):
                    page = browser.new_page()
                    page.set_content(
                        "<style>[x-cloak] { display: none !important; }</style>"
                        + self.render_account(protected=protected)
                    )
                    page.add_script_tag(
                        content=(
                            "window.requests = [];"
                            "window.htmx = {ajax: (method, url, options) => {"
                            "window.requests.push({method, url, options}); }};"
                        )
                    )
                    page.add_script_tag(path=str(ROOT / "shared/ui/static/js/alpine-shared-components.js"))
                    page.add_script_tag(path=str(ROOT / "services/platform/static/js/alpine-csp.min.js"))
                    modal = page.locator('[x-data="dangerousActionModal"]')
                    expect(modal).not_to_have_attribute("x-cloak", "")
                    page.evaluate(
                        """functionName => {
                            const button = document.querySelector(
                                '[data-invoke="' + functionName + 'Action"]'
                            );
                            window[functionName](button);
                        }""",
                        function,
                    )
                    expect(modal).to_be_visible()
                    expect(modal.locator('[x-text="title"]')).to_have_text(translation.gettext(title))
                    message = modal.locator('[x-html="message"]')
                    expect(message).to_contain_text("hosting.example.com")
                    expect(message).to_contain_text("Această acțiune nu poate fi anulată.")
                    phrase = "Sunt sigur că vreau să fac acest lucru!"
                    expect(modal.locator('[x-text="confirmText"]')).to_have_text(phrase)
                    self.assertEqual(page.evaluate("window.requests"), [])
                    modal.locator("#dangerous-action-confirmation").fill(phrase)
                    modal.locator("button").filter(has_text="Confirmă").click()
                    expect(modal).to_be_hidden()
                    options: dict[str, object] = {"target": "body"}
                    if protected:
                        options = {
                            "target": "#quick-actions-section",
                            "swap": "outerHTML",
                            "headers": {"X-CSRFToken": "test-token"},
                        }
                    self.assertEqual(
                        page.evaluate("window.requests"),
                        [{"method": method, "url": url, "options": options}],
                    )
                    page.close()
