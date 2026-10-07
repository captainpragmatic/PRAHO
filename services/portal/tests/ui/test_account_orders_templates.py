"""WP16 account and ordering templates: default gates and rendered control contracts."""

from __future__ import annotations

import importlib.util
import json
import sys
from html.parser import HTMLParser
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

from django import forms
from django.core.exceptions import ValidationError
from django.template import Context, Engine
from django.test import SimpleTestCase, override_settings

from apps.common.localisation import DisplayLocalisation

ROOT = Path(__file__).resolve().parents[4]
PORTAL = ROOT / "services/portal/templates"
SHARED = ROOT / "shared/ui/templates"
BUCKET = (
    "services/portal/templates/orders/checkout.html",
    "services/portal/templates/orders/order_confirmation.html",
    "services/portal/templates/users/mfa_management.html",
    "services/portal/templates/users/create_company.html",
    "services/portal/templates/users/mfa_setup_totp.html",
    "services/portal/templates/users/profile.html",
    "services/portal/templates/users/data_export.html",
    "services/portal/templates/users/consent_history.html",
    "services/portal/templates/orders/product_catalog.html",
    "services/portal/templates/users/privacy_dashboard.html",
    "services/portal/templates/users/company_profile_edit.html",
    "services/portal/templates/users/company_profile.html",
    "services/portal/templates/users/change_password.html",
    "services/portal/templates/orders/partials/cart_totals.html",
    "services/portal/templates/dashboard/dashboard.html",
    "services/portal/templates/orders/partials/trust_signals.html",
    "services/portal/templates/orders/product_detail.html",
    "services/portal/templates/orders/partials/mini_cart_content.html",
    "services/portal/templates/orders/partials/cart_items.html",
    "services/portal/templates/users/mfa_backup_codes.html",
    "services/portal/templates/users/login.html",
    "services/portal/templates/orders/partials/error_message.html",
    "services/portal/templates/dashboard/account_overview.html",
    "services/portal/templates/components/customer_selector.html",
    "services/portal/templates/components/cookie_consent_banner.html",
    "services/portal/templates/users/register.html",
    "services/portal/templates/users/password_reset.html",
    "services/portal/templates/orders/partials/cart_updated.html",
    "services/portal/templates/users/password_reset_confirm.html",
    "services/portal/templates/orders/partials/cart_empty.html",
    "services/portal/templates/components/mobile_header.html",
    "shared/ui/templates/components/nav_dropdown.html",
    "shared/ui/templates/components/dangerous_action_modal.html",
)


class Elements(HTMLParser):
    def __init__(self, source: str) -> None:
        super().__init__()
        self.elements: list[tuple[str, dict[str, str]]] = []
        self.feed(source)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.elements.append((tag, {name: value or "" for name, value in attrs}))

    def find(self, tag: str, **attributes: str) -> dict[str, str]:
        matches = [
            attrs
            for element, attrs in self.elements
            if element == tag and all(attrs.get(key) == value for key, value in attributes.items())
        ]
        if len(matches) != 1:
            raise AssertionError(f"Expected one {tag} with {attributes}, found {len(matches)}")
        return matches[0]


def scanner(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"wp16_{name}", ROOT / "scripts" / f"{name}.py")
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load scanner {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@override_settings(DEBUG=True, TESTING=True, LANGUAGE_CODE="en")
class Wp16AccountOrdersTests(SimpleTestCase):
    def render(self, name: str, values: dict[str, object] | None = None) -> str:
        engine = Engine(
            dirs=[str(PORTAL), str(SHARED)],
            loaders=[
                (
                    "django.template.loaders.locmem.Loader",
                    {"base.html": "{% block content %}{% endblock %}{% block extra_js %}{% endblock %}"},
                ),
                "django.template.loaders.filesystem.Loader",
            ],
            libraries={
                "i18n": "django.templatetags.i18n",
                "static": "django.templatetags.static",
                "ui_components": "apps.ui.templatetags.ui_components",
                "formatting": "apps.ui.templatetags.formatting",
                "localisation_tags": "apps.ui.templatetags.localisation_tags",
            },
        )
        policy = DisplayLocalisation("en", "RO", "Europe/Bucharest", "d.m.Y")
        with patch("apps.ui.templatetags.localisation_tags.get_request_localisation", return_value=policy):
            return engine.get_template(name).render(Context({"csrf_token": "test-token", **(values or {})}))

    def test_default_template_gate_has_no_bucket_findings(self) -> None:
        module = scanner("lint_template_components")
        findings = [
            str(finding)
            for relative in BUCKET
            for finding in module.scan_file(ROOT / relative)
            if not finding.exempted and finding.code in {f"TMPL{number:03d}" for number in range(1, 10)}
        ]
        self.assertEqual(findings, [])

    def test_default_accessibility_gate_has_no_bucket_findings(self) -> None:
        module = scanner("audit_accessibility")
        findings = [
            str(finding)
            for relative in BUCKET
            for finding in module.check_file(ROOT / relative)
            if finding.severity in {"critical", "serious"}
        ]
        self.assertEqual(findings, [])

    def test_default_dark_mode_gate_has_no_bucket_findings(self) -> None:
        module = scanner("audit_dark_mode")
        findings = [
            str(finding)
            for relative in BUCKET
            for finding in module.check_file(ROOT / relative)
            if finding.severity == "blocker"
        ]
        self.assertEqual(findings, [])

    def test_product_controls_keep_submission_contract_and_labels(self) -> None:
        source = self.render(
            "orders/product_detail.html",
            {
                "product": {"name": "Hosting", "slug": "hosting", "description": "", "prices": [{"currency": "RON"}]},
                "billing_periods": [{"value": "monthly", "label": "Monthly", "amount": "10.00"}],
            },
        )
        elements = Elements(source)
        period = elements.find("select", name="billing_period")
        self.assertEqual(period.get("id"), "id_billing_period")
        elements.find("label", **{"for": "id_billing_period"})
        elements.find("option", value="monthly")
        quantity = elements.find("input", name="quantity")
        self.assertEqual(quantity["id"], "id_quantity")
        self.assertEqual(quantity["min"], "1")
        self.assertEqual(quantity["value"], "1")
        elements.find("label", **{"for": "id_quantity"})
        self.assertIn('hx-target="#cart-widget"', source)
        self.assertIn('data-htmx-after="cart-updated"', source)

    def test_company_selector_keeps_memberships_and_accessible_name(self) -> None:
        form = forms.Form()
        for name in ("first_name", "last_name", "phone", "preferred_language", "timezone", "date_format"):
            form.fields[name] = forms.CharField(required=False)
        source = self.render(
            "users/profile.html",
            {
                "form": form,
                "user_memberships": [
                    {"customer_id": 1, "customer_name": "First", "role": "owner"},
                    {"customer_id": 2, "customer_name": "Second", "role": "viewer"},
                ],
                "selected_customer_id": 2,
                "customer_email": "customer@example.com",
            },
        )
        elements = Elements(source)
        selector = elements.find("select", **{"data-action": "switch-customer"})
        self.assertEqual(selector.get("aria-label"), "Company")
        self.assertIn("selected", elements.find("option", value="2"))
        self.assertNotIn("selected", elements.find("option", value="1"))

    def test_modal_backdrop_is_a_named_keyboard_control(self) -> None:
        source = self.render("components/dangerous_action_modal.html")
        self.assertIn('@confirm-dangerous-action.window="onConfirmRequest($event)"', source)
        elements = Elements(source)
        backdrop = elements.find("button", **{"@click": "close()", "aria-label": "Close dialog"})
        self.assertEqual(backdrop["type"], "button")
        elements.find("label", **{"for": "dangerous-action-confirmation"})
        elements.find("input", id="dangerous-action-confirmation")
        self.assertFalse(any(tag == "div" and attrs.get("@click") == "close()" for tag, attrs in elements.elements))

    def test_dropdown_has_named_group_and_keeps_outside_click_binding(self) -> None:
        source = self.render("components/nav_dropdown.html", {"title": "Account", "items": []})
        group = Elements(source).find("div", **{"x-data": "navDropdown"})
        self.assertEqual(group.get("role"), "group")
        self.assertEqual(group.get("aria-label"), "Account")
        self.assertEqual(group.get("tabindex"), "-1")
        self.assertEqual(group["@click.away"], "open = false")

    def test_customer_selector_uses_external_script_and_keeps_delegation(self) -> None:
        source = self.render("components/customer_selector.html")
        elements = Elements(source)
        scripts = [attrs for tag, attrs in elements.elements if tag == "script"]
        self.assertEqual(len(scripts), 1)
        self.assertEqual(scripts[0].get("src"), "/static/js/customer-selector.js")
        self.assertIn('id="customerSelectorBtn"', source)
        self.assertIn('id="customerSelectorDropdown"', source)
        self.assertIn('data-action="toggle-customer-selector"', source)

    def test_outage_notices_render_accessible_dark_aware_alerts(self) -> None:
        for name in ("dashboard/dashboard.html", "dashboard/account_overview.html"):
            with self.subTest(template=name):
                source = self.render(name, {"platform_available": False})
                self.assertIn('role="alert"', source)
                self.assertIn("dark:bg-red-950", source)
                self.assertIn("Platform service temporarily unavailable. Some features may be limited.", source)

    def test_checkout_keeps_payment_bindings_and_loading_hooks(self) -> None:
        source = self.render("orders/checkout.html", {"can_submit": True})
        elements = Elements(source)
        notes = elements.find("textarea", name="notes")
        self.assertEqual(notes["id"], "notes")
        self.assertEqual(notes["maxlength"], "500")
        self.assertEqual(notes["rows"], "4")
        self.assertIn("resize-none", notes["class"])
        self.assertIn('aria-label="Order notes"', source)
        self.assertIn("@change=\"paymentMethod = 'card'\"", source)
        self.assertIn("@change=\"paymentMethod = 'bank_transfer'\"", source)
        for hook in ("checkout-submit", "button-text", "button-loading"):
            self.assertIn(f'id="{hook}"', source)

    def test_company_fields_keep_constraints_values_and_all_errors(self) -> None:
        for template, names in (
            (
                "users/company_profile_edit.html",
                ("company_name", "industry", "primary_email", "primary_phone", "website"),
            ),
            (
                "users/create_company.html",
                (
                    "company_name",
                    "industry",
                    "vat_number",
                    "trade_registry_number",
                    "street_address",
                    "city",
                    "state",
                    "postal_code",
                    "primary_email",
                    "primary_phone",
                    "website",
                ),
            ),
        ):
            with self.subTest(template=template):
                form = forms.Form(data=dict.fromkeys(names, "value"))
                for name in names:
                    form.fields[name] = forms.CharField(label=name, max_length=200, help_text="Help", required=False)
                form.fields["country"] = forms.ChoiceField(choices=[("RO", "Romania")], required=False)
                form.fields["agree_terms"] = forms.BooleanField(label="Agree", required=False)
                form.add_error("company_name", ValidationError(["First problem", "Second problem"]))
                source = self.render(template, {"form": form})
                elements = Elements(source)
                alerts = [attrs for tag, attrs in elements.elements if tag == "div" and attrs.get("role") == "alert"]
                self.assertEqual(len(alerts), 2)
                self.assertIn("First problem", source)
                self.assertIn("Second problem", source)
                for name in names:
                    control = elements.find("input", name=name)
                    self.assertEqual(control["id"], f"id_{name}")
                    self.assertEqual(control["maxlength"], "200")
                    elements.find("label", **{"for": f"id_{name}"})
                    if name != "company_name":
                        self.assertEqual(control["value"], "value")

    def test_mini_cart_remove_keeps_payload_and_swap_contract(self) -> None:
        source = self.render(
            "orders/partials/mini_cart_content.html",
            {
                "cart_items": [{"product_slug": "hosting", "billing_period": "annual", "product_name": "Hosting"}],
                "total_items": 1,
            },
        )
        control = Elements(source).find("button", **{"hx-target": "#cart-widget"})
        self.assertEqual(json.loads(control["hx-vals"]), {"product_slug": "hosting", "billing_period": "annual"})
        self.assertEqual(json.loads(control["hx-headers"]), {"X-CSRFToken": "test-token"})
        self.assertEqual(control["hx-swap"], "outerHTML")
        self.assertEqual(control["data-htmx-after"], "cart-updated")
        self.assertEqual(control["aria-label"], "Remove from cart")
        self.assertTrue(control["hx-confirm"])

    def test_checkout_link_keeps_cart_version(self) -> None:
        source = self.render(
            "orders/partials/cart_totals.html",
            {"calculation": {"total_cents": 100, "currency": "RON"}, "cart": {"get_cart_version": "version-16"}},
        )
        control = Elements(source).find("a", href="/order/checkout/")
        self.assertIn("ui-btn", control["class"])
        self.assertEqual(control["data-cart-version"], "version-16")

    def test_profile_completion_link_keeps_checkout_return_url(self) -> None:
        source = self.render(
            "orders/checkout.html",
            {"preflight": {"valid": False, "errors": ["Missing profile"], "display_errors": []}},
        )
        control = Elements(source).find("a", href="/company/edit/?next=/order/checkout/")
        self.assertIn("ui-btn", control["class"])
        self.assertIn('id="validation-errors-section"', source)
        self.assertIn("Missing profile", source)
