"""WP16 portal billing, services and support: default gates and rendered markup."""

from __future__ import annotations

import importlib.util
import sys
from html.parser import HTMLParser
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

from django.template import Context, Engine
from django.test import SimpleTestCase, override_settings

from apps.common.localisation import DisplayLocalisation

ROOT = Path(__file__).resolve().parents[4]
BUCKET = (
    "services/portal/templates/services/service_detail.html",
    "services/portal/templates/services/service_request_action.html",
    "services/portal/templates/billing/proforma_detail.html",
    "services/portal/templates/services/partials/usage_chart.html",
    "services/portal/templates/styleguide/index.html",
    "services/portal/templates/services/plans_list.html",
    "services/portal/templates/customers/address_form.html",
    "services/portal/templates/legal/cookie_policy.html",
    "services/portal/templates/tickets/ticket_create.html",
    "services/portal/templates/customers/team.html",
    "services/portal/templates/customers/team_invite.html",
    "services/portal/templates/billing/invoice_detail.html",
    "services/portal/templates/base.html",
    "services/portal/templates/tickets/ticket_detail.html",
    "services/portal/templates/services/partials/services_table.html",
    "services/portal/templates/tickets/partials/status_and_comments.html",
    "services/portal/templates/customers/tax_profile.html",
    "services/portal/templates/tickets/partials/replies_list.html",
    "services/portal/templates/billing/proforma_not_found.html",
    "services/portal/templates/billing/invoice_not_found.html",
    "services/portal/templates/tickets/partials/dashboard_widget.html",
    "services/portal/templates/services/partials/dashboard_widget.html",
    "services/portal/templates/customers/addresses.html",
    "services/portal/templates/billing/partials/invoices_table.html",
    "services/portal/templates/tickets/ticket_list.html",
    "services/portal/templates/tickets/partials/tickets_table.html",
    "services/portal/templates/services/service_list.html",
    "services/portal/templates/billing/recurring_payments.html",
    "services/portal/templates/billing/partials/invoice_extra_filters.html",
    "services/portal/templates/billing/invoices_list.html",
)


def scanner(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"wp16_support_{name}", ROOT / "scripts" / f"{name}.py")
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load scanner {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


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


@override_settings(DEBUG=True, TESTING=True, LANGUAGE_CODE="en")
class Wp16SupportBillingTests(SimpleTestCase):
    def render(self, name: str, values: dict[str, object] | None = None) -> str:
        overrides = (
            {"components/mobile_header.html": ""}
            if name == "base.html"
            else {"base.html": "{% block content %}{% endblock %}{% block extra_js %}{% endblock %}"}
        )
        engine = Engine(
            dirs=[str(ROOT / "services/portal/templates"), str(ROOT / "shared/ui/templates")],
            loaders=[
                ("django.template.loaders.locmem.Loader", overrides),
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
        findings = [
            str(finding)
            for path in BUCKET
            for finding in scanner("lint_template_components").scan_file(ROOT / path)
            if not finding.exempted and finding.code in {f"TMPL{number:03d}" for number in range(1, 10)}
        ]
        self.assertEqual(findings, [])

    def test_default_accessibility_gate_has_no_bucket_findings(self) -> None:
        findings = [
            str(finding)
            for path in BUCKET
            for finding in scanner("audit_accessibility").check_file(ROOT / path)
            if finding.severity in {"critical", "serious"}
        ]
        self.assertEqual(findings, [])

    def test_default_dark_mode_gate_has_no_bucket_findings(self) -> None:
        findings = [
            str(finding)
            for path in BUCKET
            for finding in scanner("audit_dark_mode").check_file(ROOT / path)
            if finding.severity == "blocker"
        ]
        self.assertEqual(findings, [])

    def test_address_form_preserves_values_constraints_and_country(self) -> None:
        source = self.render(
            "customers/address_form.html",
            {
                "values": {"label": "Office", "address_line1": "Main Street", "city": "Paris"},
                "country_choices": [("RO", "Romania"), ("FR", "France")],
                "selected_country": "FR",
            },
        )
        elements = Elements(source)
        self.assertIn("ui-btn", elements.find("button", type="submit")["class"])
        for name, value in (("label", "Office"), ("address_line1", "Main Street"), ("city", "Paris")):
            control = elements.find("input", name=name)
            self.assertEqual(control["id"], name)
            self.assertEqual(control["value"], value)
            elements.find("label", **{"for": name})
        self.assertEqual(elements.find("input", name="label")["maxlength"], "50")
        self.assertIn("required", elements.find("input", name="address_line1"))
        self.assertIn("required", elements.find("input", name="city"))
        self.assertEqual(elements.find("select", name="country")["id"], "country")
        self.assertIn("selected", elements.find("option", value="FR"))
        self.assertNotIn("selected", elements.find("option", value="RO"))
        for name in ("is_primary", "is_billing"):
            control = elements.find("input", name=name)
            self.assertEqual(control["value"], "on")
            self.assertNotIn("checked", control)
            elements.find("label", **{"for": name})

    def test_tax_form_preserves_checked_state_and_submission(self) -> None:
        for checked in (True, False):
            with self.subTest(checked=checked):
                source = self.render(
                    "customers/tax_profile.html",
                    {"can_edit": True, "tax_data": {"is_vat_payer": checked, "registration_number": "J40/123/2020"}},
                )
                elements = Elements(source)
                self.assertIn("ui-btn", elements.find("button", type="submit")["class"])
                self.assertEqual("checked" in elements.find("input", id="is_vat_payer"), checked)
                elements.find("label", **{"for": "is_vat_payer"})
                self.assertEqual(elements.find("input", name="trade_registry_number")["value"], "J40/123/2020")

    def test_invite_form_preserves_roles_required_fields_and_labels(self) -> None:
        source = self.render("customers/team_invite.html")
        elements = Elements(source)
        self.assertIn("ui-btn", elements.find("button", type="submit")["class"])
        self.assertIn("required", elements.find("input", name="email"))
        for name in ("email", "first_name", "last_name", "role"):
            elements.find("label", **{"for": name})
        for role in ("viewer", "tech", "billing", "owner"):
            elements.find("option", value=role)
        self.assertEqual(elements.find("select", name="role")["id"], "role")

    def test_team_role_controls_are_named_and_keep_member_actions(self) -> None:
        source = self.render(
            "customers/team.html",
            {"can_manage_team": True, "users": [{"user_id": 42, "role": "tech", "first_name": "Ada"}]},
        )
        elements = Elements(source)
        self.assertEqual(elements.find("select", name="role").get("aria-label"), "Role")
        self.assertIn("selected", elements.find("option", value="tech"))
        self.assertNotIn("selected", elements.find("option", value="viewer"))
        for suffix in ("role", "remove"):
            elements.find("form", action=f"/company/team/42/{suffix}/")
        self.assertTrue(elements.find("form", action="/company/team/42/remove/")["data-confirm"])
        buttons = [attrs for tag, attrs in elements.elements if tag == "button" and attrs.get("type") == "submit"]
        self.assertEqual(len(buttons), 2)
        self.assertTrue(all("ui-btn" in attrs["class"] for attrs in buttons))

    def test_invoice_filter_has_name_and_keeps_htmx_contract(self) -> None:
        source = self.render(
            "billing/partials/invoice_extra_filters.html",
            {
                "filter_search_url": "/billing/search/",
                "filter_content_id": "invoices-content",
                "filter_skeleton_id": "invoices-skeleton",
                "status_choices": [("paid", "Paid")],
                "status_filter": "paid",
            },
        )
        control = Elements(source).find("select", name="status")
        self.assertEqual(control.get("aria-label"), "Status")
        self.assertEqual(control["hx-target"], "#invoices-content")
        self.assertEqual(control["hx-sync"], "closest .list-filters-sync:replace")
        self.assertEqual(control["hx-include"], "#list-filter-search, #list-filter-active-tab")
        self.assertEqual(control["hx-indicator"], "#invoices-skeleton")

    def test_recurring_selector_is_named_and_preserves_enrollment_hooks(self) -> None:
        source = self.render(
            "billing/recurring_payments.html",
            {
                "overview": {"success": True},
                "subscriptions": [
                    {
                        "name": "Hosting",
                        "control_name": "subscription_42",
                        "control_id": "subscription-42",
                        "authorization_id": "auth-1",
                        "authorization_options": [{"value": "auth-1", "label": "Card"}],
                    }
                ],
            },
        )
        elements = Elements(source)
        control = elements.find("select", id="subscription-42")
        self.assertEqual(control.get("aria-label"), "Automatic payment authorization")
        self.assertEqual(control["name"], "subscription_42")
        self.assertIn("subscription-authorization", control["class"])
        self.assertIn("selected", elements.find("option", value="auth-1"))

    def test_service_request_controls_have_names_and_preserve_visual_label_hooks(self) -> None:
        source = self.render(
            "services/service_request_action.html",
            {
                "service_id": 42,
                "service": {"service_name": "Hosting", "status": "active"},
                "action_types": [("upgrade_request", "Upgrade"), ("cancel_request", "Cancel")],
                "selected_action": "cancel_request",
                "reason": "No longer needed",
            },
        )
        elements = Elements(source)
        self.assertEqual(elements.find("input", id="action_cancel_request").get("aria-label"), "Cancel")
        self.assertEqual(elements.find("input", id="action_upgrade_request").get("aria-label"), "Upgrade")
        self.assertIn("checked", elements.find("input", id="action_cancel_request"))
        self.assertNotIn("checked", elements.find("input", id="action_upgrade_request"))
        elements.find("label", **{"for": "action_cancel_request"})
        icons = [attrs for tag, attrs in elements.elements if tag == "div" and "action-icon" in attrs.get("class", "")]
        self.assertEqual(len(icons), 2)
        control = elements.find("textarea", id="reason")
        self.assertEqual(control.get("aria-label"), "Reason")
        self.assertEqual(control["maxlength"], "4000")
        self.assertIn("No longer needed", source)
        self.assertIn('id="reason-required"', source)

    def test_ticket_title_uses_the_id_required_by_its_label_and_script(self) -> None:
        source = self.render("tickets/ticket_create.html")
        control = Elements(source).find("input", name="title")
        self.assertEqual(control.get("id"), "title")
        self.assertEqual(control.get("aria-label"), "Title")
        self.assertEqual(control["placeholder"], "Brief description of the issue")
        self.assertIn("required", control)
        Elements(source).find("label", **{"for": "title"})
        self.assertIn('id="form-error-message"', source)

    def test_reply_is_named_and_keeps_submission_loading_hooks(self) -> None:
        source = self.render("tickets/partials/status_and_comments.html", {"ticket": {"id": 42, "status": "open"}})
        elements = Elements(source)
        self.assertEqual(elements.find("textarea", name="message").get("aria-label"), "Reply")
        self.assertEqual(elements.find("textarea", name="message")["id"], "input-message")
        self.assertEqual(elements.find("form", id="reply-form")["hx-target"], "#ticket-status-and-comments")
        for tag, hook in (("svg", "submit-spinner"), ("span", "submit-text"), ("input", "file-input")):
            elements.find(tag, id=hook)

    def test_error_notices_render_alerts_and_keep_recovery_links(self) -> None:
        for name in ("services/partials/dashboard_widget.html", "tickets/partials/dashboard_widget.html"):
            with self.subTest(template=name):
                source = self.render(name, {"error": True})
                self.assertIn('role="alert"', source)
                self.assertIn("Unable to load your", source)
        for document in ("invoice", "proforma"):
            with self.subTest(document=document):
                source = self.render(f"billing/{document}_not_found.html", {"error": True})
                self.assertIn('role="alert"', source)
                self.assertIn("ui-btn", Elements(source).find("a", href="/billing/invoices/")["class"])

    def test_cookie_categories_use_badges_and_keep_their_text(self) -> None:
        source = self.render("legal/cookie_policy.html")
        self.assertNotIn("bg-green-700", source)
        self.assertIn("Always Active", source)
        self.assertEqual(source.count(">Optional</span>"), 3)
        self.assertIn("bg-green-100", source)
        self.assertIn("bg-yellow-100", source)

    def test_service_detail_keeps_tabs_usage_and_component_actions(self) -> None:
        source = self.render(
            "services/service_detail.html",
            {
                "service_id": 42,
                "service": {
                    "service_name": "Hosting",
                    "status": "active",
                    "currency_code": "RON",
                    "disk_usage_percentage": 25,
                    "service_plan": {"name": "Basic", "disk_space_gb": 10},
                },
            },
        )
        elements = Elements(source)
        panels = [
            attrs
            for tag, attrs in elements.elements
            if tag == "a" and attrs.get("href") == "#" and "bg-blue-600" in attrs.get("class", "")
        ]
        self.assertEqual(len(panels), 1)
        self.assertIn("ui-btn", panels[0]["class"])
        elements.find("div", **{"x-data": "tabGroup"})
        self.assertIn("width: 25%", source)
        self.assertIn("Basic", source)

    def test_usage_alerts_use_component_and_preserve_message(self) -> None:
        source = self.render(
            "services/partials/usage_chart.html",
            {"usage": {"alerts": [{"type": "warning", "message": "Storage nearly full"}]}, "period": "month"},
        )
        self.assertIn('role="alert"', source)
        self.assertIn("Storage nearly full", source)
        self.assertIn("dark:bg-yellow-950", source)

    def test_plan_upgrade_control_uses_button_component(self) -> None:
        source = self.render("services/plans_list.html", {"plans": [{"name": "Hosting", "currency_code": "RON"}]})
        self.assertIn("ui-btn", Elements(source).find("button")["class"])

    def test_base_logout_uses_button_component_and_keeps_post(self) -> None:
        source = self.render("base.html", {"request": {"session": {"customer_id": 42}}})
        form = Elements(source).find("form", action="/logout/")
        self.assertEqual(form["method"], "post")
        self.assertIn('class="ui-btn', source)
        self.assertIn("Logout", source)
