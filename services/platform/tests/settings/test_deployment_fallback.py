"""Deployment fallback cleanup and the staff UI preserve explicit choices."""

from __future__ import annotations

import json
import subprocess
from html.parser import HTMLParser
from io import StringIO
from pathlib import Path

from django.core.management import call_command
from django.http import HttpResponse
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.translation import override

from apps.settings.catalog import CATALOG_BY_KEY
from apps.settings.models import SettingActivation, SystemSetting
from apps.settings.services import SettingsService, get_default_from_email
from tests.factories.core_factories import create_admin_user

KEY = "efactura.enabled"


class FieldParser(HTMLParser):
    def __init__(self, key: str) -> None:
        super().__init__()
        self.target = f"field-{key}"
        self.field: dict[str, str | None] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag == "input" and attributes.get("id") == self.target:
            self.field = attributes


@override_settings(EFACTURA_ENABLED=False, DEFAULT_FROM_EMAIL="deployment@example.test", LANGUAGE_CODE="en")
class DeploymentFallbackTests(TestCase):
    def setUp(self) -> None:
        self.client.force_login(create_admin_user(username="seed2_admin"))

    def sync(self, category: str = "efactura", *, force: bool = False) -> str:
        output = StringIO()
        with override("en"):
            call_command("setup_default_settings", category=category, force=force, stdout=output)
        return output.getvalue()

    def write(self, key: str, value: object) -> SystemSetting:
        result = SettingsService.update_setting(key, value)
        self.assertTrue(result.is_ok(), result)
        return SystemSetting.objects.get(key=key)

    def page(self, group: str = "efactura") -> HttpResponse:
        response = self.client.get(reverse("settings:group", args=[group]))
        self.assertEqual(response.status_code, 200)
        return response

    def post(self, changes: dict[str, object], baselines: dict[str, str | None]) -> HttpResponse:
        return self.client.post(
            reverse("settings:save_change_set"),
            data=json.dumps({"changes": changes, "baselines": baselines}),
            content_type="application/json",
        )

    def test_first_sync_removes_seed_and_records_completed_receipt(self) -> None:
        self.write(KEY, True)
        output = self.sync()
        self.assertFalse(SystemSetting.objects.filter(key=KEY).exists())
        self.assertIn(f"Removed deployment-fallback default: {KEY}", output)
        self.assertTrue(
            SettingActivation.objects.filter(
                key=KEY, version="deployment-fallback-v1", completed_at__isnull=False
            ).exists()
        )

    def test_catalog_default_override_survives_later_sync_and_force(self) -> None:
        self.sync()
        self.write(KEY, True)
        for force in (False, True):
            output = self.sync(force=force)
            self.assertTrue(SystemSetting.objects.filter(key=KEY, value=True).exists())
            self.assertNotIn(f"Removed deployment-fallback default: {KEY}", output)

    def test_absent_key_gets_receipt_before_a_later_explicit_write(self) -> None:
        self.sync("company")
        key = "company.email_noreply"
        self.write(key, CATALOG_BY_KEY[key].default)
        self.sync("company")
        self.assertTrue(SystemSetting.objects.filter(key=key).exists())

    def test_catalog_default_sender_is_an_explicit_choice(self) -> None:
        key = "company.email_noreply"
        self.write(key, CATALOG_BY_KEY[key].default)
        self.assertEqual(get_default_from_email(), CATALOG_BY_KEY[key].default)

    def test_page_renders_deployment_boolean_and_inheritance(self) -> None:
        response = self.page()
        parser = FieldParser(KEY)
        parser.feed(response.content.decode())
        self.assertTrue(parser.field)
        self.assertNotIn("checked", parser.field)
        self.assertContains(response, "Inherited from deployment")
        self.assertContains(response, "EFACTURA_ENABLED")

    def test_company_sender_page_renders_deployment_address(self) -> None:
        response = self.page("company")
        parser = FieldParser("company.email_noreply")
        parser.feed(response.content.decode())
        self.assertEqual(parser.field.get("value"), "deployment@example.test")
        self.assertContains(response, "DEFAULT_FROM_EMAIL")

    def test_virtualmin_quota_page_shows_server_default(self) -> None:
        response = self.page("virtualmin")
        parser = FieldParser("virtualmin.domain_quota_default_mb")
        parser.feed(response.content.decode())
        self.assertEqual(parser.field.get("value"), "")
        self.assertContains(response, "Virtualmin default")

    def test_same_displayed_value_can_be_saved_then_cleared(self) -> None:
        self.sync()
        saved = self.post({KEY: False}, {KEY: None})
        self.assertEqual(saved.status_code, 200)
        self.assertTrue(SystemSetting.objects.filter(key=KEY, value=False).exists())
        baseline = saved.json()["saved"][KEY]["baseline"]
        cleared = self.post({KEY: None}, {KEY: baseline})
        self.assertEqual(cleared.status_code, 200)
        self.assertIs(saved.json()["saved"][KEY].get("inherited"), False)
        self.assertEqual(cleared.json()["saved"][KEY], {"baseline": None, "value": False, "inherited": True})
        self.assertFalse(SystemSetting.objects.filter(key=KEY).exists())
        self.assertContains(self.page(), "Inherited from deployment")

    def test_stale_clear_rolls_back_other_changes(self) -> None:
        row = self.write(KEY, True)
        response = self.post({KEY: None, "efactura.retry.max_retries": 2}, {KEY: "stale"})
        self.assertEqual(response.status_code, 409)
        row.refresh_from_db()
        self.assertIs(row.value, True)
        self.assertFalse(SystemSetting.objects.filter(key="efactura.retry.max_retries").exists())

    @override_settings(EFACTURA_CLIENT_SECRET="deployment-secret-do-not-render")
    def test_deployment_credentials_are_configured_without_disclosure(self) -> None:
        response = self.page()
        self.assertContains(response, "Inherited from deployment")
        self.assertContains(response, 'x-data="settingsSecretRow(true)"')
        self.assertNotContains(response, "deployment-secret-do-not-render")
        row = self.write("efactura.oauth.client_secret", "stored-secret")
        cleared = self.client.post(
            reverse("settings:secret_clear", args=[row.key]),
            data=json.dumps({"reason": "Return to deployment"}),
            content_type="application/json",
        )
        self.assertEqual(cleared.status_code, 200)
        self.assertFalse(SystemSetting.objects.filter(key=row.key).exists())
        self.assertIs(cleared.json()["configured"], True)
        denied = self.post({row.key: None}, {row.key: None})
        self.assertEqual(denied.status_code, 400)

    def form_payload(self, action: str) -> dict[str, object]:
        # Execute the production controller; only its HTTP transport is replaced.
        source = Path(__file__).resolve().parents[2] / "static/js/alpine-components.js"
        script = """
const fs = require("fs");
global.window = {addEventListener: () => {}};
global.document = {
  addEventListener: (_, callback) => callback(),
  querySelector: () => ({value: "csrf"})
};
const registry = {};
global.Alpine = {data: (name, factory) => { registry[name] = factory; }};
eval(fs.readFileSync(process.argv[1], "utf8"));
const el = {
  dataset: {key: "efactura.enabled", kind: "toggle", baseline: process.argv[3], default: "true"},
  checked: process.argv[2] === "inherit",
  closest: () => ({dataset: {
    deploymentFallback: "1", inherited: process.argv[2] === "inherit" ? "0" : "1", fallback: "false"
  }})
};
const form = registry.settingsForm("/settings/save/");
form.$root = {
  dataset: {}, querySelector: () => el,
  querySelectorAll: (selector) => selector.includes("[data-critical]") ? [] : [el]
};
form.$dispatch = () => {};
form.initField(el);
if (process.argv[2] === "inherit") {
  if (form.inheritField) form.inheritField(el.dataset.key);
  else form.resetField(el.dataset.key);
} else if (form.overrideField) form.overrideField(el.dataset.key);
else { el.checked = true; form.syncField(el); el.checked = false; form.syncField(el); }
let payload = {changes: {}};
global.fetch = async (_, request) => {
  payload = JSON.parse(request.body);
  return {json: async () => ({success: false, errors: {}}), status: 400};
};
(async () => { await form.save(); process.stdout.write(JSON.stringify(payload)); })();
"""
        row = SystemSetting.objects.filter(key=KEY).first()
        baseline = row.updated_at.isoformat() if row is not None else ""
        result = subprocess.run(  # noqa: S603  # Fixed executable and local controller; no shell.
            ["node", "-e", script, str(source), action, baseline],  # noqa: S607  # Fixed Node invocation.
            check=True,
            capture_output=True,
            text=True,
        )
        payload: dict[str, object] = json.loads(result.stdout)
        return payload

    def test_form_posts_an_explicit_unchanged_value(self) -> None:
        payload = self.form_payload("override")
        self.assertEqual(payload["changes"], {KEY: False})
        saved = self.client.post(
            reverse("settings:save_change_set"), data=json.dumps(payload), content_type="application/json"
        )
        self.assertEqual(saved.status_code, 200)
        self.assertTrue(SystemSetting.objects.filter(key=KEY, value=False).exists())

    def test_form_clear_posts_null_and_deletes_override(self) -> None:
        self.write(KEY, True)
        payload = self.form_payload("inherit")
        self.assertEqual(payload["changes"], {KEY: None})
        cleared = self.client.post(
            reverse("settings:save_change_set"), data=json.dumps(payload), content_type="application/json"
        )
        self.assertEqual(cleared.status_code, 200)
        self.assertFalse(SystemSetting.objects.filter(key=KEY).exists())


class DeploymentSourceNamesTests(TestCase):
    """The settings page must name the deployment value the runtime actually falls back to."""

    def test_identity_and_oauth_keys_inherit_from_the_settings_their_readers_use(self) -> None:
        expected = {
            "efactura.oauth.client_id": "EFACTURA_CLIENT_ID",
            "efactura.oauth.client_secret": "EFACTURA_CLIENT_SECRET",
            "efactura.company.cui": "EFACTURA_COMPANY_CUI",
            "efactura.company.name": "COMPANY_NAME",
            "efactura.company.country_code": "COMPANY_COUNTRY_CODE",
            "efactura.company.bank_account": "COMPANY_BANK_ACCOUNT",
            "company.email_noreply": "DEFAULT_FROM_EMAIL",
        }
        for key, name in expected.items():
            with self.subTest(key=key):
                self.assertEqual(CATALOG_BY_KEY[key].deployment_source, name)
