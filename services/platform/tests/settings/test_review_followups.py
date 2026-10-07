"""Inherited settings match consumers, clearing is attributed, and credential rows refresh."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import cast

from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.core.cache import cache
from django.http import HttpResponse
from django.test import TestCase, override_settings
from django.urls import reverse

from apps.audit.models import AuditEvent
from apps.billing.efactura.client import EFacturaConfig
from apps.billing.efactura.settings import EFacturaSettings
from apps.billing.efactura.xml_builder import BaseUBLBuilder, _supplier_setting
from apps.settings.catalog import CATALOG_BY_KEY
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService, get_default_from_email
from tests.factories.billing_factories import InvoiceFactory
from tests.factories.core_factories import create_admin_user
from tests.helpers.task_queue import quiet_task_queue
from tests.settings.test_deployment_fallback import FieldParser


@override_settings(
    LANGUAGE_CODE="en",
    DISABLE_AUDIT_SIGNALS=False,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class SettingsReviewFollowupTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        quiet_task_queue(self)
        SystemSetting.objects.filter(
            key__in=[definition.key for definition in CATALOG_BY_KEY.values() if definition.deployment_fallback]
        ).delete()
        self.admin = create_admin_user(username="settings_followup_admin")
        self.client.force_login(self.admin)

    def page(self, group: str = "efactura") -> HttpResponse:
        response = self.client.get(reverse("settings:group", args=[group]))
        self.assertEqual(response.status_code, 200)
        return response

    def field(self, response: HttpResponse, key: str) -> dict[str, str | None]:
        parser = FieldParser(key)
        parser.feed(response.content.decode())
        self.assertTrue(parser.field, key)
        return parser.field

    def write(self, key: str, value: object) -> SystemSetting:
        result = SettingsService.update_setting(key, value, user_id=self.admin.pk)
        self.assertTrue(result.is_ok(), result)
        return SystemSetting.objects.get(key=key)

    def post(self, url: str, payload: dict[str, object]) -> dict[str, object]:
        response = self.client.post(url, data=json.dumps(payload), content_type="application/json")
        self.assertEqual(response.status_code, 200, response.content)
        return cast("dict[str, object]", response.json())

    @override_settings(
        COMPANY_NAME="Legacy supplier",
        COMPANY_CITY="Legacy city",
        COMPANY_BANK_ACCOUNT="legacy-iban",
        COMPANY_BANK_NAME="Legacy bank",
        EFACTURA_COMPANY_NAME="ANAF supplier",
        EFACTURA_COMPANY_CITY="ANAF city",
        EFACTURA_COMPANY_BANK_ACCOUNT="anaf-iban",
        EFACTURA_COMPANY_BANK_NAME="ANAF bank",
        EFACTURA_CLIENT_ID="deployment-client",
        EFACTURA_OAUTH_CLIENT_ID="unused-generic-client",
        DEFAULT_FROM_EMAIL="deployment@example.test",
    )
    def test_rendered_inheritance_matches_identity_bank_oauth_sender_and_quota_consumers(self) -> None:
        supplier = BaseUBLBuilder(InvoiceFactory(status="draft"))._get_supplier_info()
        config = EFacturaConfig.from_settings()
        expected = {
            "efactura.company.name": supplier.name,
            "efactura.company.city": supplier.city,
            "efactura.company.bank_account": _supplier_setting(
                "efactura.company.bank_account", settings.COMPANY_BANK_ACCOUNT
            ),
            "efactura.company.bank_name": _supplier_setting("efactura.company.bank_name", settings.COMPANY_BANK_NAME),
            "efactura.oauth.client_id": config.client_id,
        }
        response = self.page()
        for key, value in expected.items():
            with self.subTest(key=key):
                self.assertEqual(self.field(response, key).get("value"), value)
        self.assertEqual(
            self.field(self.page("company"), "company.email_noreply").get("value"), get_default_from_email()
        )
        for key in ("virtualmin.domain_quota_default_mb", "virtualmin.bandwidth_quota_default_mb"):
            with self.subTest(key=key):
                self.assertEqual(self.field(self.page("virtualmin"), key).get("value"), "")
        self.assertContains(self.page("virtualmin"), "Virtualmin default")

    @override_settings(EFACTURA_COMPANY_COUNTRY_CODE="", COMPANY_COUNTRY_CODE="", COMPANY_COUNTRY="Germany")
    def test_country_inheritance_uses_the_normalized_operator_fallback(self) -> None:
        supplier = BaseUBLBuilder(InvoiceFactory(status="draft"))._get_supplier_info()
        self.assertEqual(supplier.country_code, "DE")
        self.assertEqual(self.field(self.page(), "efactura.company.country_code").get("value"), supplier.country_code)

    @override_settings(EFACTURA_ENABLED="false", EFACTURA_POLLING_BATCH_SIZE="invalid")
    def test_generic_inheritance_uses_the_consumers_type_conversion(self) -> None:
        consumer = EFacturaSettings()
        response = self.page()
        self.assertEqual("checked" in self.field(response, "efactura.enabled"), consumer.enabled)
        self.assertEqual(
            self.field(response, "efactura.polling.batch_size").get("value"), str(consumer.poll_batch_size)
        )

    @override_settings(COMPANY_NAME="Legacy supplier", EFACTURA_COMPANY_NAME="ANAF supplier", EFACTURA_ENABLED=True)
    def test_fallback_preview_ignores_overrides_and_restores_normal_reads(self) -> None:
        self.write("efactura.company.name", "Stored supplier")
        self.write("efactura.enabled", False)
        self.assertEqual(CATALOG_BY_KEY["efactura.company.name"].deployment_default(), "ANAF supplier")
        self.assertIs(CATALOG_BY_KEY["efactura.enabled"].deployment_default(), True)
        self.assertEqual(SettingsService.get_stored_setting("efactura.company.name"), "Stored supplier")
        self.assertEqual(BaseUBLBuilder(InvoiceFactory(status="draft"))._get_supplier_info().name, "Stored supplier")
        self.assertIs(EFacturaSettings().enabled, False)

    def assert_clear_event(self, row: SystemSetting, payload: dict[str, object], old_value: str, reason: str) -> None:
        change_set_id = payload.get("change_set_id")
        self.assertIsInstance(change_set_id, str)
        self.assertTrue(change_set_id)
        event = AuditEvent.objects.filter(
            action="setting_override_cleared",
            metadata__setting_key=row.key,
            metadata__change_set_id=change_set_id,
        ).first()
        self.assertIsNotNone(event, "Clearing an override must persist an attributed transition")
        assert event is not None
        self.assertEqual(event.user_id, self.admin.pk)
        self.assertEqual(event.actor_type, "user")
        self.assertEqual(event.content_type, ContentType.objects.get_for_model(SystemSetting))
        self.assertEqual(event.object_id, str(row.pk))
        self.assertEqual(event.metadata["reason"], reason)
        self.assertEqual(event.metadata["change_set_id"], change_set_id)
        self.assertIs(event.metadata["inherited"], True)
        self.assertEqual(event.old_values, {"value": old_value})
        self.assertEqual(event.new_values, {"value": "inherited"})

    @override_settings(EFACTURA_COMPANY_NAME="ANAF supplier")
    def test_change_set_clear_persists_actor_reason_change_set_and_transition(self) -> None:
        row = self.write("efactura.company.name", "Stored supplier")
        reason = "Return to deployment identity"
        payload = self.post(
            reverse("settings:save_change_set"),
            {
                "changes": {row.key: None},
                "baselines": {row.key: row.updated_at.isoformat()},
                "reason": reason,
            },
        )
        self.assertFalse(SystemSetting.objects.filter(key=row.key).exists())
        self.assert_clear_event(row, payload, "Stored supplier", reason)

    @override_settings(EFACTURA_CLIENT_SECRET="deployment-secret")
    def test_secret_clear_persists_an_attributed_masked_transition(self) -> None:
        row = self.write("efactura.oauth.client_secret", "stored-secret")
        reason = "Return to deployment credential"
        payload = self.post(reverse("settings:secret_clear", args=[row.key]), {"reason": reason})
        self.assertFalse(SystemSetting.objects.filter(key=row.key).exists())
        self.assertIs(payload["inherited"], True)
        self.assertIs(payload["configured"], True)
        self.assert_clear_event(row, payload, "(hidden)", reason)
        event = AuditEvent.objects.get(
            action="setting_override_cleared", metadata__change_set_id=payload["change_set_id"]
        )
        self.assertNotIn("stored-secret", json.dumps(event.old_values))
        self.assertNotIn("deployment-secret", json.dumps(event.new_values))

    @override_settings(EFACTURA_CLIENT_SECRET="deployment-secret")
    def test_replacing_an_inherited_credential_refreshes_its_rendered_state(self) -> None:
        response = self.page()
        root = re.search(r'id="setting-efactura\.oauth\.client_secret"[^>]*', response.content.decode())
        self.assertIsNotNone(root)
        assert root is not None
        marker = re.search(r'data-deployment-fallback="([01])"', root.group())
        fallback_flag = marker.group(1) if marker is not None else "0"
        payload = self.post(
            reverse("settings:secret_set", args=["efactura.oauth.client_secret"]),
            {"value": "replacement-secret"},
        )
        source = Path(__file__).resolve().parents[2] / "static/js/alpine-components.js"
        script = """
const fs = require("fs");
let reloads = 0;
global.window = {addEventListener: () => {}, location: {reload: () => { reloads++; }}};
global.document = {addEventListener: (_, callback) => callback(), querySelector: () => ({value: "csrf"})};
const registry = {};
global.Alpine = {data: (name, factory) => { registry[name] = factory; }};
eval(fs.readFileSync(process.argv[1], "utf8"));
const row = registry.settingsSecretRow(true);
row.$root = {dataset: {setUrl: "/secret/", deploymentFallback: process.argv[2]}};
row.secret = "replacement-secret";
global.fetch = async () => ({json: async () => JSON.parse(process.argv[3])});
(async () => {
  await row.saveSecret();
  process.stdout.write(JSON.stringify({reloads, configured: row.configured, secret: row.secret}));
})();
"""
        result = subprocess.run(  # noqa: S603  # Fixed Node executable; local source and JSON, no shell.
            ["node", "-e", script, str(source), fallback_flag, json.dumps(payload)],  # noqa: S607
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(json.loads(result.stdout), {"reloads": 1, "configured": True, "secret": ""})
        refreshed = self.page()
        self.assertContains(refreshed, "Explicit override")
        self.assertNotContains(refreshed, "replacement-secret")
        self.assertNotContains(refreshed, "deployment-secret")
