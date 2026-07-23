"""
Catalog, curation-migration, maintenance-gate, and guardrail-plumbing tests (C2).
"""

from __future__ import annotations

import importlib
import tempfile
from io import StringIO
from pathlib import Path

from django.core.management import call_command
from django.http import HttpResponse
from django.test import RequestFactory, TestCase, override_settings

from apps.common.checks import get_max_session_age_seconds
from apps.common.encryption import decrypt_value, encrypt_value, is_encrypted
from apps.common.middleware import MaintenanceModeMiddleware
from apps.settings.catalog import CATALOG, CATALOG_BY_KEY, GROUPS_BY_SLUG, SettingDef
from apps.settings.key_scan import extract_catalog_defaults, extract_string_literals
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService
from tests.factories.core_factories import create_staff_user

_MIGRATION = importlib.import_module("apps.settings.migrations.0003_curate_catalog_rows")

VALID_DATA_TYPES = {"string", "integer", "boolean", "decimal", "list", "json"}
VALID_INPUT_KINDS = {"text", "number", "toggle", "select", "chips", "json", "secret"}


class CatalogIntegrityTests(TestCase):
    """Structural invariants of the settings catalog."""

    def test_keys_are_unique(self) -> None:
        keys = [d.key for d in CATALOG]
        self.assertEqual(len(keys), len(set(keys)))

    def test_every_entry_references_a_declared_group(self) -> None:
        for definition in CATALOG:
            self.assertIn(definition.group, GROUPS_BY_SLUG, f"{definition.key} references unknown group")

    def test_types_and_input_kinds_are_valid(self) -> None:
        for definition in CATALOG:
            self.assertIn(definition.data_type, VALID_DATA_TYPES, definition.key)
            self.assertIn(definition.input_kind, VALID_INPUT_KINDS, definition.key)

    def test_sensitive_entries_use_secret_inputs(self) -> None:
        for definition in CATALOG:
            if definition.sensitive:
                self.assertEqual(definition.input_kind, "secret", definition.key)

    def test_service_defaults_derive_from_catalog(self) -> None:
        self.assertEqual(SettingsService.DEFAULT_SETTINGS, {d.key: d.default for d in CATALOG})

    def test_invoice_generation_lead_time_preserves_safe_existing_schedule(self) -> None:
        definition = CATALOG_BY_KEY["billing.invoice_generation_lead_days"]

        self.assertEqual(definition.default, 14)
        self.assertEqual(definition.validation, {"min": 7, "max": 30})

    def test_retired_keys_are_not_in_catalog(self) -> None:
        overlap = set(_MIGRATION.RETIRED_KEYS) & set(CATALOG_BY_KEY)
        self.assertEqual(overlap, set())

    def test_known_decoys_are_gone(self) -> None:
        """billing.vat_rate (TaxRule owns VAT) and the env-gated flags must stay retired."""
        for key in ("billing.vat_rate", "billing.payment_grace_period_days", "users.max_login_attempts"):
            self.assertNotIn(key, CATALOG_BY_KEY)
            self.assertIn(key, _MIGRATION.RETIRED_KEYS)


class CurationMigrationTests(TestCase):
    """The reconciliation helper applies catalog metadata to historical rows."""

    def _reconcile(self, setting: SystemSetting, definition: SettingDef) -> list[str]:
        return _MIGRATION._reconcile_row(setting, definition, encrypt_value, decrypt_value, is_encrypted)

    def test_plain_to_sensitive_transition_encrypts(self) -> None:
        setting = SystemSetting.objects.create(
            key="integrations.stripe_secret_key",
            name="x",
            description="x",
            category="integrations",
            value="sk_live_plaintext",
            default_value="",
            data_type="string",
            is_sensitive=False,
        )
        # Bypass model save encryption to simulate a mislabeled historical row
        SystemSetting.objects.filter(pk=setting.pk).update(value="sk_live_plaintext", is_sensitive=False)
        setting.refresh_from_db()

        changed = self._reconcile(setting, CATALOG_BY_KEY["integrations.stripe_secret_key"])

        self.assertIn("value", changed)
        self.assertTrue(setting.is_sensitive)
        self.assertTrue(is_encrypted(str(setting.value)))
        self.assertNotIn("sk_live_plaintext", str(setting.value))

    def test_sensitive_to_plain_transition_decrypts(self) -> None:
        encrypted = encrypt_value("praho/nodes/")
        setting = SystemSetting.objects.create(
            key="node_deployment.terraform_s3_key_prefix",
            name="x",
            description="x",
            category="node_deployment",
            value=encrypted,
            default_value="praho/nodes/",
            data_type="string",
            is_sensitive=False,
        )
        SystemSetting.objects.filter(pk=setting.pk).update(is_sensitive=True)
        setting.refresh_from_db()

        definition = CATALOG_BY_KEY["node_deployment.terraform_s3_key_prefix"]
        self.assertFalse(definition.sensitive)
        changed = self._reconcile(setting, definition)

        self.assertIn("value", changed)
        self.assertFalse(setting.is_sensitive)
        self.assertEqual(setting.value, "praho/nodes/")


class MaintenanceModeMiddlewareTests(TestCase):
    """The maintenance gate: staff-exempt 503 driven by the runtime setting."""

    def setUp(self) -> None:
        self.factory = RequestFactory()
        self.middleware = MaintenanceModeMiddleware(lambda _request: HttpResponse("ok"))

    def _request(self, path: str = "/dashboard/", user: object | None = None) -> object:
        request = self.factory.get(path)
        if user is not None:
            request.user = user
        return request

    def _enable_runtime_flag(self) -> None:
        result = SettingsService.update_setting("system.maintenance_mode", True)
        self.assertTrue(result.is_ok())

    @override_settings(MAINTENANCE_MODE=None)
    def test_non_staff_receives_503_with_retry_after(self) -> None:
        self._enable_runtime_flag()
        response = self.middleware(self._request())
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response["Retry-After"], "600")

    @override_settings(MAINTENANCE_MODE=None)
    def test_staff_passes_through(self) -> None:
        self._enable_runtime_flag()
        staff = create_staff_user(username="maint_staff", staff_role="support")
        response = self.middleware(self._request(user=staff))
        self.assertEqual(response.status_code, 200)

    @override_settings(MAINTENANCE_MODE=None)
    def test_exempt_paths_stay_reachable(self) -> None:
        self._enable_runtime_flag()
        for path in ("/auth/login/", "/static/css/app.css", "/settings/api/health/"):
            self.assertEqual(self.middleware(self._request(path=path)).status_code, 200, path)

    @override_settings(MAINTENANCE_MODE=False)
    def test_deployment_override_wins_over_runtime_setting(self) -> None:
        self._enable_runtime_flag()
        response = self.middleware(self._request())
        self.assertEqual(response.status_code, 200)

    @override_settings(MAINTENANCE_MODE=True)
    def test_deployment_override_can_force_maintenance(self) -> None:
        response = self.middleware(self._request())
        self.assertEqual(response.status_code, 503)

    @override_settings(MAINTENANCE_MODE=None)
    def test_inactive_by_default(self) -> None:
        response = self.middleware(self._request())
        self.assertEqual(response.status_code, 200)


class MiddlewarePresenceTests(TestCase):
    """The gate must be registered in every settings module that redefines MIDDLEWARE."""

    _MW = "apps.common.middleware.MaintenanceModeMiddleware"
    _AUTH = "django.contrib.auth.middleware.AuthenticationMiddleware"

    def _assert_registered_after_auth(self, settings_file: str) -> None:
        source = (Path(__file__).parents[2] / "config" / "settings" / settings_file).read_text()
        self.assertIn(self._MW, source, f"{settings_file} lost the maintenance middleware")
        self.assertLess(source.index(self._AUTH), source.index(self._MW), f"{settings_file}: must run after auth")

    def test_base_registers_the_gate(self) -> None:
        self._assert_registered_after_auth("base.py")

    def test_prod_registers_the_gate(self) -> None:
        self._assert_registered_after_auth("prod.py")

    def test_staging_registers_the_gate(self) -> None:
        self._assert_registered_after_auth("staging.py")


class SessionAgeWiringTests(TestCase):
    """security.max_session_age_seconds actually drives the security check."""

    def test_runtime_setting_changes_the_threshold(self) -> None:
        self.assertEqual(get_max_session_age_seconds(), 86400)
        result = SettingsService.update_setting("security.max_session_age_seconds", 100)
        self.assertTrue(result.is_ok())
        self.assertEqual(get_max_session_age_seconds(), 100)


class CatalogSyncCommandTests(TestCase):
    """setup_default_settings is an idempotent catalog sync."""

    def test_second_run_reports_no_changes(self) -> None:
        call_command("setup_default_settings", stdout=StringIO())
        second = StringIO()
        call_command("setup_default_settings", stdout=second)
        output = second.getvalue()
        self.assertIn("Created: 0", output)
        self.assertIn("Reconciled: 0", output)

    def test_metadata_reconciliation_updates_drifted_rows(self) -> None:
        call_command("setup_default_settings", stdout=StringIO())
        SystemSetting.objects.filter(key="billing.invoice_payment_terms_days").update(name="stale name")
        out = StringIO()
        call_command("setup_default_settings", stdout=out)
        self.assertIn("Reconciled: 1", out.getvalue())
        row = SystemSetting.objects.get(key="billing.invoice_payment_terms_days")
        self.assertEqual(row.name, CATALOG_BY_KEY["billing.invoice_payment_terms_days"].label)


class KeyScanGuardrailTests(TestCase):
    """The shared extraction can never silently go vacuous."""

    def test_catalog_extraction_is_not_empty(self) -> None:
        catalog_path = Path(__file__).parents[2] / "apps" / "settings" / "catalog.py"
        defaults = extract_catalog_defaults(catalog_path)
        self.assertGreater(len(defaults), 200)
        self.assertIn("billing.invoice_payment_terms_days", defaults)

    def test_comments_do_not_count_as_literals(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as handle:
            handle.write(
                '# uses "billing.invoice_payment_terms_days" in a comment\nreal = "orders.card_timeout_hours"\n'
            )
            path = Path(handle.name)
        literals = extract_string_literals(path)
        path.unlink()
        self.assertIn("orders.card_timeout_hours", literals)
        self.assertNotIn("billing.invoice_payment_terms_days", literals)
