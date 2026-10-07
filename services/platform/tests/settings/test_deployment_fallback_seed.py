"""Deployment fallbacks survive catalog sync; staff overrides remain writable."""

from __future__ import annotations

import ast
import json
from io import StringIO
from pathlib import Path

from django.core.management import call_command
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from apps.billing.efactura.client import EFacturaConfig
from apps.billing.efactura.settings import (
    EFACTURA_DEFAULTS,
    EFacturaSettingKeys,
    EFacturaSettings,
    company_identity_setting,
)
from apps.settings.catalog import CATALOG_BY_KEY, SettingDef
from apps.settings.key_scan import iter_scannable_python_files
from apps.settings.management.commands import setup_default_settings as sync
from apps.settings.models import SettingActivation, SystemSetting
from apps.settings.services import get_default_from_email
from tests.factories.core_factories import create_admin_user, create_staff_user

QUOTA_KEYS = frozenset({"virtualmin.domain_quota_default_mb", "virtualmin.bandwidth_quota_default_mb"})
REQUIRED_KEYS = frozenset(EFACTURA_DEFAULTS) | QUOTA_KEYS | {"company.email_noreply"}
APPS_ROOT = Path(__file__).resolve().parents[2] / "apps"


def distinct_value(definition: SettingDef) -> str | int | bool:
    """Choose a deployment/override value different from the catalog default."""
    default = definition.default
    if isinstance(default, bool):
        return not default
    if isinstance(default, int):
        return default + 7
    if definition.key == "efactura.environment":
        return "production"
    return "deployment@example.test" if definition.key == "company.email_noreply" else "deployment-value"


def run_sync(*, force: bool = False, category: str | None = None) -> str:
    output = StringIO()
    if category is None:
        call_command("setup_default_settings", force=force, stdout=output)
    else:
        call_command("setup_default_settings", force=force, category=category, stdout=output)
    return output.getvalue()


def seed(key: str, value: object) -> SystemSetting:
    return SystemSetting.objects.create(key=key, value=value, **sync._row_defaults(CATALOG_BY_KEY[key]))


def literal_key(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "EFacturaSettingKeys":
        value: object = getattr(EFacturaSettingKeys, node.attr, None)
        return value if isinstance(value, str) else None
    return None


def called_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return node.func.id if isinstance(node.func, ast.Name) else None


def key_argument(node: ast.Call) -> ast.expr | None:
    if node.args:
        return node.args[0]
    return next((keyword.value for keyword in node.keywords if keyword.arg == "key"), None)


def row_reader_keys() -> set[str]:
    """Follow key-forwarding wrappers within each production module."""
    keys: set[str] = set()
    for path in iter_scannable_python_files(APPS_ROOT):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        readers = {"get_value_by_key", "get_stored_setting"}
        while True:
            discovered = set(readers)
            for function in ast.walk(tree):
                if not isinstance(function, ast.FunctionDef):
                    continue
                parameters = {argument.arg for argument in function.args.args}
                for node in ast.walk(function):
                    if (
                        isinstance(node, ast.Call)
                        and called_name(node) in readers
                        and isinstance(argument := key_argument(node), ast.Name)
                        and argument.id in parameters
                    ):
                        discovered.add(function.name)
            if discovered == readers:
                break
            readers = discovered
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and called_name(node) in readers:
                argument = key_argument(node)
                key = literal_key(argument) if argument is not None else None
                if key is not None:
                    keys.add(key)
    return keys


class DeploymentFallbackCatalogTests(SimpleTestCase):
    def test_row_only_consumers_are_flagged_including_forwarding_wrappers(self) -> None:
        consumed = row_reader_keys()
        self.assertIn("virtualmin.bandwidth_quota_default_mb", consumed)
        self.assertIn("efactura.company.bank_name", consumed)
        self.assertIn("efactura.oauth.client_secret", consumed)
        self.assertIn("company.email_noreply", consumed)
        self.assertEqual(consumed, set(REQUIRED_KEYS))
        required = consumed | REQUIRED_KEYS
        missing = sorted(
            key
            for key in required
            if key not in CATALOG_BY_KEY or not getattr(CATALOG_BY_KEY[key], "deployment_fallback", False)
        )
        self.assertEqual(missing, [], f"Row-only consumers must preserve deployment fallbacks: {missing}")
        flagged = {key for key, definition in CATALOG_BY_KEY.items() if definition.deployment_fallback}
        self.assertEqual(flagged, required, "Every flagged key needs a real-reader case in this suite.")


class DeploymentFallbackSeedTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        SystemSetting.objects.filter(key__in=REQUIRED_KEYS).delete()

    def test_sync_preserves_every_efactura_and_sender_deployment_value(self) -> None:
        values = {key: distinct_value(CATALOG_BY_KEY[key]) for key in REQUIRED_KEYS - QUOTA_KEYS}
        django_values = {
            key.replace(".", "_").upper(): value for key, value in values.items() if key.startswith("efactura.")
        }
        django_values["DEFAULT_FROM_EMAIL"] = values["company.email_noreply"]
        with override_settings(**django_values):
            run_sync()
            for key, expected in sorted(values.items()):
                with self.subTest(key=key):
                    resolved = (
                        get_default_from_email()
                        if key == "company.email_noreply"
                        else EFacturaSettings()._get_setting(key)
                    )
                    self.assertEqual(resolved, expected)
                    self.assertFalse(SystemSetting.objects.filter(key=key).exists())

    @override_settings(
        EFACTURA_CLIENT_ID="deployment-client",
        EFACTURA_CLIENT_SECRET="deployment-credential",
        EFACTURA_COMPANY_BANK_ACCOUNT="deployment-iban",
        EFACTURA_COMPANY_BANK_NAME="deployment-bank",
    )
    def test_sync_preserves_oauth_and_bank_row_only_readers(self) -> None:
        run_sync()
        config = EFacturaConfig.from_settings()
        self.assertEqual((config.client_id, config.client_secret), ("deployment-client", "deployment-credential"))
        for key, expected in (
            ("efactura.company.bank_account", "deployment-iban"),
            ("efactura.company.bank_name", "deployment-bank"),
        ):
            with self.subTest(key=key):
                self.assertEqual(company_identity_setting(key, "legacy-bank"), expected)

    def test_cleanup_removes_defaults_and_reports_preserved_overrides_even_with_force(self) -> None:
        for key in sorted(REQUIRED_KEYS):
            seed(key, CATALOG_BY_KEY[key].default)
            SettingActivation.objects.create(key=key, version="previous", completed_at=timezone.now())
        output = run_sync()
        for key in sorted(REQUIRED_KEYS):
            with self.subTest(key=key, phase="cleanup"):
                self.assertFalse(SystemSetting.objects.filter(key=key).exists())
                self.assertIn(f"Removed deployment-fallback default: {key}", output)

        SystemSetting.objects.filter(key__in=REQUIRED_KEYS).delete()
        overrides = {key: distinct_value(CATALOG_BY_KEY[key]) for key in REQUIRED_KEYS}
        for key, value in overrides.items():
            seed(key, value)
        output = run_sync(force=True)
        for key, expected in sorted(overrides.items()):
            with self.subTest(key=key, phase="override"):
                row = SystemSetting.objects.get(key=key)
                self.assertEqual(row.get_typed_value(), expected)
                self.assertIn(f"Retained deployment-fallback override: {key}", output)
                if row.is_sensitive:
                    self.assertNotIn(str(expected), output)

    def test_registered_activation_cannot_create_a_deployment_fallback_row(self) -> None:
        key = "company.email_noreply"
        previous = sync.DEFAULT_VALUE_MIGRATIONS.get(key)
        sync.DEFAULT_VALUE_MIGRATIONS[key] = (CATALOG_BY_KEY[key].default, CATALOG_BY_KEY[key].default)

        def restore() -> None:
            if previous is None:
                sync.DEFAULT_VALUE_MIGRATIONS.pop(key, None)
            else:
                sync.DEFAULT_VALUE_MIGRATIONS[key] = previous

        self.addCleanup(restore)
        run_sync()
        self.assertFalse(SystemSetting.objects.filter(key=key).exists())
        self.assertFalse(SettingActivation.objects.filter(key=key).exists())

    def test_category_filter_limits_cleanup_to_catalog_group(self) -> None:
        sender = seed("company.email_noreply", CATALOG_BY_KEY["company.email_noreply"].default)
        oauth = seed("efactura.oauth.client_id", "")
        # Stale row metadata must not change the catalog-owned category selection.
        SystemSetting.objects.filter(pk=sender.pk).update(category="stale")
        output = run_sync(category="company")
        self.assertFalse(SystemSetting.objects.filter(pk=sender.pk).exists())
        self.assertTrue(SystemSetting.objects.filter(pk=oauth.pk).exists())
        self.assertIn("Removed deployment-fallback default: company.email_noreply", output)
        self.assertNotIn("Removed deployment-fallback default: efactura.oauth.client_id", output)

    def test_empty_efactura_strings_fall_back_without_discarding_false_zero_or_whitespace(self) -> None:
        for key in sorted(EFACTURA_DEFAULTS):
            definition = CATALOG_BY_KEY[key]
            if definition.data_type != "string":
                continue
            with self.subTest(key=key):
                row = seed(key, "")
                with override_settings(**{key.replace(".", "_").upper(): "deployment-value"}):
                    self.assertEqual(EFacturaSettings()._get_setting(key), "deployment-value")
                    row.value = " "
                    row.save(update_fields=["value", "updated_at"])
                    self.assertEqual(EFacturaSettings()._get_setting(key), " ")
                row.delete()
        for key, stored, deployment in (
            ("efactura.enabled", False, True),
            ("efactura.retry.max_retries", 0, 7),
        ):
            with self.subTest(key=key):
                seed(key, stored)
                with override_settings(**{key.replace(".", "_").upper(): deployment}):
                    resolved = EFacturaSettings()._get_setting(key)
                    self.assertEqual(resolved, stored)
                    self.assertIs(type(resolved), type(stored))

    @override_settings(DEFAULT_FROM_EMAIL="deployment@example.test")
    def test_seeded_and_empty_sender_rows_do_not_replace_deployment_sender(self) -> None:
        key = "company.email_noreply"
        for value in (CATALOG_BY_KEY[key].default, ""):
            SystemSetting.objects.filter(key=key).delete()
            with self.subTest(value=value):
                row = seed(key, value)
                self.assertEqual(get_default_from_email(), "deployment@example.test")
                row.delete()
        SystemSetting.objects.filter(key=key).delete()
        seed(key, "staff@example.test")
        self.assertEqual(get_default_from_email(), "staff@example.test")

    def test_unseeded_keys_remain_visible_and_staff_save_creates_sender_override(self) -> None:
        run_sync()
        admin = create_admin_user(username="seed_ui_admin")
        self.client.force_login(admin)
        for group in sorted({CATALOG_BY_KEY[key].group for key in REQUIRED_KEYS}):
            response = self.client.get(reverse("settings:group", args=[group]))
            for key in sorted(REQUIRED_KEYS):
                if CATALOG_BY_KEY[key].group == group:
                    with self.subTest(key=key):
                        self.assertFalse(SystemSetting.objects.filter(key=key).exists())
                        self.assertContains(response, key)
        self.client.force_login(create_staff_user(username="seed_ui_staff", staff_role="support"))
        key = "company.email_noreply"
        response = self.client.post(
            reverse("settings:save_change_set"),
            data=json.dumps({"changes": {key: "staff@example.test"}, "baselines": {key: None}}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200, response.content)
        payload = response.json()
        self.assertTrue(payload["success"])
        self.assertEqual(payload["saved"][key]["value"], "staff@example.test")
        self.assertTrue(payload["saved"][key]["baseline"])
        self.assertEqual(SystemSetting.objects.get(key=key).get_typed_value(), "staff@example.test")
        self.assertEqual(get_default_from_email(), "staff@example.test")
