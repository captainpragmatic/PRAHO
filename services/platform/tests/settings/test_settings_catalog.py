"""
Catalog, maintenance-gate, and guardrail-plumbing tests (C2).
"""

from __future__ import annotations

import tempfile
from io import StringIO
from pathlib import Path

from django.core.management import call_command
from django.http import HttpResponse
from django.test import RequestFactory, TestCase, override_settings

from apps.common.checks import get_max_session_age_seconds
from apps.common.middleware import MaintenanceModeMiddleware
from apps.settings.catalog import CATALOG, CATALOG_BY_KEY, GROUPS_BY_SLUG
from apps.settings.key_scan import extract_catalog_defaults, extract_string_literals
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService
from tests.factories.core_factories import create_staff_user

# Keys the catalog curation retired. Recorded here so the catalog can never
# quietly re-adopt one; the curation itself left with the migration reset.
RETIRED_KEYS = frozenset(
    {
        "billing.negative_balance_threshold",
        "billing.payment_grace_period_days",
        "billing.payment_retry_attempts",
        "billing.payment_retry_delay_hours",
        "billing.vat_rate",
        "domains.auto_renewal_enabled",
        "domains.max_per_package",
        "domains.max_subdomains_per_domain",
        "domains.registration_enabled",
        "domains.renewal_notice_days",
        "gdpr.audit_log_retention_years",
        "gdpr.data_retention_years",
        "gdpr.export_retention_days",
        "gdpr.log_retention_months",
        "integrations.api_connection_timeout_seconds",
        "integrations.api_request_timeout_seconds",
        "integrations.webhook_batch_size",
        "integrations.webhook_retry_attempts",
        "integrations.webhook_timeout_seconds",
        "monitoring.alert_cooldown_minutes",
        "monitoring.cpu_warning_threshold",
        "monitoring.disk_warning_threshold",
        "monitoring.health_check_interval_minutes",
        "monitoring.memory_warning_threshold",
        "node_deployment.auto_registration",
        "node_deployment.cost_tracking_enabled",
        "node_deployment.default_environment",
        "node_deployment.default_provider",
        "node_deployment.default_region",
        "node_deployment.timeout_ansible_playbook",
        "node_deployment.timeout_terraform_apply",
        "node_deployment.timeout_validation",
        "notifications.digest_frequency_hours",
        "notifications.email_enabled",
        "notifications.max_history",
        "notifications.sms_enabled",
        "provisioning.auto_setup_enabled",
        "provisioning.default_bandwidth_quota_gb",
        "provisioning.default_disk_quota_gb",
        "provisioning.max_email_accounts_per_package",
        "provisioning.setup_timeout_minutes",
        "provisioning.suspend_timeout_minutes",
        "provisioning.terminate_timeout_minutes",
        "security.api_burst_limit",
        "security.rate_limit_per_hour",
        "security.require_2fa_for_admin",
        "security.session_validation_rate_limit",
        "system.backup_retention_days",
        "tickets.auto_escalation_hours",
        "tickets.max_attachments_per_ticket",
        "tickets.max_reassignments",
        "tickets.sla_critical_response_hours",
        "tickets.sla_high_response_hours",
        "tickets.sla_low_response_hours",
        "tickets.sla_standard_response_hours",
        "ui.default_page_size",
        "ui.max_attachment_size_mb",
        "ui.max_page_size",
        "ui.min_page_size",
        "users.account_lockout_duration_minutes",
        "users.backup_code_count",
        "users.login_rate_limit_per_hour",
        "users.max_login_attempts",
        "users.mfa_required_for_staff",
        "users.session_timeout_minutes",
        "virtualmin.api_endpoint_path",
        "virtualmin.ssh_username",
        "virtualmin.use_ssl",
    }
)

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

    def test_domain_renewal_notice_schedule_is_a_validated_integer_list(self) -> None:
        definition = CATALOG_BY_KEY["domains.renewal_notice_schedule_days"]

        self.assertEqual(definition.default, [30, 14, 7, 3, 1])
        self.assertEqual(definition.data_type, "list")
        self.assertEqual(definition.input_kind, "chips")
        self.assertEqual(
            definition.validation,
            {
                "min_items": 1,
                "item_type": "integer",
                "item_min": 1,
                "unique_items": True,
                "order": "descending",
            },
        )

    def test_invitation_rate_limits_have_unambiguous_policy_identities(self) -> None:
        expected_defaults = {
            "security.membership_invitation_limit_per_inviter_per_hour": 10,
            "security.welcome_invite_limit_per_target_per_hour": 3,
            "security.join_request_notification_limit_per_customer_per_hour": 10,
        }

        for key, expected_default in expected_defaults.items():
            with self.subTest(key=key):
                self.assertEqual(CATALOG_BY_KEY[key].default, expected_default)

        membership_policy = CATALOG_BY_KEY["security.membership_invitation_limit_per_inviter_per_hour"]
        self.assertIn("separately for each inviter and each source IP", str(membership_policy.help_text))
        self.assertEqual(membership_policy.unit, "per inviter and IP/hour")

        self.assertNotIn("security.invitation_rate_limit_per_user", CATALOG_BY_KEY)
        self.assertNotIn("security.welcome_invite_limit_per_user_per_hour", CATALOG_BY_KEY)

    def test_retired_keys_are_not_in_catalog(self) -> None:
        overlap = set(RETIRED_KEYS) & set(CATALOG_BY_KEY)
        self.assertEqual(overlap, set())

    def test_known_decoys_are_gone(self) -> None:
        """billing.vat_rate (TaxRule owns VAT) and the env-gated flags must stay retired."""
        for key in ("billing.vat_rate", "billing.payment_grace_period_days", "users.max_login_attempts"):
            self.assertNotIn(key, CATALOG_BY_KEY)
            self.assertIn(key, RETIRED_KEYS)


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
