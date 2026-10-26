"""Status reports must describe the configuration used by the running service."""

import base64
import os
from contextlib import ExitStack
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.core.cache import cache
from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings
from django.utils import timezone
from django.utils.translation import get_language, override

from apps.common import system_status as status
from apps.common.localisation import LocalisationDefaults, resolve_display
from apps.common.system_status_probes import ProbeBudget, ProbeCode
from config.settings.test import LOCMEM_TEST_CACHE

KEY = base64.urlsafe_b64encode(b"k" * 32).decode()


class RuntimeStatusTests(SimpleTestCase):
    def test_definite_credentials_rejection_is_red_but_unknown_denial_is_amber(self) -> None:
        rejected = status._probe_status("Stripe", ProbeCode.UNAUTHORIZED, "verified")
        unknown = status._probe_status("Stripe", ProbeCode.FORBIDDEN, "verified")
        self.assertEqual(rejected.level, status.StatusLevel.RED)
        self.assertEqual(rejected.message, "Credentials rejected")
        self.assertEqual(unknown.level, status.StatusLevel.AMBER)
        self.assertIn("cause is unverified", unknown.detail)

    @override_settings(
        PLATFORM_API_SECRET="runtime-secret",
        PORTAL_HMAC_MODE="legacy",
        PORTAL_HMAC_CREDENTIALS="{}",
        PORTAL_HMAC_REQUIRE_ISOLATION=False,
    )
    @patch.dict(os.environ, {"HMAC_SECRET": ""})
    def test_legacy_hmac_uses_runtime_secret(self) -> None:
        result = status._check_hmac()
        self.assertEqual(result.level, status.StatusLevel.GREEN)
        self.assertIn("legacy", result.message)

    @override_settings(
        PLATFORM_API_SECRET="",
        PORTAL_HMAC_MODE="legacy",
        PORTAL_HMAC_CREDENTIALS="{}",
        PORTAL_HMAC_REQUIRE_ISOLATION=False,
    )
    @patch.dict(os.environ, {"HMAC_SECRET": "obsolete-secret"})
    def test_obsolete_env_secret_does_not_make_hmac_ready(self) -> None:
        self.assertEqual(status._check_hmac().level, status.StatusLevel.RED)

    @override_settings(ENCRYPTION_KEYS=[KEY], ENCRYPTION_KEY="")
    @patch.dict(os.environ, {"DJANGO_ENCRYPTION_KEY": ""})
    def test_encryption_checks_runtime_keyring(self) -> None:
        result = status._check_encryption()
        self.assertEqual(result.level, status.StatusLevel.GREEN)
        self.assertIn("self-test", result.detail)

    @override_settings(ENCRYPTION_KEYS=[KEY, "invalid"])
    @patch.dict(os.environ, {"DJANGO_ENCRYPTION_KEY": KEY})
    def test_invalid_previous_encryption_key_is_red(self) -> None:
        self.assertEqual(status._check_encryption().level, status.StatusLevel.RED)

    @override_settings(SENTRY_DSN="https://public@example.test/1")
    @patch.dict(os.environ, {"SENTRY_DSN": "https://public@example.test/1"})
    @patch("sentry_sdk.is_initialized", return_value=False)
    def test_sentry_dsn_without_client_is_not_active(self, _initialized: Mock) -> None:
        self.assertEqual(status._check_sentry().level, status.StatusLevel.AMBER)

    @override_settings(CREDENTIAL_VAULT_ENABLED=False, CREDENTIAL_VAULT_MASTER_KEY=KEY)
    def test_vault_checks_actual_key_even_with_unused_flag_disabled(self) -> None:
        self.assertEqual(status._check_credential_vault().level, status.StatusLevel.GREEN)

    @override_settings(DEBUG=False)
    @patch(
        "subprocess.run",
        return_value=Mock(returncode=0, stdout="# backup disabled\n0 2 * * * /other/backup.sh\n", stderr=""),
    )
    def test_comments_and_other_backups_do_not_count(self, _run: Mock) -> None:
        self.assertNotEqual(status._check_backup().level, status.StatusLevel.GREEN)

    @override_settings(PLATFORM_API_SECRET="", PORTAL_HMAC_REQUIRE_ISOLATION=False)
    def test_registry_modes_and_invalid_configuration(self) -> None:
        for mode, registry, expected in (
            ("audit", '{"portal-001":["current","previous"]}', status.StatusLevel.GREEN),
            ("enforce", '{"portal-001":"unique"}', status.StatusLevel.GREEN),
            ("enforce", "{}", status.StatusLevel.RED),
            ("audit", "not-json", status.StatusLevel.RED),
            ("unknown", "{}", status.StatusLevel.RED),
        ):
            with (
                self.subTest(mode=mode, registry=registry),
                override_settings(PORTAL_HMAC_MODE=mode, PORTAL_HMAC_CREDENTIALS=registry),
            ):
                self.assertEqual(status._check_hmac().level, expected)

    @override_settings(
        PORTAL_HMAC_MODE="enforce",
        PORTAL_HMAC_REQUIRE_ISOLATION=True,
        PORTAL_HMAC_CREDENTIALS='{"one":"same","two":"same"}',
    )
    def test_hmac_isolation_violation_is_red(self) -> None:
        self.assertEqual(status._check_hmac().level, status.StatusLevel.RED)

    @override_settings(EMAIL_BACKEND="django.core.mail.backends.console.EmailBackend")
    @patch.object(ProbeBudget, "run")
    def test_email_uses_actual_local_backend_without_probe(self, probe: Mock) -> None:
        result = status._check_email()
        self.assertEqual(result.message, "Console backend")
        self.assertEqual(result.level, status.StatusLevel.GREY)
        probe.assert_not_called()

    @override_settings(
        DEBUG=True, EMAIL_BACKEND="django.core.mail.backends.smtp.EmailBackend", EMAIL_HOST="smtp.example"
    )
    @patch.object(ProbeBudget, "run", return_value=ProbeCode.OK)
    def test_smtp_is_checked_even_in_development(self, probe: Mock) -> None:
        self.assertEqual(status._check_email().level, status.StatusLevel.GREEN)
        self.assertEqual(probe.call_args.args[0], "smtp")
        self.assertEqual(probe.call_args.args[1]["host"], "smtp.example")

    @override_settings(STRIPE_SECRET_KEY="sk_live_unused_env")
    @patch("apps.settings.services.SettingsService.get_setting", return_value=False)
    @patch.object(ProbeBudget, "run")
    def test_disabled_stripe_does_not_probe_env_key(self, probe: Mock, _setting: Mock) -> None:
        result = status._check_stripe()
        self.assertEqual(result.message, "Disabled")
        self.assertEqual(result.level, status.StatusLevel.GREY)
        probe.assert_not_called()

    @patch("apps.settings.services.SettingsService.get_setting")
    @patch.object(ProbeBudget, "run", return_value=ProbeCode.OK)
    def test_stripe_runtime_keys_and_missing_webhook(self, probe: Mock, setting: Mock) -> None:
        values = {
            "integrations.stripe_enabled": True,
            "integrations.stripe_secret_key": "rk_test_runtime",
            "integrations.stripe_publishable_key": "pk_test_runtime",
            "integrations.stripe_webhook_secret": "",
        }
        setting.side_effect = lambda key, default="": values.get(key, default)
        result = status._check_stripe()
        self.assertEqual(result.level, status.StatusLevel.AMBER)
        self.assertEqual(result.message, "Webhook secret missing")
        self.assertEqual(probe.call_args.args[1]["headers"]["Authorization"], "Bearer rk_test_runtime")
        values["integrations.stripe_webhook_secret"] = "whsec_runtime"
        result = status._check_stripe()
        self.assertEqual(result.level, status.StatusLevel.GREEN)
        self.assertIn("test", result.message)
        values["integrations.stripe_publishable_key"] = "pk_live_wrong"
        self.assertEqual(status._check_stripe().message, "Key modes differ")
        self.assertEqual(probe.call_count, 2)

    @override_settings(REPO_ROOT="/srv/praho")
    def test_backup_command_must_be_active_and_belong_to_this_deployment(self) -> None:
        self.assertTrue(status._has_backup_job("0 2 * * * /srv/praho/scripts/backup.sh >> /tmp/log 2>&1"))
        self.assertTrue(status._has_backup_job("@daily /bin/bash /srv/praho/deploy/scripts/backup.sh"))
        for line in (
            "# 0 2 * * * /srv/praho/scripts/backup.sh",
            "0 2 * * * echo /srv/praho/scripts/backup.sh",
            "0 2 * * * /other/backup.sh",
        ):
            self.assertFalse(status._has_backup_job(line))

    @override_settings(DEBUG=False)
    @patch("subprocess.run", side_effect=OSError("private path"))
    def test_backup_visibility_failure_in_deployment_is_warning(self, _run: Mock) -> None:
        result = status._check_backup()
        self.assertEqual(result.level, status.StatusLevel.AMBER)
        self.assertEqual(result.message, "Schedule unverified")
        self.assertNotIn("private", result.detail)


class DatabaseStatusTests(TestCase):
    def test_database_reports_actual_engine(self) -> None:
        from django.db import connection  # noqa: PLC0415

        result = status._check_database()
        self.assertEqual(result.level, status.StatusLevel.GREEN)
        self.assertEqual(result.detail, connection.display_name)


@override_settings(CACHES=LOCMEM_TEST_CACHE)
class SnapshotTests(SimpleTestCase):
    def setUp(self) -> None:
        cache.clear()

    @override_settings(
        PLATFORM_API_SECRET="runtime-secret",
        PORTAL_HMAC_MODE="legacy",
        PORTAL_HMAC_CREDENTIALS="{}",
        PORTAL_HMAC_REQUIRE_ISOLATION=False,
    )
    @patch.object(status, "check_all_subsystems", side_effect=lambda: [status._check_hmac()])
    def test_cached_interpolated_messages_use_the_readers_language(self, _checks: Mock) -> None:
        with patch(
            "django.utils.translation._trans.gettext", side_effect=lambda message: f"{get_language()}:{message}"
        ):
            with override("ro"):
                status.refresh_and_cache_status()
            with override("en"):
                snapshot = status.get_cached_status()
                self.assertTrue(str(snapshot.results[0].name).startswith("en:"))
                self.assertTrue(str(snapshot.results[0].message).startswith("en:"))
                self.assertIn("legacy", str(snapshot.results[0].message))

    @patch.object(status, "check_all_subsystems", return_value=[])
    def test_silent_cache_write_failure_is_reported(self, _checks: Mock) -> None:
        with patch.object(status.cache, "set", return_value=None):
            snapshot = status.refresh_and_cache_status()
        self.assertFalse(snapshot.saved)
        self.assertFalse(snapshot.cache_available)

    @patch.object(status, "check_all_subsystems", return_value=[])
    def test_write_confirmation_rejects_old_snapshot_but_accepts_newer_writer(self, _checks: Mock) -> None:
        now = timezone.now()
        for age, expected in ((timedelta(seconds=-1), False), (timedelta(), False), (timedelta(seconds=1), True)):
            cache.set(status.CACHE_KEY, status.StatusSnapshot([], checked_at=now + age))
            with (
                patch.object(status.timezone, "now", return_value=now),
                patch.object(status.cache, "set", return_value=None),
            ):
                self.assertEqual(status.refresh_and_cache_status().saved, expected)

    @patch("apps.settings.services.SettingsService.get_list_setting", return_value=["EUR"])
    @patch("apps.billing.currency_service.home_currency", return_value="EUR")
    def test_fx_no_foreign_currency_message_uses_actual_home(self, _home: Mock, _pairs: Mock) -> None:
        result = status._check_fx_freshness()
        self.assertEqual(result.level, status.StatusLevel.GREY)
        self.assertIn("EUR", result.detail)
        self.assertNotIn("RON", result.detail)

    def test_stale_boundary_uses_check_time(self) -> None:
        now = timezone.now()
        with patch.object(status.timezone, "now", return_value=now):
            for age, expected in (
                (timedelta(hours=26, microseconds=-1), False),
                (timedelta(hours=26), True),
                (timedelta(hours=27), True),
            ):
                self.assertEqual(status.StatusSnapshot([], checked_at=now - age).stale, expected)

    @patch.object(status, "_check_fx_freshness")
    @patch.object(ProbeBudget, "run")
    def test_cache_read_recomputes_fx_without_external_checks(self, probe: Mock, fx: Mock) -> None:
        yesterday = timezone.now() - timedelta(days=1)
        cached = status.SubsystemStatus("FX rates", status.StatusLevel.GREEN, "Fresh", key="fx", checked_at=yesterday)
        cache.set(status.CACHE_KEY, status.StatusSnapshot([cached], checked_at=yesterday))
        fx.return_value = status.SubsystemStatus("FX rates", status.StatusLevel.RED, "No usable rate today")
        snapshot = status.get_cached_status()
        self.assertEqual(snapshot.checked_at, yesterday)
        self.assertEqual(snapshot.results[0].level, status.StatusLevel.RED)
        self.assertGreater(snapshot.results[0].checked_at, yesterday)
        probe.assert_not_called()

    @patch.object(status, "check_all_subsystems")
    def test_cache_failure_does_not_discard_results(self, check: Mock) -> None:
        check.return_value = [status.SubsystemStatus("Database", status.StatusLevel.GREEN, "Connected", key="database")]
        with patch.object(status.cache, "set", side_effect=RuntimeError("private")):
            snapshot = status.refresh_and_cache_status()
        self.assertFalse(snapshot.saved)
        self.assertFalse(snapshot.cache_available)
        self.assertEqual(snapshot.results[0].message, "Connected")
        self.assertIsNotNone(snapshot.checked_at)

    @patch.object(status.cache, "get", side_effect=RuntimeError("private"))
    def test_cache_read_failure_is_reported(self, _get: Mock) -> None:
        snapshot = status.get_cached_status()
        self.assertFalse(snapshot.cache_available)
        self.assertEqual(snapshot.results, [])

    def test_one_failed_check_does_not_prevent_other_rows(self) -> None:
        functions = (
            "database",
            "hmac",
            "email",
            "stripe",
            "efactura",
            "encryption",
            "credential_vault",
            "sentry",
            "backup",
            "fx_freshness",
        )
        with ExitStack() as stack:
            stack.enter_context(patch.object(status, "operator_is_romanian", return_value=True))
            for name in functions:
                stack.enter_context(
                    patch.object(
                        status,
                        "_check_" + name,
                        return_value=status.SubsystemStatus(name, status.StatusLevel.GREEN, "ready"),
                    )
                )
            stack.enter_context(patch.object(status, "_check_hmac", side_effect=RuntimeError("private-secret")))
            results = status.check_all_subsystems()
        self.assertEqual(len(results), 10)
        self.assertEqual(results[1].key, "hmac")
        self.assertEqual(results[1].level, status.StatusLevel.RED)
        self.assertNotIn("private-secret", str(results))
        self.assertEqual(results[-1].key, "fx")
        self.assertEqual(results[-1].level, status.StatusLevel.GREEN)

    @patch.object(status, "check_all_subsystems")
    @patch("apps.notifications.services.NotificationService.send_admin_alert", return_value=True)
    def test_daily_fx_alert_survives_snapshot_and_dedup_cache_failure(self, alert: Mock, check: Mock) -> None:
        from apps.common.tasks import system_status_check  # noqa: PLC0415

        check.return_value = [status.SubsystemStatus("Translated FX name", status.StatusLevel.RED, "missing", key="fx")]
        with (
            patch.object(status.cache, "set", side_effect=RuntimeError),
            patch.object(status.cache, "get", side_effect=RuntimeError),
        ):
            system_status_check()
        alert.assert_called_once_with("FX rates RED: missing", "", alert_type="critical")


@override_settings(CACHES=LOCMEM_TEST_CACHE, RATE_LIMITING_ENABLED=True)
class StatusRefreshViewTests(SimpleTestCase):
    def setUp(self) -> None:
        self.factory = RequestFactory()
        maintenance = patch("apps.common.context_processors._maintenance_mode_active", return_value=False)
        maintenance.start()
        self.addCleanup(maintenance.stop)

    def _request(self, *, staff: bool = True):
        request = self.factory.post("/dashboard/system-status/refresh/")
        request.user = SimpleNamespace(is_active=True, is_staff=staff, is_staff_user=staff, is_authenticated=True, pk=1)
        request.localisation = resolve_display(LocalisationDefaults(), None, staff=True)
        return request

    @patch("apps.common.counters.increment", side_effect=[1, 2])
    @patch.object(status, "refresh_and_cache_status")
    @patch.object(status, "get_cached_status")
    @patch("apps.common.rate_limiting._log_rate_limit_audit")
    def test_refresh_renders_one_replaceable_widget_and_cooldown(
        self, _audit: Mock, cached: Mock, refresh: Mock, _counter: Mock
    ) -> None:
        from apps.common.views import system_status_refresh  # noqa: PLC0415

        row = status.SubsystemStatus(
            "Portal Auth", status.StatusLevel.GREEN, "Configured (legacy)", checked_at=timezone.now()
        )
        cached.return_value = refresh.return_value = status.StatusSnapshot([row], checked_at=timezone.now())
        for expected in ("Configured (legacy)", "Please wait one minute"):
            result = system_status_refresh(self._request())
            content = result.content.decode()
            self.assertIn(expected, content)
            self.assertEqual(content.count('id="system-status-widget"'), 1)
            self.assertIn('hx-swap="outerHTML"', content)
            self.assertIn('hx-disabled-elt="this"', content)
        refresh.assert_called_once()

    @patch.object(status, "refresh_and_cache_status")
    def test_nonstaff_cannot_refresh(self, refresh: Mock) -> None:
        from apps.common.views import system_status_refresh  # noqa: PLC0415

        response = system_status_refresh(self._request(staff=False))
        self.assertIn("login", response.url)
        refresh.assert_not_called()

    @patch.object(status, "refresh_and_cache_status")
    def test_post_requires_csrf(self, refresh: Mock) -> None:
        from django.middleware.csrf import CsrfViewMiddleware  # noqa: PLC0415

        from apps.common.views import system_status_refresh  # noqa: PLC0415

        response = CsrfViewMiddleware(system_status_refresh).process_view(
            self._request(), system_status_refresh, (), {}
        )
        self.assertIsNotNone(response)
        self.assertContains(response, "CSRF", status_code=403)
        refresh.assert_not_called()
