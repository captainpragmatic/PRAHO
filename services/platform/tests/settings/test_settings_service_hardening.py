"""
Service-hardening tests for the settings module.

Covers the cache-first read path (#238), canonical value coercion, sensitive
first-write encryption, atomic change sets with optimistic concurrency,
audit attribution, critical-setting notifications, and the read-only staff API.
"""

from __future__ import annotations

import threading
from typing import Any
from unittest.mock import patch

from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.db import connection, transaction
from django.test import TestCase, TransactionTestCase, override_settings
from django.urls import reverse

from apps.audit.models import AuditEvent
from apps.common.encryption import is_encrypted
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService
from config.settings.test import LOCMEM_TEST_CACHE
from tests.factories.core_factories import create_staff_user

_MISS = object()


def _cached(key: str) -> object:
    return cache.get(SettingsService._get_cache_key(key), _MISS, version=SettingsService.CACHE_VERSION)


def _make_setting(key: str, value: object, data_type: str, **extra: object) -> SystemSetting:
    return SystemSetting.objects.create(
        key=key,
        name=key,
        description=f"test setting {key}",
        category=key.split(".", maxsplit=1)[0],
        value=value,
        default_value=value,
        data_type=data_type,
        **extra,
    )


@override_settings(CACHES=LOCMEM_TEST_CACHE)
class CacheFirstReadTests(TestCase):
    """get_setting must serve warm reads from cache without touching the database."""

    def setUp(self) -> None:
        cache.clear()

    def test_warm_cache_read_runs_zero_queries(self) -> None:
        """Reverting the cache-first order (#238) makes this fail: every read would hit the DB."""
        _make_setting("billing.proforma_validity_days", 45, "integer")
        self.assertEqual(SettingsService.get_setting("billing.proforma_validity_days"), 45)

        with self.assertNumQueries(0):
            value = SettingsService.get_setting("billing.proforma_validity_days")
        self.assertEqual(value, 45)

    def test_cached_none_default_is_served_without_query(self) -> None:
        """A cached None (missing key, no default) must count as a hit, not a miss."""
        self.assertIsNone(SettingsService.get_setting("nonexistent.key_without_default"))

        with self.assertNumQueries(0):
            self.assertIsNone(SettingsService.get_setting("nonexistent.key_without_default"))

    def test_sensitive_setting_is_never_cached(self) -> None:
        _make_setting("integrations.test_secret_key", "plain-secret", "string", is_sensitive=True)

        self.assertEqual(SettingsService.get_setting("integrations.test_secret_key"), "plain-secret")
        self.assertIs(_cached("integrations.test_secret_key"), _MISS)

        with self.assertNumQueries(1):
            SettingsService.get_setting("integrations.test_secret_key")


class CoercionMatrixTests(TestCase):
    """Canonical coercion is strict: clear errors instead of silent lossy casts."""

    def test_boolean_coercion(self) -> None:
        for raw, expected in [(True, True), ("true", True), ("1", True), ("off", False), ("", False), (False, False)]:
            self.assertIs(SettingsService._coerce_value("k.b", "boolean", raw), expected)
        with self.assertRaises(ValidationError):
            SettingsService._coerce_value("k.b", "boolean", "maybe")

    def test_integer_rejects_bool_and_garbage(self) -> None:
        self.assertEqual(SettingsService._coerce_value("k.i", "integer", "42"), 42)
        with self.assertRaises(ValidationError):
            SettingsService._coerce_value("k.i", "integer", True)
        with self.assertRaises(ValidationError):
            SettingsService._coerce_value("k.i", "integer", "4.2")

    def test_decimal_must_be_finite(self) -> None:
        self.assertEqual(str(SettingsService._coerce_value("k.d", "decimal", "0.21")), "0.21")
        with self.assertRaises(ValidationError):
            SettingsService._coerce_value("k.d", "decimal", "NaN")
        with self.assertRaises(ValidationError):
            SettingsService._coerce_value("k.d", "decimal", True)

    def test_list_requires_json_list(self) -> None:
        self.assertEqual(SettingsService._coerce_value("k.l", "list", '["a", "b"]'), ["a", "b"])
        with self.assertRaises(ValidationError):
            SettingsService._coerce_value("k.l", "list", '{"not": "a list"}')
        with self.assertRaises(ValidationError):
            SettingsService._coerce_value("k.l", "list", "['python', 'repr']")

    def test_string_rejects_non_strings(self) -> None:
        self.assertEqual(SettingsService._coerce_value("k.s", "string", "ok"), "ok")
        with self.assertRaises(ValidationError):
            SettingsService._coerce_value("k.s", "string", 7)


@override_settings(CACHES=LOCMEM_TEST_CACHE)
class SensitiveFirstWriteTests(TestCase):
    """First write for a rowless sensitive key must encrypt at rest and never cache."""

    def setUp(self) -> None:
        cache.clear()

    def test_rowless_sensitive_first_write_is_encrypted_and_uncached(self) -> None:
        result = SettingsService.update_setting("integrations.stripe_secret_key", "sk_test_abc123")
        self.assertTrue(result.is_ok())

        row = SystemSetting.objects.get(key="integrations.stripe_secret_key")
        self.assertTrue(row.is_sensitive)
        self.assertTrue(is_encrypted(str(row.value)))
        self.assertNotIn("sk_test_abc123", str(row.value))

        self.assertEqual(SettingsService.get_setting("integrations.stripe_secret_key"), "sk_test_abc123")
        self.assertIs(_cached("integrations.stripe_secret_key"), _MISS)


class ChangeSetTests(TestCase):
    """apply_change_set: all-or-nothing, baseline-guarded, sensitive-free."""

    def setUp(self) -> None:
        self.terms = _make_setting("billing.invoice_payment_terms_days", 14, "integer")
        self.proforma = _make_setting("billing.proforma_validity_days", 30, "integer")

    def _baseline(self, setting: SystemSetting) -> str:
        setting.refresh_from_db()
        return setting.updated_at.isoformat()

    def test_empty_change_set_rejected(self) -> None:
        result = SettingsService.apply_change_set({}, {})
        self.assertFalse(result.is_ok())
        self.assertEqual(result.error.code, "empty")

    def test_unknown_key_rejected(self) -> None:
        result = SettingsService.apply_change_set({"nope.unknown_key": 1}, {"nope.unknown_key": None})
        self.assertFalse(result.is_ok())
        self.assertEqual(result.error.errors[0].code, "unknown_key")

    def test_sensitive_key_rejected(self) -> None:
        result = SettingsService.apply_change_set(
            {"integrations.stripe_secret_key": "sk_new"},
            {"integrations.stripe_secret_key": None},
        )
        self.assertFalse(result.is_ok())
        self.assertEqual(result.error.errors[0].code, "sensitive_key")

    def test_apply_updates_values_with_shared_change_set_id(self) -> None:
        user = create_staff_user(username="changeset_admin", staff_role="admin")
        before_events = AuditEvent.objects.count()

        result = SettingsService.apply_change_set(
            {"billing.invoice_payment_terms_days": 21, "billing.proforma_validity_days": 45},
            {
                "billing.invoice_payment_terms_days": self._baseline(self.terms),
                "billing.proforma_validity_days": self._baseline(self.proforma),
            },
            user_id=user.id,
            reason="quarterly policy review",
        )

        self.assertTrue(result.is_ok())
        self.assertEqual(SystemSetting.objects.get(key="billing.invoice_payment_terms_days").value, 21)
        self.assertEqual(SystemSetting.objects.get(key="billing.proforma_validity_days").value, 45)

        events = AuditEvent.objects.order_by("-timestamp")[: AuditEvent.objects.count() - before_events]
        self.assertEqual(len(events), 2)
        change_set_ids = {event.metadata.get("change_set_id") for event in events}
        self.assertEqual(change_set_ids, {result.value.change_set_id})
        for event in events:
            self.assertEqual(event.user, user)
            self.assertEqual(event.metadata.get("reason"), "quarterly policy review")
            self.assertIsNotNone(event.old_values)
            self.assertIsNotNone(event.new_values)

        # Fresh baselines returned for the UI to rebase on
        outcome_setting = result.value.settings["billing.invoice_payment_terms_days"]
        self.assertEqual(outcome_setting.updated_at.isoformat(), self._baseline(self.terms))

    def test_stale_baseline_conflicts_and_nothing_applies(self) -> None:
        stale = self._baseline(self.terms)
        SettingsService.update_setting("billing.invoice_payment_terms_days", 20)

        result = SettingsService.apply_change_set(
            {"billing.invoice_payment_terms_days": 30, "billing.proforma_validity_days": 60},
            {
                "billing.invoice_payment_terms_days": stale,
                "billing.proforma_validity_days": self._baseline(self.proforma),
            },
        )

        self.assertFalse(result.is_ok())
        self.assertEqual(result.error.code, "conflict")
        self.assertEqual(result.error.conflicts[0].key, "billing.invoice_payment_terms_days")
        self.assertIsNotNone(result.error.conflicts[0].server_updated_at)
        self.assertEqual(SystemSetting.objects.get(key="billing.proforma_validity_days").value, 30)

    def test_null_baseline_with_existing_row_conflicts(self) -> None:
        result = SettingsService.apply_change_set(
            {"billing.proforma_validity_days": 60},
            {"billing.proforma_validity_days": None},
        )
        self.assertFalse(result.is_ok())
        self.assertEqual(result.error.code, "conflict")

    def test_write_stage_failure_rolls_back_entire_set(self) -> None:
        # -1 violates the catalog rule {"min": 0} at the write stage (static phase only coerces)
        result = SettingsService.apply_change_set(
            {"billing.invoice_payment_terms_days": -1, "billing.proforma_validity_days": 60},
            {
                "billing.invoice_payment_terms_days": self._baseline(self.terms),
                "billing.proforma_validity_days": self._baseline(self.proforma),
            },
        )

        self.assertFalse(result.is_ok())
        self.assertEqual(result.error.code, "validation")
        self.assertEqual(SystemSetting.objects.get(key="billing.invoice_payment_terms_days").value, 14)
        self.assertEqual(SystemSetting.objects.get(key="billing.proforma_validity_days").value, 30)

    def test_conflict_produces_no_audit_events(self) -> None:
        before = AuditEvent.objects.count()
        SettingsService.apply_change_set(
            {"billing.proforma_validity_days": 60},
            {"billing.proforma_validity_days": "2000-01-01T00:00:00"},
        )
        self.assertEqual(AuditEvent.objects.count(), before)


class CriticalSettingNotificationTests(TestCase):
    """Critical-setting alerts fire only after the transaction commits."""

    def test_alert_sent_after_commit(self) -> None:
        with (
            patch("apps.settings.signals._send_critical_setting_notification") as mock_send,
            self.captureOnCommitCallbacks(execute=True),
        ):
            result = SettingsService.update_setting("system.maintenance_mode", True)
            self.assertTrue(result.is_ok())
            mock_send.assert_not_called()
        mock_send.assert_called_once()

    def test_no_alert_after_rollback(self) -> None:
        with (
            patch("apps.settings.signals._send_critical_setting_notification") as mock_send,
            self.captureOnCommitCallbacks(execute=True),
            self.assertRaises(RuntimeError),
            transaction.atomic(),
        ):
            SettingsService.update_setting("system.maintenance_mode", True)
            raise RuntimeError("force rollback")
        mock_send.assert_not_called()


class SettingsApiReadOnlyTests(TestCase):
    """The staff API is read-only and never discloses sensitive values."""

    def setUp(self) -> None:
        self.staff = create_staff_user(username="api_staff", staff_role="support")
        self.client.force_login(self.staff)
        _make_setting("billing.proforma_validity_days", 30, "integer")
        _make_setting("integrations.api_probe_secret_key", "super-secret", "string", is_sensitive=True)

    def test_list_redacts_sensitive_values(self) -> None:
        response = self.client.get(reverse("settings:settings_api"))
        self.assertEqual(response.status_code, 200)
        payload = response.json()["categories"]
        sensitive = payload["integrations"]["settings"]["integrations.api_probe_secret_key"]
        self.assertIsNone(sensitive["value"])
        self.assertTrue(sensitive["configured"])
        self.assertNotIn("super-secret", response.content.decode())

    def test_detail_redacts_sensitive_value(self) -> None:
        response = self.client.get(reverse("settings:setting_detail_api", args=["integrations.api_probe_secret_key"]))
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.json()["setting"]["value"])
        self.assertNotIn("super-secret", response.content.decode())

    def test_post_is_rejected(self) -> None:
        response = self.client.post(
            reverse("settings:settings_api"),
            data='{"key": "billing.proforma_validity_days", "value": 60}',
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 405)
        self.assertEqual(SystemSetting.objects.get(key="billing.proforma_validity_days").value, 30)

    def test_anonymous_cannot_read(self) -> None:
        self.client.logout()
        response = self.client.get(reverse("settings:settings_api"))
        self.assertNotEqual(response.status_code, 200)


class ChangeSetPostgresConcurrencyTests(TransactionTestCase):
    """Reversed-key-order change sets must not deadlock (PostgreSQL only)."""

    def setUp(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("Row-locking semantics require PostgreSQL")
        _make_setting("billing.invoice_payment_terms_days", 14, "integer")
        _make_setting("billing.proforma_validity_days", 30, "integer")

    def test_overlapping_change_sets_do_not_deadlock(self) -> None:
        baselines = {
            key: SystemSetting.objects.get(key=key).updated_at.isoformat()
            for key in ("billing.invoice_payment_terms_days", "billing.proforma_validity_days")
        }
        results: dict[str, Any] = {}

        def apply(label: str, changes: dict[str, object]) -> None:
            try:
                results[label] = SettingsService.apply_change_set(dict(changes), dict(baselines))
            finally:
                connection.close()

        # Same keys, opposite insertion order — deterministic lock ordering must serialize them
        thread_a = threading.Thread(
            target=apply,
            args=("a", {"billing.invoice_payment_terms_days": 21, "billing.proforma_validity_days": 45}),
        )
        thread_b = threading.Thread(
            target=apply,
            args=("b", {"billing.proforma_validity_days": 60, "billing.invoice_payment_terms_days": 28}),
        )
        thread_a.start()
        thread_b.start()
        thread_a.join(timeout=15)
        thread_b.join(timeout=15)
        self.assertFalse(thread_a.is_alive() or thread_b.is_alive(), "change sets deadlocked")

        outcomes = [result.is_ok() for result in results.values()]
        # One wins; the loser sees a baseline conflict — never a deadlock or partial write
        self.assertIn(True, outcomes)
        values = {
            SystemSetting.objects.get(key="billing.invoice_payment_terms_days").value,
            SystemSetting.objects.get(key="billing.proforma_validity_days").value,
        }
        self.assertIn(values, [{21, 45}, {28, 60}])


class CreationPathValidationTests(TestCase):
    """Catalog rules must apply on the FIRST write too (review of #377): the
    creation branch coerced but never ran _apply_rules or full_clean, so a
    staff write could persist an out-of-range value before the row existed."""

    def test_first_write_enforces_catalog_rules(self) -> None:
        SystemSetting.objects.filter(key="audit.compliant_score_threshold").delete()

        result = SettingsService.update_setting("audit.compliant_score_threshold", -5)

        self.assertTrue(result.is_err(), "an out-of-range first write must be rejected")
        self.assertFalse(
            SystemSetting.objects.filter(key="audit.compliant_score_threshold").exists(),
            "no row may be created from a value that fails catalog rules",
        )

    def test_first_write_accepts_a_valid_value(self) -> None:
        SystemSetting.objects.filter(key="audit.compliant_score_threshold").delete()

        result = SettingsService.update_setting("audit.compliant_score_threshold", 85)

        self.assertTrue(result.is_ok())


class AuditFailureIsolationTests(TestCase):
    """A failing audit write must neither poison nor roll back the setting change (fail-open)."""

    def test_audit_db_failure_does_not_poison_setting_write(self) -> None:
        """Revert-proof form: the audit failure executes REAL failing SQL, so the
        connection is genuinely marked needs-rollback. Only the signal handler's
        savepoint clears it - remove that savepoint and the setting write (and this
        test's read-back) dies with TransactionManagementError."""
        _make_setting("billing.proforma_validity_days", 30, "integer")

        def _poisoning_audit_failure(*args: Any, **kwargs: Any) -> None:
            # A failing ORM save sets needs_rollback via mark_for_rollback_on_error -
            # the exact mechanism of the lazy-proxy incident (a raw cursor error would
            # not set the flag on SQLite and the test would pass vacuously).
            AuditEvent.objects.create(metadata={"unserializable": object()})

        with patch(
            "apps.settings.signals.AuditService.log_simple_event",
            side_effect=_poisoning_audit_failure,
        ):
            result = SettingsService.update_setting("billing.proforma_validity_days", 45)
            self.assertTrue(result.is_ok())

        row = SystemSetting.objects.get(key="billing.proforma_validity_days")
        self.assertEqual(row.get_typed_value(), 45)
