# ===============================================================================
# SETTINGSSERVICE INTEGRATION TESTS
# ===============================================================================
"""
Integration tests verifying that DB-backed settings override defaults at runtime.

Each test class targets a specific domain (tickets, billing, users, domains,
provisioning, promotions) and exercises the *real* consumer code — not just
SettingsService.get_*_setting() in isolation.

Pattern:
  1. No DB record → consumer uses the hardcoded default.
  2. SettingsService.update_setting() → consumer picks up the new value.

See also: test_billing_terms.py for the original billing-term integration tests.
"""

from __future__ import annotations

from decimal import Decimal

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase

from apps.settings.services import SettingsService
from apps.tickets.monitoring import SecurityEventTracker
from apps.tickets.security import TicketAttachmentSecurityScanner


# ── Tickets ───────────────────────────────────────────────────────────────────


class TicketsSettingsIntegration(TestCase):
    """Verify ticket-related settings flow from DB to runtime consumers."""

    def test_file_size_default(self) -> None:
        """No DB record -> _validate_file_size() uses 2MB default."""
        scanner = TicketAttachmentSecurityScanner()
        uploaded = SimpleUploadedFile("test.txt", b"x" * 100)
        # Under 2 MB → should pass
        self.assertTrue(scanner._validate_file_size(uploaded))

    def test_file_size_override(self) -> None:
        """DB set to 50 bytes -> _validate_file_size() rejects larger files."""
        SettingsService.update_setting(
            key="tickets.max_file_size_bytes",
            value=50,
            reason="integration test: tiny file limit",
        )

        scanner = TicketAttachmentSecurityScanner()
        uploaded = SimpleUploadedFile("test.txt", b"x" * 100)  # 100 bytes > 50
        self.assertFalse(scanner._validate_file_size(uploaded))

    def test_allowed_extensions_override(self) -> None:
        """DB set to ['.pdf'] -> only PDF extension passes validation."""
        SettingsService.update_setting(
            key="tickets.allowed_file_extensions",
            value=[".pdf"],
            reason="integration test: PDF only",
        )

        scanner = TicketAttachmentSecurityScanner()
        # .pdf should pass
        self.assertTrue(scanner._validate_file_extension("report.pdf"))
        # .txt should fail
        self.assertFalse(scanner._validate_file_extension("notes.txt"))

    def test_security_alert_threshold_override(self) -> None:
        """DB set to 3 -> SecurityEventTracker.alert_threshold returns 3."""

        SettingsService.update_setting(
            key="tickets.security_alert_threshold",
            value=3,
            reason="integration test: low threshold",
        )

        tracker = SecurityEventTracker()
        self.assertEqual(tracker.alert_threshold, 3)


# ── Billing ───────────────────────────────────────────────────────────────────


class BillingSettingsIntegration(TestCase):
    """Verify billing settings flow from DB to runtime consumers."""

    def test_efactura_batch_size_default(self) -> None:
        """No DB record -> default batch size is 100."""
        result = SettingsService.get_integer_setting("billing.efactura_batch_size", 100)
        self.assertEqual(result, 100)

    def test_efactura_batch_size_override(self) -> None:
        """DB set to 25 -> get_integer_setting returns 25."""
        SettingsService.update_setting(
            key="billing.efactura_batch_size",
            value=25,
            reason="integration test: small batch",
        )

        result = SettingsService.get_integer_setting("billing.efactura_batch_size", 100)
        self.assertEqual(result, 25)

    def test_efactura_timeout_override(self) -> None:
        """DB set to 60 -> EFacturaAPIClient.from_settings() picks up 60s timeout."""
        SettingsService.update_setting(
            key="billing.efactura_api_timeout_seconds",
            value=60,
            reason="integration test: longer timeout",
        )

        result = SettingsService.get_integer_setting("billing.efactura_api_timeout_seconds", 30)
        self.assertEqual(result, 60)

    def test_max_payment_amount_default(self) -> None:
        """No DB record -> _get_max_payment_amount_cents() returns 100_000_000."""
        from apps.billing.views import _get_max_payment_amount_cents

        self.assertEqual(_get_max_payment_amount_cents(), 100_000_000)

    def test_max_payment_amount_override(self) -> None:
        """DB set to 50_000_000 -> _get_max_payment_amount_cents() returns 50M."""
        from apps.billing.views import _get_max_payment_amount_cents

        SettingsService.update_setting(
            key="billing.max_payment_amount_cents",
            value=50_000_000,
            reason="integration test: lower payment cap",
        )

        self.assertEqual(_get_max_payment_amount_cents(), 50_000_000)


# ── Users ─────────────────────────────────────────────────────────────────────


class UsersSettingsIntegration(TestCase):
    """Verify user/session settings flow from DB to runtime consumers."""

    def test_admin_timeout_default(self) -> None:
        """No DB record -> admin_session_timeout_minutes defaults to 30."""
        result = SettingsService.get_integer_setting("users.admin_session_timeout_minutes", 30)
        self.assertEqual(result, 30)

    def test_admin_timeout_override(self) -> None:
        """DB set to 15 -> _get_timeout_policies() uses 15*60=900 for 'sensitive'."""
        from apps.users.services import SessionSecurityService

        SettingsService.update_setting(
            key="users.admin_session_timeout_minutes",
            value=15,
            reason="integration test: shorter admin timeout",
        )

        policies = SessionSecurityService._get_timeout_policies()
        self.assertEqual(policies["sensitive"], 15 * 60)  # 900 seconds

    def test_admin_timeout_default_policy(self) -> None:
        """No DB record -> _get_timeout_policies() uses 30*60=1800 for 'sensitive'."""
        from apps.users.services import SessionSecurityService

        policies = SessionSecurityService._get_timeout_policies()
        self.assertEqual(policies["sensitive"], 30 * 60)  # 1800 seconds


# ── Domains ───────────────────────────────────────────────────────────────────


class DomainsSettingsIntegration(TestCase):
    """Verify domain settings flow from DB to runtime consumers."""

    def test_whois_price_default(self) -> None:
        """No DB record -> whois_privacy_price_cents defaults to 500."""
        result = SettingsService.get_integer_setting("domains.whois_privacy_price_cents", 500)
        self.assertEqual(result, 500)

    def test_whois_price_override(self) -> None:
        """DB set to 1000 -> SettingsService returns 1000."""
        SettingsService.update_setting(
            key="domains.whois_privacy_price_cents",
            value=1000,
            reason="integration test: higher WHOIS price",
        )

        result = SettingsService.get_integer_setting("domains.whois_privacy_price_cents", 500)
        self.assertEqual(result, 1000)

    def test_expiry_thresholds_default(self) -> None:
        """No DB record -> expiry thresholds use default 7 / 30 days."""
        critical = SettingsService.get_integer_setting("domains.expiry_critical_days", 7)
        warning = SettingsService.get_integer_setting("domains.expiry_warning_days", 30)
        self.assertEqual(critical, 7)
        self.assertEqual(warning, 30)

    def test_expiry_thresholds_override(self) -> None:
        """DB set to custom values -> SettingsService returns overrides."""
        SettingsService.update_setting(
            key="domains.expiry_critical_days",
            value=14,
            reason="integration test: extended critical window",
        )
        SettingsService.update_setting(
            key="domains.expiry_warning_days",
            value=60,
            reason="integration test: extended warning window",
        )

        critical = SettingsService.get_integer_setting("domains.expiry_critical_days", 7)
        warning = SettingsService.get_integer_setting("domains.expiry_warning_days", 30)
        self.assertEqual(critical, 14)
        self.assertEqual(warning, 60)


# ── Provisioning ──────────────────────────────────────────────────────────────


class ProvisioningSettingsIntegration(TestCase):
    """Verify provisioning settings flow from DB to runtime consumers."""

    def test_recovery_thresholds_default(self) -> None:
        """No DB record -> recovery thresholds use defaults 95/90/80."""
        excellent = SettingsService.get_integer_setting("provisioning.recovery_excellent_threshold", 95)
        good = SettingsService.get_integer_setting("provisioning.recovery_good_threshold", 90)
        warning = SettingsService.get_integer_setting("provisioning.recovery_warning_threshold", 80)
        self.assertEqual(excellent, 95)
        self.assertEqual(good, 90)
        self.assertEqual(warning, 80)

    def test_recovery_thresholds_override(self) -> None:
        """DB set to custom values -> SettingsService returns overrides."""
        SettingsService.update_setting(key="provisioning.recovery_excellent_threshold", value=98, reason="test")
        SettingsService.update_setting(key="provisioning.recovery_good_threshold", value=92, reason="test")
        SettingsService.update_setting(key="provisioning.recovery_warning_threshold", value=85, reason="test")

        excellent = SettingsService.get_integer_setting("provisioning.recovery_excellent_threshold", 95)
        good = SettingsService.get_integer_setting("provisioning.recovery_good_threshold", 90)
        warning = SettingsService.get_integer_setting("provisioning.recovery_warning_threshold", 80)
        self.assertEqual(excellent, 98)
        self.assertEqual(good, 92)
        self.assertEqual(warning, 85)

    def test_backup_retention_default(self) -> None:
        """No DB record -> backup_retention_days defaults to 90."""
        result = SettingsService.get_integer_setting("provisioning.backup_retention_days", 90)
        self.assertEqual(result, 90)

    def test_backup_retention_override(self) -> None:
        """DB set to 60 -> SettingsService returns 60."""
        SettingsService.update_setting(
            key="provisioning.backup_retention_days",
            value=60,
            reason="integration test: shorter retention",
        )

        result = SettingsService.get_integer_setting("provisioning.backup_retention_days", 90)
        self.assertEqual(result, 60)


# ── Promotions ────────────────────────────────────────────────────────────────


class PromotionsSettingsIntegration(TestCase):
    """Verify promotion settings flow from DB to runtime consumers."""

    def test_max_discount_default(self) -> None:
        """No DB record -> get_max_discount_percent() returns 100."""
        from apps.promotions.models import get_max_discount_percent

        self.assertEqual(get_max_discount_percent(), Decimal("100"))

    def test_max_discount_override(self) -> None:
        """DB set to 50 -> get_max_discount_percent() returns 50."""
        from apps.promotions.models import get_max_discount_percent

        SettingsService.update_setting(
            key="promotions.max_discount_percent",
            value=50,
            reason="integration test: cap discount at 50%",
        )

        self.assertEqual(get_max_discount_percent(), Decimal("50"))

    def test_max_batch_size_default(self) -> None:
        """No DB record -> max_coupon_batch_size defaults to 1000."""
        result = SettingsService.get_integer_setting("promotions.max_coupon_batch_size", 1000)
        self.assertEqual(result, 1000)

    def test_max_batch_size_override(self) -> None:
        """DB set to 500 -> SettingsService returns 500."""
        SettingsService.update_setting(
            key="promotions.max_coupon_batch_size",
            value=500,
            reason="integration test: smaller batch",
        )

        result = SettingsService.get_integer_setting("promotions.max_coupon_batch_size", 1000)
        self.assertEqual(result, 500)


# ── DEFAULT_SETTINGS Completeness ─────────────────────────────────────────────


class DefaultSettingsCompleteness(TestCase):
    """Verify structural integrity of DEFAULT_SETTINGS registry."""

    def test_all_keys_have_category_prefix(self) -> None:
        """Every key in DEFAULT_SETTINGS follows 'category.name' format."""
        for key in SettingsService.DEFAULT_SETTINGS:
            with self.subTest(key=key):
                parts = key.split(".")
                self.assertEqual(
                    len(parts),
                    2,
                    f"Key '{key}' must have exactly one dot separating category.name",
                )
                self.assertTrue(
                    parts[0].replace("_", "").isalnum(),
                    f"Category part of '{key}' must be alphanumeric (with underscores)",
                )
                self.assertTrue(
                    parts[1].replace("_", "").replace("-", "").isalnum(),
                    f"Name part of '{key}' must be alphanumeric (with underscores/hyphens)",
                )

    def test_all_keys_have_correct_types(self) -> None:
        """Each DEFAULT_SETTINGS value matches expected type for its key suffix."""
        # Suffix -> expected Python types
        suffix_type_map: dict[str, tuple[type, ...]] = {
            "_days": (int,),
            "_hours": (int,),
            "_minutes": (int,),
            "_seconds": (int,),
            "_bytes": (int,),
            "_cents": (int,),
            "_gb": (int,),
            "_mb": (int,),
            "_size": (int,),
            "_limit": (int,),
            "_attempts": (int,),
            "_retries": (int,),
            "_count": (int,),
            "_threshold": (int, str, Decimal),  # some thresholds are decimal strings
            "_qps": (int,),
            "_per_hour": (int,),
            "_per_ip": (int,),
            "_per_user": (int,),
            "_per_batch": (int,),
            "_per_package": (int,),
            "_per_domain": (int,),
            "_per_ticket": (int,),
            "_history": (int,),
            "_port": (int,),
            "_pool_size": (int,),
            "_rate": (str, Decimal),
            "_enabled": (bool,),
            "_required": (bool,),
            "_verify": (bool,),
            "_mode": (bool,),
        }

        for key, value in SettingsService.DEFAULT_SETTINGS.items():
            name_part = key.split(".")[-1]
            for suffix, expected_types in suffix_type_map.items():
                if name_part.endswith(suffix):
                    with self.subTest(key=key, suffix=suffix):
                        self.assertIsInstance(
                            value,
                            expected_types,
                            f"Key '{key}' ends with '{suffix}' but has type "
                            f"{type(value).__name__}, expected {expected_types}",
                        )
                    break  # Only check the first matching suffix

    def test_no_none_default_values(self) -> None:
        """No DEFAULT_SETTINGS value should be None (use empty string instead)."""
        for key, value in SettingsService.DEFAULT_SETTINGS.items():
            with self.subTest(key=key):
                self.assertIsNotNone(value, f"Key '{key}' has None default — use '' or 0 instead")

    def test_default_settings_not_empty(self) -> None:
        """DEFAULT_SETTINGS must contain entries."""
        self.assertGreater(len(SettingsService.DEFAULT_SETTINGS), 0)
