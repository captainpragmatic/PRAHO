"""
Tests for audit event tamper detection (#217, keyed v2 tier of #313).

v1 history: `_verify_hash_chain` read metadata["integrity_hash"] and skipped the comparison
when it was absent — and nothing ever wrote it, so every integrity check reported compliant
regardless of how rows had been altered (#217).

v2: events are stamped with an HMAC-SHA256 over the evidence payload (old/new values and
metadata included; user_id/ip_address deliberately excluded so GDPR anonymization does not
raise false criticals), keyed via the audit-integrity derivation domains with key-id
rotation. Post-cutover, a missing or downgraded marker is COMPROMISED, not legacy.
"""

from __future__ import annotations

import os
from datetime import timedelta
from unittest.mock import patch

from django.contrib.contenttypes.models import ContentType
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.audit.models import AuditEvent, AuditIntegrityCheck, audit_mutation_allowed
from apps.audit.services import AuditIntegrityService
from apps.common.key_derivation import derive_key
from apps.users.models import User


class AuditEventIntegrityHashTestCase(TestCase):
    """#217: a created audit event carries a keyed MAC, and a mutated one is detected."""

    def setUp(self) -> None:
        self.user = User.objects.create_user(email="auditor@example.com", password="testpass123")
        self.content_type = ContentType.objects.get_for_model(User)

    def _event(self, description: str = "Original description", **overrides: object) -> AuditEvent:
        fields: dict[str, object] = {
            "user": self.user,
            "action": "login_success",
            "category": "authentication",
            "severity": "low",
            "content_type": self.content_type,
            "object_id": str(self.user.id),
            "description": description,
            "ip_address": "192.168.1.1",
        }
        fields.update(overrides)
        return AuditEvent.objects.create(**fields)

    def test_created_event_is_stamped_with_an_integrity_hash(self) -> None:
        """Nothing wrote integrity_hash before #217 — it appeared at exactly one line, the read."""
        event = self._event()

        event.refresh_from_db()
        self.assertIn("integrity_hash", event.metadata)
        self.assertEqual(event.metadata["integrity_hash_version"], AuditIntegrityService.HASH_VERSION)
        self.assertIn("integrity_key_id", event.metadata)
        # Recomputing the marker on the stamped row must match: the payload strips the
        # reserved marker keys, so the stamp is stable under its own presence.
        recomputed = AuditIntegrityService.integrity_stamp_marker(event)
        self.assertEqual(event.metadata["integrity_hash"], recomputed["integrity_hash"])

    def test_untampered_event_verifies_clean(self) -> None:
        event = self._event()
        event.refresh_from_db()

        issues = AuditIntegrityService._verify_hash_chain([event])

        self.assertEqual(issues, [])

    def test_tampered_event_is_detected(self) -> None:
        """The whole point of #217: rewriting an audit row must be caught."""
        event = self._event()
        event.refresh_from_db()

        # Rewrite history the way an attacker would: straight to the column, no signal.
        with audit_mutation_allowed("test fixture"):
            AuditEvent.objects.filter(pk=event.pk).update(description="TAMPERED — this never happened")
        event.refresh_from_db()

        issues = AuditIntegrityService._verify_hash_chain([event])

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["type"], "hash_mismatch")
        self.assertEqual(issues[0]["severity"], "critical")

    def test_nested_metadata_tamper_is_detected(self) -> None:
        """v2 covers metadata: rewriting evidence inside the blob must change the MAC."""
        event = self._event()
        event.refresh_from_db()
        with audit_mutation_allowed("test fixture"):
            AuditEvent.objects.filter(pk=event.pk).update(
                metadata={**event.metadata, "amount_cents": 1}  # attacker shrinks the evidence
            )
        event.refresh_from_db()
        # Restore the marker keys the update just clobbered? No — the update above kept
        # them (spread), so only the covered payload changed.
        issues = AuditIntegrityService._verify_hash_chain([event])

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["type"], "hash_mismatch")

    def test_old_new_values_tamper_is_detected(self) -> None:
        """v2 covers old_values/new_values — v1 did not, which left the evidence unprotected."""
        event = self._event()
        event.refresh_from_db()
        with audit_mutation_allowed("test fixture"):
            AuditEvent.objects.filter(pk=event.pk).update(new_values={"value": "laundered"})
        event.refresh_from_db()

        issues = AuditIntegrityService._verify_hash_chain([event])

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["type"], "hash_mismatch")

    def test_gdpr_anonymization_causes_no_false_positive(self) -> None:
        """The M1 kill-shot: v1 covered user_id and ip_address, so GDPR anonymization made
        every anonymized row a false CRITICAL. v2 excludes both fields."""
        event = self._event()
        event.refresh_from_db()

        with audit_mutation_allowed("gdpr_anonymization"):
            AuditEvent.objects.filter(pk=event.pk).update(ip_address="0.0.0.0", user_agent="Anonymized", user=None)
        event.refresh_from_db()

        issues = AuditIntegrityService._verify_hash_chain([event])

        self.assertEqual(issues, [])

    def test_hashed_era_event_with_a_stripped_hash_is_critical(self) -> None:
        """Deleting the hash must not buy an attacker a clean report.

        The version marker survives independently, so a row written after hashing began is
        still known to need one.
        """
        event = self._event()
        event.refresh_from_db()
        metadata = dict(event.metadata)
        del metadata["integrity_hash"]
        with audit_mutation_allowed("test fixture"):
            AuditEvent.objects.filter(pk=event.pk).update(metadata=metadata)
        event.refresh_from_db()

        issues = AuditIntegrityService._verify_hash_chain([event])

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["type"], "missing_integrity_hash")
        self.assertEqual(issues[0]["severity"], "critical")

    def test_stripped_marker_is_a_downgrade_attack_post_cutover(self) -> None:
        """Post-cutover (AUDIT_INTEGRITY_REQUIRE_V2, the default), a row with no marker at
        all is COMPROMISED — an attacker stripping both keys must not demote the row to an
        info-level legacy finding."""
        event = self._event()
        with audit_mutation_allowed("test fixture"):
            AuditEvent.objects.filter(pk=event.pk).update(metadata={})
        event.refresh_from_db()

        issues = AuditIntegrityService._verify_hash_chain([event])

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["type"], "integrity_marker_downgrade")
        self.assertEqual(issues[0]["severity"], "critical")

    @override_settings(AUDIT_INTEGRITY_REQUIRE_V2=False)
    def test_legacy_event_is_unverifiable_only_during_migration_window(self) -> None:
        """During the restamp window (setting disabled), unmarked rows report info-level —
        thousands of critical legacy findings would bury a real mismatch."""
        event = self._event()
        with audit_mutation_allowed("test fixture"):
            AuditEvent.objects.filter(pk=event.pk).update(metadata={})
        event.refresh_from_db()

        issues = AuditIntegrityService._verify_hash_chain([event])

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["type"], "unverifiable_legacy_event")
        self.assertEqual(issues[0]["severity"], "info")

    @override_settings(AUDIT_INTEGRITY_REQUIRE_V2=False)
    def test_v1_row_verifies_under_legacy_algorithm_during_migration_window(self) -> None:
        event = self._event()
        event.refresh_from_db()
        v1_metadata = {
            "integrity_hash": AuditIntegrityService._calculate_event_hash(event),
            "integrity_hash_version": 1,
        }
        with audit_mutation_allowed("test fixture"):
            AuditEvent.objects.filter(pk=event.pk).update(metadata=v1_metadata)
        event.refresh_from_db()

        self.assertEqual(AuditIntegrityService._verify_hash_chain([event]), [])

    def test_v1_row_is_compromised_post_cutover(self) -> None:
        event = self._event()
        event.refresh_from_db()
        v1_metadata = {
            "integrity_hash": AuditIntegrityService._calculate_event_hash(event),
            "integrity_hash_version": 1,
        }
        with audit_mutation_allowed("test fixture"):
            AuditEvent.objects.filter(pk=event.pk).update(metadata=v1_metadata)
        event.refresh_from_db()

        issues = AuditIntegrityService._verify_hash_chain([event])

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["type"], "integrity_marker_downgrade")

    def test_hash_survives_a_legitimate_metadata_read(self) -> None:
        """Non-regression: the MAC payload strips its own marker keys, so recomputation on
        the stamped row is stable."""
        event = self._event()
        event.refresh_from_db()
        original_hash = event.metadata["integrity_hash"]

        self.assertEqual(AuditIntegrityService.integrity_stamp_marker(event)["integrity_hash"], original_hash)

    def test_stamping_failure_still_marks_the_event_for_critical_follow_up(self) -> None:
        """#304 review: a stamping failure must not leave the row byte-identical to a legacy
        row — that demotes it to an info-level "unverifiable" finding, the exact
        low-visibility outcome #217 eliminates. The fallback lands the version marker alone,
        so verification reports missing_integrity_hash (critical)."""
        with patch.object(AuditIntegrityService, "integrity_stamp_marker", side_effect=RuntimeError("hash boom")):
            event = self._event(description="Stamping failed for this row")

        event.refresh_from_db()
        self.assertNotIn("integrity_hash", event.metadata)
        self.assertEqual(event.metadata["integrity_hash_version"], AuditIntegrityService.HASH_VERSION)

        issues = AuditIntegrityService._verify_hash_chain([event])
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["type"], "missing_integrity_hash")
        self.assertEqual(issues[0]["severity"], "critical")

    def test_one_malformed_row_does_not_abort_the_sweep(self) -> None:
        """#304 review: a per-event computation failure used to propagate and abort the whole
        verification run — every other event in the window silently went unverified. The bad
        row now yields its own critical finding and the sweep continues, still catching the
        tampered row after it."""
        broken = self._event(description="This row will fail verification computation")
        tampered = self._event(description="This row gets tampered")
        with audit_mutation_allowed("test fixture"):
            AuditEvent.objects.filter(pk=tampered.pk).update(description="Rewritten by an attacker")
        broken.refresh_from_db()
        tampered.refresh_from_db()

        real_mac = AuditIntegrityService._compute_event_mac.__func__

        def mac(event: AuditEvent, key: bytes) -> str:
            if event.pk == broken.pk:
                raise RuntimeError("verification boom")
            return real_mac(AuditIntegrityService, event, key)

        with patch.object(AuditIntegrityService, "_compute_event_mac", side_effect=mac):
            issues = AuditIntegrityService._verify_hash_chain([broken, tampered])

        kinds = {issue["type"] for issue in issues}
        self.assertIn("verification_error", kinds)
        self.assertIn("hash_mismatch", kinds)


class IntegrityKeyLifecycleTestCase(TestCase):
    """Key provisioning and rotation semantics (W11)."""

    def setUp(self) -> None:
        self.user = User.objects.create_user(email="keys@example.com", password="testpass123")
        self.content_type = ContentType.objects.get_for_model(User)
        # derive_key caches per-domain; every env change here must clear it, and the
        # cache must not leak test keys into other tests.
        derive_key.cache_clear()
        self.addCleanup(derive_key.cache_clear)

    def _event(self) -> AuditEvent:
        return AuditEvent.objects.create(
            user=self.user,
            action="login_success",
            category="authentication",
            severity="low",
            content_type=self.content_type,
            object_id=str(self.user.id),
            description="key lifecycle",
        )

    def test_unprovisioned_slots_collapse_to_one_key(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AUDIT_INTEGRITY_SECRET", None)
            os.environ.pop("AUDIT_INTEGRITY_SECRET_PREVIOUS", None)
            derive_key.cache_clear()
            keys = AuditIntegrityService._integrity_keys()
        self.assertEqual(len(keys), 1)

    def test_stamp_verifies_via_previous_key_after_rotation(self) -> None:
        """A row stamped under the old secret must verify after the secret rotates into the
        _PREVIOUS slot — rotation must not invalidate stamped history."""
        old_secret = "old-secret-material-0123456789abcdef"  # test key material
        new_secret = "new-secret-material-0123456789abcdef"  # test key material

        with patch.dict(os.environ, {"AUDIT_INTEGRITY_SECRET": old_secret}):
            os.environ.pop("AUDIT_INTEGRITY_SECRET_PREVIOUS", None)
            derive_key.cache_clear()
            event = self._event()
            event.refresh_from_db()
            self.assertEqual(AuditIntegrityService._verify_hash_chain([event]), [])

        with patch.dict(
            os.environ,
            {"AUDIT_INTEGRITY_SECRET": new_secret, "AUDIT_INTEGRITY_SECRET_PREVIOUS": old_secret},
        ):
            derive_key.cache_clear()
            event.refresh_from_db()
            self.assertEqual(AuditIntegrityService._verify_hash_chain([event]), [])

    def test_stamp_fails_verification_once_key_is_fully_retired(self) -> None:
        old_secret = "old-secret-material-0123456789abcdef"  # test key material
        new_secret = "new-secret-material-0123456789abcdef"  # test key material

        with patch.dict(os.environ, {"AUDIT_INTEGRITY_SECRET": old_secret}):
            os.environ.pop("AUDIT_INTEGRITY_SECRET_PREVIOUS", None)
            derive_key.cache_clear()
            event = self._event()
            event.refresh_from_db()

        with patch.dict(os.environ, {"AUDIT_INTEGRITY_SECRET": new_secret}):
            os.environ.pop("AUDIT_INTEGRITY_SECRET_PREVIOUS", None)
            derive_key.cache_clear()
            issues = AuditIntegrityService._verify_hash_chain([event])

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["type"], "hash_mismatch")
        self.assertIn("unrecognized key id", issues[0]["description"])


class VerifyAuditIntegrityHonestyTestCase(TestCase):
    """W3: the check never lies about its own health."""

    def setUp(self) -> None:
        self.user = User.objects.create_user(email="honesty@example.com", password="testpass123")
        self.content_type = ContentType.objects.get_for_model(User)

    def test_empty_window_is_a_warning_not_healthy(self) -> None:
        """Zero events means nothing was verified — "healthy" would be evidence-free."""
        window_start = timezone.now() + timedelta(days=300)
        window_end = window_start + timedelta(hours=1)

        result = AuditIntegrityService.verify_audit_integrity(window_start, window_end)

        check = result.unwrap()
        self.assertEqual(check.status, "warning")
        self.assertEqual(check.records_checked, 0)
        self.assertEqual(check.findings[0]["type"], "empty_verification_window")

    def test_crash_persists_an_error_status_row(self) -> None:
        """A verification crash must land a status="error" row (outside the failed
        transaction) so dashboards count failures instead of defaulting to healthy."""
        start = timezone.now() - timedelta(hours=1)
        end = timezone.now() + timedelta(hours=1)

        with patch.object(AuditIntegrityService, "_verify_hash_chain", side_effect=RuntimeError("checker crashed")):
            result = AuditIntegrityService.verify_audit_integrity(start, end)

        check = result.unwrap()
        self.assertEqual(check.status, "error")
        self.assertEqual(check.findings[0]["type"], "verification_error")
        # And it is really persisted, not just returned
        self.assertTrue(AuditIntegrityCheck.objects.filter(pk=check.pk, status="error").exists())
