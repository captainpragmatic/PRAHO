"""
Tests for the retention infrastructure added by ADR-0043: seeded policies,
enforced is_mandatory semantics, the single scheduling vehicle, and durable
file-integrity baselines.
"""

from __future__ import annotations

from io import StringIO
from unittest.mock import patch

from django.core.management import CommandError, call_command
from django.db import IntegrityError, transaction
from django.test import TestCase

from apps.audit.models import (
    AuditImmutabilityError,
    AuditRetentionPolicy,
    FileIntegrityBaseline,
    audit_mutation_allowed,
)
from apps.audit.tasks import rebaseline_file_integrity, run_file_integrity_check, setup_audit_scheduled_tasks


class RetentionPolicySeedingTestCase(TestCase):
    def test_seed_creates_policies_for_every_category(self) -> None:
        out = StringIO()
        call_command("setup_audit_retention_policies", stdout=out)

        categories = set(AuditRetentionPolicy.objects.filter(is_active=True).values_list("category", flat=True))
        self.assertIn("business_operation", categories)
        self.assertIn("privacy", categories)
        self.assertIn("data_protection", categories)
        self.assertIn("authentication", categories)

        business = AuditRetentionPolicy.objects.get(category="business_operation", is_active=True)
        self.assertTrue(business.is_mandatory)
        self.assertEqual(business.action, "delete")
        self.assertGreaterEqual(business.retention_days, 3653)

        privacy = AuditRetentionPolicy.objects.get(category="privacy", is_active=True)
        self.assertTrue(privacy.is_mandatory)
        self.assertEqual(privacy.action, "anonymize")

    def test_seed_is_idempotent(self) -> None:
        call_command("setup_audit_retention_policies", stdout=StringIO())
        count = AuditRetentionPolicy.objects.count()
        out = StringIO()
        call_command("setup_audit_retention_policies", stdout=out)
        self.assertEqual(AuditRetentionPolicy.objects.count(), count)
        self.assertIn("0 created", out.getvalue())

    def test_seed_refuses_conflicting_active_policy_without_repair(self) -> None:
        AuditRetentionPolicy.objects.create(
            name="custom auth policy", category="authentication", severity="", retention_days=99, action="delete"
        )
        with self.assertRaises(CommandError):
            call_command("setup_audit_retention_policies", stdout=StringIO())

    def test_seed_repair_deactivates_non_mandatory_conflict(self) -> None:
        conflict = AuditRetentionPolicy.objects.create(
            name="custom auth policy", category="authentication", severity="", retention_days=99, action="delete"
        )
        call_command("setup_audit_retention_policies", "--repair", stdout=StringIO())
        conflict.refresh_from_db()
        self.assertFalse(conflict.is_active)
        self.assertTrue(AuditRetentionPolicy.objects.filter(category="authentication", is_active=True).exists())

    def test_seed_never_auto_repairs_mandatory_conflict(self) -> None:
        AuditRetentionPolicy.objects.create(
            name="legal auth hold",
            category="authentication",
            severity="",
            retention_days=3000,
            action="delete",
            is_mandatory=True,
        )
        with self.assertRaises(CommandError):
            call_command("setup_audit_retention_policies", "--repair", stdout=StringIO())


class MandatoryPolicyEnforcementTestCase(TestCase):
    def setUp(self) -> None:
        self.policy = AuditRetentionPolicy.objects.create(
            name="mandatory policy",
            category="privacy",
            severity="",
            retention_days=1827,
            action="anonymize",
            is_mandatory=True,
        )

    def test_deactivating_mandatory_policy_raises(self) -> None:
        self.policy.is_active = False
        with self.assertRaises(AuditImmutabilityError):
            self.policy.save()

    def test_demoting_mandatory_policy_raises(self) -> None:
        self.policy.is_mandatory = False
        with self.assertRaises(AuditImmutabilityError):
            self.policy.save()

    def test_deleting_mandatory_policy_raises(self) -> None:
        with self.assertRaises(AuditImmutabilityError):
            self.policy.delete()

    def test_escape_hatch_allows_seeder_reconciliation(self) -> None:
        with audit_mutation_allowed("retention_policy_seed"):
            self.policy.retention_days = 2000
            self.policy.save()
        self.policy.refresh_from_db()
        self.assertEqual(self.policy.retention_days, 2000)

    def test_db_refuses_mandatory_inactive_row(self) -> None:
        with self.assertRaises(IntegrityError), transaction.atomic():
            AuditRetentionPolicy.objects.create(
                name="broken",
                category="compliance",
                severity="",
                retention_days=100,
                action="delete",
                is_mandatory=True,
                is_active=False,
            )

    def test_db_refuses_second_active_policy_per_scope(self) -> None:
        with self.assertRaises(IntegrityError), transaction.atomic():
            AuditRetentionPolicy.objects.create(
                name="duplicate scope", category="privacy", severity="", retention_days=10, action="anonymize"
            )


class AuditSchedulerTestCase(TestCase):
    def test_creates_all_four_schedules_and_is_idempotent(self) -> None:
        from django_q.models import Schedule  # noqa: PLC0415  # Deferred: optional dependency

        first = setup_audit_scheduled_tasks()
        self.assertEqual(
            set(first),
            {
                "audit-integrity-daily",
                "audit-retention-weekly",
                "audit-integrity-cleanup-weekly",
                "audit-file-integrity-daily",
            },
        )
        self.assertTrue(all(outcome == "created" for outcome in first.values()))

        second = setup_audit_scheduled_tasks()
        self.assertTrue(all(outcome == "already_exists" for outcome in second.values()))
        self.assertEqual(Schedule.objects.filter(name__startswith="audit-").count(), 4)

    def test_retires_pre_consolidation_schedule_names(self) -> None:
        from django_q.models import Schedule  # noqa: PLC0415  # Deferred: optional dependency

        Schedule.objects.create(
            name="audit_integrity_hourly",
            func="apps.audit.tasks.run_integrity_check",
            schedule_type=Schedule.HOURLY,
        )
        setup_audit_scheduled_tasks()
        self.assertFalse(Schedule.objects.filter(name="audit_integrity_hourly").exists())


class FileIntegrityBaselineTestCase(TestCase):
    def test_no_baselines_is_an_error_not_healthy(self) -> None:
        """Zero baselines means nothing was verified - the pre-W10 code treated every
        file as 'new' and reported healthy on a completely unbaselined system."""
        results = run_file_integrity_check()
        self.assertEqual(results["status"], "error")
        self.assertIn("rebaseline", results["error"])

    def test_rebaseline_then_check_is_healthy(self) -> None:
        rebaseline = rebaseline_file_integrity()
        self.assertGreater(rebaseline["baselined"], 0)

        results = run_file_integrity_check()
        self.assertEqual(results["status"], "healthy")
        self.assertEqual(results["changes_detected"], [])

    def test_changed_file_is_compromised_and_baseline_untouched(self) -> None:
        rebaseline_file_integrity()
        baseline = FileIntegrityBaseline.objects.first()
        original_hash = "0" * 64
        FileIntegrityBaseline.objects.filter(pk=baseline.pk).update(sha256=original_hash)

        results = run_file_integrity_check()

        self.assertEqual(results["status"], "compromised")
        self.assertEqual(len(results["changes_detected"]), 1)
        self.assertEqual(results["changes_detected"][0]["path"], baseline.path)
        # Baselines NEVER mutate during a check - a second run still alarms
        baseline.refresh_from_db()
        self.assertEqual(baseline.sha256, original_hash)
        second = run_file_integrity_check()
        self.assertEqual(second["status"], "compromised")

    def test_missing_file_is_a_warning(self) -> None:
        rebaseline_file_integrity()
        FileIntegrityBaseline.objects.create(path="apps/ghost/removed_module.py", sha256="a" * 64)

        results = run_file_integrity_check()

        self.assertEqual(results["status"], "warning")
        self.assertEqual(results["missing_files"][0]["path"], "apps/ghost/removed_module.py")

    def test_survives_cache_clear(self) -> None:
        """The whole point of durable baselines: a cache flush must not re-baseline."""
        from django.core.cache import cache  # noqa: PLC0415  # Deferred: test-local

        rebaseline_file_integrity()
        FileIntegrityBaseline.objects.filter(pk=FileIntegrityBaseline.objects.first().pk).update(sha256="0" * 64)
        cache.clear()

        results = run_file_integrity_check()
        self.assertEqual(results["status"], "compromised")

    @patch("apps.audit.tasks._calculate_file_hash", side_effect=OSError("permission denied"))
    def test_hashing_failure_is_an_error(self, _mock_hash) -> None:
        FileIntegrityBaseline.objects.create(path="config/urls.py", sha256="b" * 64)
        results = run_file_integrity_check()
        self.assertEqual(results["status"], "error")
        self.assertGreater(len(results["hash_errors"]), 0)

    def test_rebaseline_aborts_on_hashing_failure_and_preserves_baselines(self) -> None:
        """A partial rebaseline would permanently lose the trusted hash for the
        failed file - on any hashing error the existing set must stay untouched."""
        rebaseline_file_integrity()
        before = dict(FileIntegrityBaseline.objects.values_list("path", "sha256"))
        self.assertGreater(len(before), 0)

        with patch("apps.audit.tasks._calculate_file_hash", side_effect=OSError("disk error")):
            result = rebaseline_file_integrity()

        self.assertEqual(result["baselined"], 0)
        self.assertGreater(len(result["errors"]), 0)
        self.assertIsNone(result["rebaselined_at"])
        after = dict(FileIntegrityBaseline.objects.values_list("path", "sha256"))
        self.assertEqual(after, before)


class IntegrityTaskStatusRollupTestCase(TestCase):
    """The scheduled task must never report healthy when verification could not run."""

    def test_err_from_verifier_degrades_aggregate_status(self) -> None:
        from apps.audit.tasks import run_integrity_check  # noqa: PLC0415  # Deferred: test-local
        from apps.common.types import Err  # noqa: PLC0415  # Deferred: test-local

        with patch(
            "apps.audit.tasks.AuditIntegrityService.verify_audit_integrity",
            return_value=Err("db unavailable"),
        ):
            results = run_integrity_check(check_type="hash_verification")

        self.assertEqual(results["status"], "error")
        self.assertEqual(results["checks"][0]["status"], "error")

    def test_exception_from_verifier_degrades_aggregate_status(self) -> None:
        from apps.audit.tasks import run_integrity_check  # noqa: PLC0415  # Deferred: test-local

        with patch(
            "apps.audit.tasks.AuditIntegrityService.verify_audit_integrity",
            side_effect=RuntimeError("verifier exploded"),
        ):
            results = run_integrity_check(check_type="hash_verification")

        self.assertEqual(results["status"], "error")


class DedupLedgerRetentionLockInTestCase(TestCase):
    """m7: customers/tasks.py uses customer_feedback_processed events with
    metadata__note_id as an idempotency ledger. Retention must never anonymize
    them (the allowlist scrub would strip note_id and break dedup) - the category
    they resolve to must map to the long-horizon delete policy."""

    def test_ledger_events_map_to_a_delete_policy_with_long_horizon(self) -> None:
        from apps.audit.services import AuditService  # noqa: PLC0415  # Deferred: test-local

        event = AuditService.log_simple_event(
            event_type="customer_feedback_processed",
            user=None,
            content_object=None,
            description="ledger lock-in",
            actor_type="system",
            metadata={"note_id": "abc"},
        )
        call_command("setup_audit_retention_policies", stdout=StringIO())
        policy = AuditRetentionPolicy.objects.get(category=event.category, severity="", is_active=True)
        # The kill condition is ANONYMIZE: the metadata allowlist scrub strips note_id
        # and every processed note becomes reprocessable overnight. Deletion after the
        # policy horizon is acceptable - a years-old note re-analysis is a no-op.
        self.assertEqual(policy.action, "delete")
        self.assertGreaterEqual(policy.retention_days, 1096)
