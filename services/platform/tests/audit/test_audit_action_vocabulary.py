"""Every audit action the platform writes is a registered one (ADR-0016, owner decision O3).

Enforcement is this guard plus a runtime check in ``AuditService.log_event``; there is no
database constraint, because the list grows too often for a migration per action. The guard
reads the code's syntax tree (tests/audit/action_vocabulary_scan.py), so a new writer with an
unregistered action fails here, in the PR that adds it.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from django.test import SimpleTestCase, TestCase, override_settings

from apps.audit.models import AuditEvent
from apps.audit.services import AuditService, UnregisteredAuditActionError
from apps.billing.payment_models import Payment
from apps.provisioning.virtualmin_migration_models import NodeDrain
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob
from tests.audit.action_vocabulary_scan import registered_actions, scan


def _choice_values(choices: Iterable[tuple[Any, Any]]) -> set[str]:
    return {str(value) for value, _label in choices}


def declared_dynamic_actions() -> dict[tuple[str, str], set[str]]:
    """Writer sites whose action is built at runtime, with every value they can produce.

    Built from the models' own status lists, so a status added later fails the guard until its
    action is registered. A new runtime-built writer must be listed here (or use a literal).
    """
    return {
        ("billing/signals.py", "event_type"): {
            "invoice_provider_issue_attempted",
            "invoice_provider_issued",
            "invoice_provider_issue_failed",
            "invoice_provider_outcome_unknown",
        },
        ("billing/signals.py", "'payment_initiated' if created else f'payment_{instance.status}'"): {
            "payment_initiated",
            *(f"payment_{status}" for status in _choice_values(Payment.STATUS_CHOICES)),
        },
        ("notifications/signals.py", "f'email_{status}'"): {"email_bounced", "email_complained", "email_failed"},
        ("provisioning/virtualmin_drain_service.py", "f'node_drain_{action}'"): {
            "node_drain_paused" if status == "paused_needs_review" else f"node_drain_{status}"
            for status in _choice_values(NodeDrain.Status.choices)
        },
        ("provisioning/virtualmin_signals.py", "f'virtualmin_provisioning_job_{job.status}'"): {
            f"virtualmin_provisioning_job_{status}"
            for status in _choice_values(VirtualminProvisioningJob.STATUS_CHOICES)
        },
        ("provisioning/virtualmin_signals.py", "event_action"): {
            f"virtualmin_provisioning_job_{status}"
            for status in _choice_values(VirtualminProvisioningJob.STATUS_CHOICES)
        },
        # Picks a random registered choice to fabricate sample rows; it writes nothing a person did.
        (
            "audit/management/commands/generate_audit_events.py",
            "random.choice([choice[0] for choice in AuditEvent.ACTION_CHOICES])",
        ): set(),
    }


class ActionVocabularyGuardTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.scan = scan()
        cls.registered = registered_actions()

    def test_every_action_the_code_writes_is_registered(self) -> None:
        written = set(self.scan.literals)
        for values in declared_dynamic_actions().values():
            written |= values
        missing = sorted(written - self.registered)
        self.assertEqual(
            missing,
            [],
            "These audit actions are written but not listed in AuditEvent.ACTION_CHOICES "
            "(add them there and in a migration):\n  " + "\n  ".join(missing),
        )

    def test_a_writer_whose_action_is_built_at_runtime_is_declared(self) -> None:
        declared = set(declared_dynamic_actions())
        found = {(file, expression) for file, _callee, expression in self.scan.unresolved}
        self.assertEqual(
            sorted(found - declared),
            [],
            "A new audit writer builds its action at runtime. Use a literal, or declare every value "
            "it can produce in declared_dynamic_actions().",
        )
        self.assertEqual(sorted(declared - found), [], "A declared dynamic writer no longer exists; remove it.")

    def test_registered_actions_fit_the_column_and_are_unique(self) -> None:
        names = [value for value, _label in AuditEvent.ACTION_CHOICES]
        self.assertEqual(len(names), len(set(names)), "ACTION_CHOICES lists an action twice")
        max_length = AuditEvent._meta.get_field("action").max_length
        for name in names:
            with self.subTest(action=name):
                self.assertLessEqual(len(name), max_length)
                self.assertRegex(name, re.compile(r"^[a-z0-9_]+$"))

    def test_the_guard_reads_the_code(self) -> None:
        """A scan that found nothing would pass everything: pin a few writers it must see."""
        for action in ("login_success", "customer_created", "invoice_provider_issued", "d390_export"):
            with self.subTest(action=action):
                known = set(self.scan.literals) | {a for v in declared_dynamic_actions().values() for a in v}
                self.assertIn(action, known)


class UnregisteredActionRuntimeTests(TestCase):
    def test_an_unregistered_action_is_refused_under_test(self) -> None:
        with self.assertRaises(UnregisteredAuditActionError):
            AuditService.log_simple_event("an_action_nobody_registered", description="x")
        self.assertFalse(AuditEvent.objects.filter(action="an_action_nobody_registered").exists())

    @override_settings(TESTING=False)
    def test_in_production_it_is_written_and_shouted_about(self) -> None:
        with self.assertLogs("apps.audit.services", level="ERROR") as logs:
            AuditService.log_simple_event("an_action_nobody_registered", description="x")
        self.assertIn("an_action_nobody_registered", "\n".join(logs.output))
        self.assertTrue(AuditEvent.objects.filter(action="an_action_nobody_registered").exists())
