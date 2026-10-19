"""Every audit action the platform writes is a registered one (ADR-0016, owner decision O3).

Enforcement is this guard plus a runtime check in ``AuditService.log_event``; there is no
database constraint, because the list grows too often for a migration per action. The guard
reads the code's syntax tree (tests/audit/action_vocabulary_scan.py), so a new writer with an
unregistered action fails here, in the PR that adds it.
"""

from __future__ import annotations

import functools
import os
import re
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from django.test import SimpleTestCase, TestCase, override_settings

from apps.audit.classification import classify
from apps.audit.models import AuditEvent
from apps.audit.services import AuditService, UnregisteredAuditActionError
from apps.billing.payment_models import Payment
from apps.provisioning.virtualmin_migration_models import NodeDrain
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob
from tests.audit import action_vocabulary_scan
from tests.audit.action_vocabulary_scan import APPS_ROOT, Scan, registered_actions


@functools.cache
def scan() -> Scan:
    """The scan takes seconds; the tests in this module share one."""
    return action_vocabulary_scan.scan()


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


class WrapperTemplatesTests(SimpleTestCase):
    """A wrapper that writes one parameter under several templates writes every one of them."""

    def test_a_decorator_writing_success_and_failed_teaches_both(self) -> None:
        import ast  # noqa: PLC0415
        from pathlib import Path  # noqa: PLC0415

        from tests.audit.action_vocabulary_scan import _learn_wrappers  # noqa: PLC0415

        planted = (
            "def audit_call(event_type):\n"
            "    def decorator(func):\n"
            "        def wrapper():\n"
            "            try:\n"
            "                log_security_event(f'{event_type}_success', {})\n"
            "            except Exception:\n"
            "                log_security_event(f'{event_type}_failed', {})\n"
            "        return wrapper\n"
            "    return decorator\n"
        )
        path = Path("planted.py")
        writers = _learn_wrappers({path: ast.parse(planted)})

        spec = writers.spec(path, "audit_call")
        assert spec is not None
        self.assertEqual(set(spec["event_type"][1]), {"{}_success", "{}_failed"})

    def test_the_real_service_call_decorator_registers_its_success_actions(self) -> None:
        found = scan().literals
        self.assertIn("backup_domain_success", found)
        self.assertIn("backup_domain_failed", found)


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


EVENTS_DOCUMENT = APPS_ROOT / "audit" / "BUSINESS_AUDIT_EVENTS.md"
REGENERATE_HINT = "UPDATE_AUDIT_EVENTS_DOC=1 make test-file FILE=tests.audit.test_audit_action_vocabulary"

_CATEGORY_TITLES = {
    "authentication": "Authentication and sessions",
    "authorization": "Authorization and access",
    "account_management": "Account management",
    "privacy": "Privacy and consent",
    "data_protection": "Data protection (export, erasure, breach)",
    "security_event": "Security events",
    "integration": "Integrations and webhooks",
    "system_admin": "System administration and infrastructure",
    "compliance": "Compliance (VAT, e-Factura, legal documents)",
    "business_operation": "Business operations (billing, orders, services, support)",
}


def _writer_apps(sites: Iterable[str]) -> str:
    return ", ".join(sorted({site.split("/", 1)[0] for site in sites}))


def render_events_document(found: Scan) -> str:
    """The list of audit events, built from what the code writes (never from what someone remembered)."""
    sites: dict[str, set[str]] = defaultdict(set)
    for action, where in found.literals.items():
        sites[action] |= where
    for (file, _expression), values in declared_dynamic_actions().items():
        for action in values:
            sites[action].add(file)

    by_category: dict[str, list[str]] = defaultdict(list)
    for action in sorted(sites):
        by_category[classify(action).category].append(action)

    lines = [
        "# PRAHO audit events",
        "",
        f"<!-- Generated by tests/audit/test_audit_action_vocabulary.py. Do not edit. Regenerate: {REGENERATE_HINT} -->",
        "",
        "Every audit action the platform writes, with how it is classified. An action appears here only",
        "when some code writes it; the list is read from the code, so it cannot drift from it. The",
        "classification (category, severity, sensitivity, review) comes from `apps/audit/classification.py`.",
        "See ADR-0016 for what must be audited and ADR-0043 for what an event may hold.",
        "",
        f"{len(sites)} actions, in {len(by_category)} categories.",
    ]
    for category in sorted(by_category, key=lambda name: _CATEGORY_TITLES.get(name, name)):
        lines += [
            "",
            f"## {_CATEGORY_TITLES.get(category, category)}",
            "",
            "| Action | Severity | Review | Sensitive | Written by |",
            "|---|---|---|---|---|",
        ]
        for action in by_category[category]:
            result = classify(action)
            lines.append(
                f"| `{action}` | {result.severity} | {'yes' if result.requires_review else 'no'} | "
                f"{'yes' if result.is_sensitive else 'no'} | {_writer_apps(sites[action])} |"
            )
    return "\n".join(lines) + "\n"


class EventsDocumentTests(SimpleTestCase):
    def test_the_events_document_is_generated_from_the_code(self) -> None:
        rendered = render_events_document(scan())
        if os.environ.get("UPDATE_AUDIT_EVENTS_DOC"):
            EVENTS_DOCUMENT.write_text(rendered)
        self.assertEqual(
            Path(EVENTS_DOCUMENT).read_text(),
            rendered,
            f"apps/audit/BUSINESS_AUDIT_EVENTS.md is generated from the code. Regenerate it: {REGENERATE_HINT}",
        )

    def test_the_document_lists_no_action_without_a_writer(self) -> None:
        written = set(scan().literals)
        for values in declared_dynamic_actions().values():
            written |= values
        documented = set(re.findall(r"^\| `([a-z0-9_]+)` \|", Path(EVENTS_DOCUMENT).read_text(), re.M))
        self.assertEqual(sorted(documented - written), [])
