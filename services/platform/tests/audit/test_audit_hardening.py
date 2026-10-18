"""Audit hardening (rows 44, 47, 49, 57, 58): nothing fails silently, nothing is invented."""

from __future__ import annotations

import ast
import logging
from pathlib import Path
from unittest.mock import patch

from django.db import transaction
from django.test import SimpleTestCase, TestCase, override_settings

from apps.audit import signals as audit_signals
from apps.audit.checks import check_audit_write_failures
from apps.audit.models import USER_AGENT_MAX_LENGTH, AuditEvent
from apps.audit.services import AuditContext, AuditEventData, AuditService
from apps.audit.switches import audit_signals_disabled
from apps.common import audit_failures, counters
from apps.common.transactions import best_effort_atomic, swallow_application_errors
from apps.common.validators import log_security_event
from apps.users.models import User

PLATFORM_APPS = Path(__file__).resolve().parents[2] / "apps"
logger = logging.getLogger(__name__)


class FallbackLogTests(TestCase):
    def test_the_validators_fallback_logs_the_keys_and_never_the_values(self) -> None:
        with (
            patch("apps.audit.services.AuditService.log_simple_event", side_effect=RuntimeError("audit store down")),
            self.assertLogs("apps.common.validators", level="WARNING") as logs,
        ):
            log_security_event(
                "suspicious_activity",
                {"customer_email": "ioana@example.test", "amount_cents": 1999},
                request_ip="203.0.113.5",
            )

        text = "\n".join(logs.output)
        self.assertIn("suspicious_activity", text)
        self.assertIn("customer_email", text)
        self.assertIn("amount_cents", text)
        self.assertNotIn("ioana@example.test", text)
        self.assertNotIn("1999", text)


class WriteFailureCounterTests(TestCase):
    def setUp(self) -> None:
        counters.reset(audit_failures.AUDIT_WRITE_FAILURES_KEY)

    def fail_the_insert(self):
        return patch("apps.audit.services.AuditEvent.objects.create", side_effect=ValueError("insert refused"))

    def test_a_swallowed_audit_write_is_counted(self) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            with (
                self.fail_the_insert(),
                self.assertLogs("apps.audit.services", level="ERROR"),
                best_effort_atomic(logger=logger, scope="test", message="audit write failed"),
            ):
                AuditService.log_simple_event("view")
            self.assertEqual(audit_failures.count(), 0, "counted after commit, never inside the caller's transaction")

        self.assertEqual(audit_failures.count(), 1)

    def test_swallow_application_errors_counts_it_too(self) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            with (
                self.fail_the_insert(),
                self.assertLogs(level="ERROR"),
                swallow_application_errors(logger=logger, scope="test", message="audit write failed"),
            ):
                AuditService.log_simple_event("view")
            self.assertEqual(audit_failures.count(), 0, "counted after commit, never inside the caller's transaction")

        self.assertEqual(audit_failures.count(), 1)

    def test_a_swallowed_failure_in_a_rolled_back_action_is_not_counted(self) -> None:
        # The action whose audit write failed then rolls back itself.
        with self.captureOnCommitCallbacks(execute=True), self.assertRaises(RuntimeError), transaction.atomic():
            with (
                self.fail_the_insert(),
                self.assertLogs("apps.audit.services", level="ERROR"),
                best_effort_atomic(logger=logger, scope="test", message="audit write failed"),
            ):
                AuditService.log_simple_event("view")
            raise RuntimeError("the action fails after its audit write")

        self.assertEqual(audit_failures.count(), 0)

    def test_a_failed_security_event_is_counted(self) -> None:
        """log_security_event swallows a failed audit write on purpose; the counter still hears of it."""
        with self.captureOnCommitCallbacks(execute=True), self.fail_the_insert(), self.assertLogs(level="WARNING"):
            log_security_event("sessions_revoked_password_reset", {"reason": "x"})

        self.assertEqual(audit_failures.count(), 1)

    def test_a_failure_that_reaches_the_caller_is_not_counted(self) -> None:
        with (
            self.fail_the_insert(),
            self.assertLogs("apps.audit.services", level="ERROR"),
            self.assertRaises(ValueError),
        ):
            AuditService.log_simple_event("view")

        self.assertEqual(audit_failures.count(), 0)

    def test_an_unrelated_swallowed_failure_is_not_counted(self) -> None:
        with (
            self.assertLogs(level="ERROR"),
            best_effort_atomic(logger=logger, scope="test", message="something else failed"),
        ):
            raise ValueError("not an audit write")

        self.assertEqual(audit_failures.count(), 0)

    def test_the_health_check_warns_once_a_write_has_failed(self) -> None:
        self.assertEqual(check_audit_write_failures(None, databases=["default"]), [])
        with (
            self.captureOnCommitCallbacks(execute=True),
            self.fail_the_insert(),
            self.assertLogs(level="ERROR"),
            best_effort_atomic(logger=logger, scope="test", message="audit write failed"),
        ):
            AuditService.log_simple_event("view")

        (warning,) = check_audit_write_failures(None, databases=["default"])
        self.assertEqual(warning.id, "audit.W001")
        self.assertEqual(check_audit_write_failures(None, databases=None), [])


class DisableSignalsGateTests(SimpleTestCase):
    def test_the_flag_is_honoured_only_under_testing(self) -> None:
        with override_settings(DISABLE_AUDIT_SIGNALS=True, TESTING=True):
            self.assertTrue(audit_signals_disabled())
        # The warning is once per process: start from a process that has not warned yet.
        with (
            patch("apps.audit.switches._warned", False),
            override_settings(DISABLE_AUDIT_SIGNALS=True, TESTING=False),
            self.assertLogs("apps.audit.switches"),
        ):
            self.assertFalse(audit_signals_disabled())
        with override_settings(DISABLE_AUDIT_SIGNALS=False, TESTING=True):
            self.assertFalse(audit_signals_disabled())

    def test_nothing_else_reads_the_flag(self) -> None:
        readers = []
        for path in sorted(PLATFORM_APPS.rglob("*.py")):
            if "/tests/" in str(path) or path.name == "switches.py":
                continue
            if "DISABLE_AUDIT_SIGNALS" in path.read_text():
                tree = ast.parse(path.read_text())
                if any(
                    isinstance(node, ast.Constant) and node.value == "DISABLE_AUDIT_SIGNALS" for node in ast.walk(tree)
                ):
                    readers.append(str(path.relative_to(PLATFORM_APPS)))
        self.assertEqual(readers, [], "Read the flag through apps.audit.switches.audit_signals_disabled()")


class UnsentSignalsTests(SimpleTestCase):
    def test_every_custom_audit_signal_is_sent_by_some_code(self) -> None:
        tree = ast.parse((PLATFORM_APPS / "audit" / "signals.py").read_text())
        defined = {
            target.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Call)
            and ast.unparse(node.value.func) == "Signal"
            for target in node.targets
            if isinstance(target, ast.Name)
        }
        sources = "\n".join(path.read_text() for path in PLATFORM_APPS.rglob("*.py") if "/tests/" not in str(path))
        unsent = sorted(name for name in defined if f"{name}.send(" not in sources)
        self.assertEqual(unsent, [], "A signal nothing sends audits nothing: delete it with its receiver")
        self.assertEqual(defined, {"cookie_consent_updated"})


class AccountLockoutAuditTests(TestCase):
    @override_settings(ACCOUNT_LOCKOUT_THRESHOLD=2, DISABLE_ACCOUNT_LOCKOUT=False)
    def test_a_lockout_is_audited_when_it_begins(self) -> None:
        user = User.objects.create_user(email="lockout-subject@example.test", password="pw-1234-abcd")

        user.increment_failed_login_attempts()
        self.assertFalse(AuditEvent.objects.filter(action="account_locked").exists())
        user.increment_failed_login_attempts()

        (event,) = AuditEvent.objects.filter(action="account_locked")
        self.assertEqual(event.object_id, str(user.pk))
        self.assertEqual(event.actor_type, "system")
        self.assertEqual(event.metadata["failed_attempts_count"], 2)
        self.assertNotIn("lockout-subject@example.test", str(event.metadata) + event.description)

    @override_settings(ACCOUNT_LOCKOUT_THRESHOLD=1, DISABLE_ACCOUNT_LOCKOUT=False)
    def test_failures_while_locked_do_not_write_more_lockout_events(self) -> None:
        user = User.objects.create_user(email="lockout-twice@example.test", password="pw-1234-abcd")

        for _ in range(3):
            user.increment_failed_login_attempts()

        self.assertEqual(AuditEvent.objects.filter(action="account_locked").count(), 1)


class RequestIdentityTests(TestCase):
    def test_no_request_id_is_invented(self) -> None:
        event = AuditService.log_simple_event("view")
        self.assertEqual(event.request_id, "")

        carried = AuditService.log_event(
            AuditEventData(event_type="view"), AuditContext(request_id="req-from-the-edge")
        )
        self.assertEqual(carried.request_id, "req-from-the-edge")

    def test_only_the_start_of_a_user_agent_is_stored(self) -> None:
        long_agent = "Mozilla/5.0 " + "x" * 2000
        via_service = AuditService.log_event(AuditEventData(event_type="view"), AuditContext(user_agent=long_agent))
        direct = AuditEvent.objects.create(
            action="view", category="business_operation", severity="low", user_agent=long_agent
        )
        bulk = AuditEvent.objects.bulk_create(
            [AuditEvent(action="view", category="business_operation", severity="low", user_agent=long_agent)]
        )[0]

        for event in (via_service, direct, bulk):
            event.refresh_from_db()
            self.assertEqual(len(event.user_agent), USER_AGENT_MAX_LENGTH)
            self.assertTrue(event.user_agent.startswith("Mozilla/5.0 x"))

    def test_the_audit_logs_name_the_actor_by_id_not_by_email(self) -> None:
        user = User.objects.create_user(email="logged-actor@example.test", password="pw-1234-abcd")
        with self.assertLogs("apps.audit", level="INFO") as logs:
            AuditService.log_event(AuditEventData(event_type="view"), AuditContext(user=user))
            audit_signals._create_audit_event(action="view", user=user, description="x")

        text = "\n".join(logs.output)
        self.assertIn(f"user {user.pk}", text)
        self.assertNotIn("logged-actor@example.test", text)
