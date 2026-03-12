"""
Unit tests for code_health_scan.py — validates each rule against inline Python snippets.
"""

from __future__ import annotations

import ast
import sys
import textwrap
from pathlib import Path
from unittest import TestCase

# scripts/ is not on PYTHONPATH for platform tests — add it for import
_SCRIPTS_DIR = str(Path(__file__).resolve().parents[4] / "scripts")
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

from code_health_scan import CodeHealthVisitor, Issue  # noqa: E402


def _scan_snippet(source: str, filename: str = "apps/example/services.py") -> list[Issue]:
    """Parse an inline Python snippet and run CodeHealthVisitor on it."""
    source = textwrap.dedent(source)
    tree = ast.parse(source, filename=filename)
    visitor = CodeHealthVisitor(file_path=Path(filename), source_lines=source.splitlines())
    visitor.visit(tree)
    return visitor.issues


class TestTodoStubRule(TestCase):
    """Rule: todo-stub — functions with TODO markers and placeholder bodies."""

    def test_todo_stub_detected(self) -> None:
        issues = _scan_snippet("""
            def process_payment():
                # TODO: implement real payment processing
                return True
        """)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].code, "todo-stub")
        self.assertEqual(issues[0].severity, "high")

    def test_todo_stub_no_false_positive(self) -> None:
        """A function with TODO but real branching logic is NOT a stub."""
        issues = _scan_snippet("""
            def process_payment(amount):
                # TODO: add retry logic
                if amount <= 0:
                    raise ValueError("Invalid amount")
                return process(amount)
        """)
        todo_issues = [i for i in issues if i.code == "todo-stub"]
        self.assertEqual(len(todo_issues), 0)

    def test_todo_stub_pass_body(self) -> None:
        issues = _scan_snippet("""
            def placeholder():
                # FIXME: not yet done
                pass
        """)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].code, "todo-stub")

    def test_todo_stub_docstring_only(self) -> None:
        issues = _scan_snippet('''
            def placeholder():
                """HACK: temporary stub"""
        ''')
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].code, "todo-stub")


class TestMagicGetattrRule(TestCase):
    """Rule: magic-getattr-default — large numeric getattr defaults."""

    def test_magic_getattr_above_threshold(self) -> None:
        issues = _scan_snippet("""
            total = getattr(order, "total_cents", 15000)
        """)
        magic = [i for i in issues if i.code == "magic-getattr-default"]
        self.assertEqual(len(magic), 1)
        self.assertEqual(magic[0].severity, "medium")

    def test_magic_getattr_below_threshold(self) -> None:
        issues = _scan_snippet("""
            total = getattr(order, "total_cents", 50)
        """)
        magic = [i for i in issues if i.code == "magic-getattr-default"]
        self.assertEqual(len(magic), 0)

    def test_magic_getattr_string_default_ignored(self) -> None:
        issues = _scan_snippet("""
            val = getattr(obj, "name", "unknown")
        """)
        magic = [i for i in issues if i.code == "magic-getattr-default"]
        self.assertEqual(len(magic), 0)


class TestAlwaysTrueAuthRule(TestCase):
    """Rule: always-true-auth — auth functions that unconditionally return True."""

    def test_always_true_auth_critical(self) -> None:
        issues = _scan_snippet("""
            def verify_token(token):
                return True
        """)
        auth = [i for i in issues if i.code == "always-true-auth"]
        self.assertEqual(len(auth), 1)
        self.assertEqual(auth[0].severity, "critical")

    def test_always_true_auth_with_branching(self) -> None:
        """Auth function with real logic should not be flagged."""
        issues = _scan_snippet("""
            def verify_token(token):
                if not token:
                    return False
                return hmac.compare_digest(token, expected)
        """)
        auth = [i for i in issues if i.code == "always-true-auth"]
        self.assertEqual(len(auth), 0)

    def test_always_true_auth_with_docstring(self) -> None:
        """Even with a docstring, unconditional return True is flagged."""
        issues = _scan_snippet('''
            def authenticate_user(credentials):
                """Authenticate a user."""
                return True
        ''')
        auth = [i for i in issues if i.code == "always-true-auth"]
        self.assertEqual(len(auth), 1)

    def test_non_auth_function_not_flagged(self) -> None:
        """Functions without auth prefixes are not checked."""
        issues = _scan_snippet("""
            def process_data():
                return True
        """)
        auth = [i for i in issues if i.code == "always-true-auth"]
        self.assertEqual(len(auth), 0)


class TestSaveWithoutAtomicRule(TestCase):
    """Rule: save-without-atomic — .save() in service files without transaction.atomic()."""

    def test_save_without_atomic_in_service(self) -> None:
        issues = _scan_snippet(
            """
            def update_customer(customer):
                customer.name = "New"
                customer.save()
            """,
            filename="apps/customers/services.py",
        )
        saves = [i for i in issues if i.code == "save-without-atomic"]
        self.assertEqual(len(saves), 1)

    def test_save_inside_atomic_no_issue(self) -> None:
        issues = _scan_snippet(
            """
            from django.db import transaction
            def update_customer(customer):
                with transaction.atomic():
                    customer.name = "New"
                    customer.save()
            """,
            filename="apps/customers/services.py",
        )
        saves = [i for i in issues if i.code == "save-without-atomic"]
        self.assertEqual(len(saves), 0)

    def test_save_with_update_fields_no_issue(self) -> None:
        """save(update_fields=[...]) is targeted and safe — not flagged."""
        issues = _scan_snippet(
            """
            def update_customer(customer):
                customer.name = "New"
                customer.save(update_fields=["name"])
            """,
            filename="apps/customers/services.py",
        )
        saves = [i for i in issues if i.code == "save-without-atomic"]
        self.assertEqual(len(saves), 0)

    def test_save_in_non_service_file_no_issue(self) -> None:
        """Non-service files are exempt."""
        issues = _scan_snippet(
            """
            def update_customer(customer):
                customer.save()
            """,
            filename="apps/customers/views.py",
        )
        saves = [i for i in issues if i.code == "save-without-atomic"]
        self.assertEqual(len(saves), 0)


class TestSignalSavesSenderRule(TestCase):
    """Rule: signal-saves-sender — post_save handlers calling .save() without guard."""

    def test_signal_saves_sender_flagged(self) -> None:
        issues = _scan_snippet("""
            from django.db.models.signals import post_save
            from django.dispatch import receiver

            @receiver(post_save, sender=MyModel)
            def update_totals(sender, instance, **kwargs):
                instance.total = calculate()
                instance.save()
        """)
        signal = [i for i in issues if i.code == "signal-saves-sender"]
        self.assertEqual(len(signal), 1)
        self.assertEqual(signal[0].severity, "medium")

    def test_signal_with_guard_no_issue(self) -> None:
        issues = _scan_snippet("""
            from django.db.models.signals import post_save
            from django.dispatch import receiver

            @receiver(post_save, sender=MyModel)
            def update_totals(sender, instance, **kwargs):
                if getattr(instance, '_processing', False):
                    return
                instance._processing = True
                instance.total = calculate()
                instance.save()
        """)
        signal = [i for i in issues if i.code == "signal-saves-sender"]
        self.assertEqual(len(signal), 0)

    def test_signal_with_update_fields_guard(self) -> None:
        """update_fields in source text is recognized as a guard."""
        issues = _scan_snippet("""
            from django.db.models.signals import post_save
            from django.dispatch import receiver

            @receiver(post_save, sender=MyModel)
            def update_totals(sender, instance, update_fields=None, **kwargs):
                if update_fields and 'total' not in update_fields:
                    return
                instance.total = calculate()
                instance.save(update_fields=['total'])
        """)
        signal = [i for i in issues if i.code == "signal-saves-sender"]
        self.assertEqual(len(signal), 0)
