"""Guard against TransactionTestCase settings that break isolation on PostgreSQL."""

from __future__ import annotations

import ast
from pathlib import Path

from django.test import SimpleTestCase

_TESTS_ROOT = Path(__file__).resolve().parents[1]


def _classes_resetting_sequences(source: str) -> list[str]:
    """Reject sequence-reset assignments in classes, including helper bases and methods.

    Literal falsey values and annotations without a value are harmless. Treat
    expressions conservatively rather than trying to execute test source.
    """
    offenders: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.ClassDef):
            continue
        for statement in ast.walk(node):
            targets: list[ast.expr] = []
            value: ast.expr | None = None
            if isinstance(statement, ast.Assign):
                targets, value = statement.targets, statement.value
            elif isinstance(statement, ast.AnnAssign):
                targets, value = [statement.target], statement.value
            elif isinstance(statement, ast.AugAssign):
                targets = [statement.target]
                # The result depends on the previous value, so reject it.
                value = ast.Name(id="_unknown_reset_sequences")
            named = any(
                (isinstance(target, ast.Name) and target.id == "reset_sequences")
                or (isinstance(target, ast.Attribute) and target.attr == "reset_sequences")
                for assignment_target in targets
                for target in ast.walk(assignment_target)
            )
            if not named or value is None:
                continue
            try:
                enabled = bool(ast.literal_eval(value))
            except (ValueError, TypeError):
                enabled = True
            if enabled and node.name not in offenders:
                offenders.append(node.name)
    return offenders


class ResetSequencesGuardTests(SimpleTestCase):
    """Keep PostgreSQL sequences ahead of rows re-created by post_migrate.

    TransactionTestCase flushes without resetting sequences; post_migrate then
    restores content types, permissions, infrastructure schedules and an ORM
    queue entry for provider sync. Resetting sequences in the next setup can
    reuse an occupied queue id. An issued invoice queues payment reminders
    inside Invoice.save(); a swallowed queue IntegrityError without a savepoint
    can roll that save back.
    """

    def test_detector_flags_true_and_ignores_false(self) -> None:
        source = (
            "class Resets(TransactionTestCase):\n    reset_sequences = True\n"
            "class Annotated(TransactionTestCase):\n    reset_sequences: bool = True\n"
            "class Explicit(TransactionTestCase):\n    reset_sequences = False\n"
            "class One(TransactionTestCase):\n    reset_sequences = 1\n"
        )
        self.assertEqual(_classes_resetting_sequences(source), ["Resets", "Annotated", "One"])

    def test_detector_finds_resets_in_helper_bases(self) -> None:
        source = (
            "class Helper:\n    reset_sequences = True\n"
            "class Inherits(Helper, TransactionTestCase):\n    pass\n"
        )
        self.assertEqual(_classes_resetting_sequences(source), ["Helper"])

    def test_detector_finds_resets_in_setup_and_conditional_bodies(self) -> None:
        source = (
            "class Late(TransactionTestCase):\n"
            "    @classmethod\n"
            "    def setUpClass(cls):\n"
            "        cls.reset_sequences = True\n"
            "        super().setUpClass()\n"
            "class Conditional(TransactionTestCase):\n"
            "    if postgres:\n"
            "        reset_sequences = True\n"
        )
        self.assertEqual(_classes_resetting_sequences(source), ["Late", "Conditional"])

    def test_detector_ignores_falsey_literals_and_unassigned_annotations(self) -> None:
        source = (
            "class Zero(TransactionTestCase):\n    reset_sequences = 0\n"
            "class Unassigned(TransactionTestCase):\n    reset_sequences: bool\n"
            "class Disabled(TransactionTestCase):\n"
            "    @classmethod\n"
            "    def setUpClass(cls):\n"
            "        cls.reset_sequences = False\n"
        )
        self.assertEqual(_classes_resetting_sequences(source), [])

    def test_detector_rejects_expressions_and_augmented_assignments(self) -> None:
        source = (
            "class Expression(TransactionTestCase):\n    reset_sequences = ENABLE_RESETS\n"
            "class Augmented(TransactionTestCase):\n"
            "    @classmethod\n"
            "    def setUpClass(cls):\n"
            "        cls.reset_sequences |= True\n"
        )
        self.assertEqual(_classes_resetting_sequences(source), ["Expression", "Augmented"])

    def test_no_test_class_resets_sequences(self) -> None:
        offenders = [
            f"{path.relative_to(_TESTS_ROOT)}::{name}"
            for path in sorted(_TESTS_ROOT.rglob("*.py"))
            for name in _classes_resetting_sequences(path.read_text(encoding="utf-8"))
        ]
        self.assertEqual(offenders, [], "Drop reset_sequences; assert on the rows you created, not on their ids.")
