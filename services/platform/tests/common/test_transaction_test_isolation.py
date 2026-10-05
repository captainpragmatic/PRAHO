"""Guard against TransactionTestCase settings that break isolation on PostgreSQL."""

from __future__ import annotations

import ast
from pathlib import Path

from django.test import SimpleTestCase

_TESTS_ROOT = Path(__file__).resolve().parents[1]


def _sequence_reset_assignment(statement: ast.AST) -> tuple[list[ast.expr], ast.expr | None]:
    """Extract assignment targets and direct setattr calls without executing source."""
    if isinstance(statement, ast.Assign):
        return statement.targets, statement.value
    if isinstance(statement, ast.AnnAssign):
        return [statement.target], statement.value
    if isinstance(statement, ast.AugAssign):
        # The result depends on the previous value, so reject it.
        return [statement.target], ast.Name(id="_unknown_reset_sequences")
    if (
        isinstance(statement, ast.Call)
        and isinstance(statement.func, ast.Name)
        and statement.func.id == "setattr"
        and len(statement.args) == 3
        and isinstance(statement.args[1], ast.Constant)
        and statement.args[1].value == "reset_sequences"
    ):
        return [ast.Attribute(value=statement.args[0], attr="reset_sequences")], statement.args[2]
    return [], None


def _reset_sequences_enabled(value: ast.expr | None) -> bool:
    """Allow only literal falsey values and annotations without a value."""
    if value is None:
        return False
    try:
        return bool(ast.literal_eval(value))
    except (ValueError, TypeError):
        return True


def _classes_resetting_sequences(source: str) -> list[str]:
    """Reject class assignments, external attribute assignments and setattr calls.

    Literal falsey values and annotations without a value are harmless. Treat
    expressions conservatively rather than trying to execute test source.
    """
    tree = ast.parse(source)
    offenders: list[str] = []
    class_nodes: set[ast.AST] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        class_nodes.update(ast.walk(node))
        for statement in ast.walk(node):
            if isinstance(statement, ast.Call):
                continue
            targets, value = _sequence_reset_assignment(statement)
            named = any(
                (isinstance(target, ast.Name) and target.id == "reset_sequences")
                or (isinstance(target, ast.Attribute) and target.attr == "reset_sequences")
                for assignment_target in targets
                for target in ast.walk(assignment_target)
            )
            if named and _reset_sequences_enabled(value) and node.name not in offenders:
                offenders.append(node.name)
    for statement in ast.walk(tree):
        if statement in class_nodes and not isinstance(statement, ast.Call):
            continue
        targets, value = _sequence_reset_assignment(statement)
        if not _reset_sequences_enabled(value):
            continue
        objects = (
            target.value
            for assignment_target in targets
            for target in ast.walk(assignment_target)
            if isinstance(target, ast.Attribute) and target.attr == "reset_sequences"
        )
        for obj in objects:
            name = obj.id if isinstance(obj, ast.Name) else "<module>"
            if name not in offenders:
                offenders.append(name)
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

    def test_detector_finds_module_level_attribute_assignments(self) -> None:
        source = "class Case(TransactionTestCase):\n    pass\nCase.reset_sequences = True\n"
        self.assertEqual(_classes_resetting_sequences(source), ["Case"])

    def test_detector_finds_function_level_attribute_assignments(self) -> None:
        source = "def enable_resets():\n    Case.reset_sequences = ENABLE_RESETS\n"
        self.assertEqual(_classes_resetting_sequences(source), ["Case"])

    def test_detector_finds_setattr_calls_anywhere(self) -> None:
        source = (
            "class Case(TransactionTestCase):\n    pass\n"
            'setattr(Case, "reset_sequences", True)\n'
            "def enable_resets():\n"
            '    setattr(FunctionCase, "reset_sequences", ENABLE_RESETS)\n'
            "class Helper:\n"
            "    def configure(self):\n"
            '        setattr(MethodCase, "reset_sequences", 1)\n'
        )
        self.assertEqual(_classes_resetting_sequences(source), ["Case", "FunctionCase", "MethodCase"])

    def test_detector_ignores_falsey_external_assignments(self) -> None:
        for value in ("False", "0", "None", '""', "[]", "{}", "()"):
            with self.subTest(value=value):
                source = (
                    f"Case.reset_sequences = {value}\n"
                    f"Annotated.reset_sequences: bool = {value}\n"
                    f'setattr(Case, "reset_sequences", {value})\n'
                    f"def disable_resets():\n    Case.reset_sequences = {value}\n"
                )
                self.assertEqual(_classes_resetting_sequences(source), [])
        self.assertEqual(_classes_resetting_sequences("Case.reset_sequences: bool\n"), [])

    def test_detector_rejects_external_expressions_and_augmented_assignments(self) -> None:
        source = (
            "Case.reset_sequences = ENABLE_RESETS\n"
            "Case.reset_sequences = True\n"
            "Annotated.reset_sequences: bool = True\n"
            "Augmented.reset_sequences |= False\n"
        )
        self.assertEqual(_classes_resetting_sequences(source), ["Case", "Annotated", "Augmented"])

    def test_detector_reports_unresolved_objects_as_module(self) -> None:
        for source in (
            "get_case().reset_sequences = True\n",
            'setattr(get_case(), "reset_sequences", ENABLE_RESETS)\n',
        ):
            with self.subTest(source=source):
                self.assertEqual(_classes_resetting_sequences(source), ["<module>"])

    def test_detector_ignores_unrelated_external_assignments(self) -> None:
        source = 'reset_sequences = True\nCase.other_setting = True\nsetattr(Case, "other_setting", True)\n'
        self.assertEqual(_classes_resetting_sequences(source), [])

    def test_no_test_class_resets_sequences(self) -> None:
        offenders = [
            f"{path.relative_to(_TESTS_ROOT)}::{name}"
            for path in sorted(_TESTS_ROOT.rglob("*.py"))
            for name in _classes_resetting_sequences(path.read_text(encoding="utf-8"))
        ]
        self.assertEqual(offenders, [], "Drop reset_sequences; assert on the rows you created, not on their ids.")
