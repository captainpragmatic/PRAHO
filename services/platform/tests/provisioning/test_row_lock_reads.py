"""Provisioning locks rows with FOR UPDATE OF self join-free and reads related rows after the lock.

PostgreSQL docs, "Transaction Isolation" (Read Committed): a SELECT ... FOR UPDATE that waits for a
concurrent update re-checks only the newest version of the row it locks; rows joined in the same
statement keep the values of the statement's starting snapshot.
"""

from __future__ import annotations

import ast
from pathlib import Path

from django.test import SimpleTestCase

PROVISIONING = Path(__file__).resolve().parents[2] / "apps" / "provisioning"


def _chain(call: ast.Call) -> list[ast.Call]:
    """Every call in one method chain, from the outermost call down."""
    calls = []
    node: ast.expr = call
    while isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        calls.append(node)
        node = node.func.value
    return calls


def lock_join_lines(source: str) -> list[int]:
    """Lines where one chain both locks OF self (select_for_update(of=...)) and joins (select_related)."""
    tree = ast.parse(source)
    inner = {id(call) for node in ast.walk(tree) if isinstance(node, ast.Call) for call in _chain(node)[1:]}
    lines = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or id(node) in inner:
            continue  # Inspect each chain once, from its outermost call.
        calls = _chain(node)
        names = {call.func.attr for call in calls if isinstance(call.func, ast.Attribute)}
        locks_self = [
            call
            for call in calls
            if isinstance(call.func, ast.Attribute)
            and call.func.attr == "select_for_update"
            and any(keyword.arg == "of" for keyword in call.keywords)
        ]
        if locks_self and "select_related" in names:
            lines.append(locks_self[0].lineno)
    return sorted(lines)


class LockJoinDetectionTests(SimpleTestCase):
    def test_catches_either_order_and_calls_in_between(self) -> None:
        cases = {
            'M.objects.select_for_update(of=("self",)).select_related("service").get(pk=1)': [1],
            'M.objects.select_related("service").select_for_update(of=("self",)).get(pk=1)': [1],
            'M.objects.select_for_update(of=("self",)).filter(pk=1).select_related("a__b").first()': [1],
            'M.objects.select_related("s").filter(pk=1).select_for_update(no_key=True, of=("self",))': [1],
        }
        for source, expected in cases.items():
            with self.subTest(source=source):
                self.assertEqual(lock_join_lines(source), expected)

    def test_ignores_locks_of_every_joined_row_and_separate_statements(self) -> None:
        cases = (
            'M.objects.select_for_update().select_related("service").get(pk=1)',  # Joined rows are locked too.
            'a = M.objects.select_for_update(of=("self",)).get(pk=1)\nb = M.objects.select_related("s").get(pk=1)',
        )
        for source in cases:
            with self.subTest(source=source):
                self.assertEqual(lock_join_lines(source), [])


class RowLockReadsTests(SimpleTestCase):
    def test_no_row_lock_joins_rows_it_does_not_lock(self) -> None:
        offenders = [
            f"{path.relative_to(PROVISIONING)}:{line}"
            for path in sorted(PROVISIONING.rglob("*.py"))
            if "migrations" not in path.parts
            for line in lock_join_lines(path.read_text(encoding="utf-8"))
        ]
        self.assertEqual(offenders, [])
